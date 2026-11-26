#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use debar_clamav_signatures::{
    Account, DatabaseError, DatabaseFile, LineOutcome, MalformedExpression, MalformedLogicalLine,
    MalformedSubsignature, compile,
};
use debar_image::{
    Image, ImageBuilder, InclusiveRange, KindCondition, LogicalSignatureId, ObjectKind,
    SignatureGroup, UnwantedCategory,
};

const GENERIC: SignatureGroup = SignatureGroup(0);

fn compile_ldb(name: &str, text: &str) -> Result<(Vec<u8>, Account), DatabaseError> {
    let files = [DatabaseFile {
        name,
        contents: text.as_bytes(),
    }];
    let mut builder = ImageBuilder::new();
    let account = compile(&files, &mut builder)?;
    Ok((builder.finish().unwrap(), account))
}

fn outcomes(text: &str) -> Vec<LineOutcome> {
    compile_ldb("test.ldb", text).unwrap().1.files[0]
        .lines
        .clone()
}

fn malformed(text: &str) -> MalformedLogicalLine {
    match compile_ldb("test.ldb", text) {
        Err(DatabaseError::MalformedLogicalLine { reason, .. }) => reason,
        other => panic!("expected a malformed line, got {other:?}"),
    }
}

fn holds(expression: &str, subsignatures: usize, counts: &[u64]) -> bool {
    let bodies = vec!["41424344"; subsignatures].join(";");
    let (bytes, _) = compile_ldb(
        "test.ldb",
        &format!("Test.L;Target:0;{expression};{bodies}\n"),
    )
    .unwrap();
    let image = Image::open(&bytes).unwrap();
    let group = image.logical_group(GENERIC).unwrap().unwrap();
    let record = group.signature(LogicalSignatureId(0)).unwrap();
    group
        .expression_holds(LogicalSignatureId(0), &record, |index| {
            counts[usize::from(index)]
        })
        .unwrap()
}

#[test]
fn every_logical_line_has_one_outcome() {
    let text = "\
#a comment
Test.Engine;Engine:51-233,Target:0;0;41424344
Test.Target15;Target:15;0;41424344
Test.Unknown;Target:0,Colour:red;0;41424344
Test.UnknownType;Engine:51-255,Target:0,Container:CL_TYPE_NONSENSE;0;41424344
Test.Regex;Target:0;0&1;41424344;0/abc/
Test.Compiled;Engine:51-255,Target:0;0&1;41424344;45464748::i
";
    assert_eq!(
        outcomes(text),
        [
            LineOutcome::Comment,
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::TargetNotLoaded,
            LineOutcome::NotLoaded,
            LineOutcome::NotLoaded,
            LineOutcome::NotYetCompiled,
            LineOutcome::Compiled,
        ]
    );
}

#[test]
fn an_unparenthesised_chain_splits_at_its_first_operator() {
    assert!(holds("0|1&2", 3, &[1, 0, 0]));
    assert!(!holds("0&1|2", 3, &[0, 0, 1]));
    assert!(holds("0&1|2", 3, &[1, 0, 1]));
}

#[test]
fn a_parenthesised_chain_splits_at_its_last_operator() {
    assert!(holds("(0&1|2)", 3, &[0, 0, 1]));
    assert!(!holds("(0|1&2)", 3, &[1, 0, 0]));
}

#[test]
fn count_modifiers_compare_a_leaf_or_a_block() {
    assert!(holds("0>2", 1, &[3]));
    assert!(!holds("0>2", 1, &[2]));
    assert!(holds("0=0&1", 2, &[0, 1]));
    assert!(holds("(0|1)>1,2", 2, &[1, 1]));
    assert!(!holds("(0|1)>1,2", 2, &[2, 0]));
    assert!(holds("0=1,2", 1, &[1]));
}

#[test]
fn text_after_a_leaf_index_that_is_not_a_modifier_is_ignored() {
    assert!(holds("0:0&1", 2, &[1, 1]));
}

#[test]
fn a_malformed_expression_or_count_fails_the_compile() {
    for (text, reason) in [
        (
            "T;Target:0;(0&1;41424344;45464748\n",
            MalformedLogicalLine::Expression(MalformedExpression::UnbalancedParentheses),
        ),
        (
            "T;Target:0;(0)=1;41424344\n",
            MalformedLogicalLine::Expression(MalformedExpression::ModifierOnAGroupWithoutOperator),
        ),
        (
            "T;Target:0;0&1;41424344\n",
            MalformedLogicalLine::SubsignatureCountDisagrees { named: 2, given: 1 },
        ),
        (
            "T;Target:0;0;41424344;45464748\n",
            MalformedLogicalLine::SubsignatureCountDisagrees { named: 1, given: 2 },
        ),
        ("T;Target:0;0\n", MalformedLogicalLine::TooFewFields),
        (
            "T;Engine:51-255;0;41424344\n",
            MalformedLogicalLine::NoTarget,
        ),
        (
            "T;Target:0,Engine:51-255;0;41424344\n",
            MalformedLogicalLine::EngineNotFirst,
        ),
        (
            "T;Target:0,FileSize:1-9;0;41424344\n",
            MalformedLogicalLine::AttributeNeedsEngine,
        ),
        (
            "T;Engine:51-255,Target:0,FileSize:9;0;41424344\n",
            MalformedLogicalLine::MalformedAttribute,
        ),
        (
            "T;Engine:51-255,Target:0,IconGroup1:x;0;41424344\n",
            MalformedLogicalLine::IconGroupOnTarget { target: 0 },
        ),
        (";Target:0;0;41424344\n", MalformedLogicalLine::EmptyName),
        (
            "T;Target:0;0;41424344::z\n",
            MalformedLogicalLine::Subsignature {
                index: 0,
                reason: MalformedSubsignature::UnknownModifier(b'z'),
            },
        ),
    ] {
        assert_eq!(malformed(text), reason, "{text}");
    }
}

#[test]
fn a_line_skipped_by_its_engine_range_still_fails_on_a_bad_expression() {
    assert!(matches!(
        malformed("T;Engine:300-400,Target:0;0&;41424344\n"),
        MalformedLogicalLine::Expression(_)
    ));
    assert_eq!(
        outcomes("T;Engine:300-400,Target:0;0;zz\n"),
        [LineOutcome::OutsideFunctionalityLevel]
    );
}

#[test]
fn a_two_byte_subsignature_body_loads() {
    assert_eq!(outcomes("T;Target:0;0;4142\n"), [LineOutcome::Compiled]);
}

#[test]
fn conditions_are_kept_with_the_signature() {
    let (bytes, _) = compile_ldb(
        "test.ldb",
        "T;Engine:51-255,Target:1,FileSize:10-20,Container:CL_TYPE_ZIP,Intermediates:CL_TYPE_ANY>CL_TYPE_ZIP,NumberOfSections:2-3,HandlerType:CL_TYPE_PDF;0;41424344\n",
    )
    .unwrap();
    let image = Image::open(&bytes).unwrap();
    let group = image.logical_group(SignatureGroup(1)).unwrap().unwrap();
    let record = group.signature(LogicalSignatureId(0)).unwrap();
    let conditions = group.conditions(&record).unwrap().unwrap();
    assert_eq!(
        conditions.file_size,
        Some(InclusiveRange {
            lowest: 10,
            highest: 20
        })
    );
    assert_eq!(
        conditions.container,
        Some(KindCondition::Kind(ObjectKind::Zip))
    );
    assert_eq!(
        conditions.intermediates,
        [KindCondition::AnyKind, KindCondition::Kind(ObjectKind::Zip)]
    );
    assert_eq!(
        conditions.number_of_sections,
        Some(InclusiveRange {
            lowest: 2,
            highest: 3
        })
    );
    assert_eq!(conditions.handler_type, Some(ObjectKind::Pdf));
}

#[test]
fn a_potentially_unwanted_line_is_kept_with_its_category() {
    let (bytes, account) = compile_ldb(
        "test.ldu",
        "PUA.Win.Packer.Thing-1;Target:0;0;41424344\nPUA.Lonely;Target:0;0;45464748\n",
    )
    .unwrap();
    assert_eq!(
        account.files[0].kind,
        "logical signatures, potentially unwanted"
    );
    let image = Image::open(&bytes).unwrap();
    let group = image.logical_group(GENERIC).unwrap().unwrap();
    let categories: Vec<Option<UnwantedCategory<'_>>> = (0..2)
        .map(|id| {
            let record = group.signature(LogicalSignatureId(id)).unwrap();
            image.unwanted_category(record.name).unwrap()
        })
        .collect();
    assert_eq!(
        categories,
        [
            Some(UnwantedCategory::Named(".Win.Packer.")),
            Some(UnwantedCategory::Unnamed)
        ]
    );
}
