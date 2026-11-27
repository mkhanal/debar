#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use debar_image::{
    ByteComparison, ByteEncoding, ByteOrder, ByteSet, Category, ContainerSignature,
    ContentSubsignature, CountComparison, CountTest, Expression, ExpressionAnchoring,
    ExpressionForm, ExpressionMatches, ExpressionTree, Greed, Image, ImageBuilder, Indicator,
    KindCondition, KindDescription, LogicalConditions, LogicalOutcome, LogicalSignature,
    LookDirection, MaskedByte, ObjectKind, OwnBytes, Pattern, PatternElement, Placement,
    RecognitionRank, RegularExpressionSubsignature, ReportWindows, SignatureGroup,
    SignatureProgramId, SizeCondition, Subsignature, TreeRepetition, ValueComparison,
};
use debar_matching::{
    ContainerEntry, GroupSelection, ObjectContext, PatternRequest, PatternSettings,
    UnwantedCategories, container_entry_detections, scan_object,
};
use regex_syntax::hir::Hir;

const GENERIC: SignatureGroup = SignatureGroup(0);

fn hir(pattern: &str) -> Hir {
    regex_syntax::ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .build()
        .parse(pattern)
        .unwrap()
}

fn content(bytes: &[u8]) -> Subsignature {
    Subsignature::Content(ContentSubsignature {
        placement: Placement::Anywhere,
        patterns: vec![Pattern {
            before: None,
            elements: bytes
                .iter()
                .map(|byte| PatternElement::Byte(MaskedByte::exactly(*byte)))
                .collect(),
            after: None,
        }],
    })
}

fn leaf(index: u16) -> Expression {
    Expression::Subsignature { index, count: None }
}

fn counted(index: u16, comparison: CountComparison) -> Expression {
    Expression::Subsignature {
        index,
        count: Some(CountTest {
            comparison,
            distinct_at_least: 0,
        }),
    }
}

fn regular(pattern: &str) -> RegularExpressionSubsignature {
    RegularExpressionSubsignature {
        trigger: Some(leaf(0)),
        placement: Placement::Anywhere,
        expression: ExpressionForm::Linear(hir(pattern)),
        anchoring: ExpressionAnchoring::AtAnUnshiftedPlacement,
        matches: ExpressionMatches::First,
        bounded_by_shift: false,
    }
}

fn binary_data() -> KindDescription {
    KindDescription {
        format_name: "binary data".to_owned(),
        groups: vec![GENERIC],
        recognition: RecognitionRank::default(),
        own_bytes: OwnBytes::Matched {
            as_kind: None,
            recognising_types: false,
        },
        matched_again_as: None,
        found_in_full_scan_retypes: Vec::new(),
        executable: false,
    }
}

struct Signature {
    name: &'static str,
    expression: Expression,
    subsignatures: Vec<Subsignature>,
}

fn image_of(signatures: &[Signature], windows: Option<ReportWindows>) -> Vec<u8> {
    let mut builder = ImageBuilder::new();
    for signature in signatures {
        builder
            .add_logical_signature(&LogicalSignature {
                outcome: LogicalOutcome::Detection,
                group: GENERIC,
                category: Category::Malware,
                name: signature.name,
                indicator: Indicator::Strong,
                expression: &signature.expression,
                subsignatures: &signature.subsignatures,
                conditions: &LogicalConditions::default(),
            })
            .unwrap();
    }
    if let Some(windows) = windows {
        builder.set_report_windows(GENERIC, windows);
    }
    builder.describe_object_kind(ObjectKind::BinaryData, binary_data());
    builder.finish().unwrap()
}

fn detected_with(
    image: &[u8],
    object: &[u8],
    image_fuzzy_hash: Option<u64>,
    largest: Option<u64>,
) -> Vec<String> {
    let image = Image::open(image).unwrap();
    let request = PatternRequest {
        selection: GroupSelection::ForKind(ObjectKind::BinaryData),
        settings: PatternSettings {
            potentially_unwanted: false,
            unwanted_categories: UnwantedCategories::Every,
            every_match: true,
            largest_object_for_regular_expressions: largest,
        },
        object_length: object.len() as u64,
        context: ObjectContext::TOP_LEVEL,
        image_fuzzy_hash,
    };
    scan_object(&image, request, || None, object)
        .unwrap()
        .logical
        .detections
        .into_iter()
        .map(|detection| detection.name)
        .collect()
}

fn detected(signature: Signature, object: &[u8]) -> bool {
    !detected_with(&image_of(&[signature], None), object, None, None).is_empty()
}

fn with_expression(expression: Expression, regular: RegularExpressionSubsignature) -> Signature {
    Signature {
        name: "Test.Regular",
        expression,
        subsignatures: vec![content(b"MARK"), Subsignature::RegularExpression(regular)],
    }
}

#[test]
fn a_regular_expression_matches_only_when_its_trigger_holds() {
    let signature = || with_expression(leaf(1), regular("x[0-9]+y"));
    assert!(detected(signature(), b"MARK....x123y"));
    assert!(!detected(signature(), b"....x123y"));
    assert!(!detected(signature(), b"MARK....xy"));
}

#[test]
fn a_regular_expression_from_a_start_offset_is_anchored_there() {
    let placed = |searching| RegularExpressionSubsignature {
        placement: Placement::FromStart {
            distance: 6,
            shift: 0,
        },
        anchoring: if searching {
            ExpressionAnchoring::NeverAtThePlacement
        } else {
            ExpressionAnchoring::AtAnUnshiftedPlacement
        },
        ..regular("abc")
    };
    assert!(detected(
        with_expression(leaf(1), placed(false)),
        b"MARK..abc"
    ));
    assert!(!detected(
        with_expression(leaf(1), placed(false)),
        b"MARK...abc"
    ));
    assert!(detected(
        with_expression(leaf(1), placed(true)),
        b"MARK...abc"
    ));
}

#[test]
fn a_shift_limits_where_a_match_may_start_unless_the_subject_is_bounded() {
    let shifted = |shift, bounded| RegularExpressionSubsignature {
        placement: Placement::FromStart { distance: 4, shift },
        bounded_by_shift: bounded,
        ..regular("abc")
    };
    assert!(detected(
        with_expression(leaf(1), shifted(2, false)),
        b"MARK..abc"
    ));
    assert!(!detected(
        with_expression(leaf(1), shifted(2, false)),
        b"MARK...abc"
    ));
    assert!(detected(
        with_expression(leaf(1), shifted(3, true)),
        b"MARKabc"
    ));
    assert!(!detected(
        with_expression(leaf(1), shifted(2, true)),
        b"MARKabc"
    ));
}

#[test]
fn an_offset_before_the_end_wrapping_to_one_before_the_start_searches_the_whole_object() {
    let before_end = |distance| RegularExpressionSubsignature {
        placement: Placement::BeforeEnd { distance, shift: 0 },
        ..regular("abc")
    };
    let object = b"MARK..abc.";
    let length = object.len() as u32;
    assert!(detected(with_expression(leaf(1), before_end(4)), object));
    assert!(!detected(with_expression(leaf(1), before_end(5)), object));
    assert!(detected(
        with_expression(leaf(1), before_end(length + 1)),
        object
    ));
    assert!(!detected(
        with_expression(leaf(1), before_end(length + 2)),
        object
    ));
}

#[test]
fn every_match_counts_matches_that_do_not_overlap() {
    let global = |pattern: &str| RegularExpressionSubsignature {
        matches: ExpressionMatches::EveryOneNotOverlapping,
        ..regular(pattern)
    };
    let three = || counted(1, CountComparison::Exactly(3));
    assert!(detected(
        with_expression(three(), global("abc")),
        b"MARKabcabcabc"
    ));
    assert!(!detected(
        with_expression(three(), regular("abc")),
        b"MARKabcabcabc"
    ));
    assert!(detected(
        with_expression(counted(1, CountComparison::Exactly(2)), global("aa")),
        b"MARKaaaa"
    ));
    assert!(detected(
        with_expression(counted(1, CountComparison::Exactly(4)), global("a+?")),
        b"MARKaaaa"
    ));
    assert!(detected(
        with_expression(counted(1, CountComparison::Exactly(1)), global("x*")),
        b"MARKabc"
    ));
}

#[test]
fn a_later_regular_expression_sees_an_earlier_ones_matches_in_its_trigger() {
    let signature = Signature {
        name: "Test.Chained",
        expression: leaf(2),
        subsignatures: vec![
            content(b"MARK"),
            Subsignature::RegularExpression(regular("one")),
            Subsignature::RegularExpression(RegularExpressionSubsignature {
                trigger: Some(leaf(1)),
                ..regular("two")
            }),
        ],
    };
    assert!(detected(signature, b"MARK one two"));
}

#[test]
fn regular_expressions_are_not_matched_in_an_object_larger_than_the_limit() {
    let image = image_of(&[with_expression(leaf(1), regular("abc"))], None);
    let object = b"MARK.....abc";
    assert_eq!(
        detected_with(&image, object, None, Some(object.len() as u64)),
        ["Test.Regular"]
    );
    assert_eq!(
        detected_with(&image, object, None, Some(object.len() as u64 - 1)),
        Vec::<String>::new()
    );
}

#[test]
fn an_expression_that_exhausts_a_backtracking_engines_step_limit_still_matches() {
    let mut nested = b"MARK".to_vec();
    nested.extend(std::iter::repeat_n(b'a', 25));
    nested.extend_from_slice(b"cab");
    assert!(detected(
        with_expression(leaf(1), regular("(a+)+b")),
        &nested
    ));
    let mut deep = b"MARK".to_vec();
    deep.extend(std::iter::repeat_n(b'a', 5_000));
    deep.push(b'c');
    assert!(detected(
        with_expression(leaf(1), regular("(a|ab)*c")),
        &deep
    ));
}

fn comparison(
    displacement: i64,
    encoding: ByteEncoding,
    values: Vec<ValueComparison>,
) -> Signature {
    Signature {
        name: "Test.Compared",
        expression: leaf(1),
        subsignatures: vec![
            content(b"MARK"),
            Subsignature::ByteComparison(ByteComparison {
                subsignature: 0,
                displacement,
                encoding,
                length: 2,
                exact: false,
                comparisons: values,
            }),
        ],
    }
}

#[test]
fn a_byte_comparison_reads_after_the_last_match_of_its_subsignature() {
    let greater = || vec![ValueComparison::Greater(512)];
    let big = ByteEncoding::Binary(ByteOrder::Big);
    assert!(detected(comparison(4, big, greater()), b"..MARK\x02\x01"));
    assert!(!detected(comparison(4, big, greater()), b"..MARK\x02\x00"));
    assert!(!detected(
        comparison(4, ByteEncoding::Binary(ByteOrder::Little), greater()),
        b"..MARK\x02\x01"
    ));
    assert!(!detected(
        comparison(4, big, greater()),
        b"..MARK\x02\x01MARK\x00"
    ));
    assert!(detected(
        comparison(
            4,
            ByteEncoding::HexadecimalText(ByteOrder::Big),
            vec![ValueComparison::Equal(0x1f)]
        ),
        b"..MARK1F"
    ));
    assert!(!detected(comparison(0, big, greater()), b"MARK\x02\x01"));
    assert!(!detected(comparison(4, big, greater()), b"..MARK\x02"));
}

#[test]
fn a_byte_comparison_reads_only_within_the_first_window() {
    let windows = Some(ReportWindows {
        length: 64,
        overlap: 8,
    });
    let signature = || {
        comparison(
            4,
            ByteEncoding::Binary(ByteOrder::Big),
            vec![ValueComparison::Greater(512)],
        )
    };
    let mut early = b"..MARK\x02\x01".to_vec();
    early.resize(200, b'.');
    assert_ne!(
        detected_with(&image_of(&[signature()], windows), &early, None, None),
        Vec::<String>::new()
    );
    let mut late = vec![b'.'; 100];
    late.extend_from_slice(b"MARK\x02\x01");
    late.resize(200, b'.');
    assert_eq!(
        detected_with(&image_of(&[signature()], windows), &late, None, None),
        Vec::<String>::new()
    );
}

#[test]
fn an_image_fuzzy_hash_counts_once_for_each_window() {
    let signature = |expression| Signature {
        name: "Test.Image",
        expression,
        subsignatures: vec![Subsignature::ImageFuzzyHash(0x803f_7967_6c59_5235)],
    };
    let windows = Some(ReportWindows {
        length: 64,
        overlap: 8,
    });
    let object = vec![b'.'; 100];
    let image = image_of(&[signature(leaf(0))], windows);
    assert_eq!(
        detected_with(&image, &object, Some(0x803f_7967_6c59_5235), None),
        ["Test.Image"]
    );
    assert_eq!(
        detected_with(&image, &object, Some(1), None),
        Vec::<String>::new()
    );
    assert_eq!(
        detected_with(&image, &object, None, None),
        Vec::<String>::new()
    );
    let twice = image_of(
        &[signature(counted(0, CountComparison::Exactly(2)))],
        windows,
    );
    assert_eq!(
        detected_with(&twice, &object, Some(0x803f_7967_6c59_5235), None),
        ["Test.Image"]
    );
}

fn container_image(signatures: &[ContainerSignature<'_>]) -> Vec<u8> {
    let mut builder = ImageBuilder::new();
    for signature in signatures {
        builder.add_container_signature(signature).unwrap();
    }
    builder.finish().unwrap()
}

fn rule(name: &str) -> ContainerSignature<'_> {
    ContainerSignature {
        name,
        indicator: Indicator::Strong,
        container: KindCondition::Kind(ObjectKind::Zip),
        container_size: SizeCondition::Any,
        entry_name: None,
        compressed_size: SizeCondition::Any,
        real_size: SizeCondition::Any,
        encrypted: None,
        position: SizeCondition::Any,
    }
}

fn entry(name: &[u8]) -> ContainerEntry<'_> {
    ContainerEntry {
        container: ObjectKind::Zip,
        container_size: 237,
        name: Some(name),
        compressed_size: 17,
        real_size: 17,
        encrypted: false,
        position: 2,
    }
}

fn container_detections(
    image: &[u8],
    entry: &ContainerEntry<'_>,
    every_match: bool,
) -> Vec<String> {
    container_entry_detections(&Image::open(image).unwrap(), entry, every_match)
        .unwrap()
        .into_iter()
        .map(|detection| detection.name)
        .collect()
}

#[test]
fn a_container_signature_searches_the_whole_entry_name() {
    let image = container_image(&[ContainerSignature {
        entry_name: Some(hir("vil\\.(exe|scr)$")),
        ..rule("Test.Name")
    }]);
    assert_eq!(
        container_detections(&image, &entry(b"dir/evil.exe"), true),
        ["Test.Name"]
    );
    assert_eq!(
        container_detections(&image, &entry(b"dir/evil.exe.txt"), true),
        Vec::<String>::new()
    );
    let nameless = ContainerEntry {
        name: None,
        ..entry(b"")
    };
    assert_eq!(
        container_detections(&image, &nameless, true),
        Vec::<String>::new()
    );
}

#[test]
fn a_container_signature_tests_every_fact_it_names() {
    let image = container_image(&[ContainerSignature {
        container_size: SizeCondition::Exactly(237),
        compressed_size: SizeCondition::Between {
            lowest: Some(10),
            highest: None,
        },
        real_size: SizeCondition::Between {
            lowest: None,
            highest: Some(17),
        },
        encrypted: Some(false),
        position: SizeCondition::Exactly(2),
        ..rule("Test.Facts")
    }]);
    assert_eq!(
        container_detections(&image, &entry(b"a"), true),
        ["Test.Facts"]
    );
    for changed in [
        ContainerEntry {
            container: ObjectKind::Rar,
            ..entry(b"a")
        },
        ContainerEntry {
            container_size: 238,
            ..entry(b"a")
        },
        ContainerEntry {
            compressed_size: 9,
            ..entry(b"a")
        },
        ContainerEntry {
            real_size: 18,
            ..entry(b"a")
        },
        ContainerEntry {
            encrypted: true,
            ..entry(b"a")
        },
        ContainerEntry {
            position: 1,
            ..entry(b"a")
        },
    ] {
        assert_eq!(
            container_detections(&image, &changed, true),
            Vec::<String>::new()
        );
    }
}

#[test]
fn container_signatures_are_tested_last_loaded_first() {
    let image = container_image(&[rule("Test.First"), rule("Test.Second")]);
    assert_eq!(
        container_detections(&image, &entry(b"a"), false),
        ["Test.Second"]
    );
    assert_eq!(
        container_detections(&image, &entry(b"a"), true),
        ["Test.Second", "Test.First"]
    );
}

fn backtracking(tree: ExpressionTree) -> RegularExpressionSubsignature {
    RegularExpressionSubsignature {
        trigger: Some(leaf(0)),
        placement: Placement::Anywhere,
        expression: ExpressionForm::Backtracking(tree),
        anchoring: ExpressionAnchoring::AtAnUnshiftedPlacement,
        matches: ExpressionMatches::First,
        bounded_by_shift: false,
    }
}

fn word_run() -> ExpressionTree {
    ExpressionTree::Repetition(Box::new(TreeRepetition {
        min: 1,
        max: None,
        greed: Greed::Greedy,
        item: ExpressionTree::Byte(ByteSet::of((0..=u8::MAX).filter(u8::is_ascii_alphanumeric))),
    }))
}

#[test]
fn a_regular_expression_with_a_backreference_matches_through_the_image() {
    let tree = ExpressionTree::Concat(vec![
        ExpressionTree::literal(b"var "),
        ExpressionTree::Capture {
            group: 1,
            item: Box::new(word_run()),
        },
        ExpressionTree::literal(b"="),
        ExpressionTree::Backreference {
            group: 1,
            caseless: false,
        },
    ]);
    let signature = || with_expression(leaf(1), backtracking(tree.clone()));
    assert!(detected(signature(), b"MARK var abc=abc;"));
    assert!(!detected(signature(), b"MARK var abc=abd;"));
}

#[test]
fn a_regular_expression_with_lookaround_matches_through_the_image() {
    let tree = ExpressionTree::Concat(vec![
        ExpressionTree::Lookaround {
            direction: LookDirection::Behind,
            negated: true,
            item: Box::new(ExpressionTree::Byte(ByteSet::of(
                (0..=u8::MAX).filter(u8::is_ascii_alphanumeric),
            ))),
        },
        ExpressionTree::literal(b"inject"),
        ExpressionTree::Lookaround {
            direction: LookDirection::Ahead,
            negated: false,
            item: Box::new(ExpressionTree::literal(b".java")),
        },
    ]);
    let signature = || with_expression(leaf(1), backtracking(tree.clone()));
    assert!(detected(signature(), b"MARK inject.java"));
    assert!(!detected(signature(), b"MARK reinject.java"));
    assert!(!detected(signature(), b"MARK inject.class"));
}

#[test]
fn a_logical_signature_that_triggers_a_program_reports_the_trigger_and_no_detection() {
    let subsignatures = [content(b"MARK")];
    let expression = leaf(0);
    let mut builder = ImageBuilder::new();
    builder
        .add_logical_signature(&LogicalSignature {
            outcome: LogicalOutcome::RunProgram(SignatureProgramId(0)),
            group: GENERIC,
            category: Category::Malware,
            name: "Test.Program",
            indicator: Indicator::Strong,
            expression: &expression,
            subsignatures: &subsignatures,
            conditions: &LogicalConditions::default(),
        })
        .unwrap();
    builder.describe_object_kind(ObjectKind::BinaryData, binary_data());
    let bytes = builder.finish().unwrap();
    let image = Image::open(&bytes).unwrap();
    let object = b"....MARK....";
    let request = PatternRequest {
        selection: GroupSelection::ForKind(ObjectKind::BinaryData),
        settings: PatternSettings {
            potentially_unwanted: false,
            unwanted_categories: UnwantedCategories::Every,
            every_match: true,
            largest_object_for_regular_expressions: None,
        },
        object_length: object.len() as u64,
        context: ObjectContext::TOP_LEVEL,
        image_fuzzy_hash: None,
    };
    let findings = scan_object(&image, request, || None, object)
        .unwrap()
        .logical;
    assert_eq!(findings.detections, []);
    assert_eq!(
        findings.program_triggers,
        [LogicalOutcome::RunProgram(SignatureProgramId(0))]
    );
}
