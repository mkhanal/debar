#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use debar_clamav_signatures::{
    Account, DatabaseError, DatabaseFile, LineOutcome, MalformedByteComparison,
    MalformedContainerLine, MalformedLogicalLine, MalformedRegularExpressionSubsignature,
    MalformedSubsignature, compile,
};
use debar_image::{Image, ImageBuilder};

fn compile_file(name: &str, text: &str) -> Result<(Vec<u8>, Account), DatabaseError> {
    let files = [DatabaseFile {
        name,
        contents: text.as_bytes(),
    }];
    let mut builder = ImageBuilder::new();
    let account = compile(&files, &mut builder)?;
    Ok((builder.finish().unwrap(), account))
}

fn logical_outcome(subsignatures: &str) -> LineOutcome {
    let expression = (0..subsignatures.split(';').count())
        .map(|index| index.to_string())
        .collect::<Vec<_>>()
        .join("&");
    let line = format!("Test.Plug;Target:0;{expression};{subsignatures}\n");
    compile_file("test.ldb", &line).unwrap().1.files[0].lines[0]
}

fn malformed_subsignature(subsignatures: &str) -> MalformedSubsignature {
    let expression = (0..subsignatures.split(';').count())
        .map(|index| index.to_string())
        .collect::<Vec<_>>()
        .join("&");
    let line = format!("Test.Plug;Target:0;{expression};{subsignatures}\n");
    match compile_file("test.ldb", &line) {
        Err(DatabaseError::MalformedLogicalLine {
            reason: MalformedLogicalLine::Subsignature { reason, .. },
            ..
        }) => reason,
        other => panic!("expected a malformed subsignature, got {other:?}"),
    }
}

fn malformed_expression(subsignatures: &str) -> MalformedRegularExpressionSubsignature {
    match malformed_subsignature(subsignatures) {
        MalformedSubsignature::RegularExpression(reason) => reason,
        other => panic!("expected a malformed regular expression, got {other:?}"),
    }
}

#[test]
fn a_regular_expression_subsignature_compiles_with_its_trigger_offset_and_flags() {
    for subsignature in [
        "414243;0/abc/",
        "414243;0/abc/::i",
        "414243;16:0/abc/i",
        "414243;EOF-1:0/abc/",
        "414243;0/c:d/",
        "414243;0/c\\//",
        "414243;0/abc/iigg",
        "414243;0/abc/gire",
        "414243;0>1/a(?:b|c)[[:digit:]]{2,}\\x41\\s\\Z/msxUAE",
    ] {
        assert_eq!(
            logical_outcome(subsignature),
            LineOutcome::Compiled,
            "{subsignature}"
        );
    }
}

#[test]
fn a_malformed_regular_expression_subsignature_fails_the_compile() {
    use MalformedRegularExpressionSubsignature as Malformed;
    assert_eq!(
        malformed_expression("414243;/abc/"),
        Malformed::StartsWithDelimiter
    );
    assert_eq!(
        malformed_expression("414243;*:/abc/"),
        Malformed::EmptyTrigger
    );
    assert_eq!(
        malformed_expression("414243;0//"),
        Malformed::EmptyExpression
    );
    assert_eq!(
        malformed_expression("414243;16:0/abc/::i"),
        Malformed::MismatchedDelimiter
    );
    assert_eq!(
        malformed_expression("414243;1/abc/"),
        Malformed::TriggerNamesItself
    );
    assert_eq!(
        malformed_expression("414243;2/abc/;414243"),
        Malformed::TriggerNamesALaterSubsignature
    );
    assert_eq!(
        malformed_expression("414243;0/abc/q"),
        Malformed::UnknownFlag(b'q')
    );
    assert!(matches!(
        malformed_expression("414243;EP+1:0/abc/"),
        Malformed::Offset(_)
    ));
    assert!(matches!(
        malformed_expression("414243;0/a(b/"),
        Malformed::Expression(_)
    ));
    assert!(matches!(
        malformed_expression("414243;0/a{3,2}/"),
        Malformed::Expression(_)
    ));
    assert!(matches!(
        malformed_expression("414243;0/\\q/"),
        Malformed::Expression(_)
    ));
}

#[test]
fn a_regular_expression_a_linear_engine_cannot_express_compiles_for_the_backtracking_engine() {
    for subsignature in [
        "414243;0/(a)\\1/",
        "414243;0/(?P<n>a)(?P=n)/",
        "414243;0/(?P=n)(?P<n>a)/",
        "414243;0/(?<n>a)\\k<n>\\g{n}\\g1\\g{-1}/",
        "414243;0/a(?=b)/",
        "414243;0/(?<!a)b/",
        "414243;0/(?<!Unix|Inet(4|6)|Any)b/",
        "414243;0/(?>a+)b/",
        "414243;0/a++b/",
        "414243;0/a$\\n/",
    ] {
        assert_eq!(
            logical_outcome(subsignature),
            LineOutcome::Compiled,
            "{subsignature}"
        );
    }
}

#[test]
fn a_regular_expression_with_a_construct_debar_does_not_support_is_not_yet_compiled() {
    for subsignature in [
        "414243;0/(*UTF)a/",
        "414243;0/(a)(?1)/",
        "414243;0/(?(1)a|b)/",
        "414243;0/a\\Kb/",
    ] {
        assert_eq!(
            logical_outcome(subsignature),
            LineOutcome::NotYetCompiled,
            "{subsignature}"
        );
    }
}

#[test]
fn a_backreference_to_a_group_that_does_not_exist_fails_the_compile() {
    for subsignature in [
        "414243;0/(a)\\g{2}/",
        "414243;0/(?P=missing)/",
        "414243;0/\\k<1a>/",
        "414243;0/(?<!a+)b/",
    ] {
        assert!(
            matches!(
                malformed_expression(subsignature),
                MalformedRegularExpressionSubsignature::Expression(_)
            ),
            "{subsignature}"
        );
    }
}

#[test]
fn a_byte_comparison_subsignature_compiles_as_the_signature_format_defines_it() {
    for subsignature in [
        "414243;0(>>26#ib2#>512)",
        "414243;0(>>0x4#hb4#=0x1F,<40)",
        "414243;0(<<2#de3#=12)zz",
        "414243;0(#ib1#=1)",
        "414243;0(>>4#a4#>1)",
        "414243;64(>>4#ib1#>1)",
    ] {
        assert_eq!(
            logical_outcome(subsignature),
            LineOutcome::Compiled,
            "{subsignature}"
        );
    }
}

#[test]
fn a_malformed_byte_comparison_fails_the_compile() {
    use MalformedByteComparison as Malformed;
    let reason = |subsignature| match malformed_subsignature(subsignature) {
        MalformedSubsignature::ByteComparison(reason) => reason,
        other => panic!("expected a malformed byte comparison, got {other:?}"),
    };
    assert_eq!(
        reason("414243;65(>>4#ib1#>1)"),
        Malformed::ReferenceBeyondSixtyFour
    );
    assert_eq!(reason("414243;0(>4#ib1#>1)"), Malformed::Offset);
    assert_eq!(reason("414243;0(>>4#ib3#>1)"), Malformed::Length);
    assert_eq!(reason("414243;0(>>4#hb19#>1)"), Malformed::Length);
    assert_eq!(reason("414243;0(>>4#hd2#>1)"), Malformed::Options);
    assert_eq!(reason("414243;0(>>4#dl2#>1)"), Malformed::Options);
    assert_eq!(reason("414243;0(>>4#ib#>1)"), Malformed::Options);
    assert_eq!(reason("414243;0(>>4#ib1#>1,>2,>3)"), Malformed::Comparisons);
    assert_eq!(reason("414243;0(>>4#ib1#!1)"), Malformed::Comparisons);
    assert_eq!(reason("414243;0(>>4#ib1#a#b)"), Malformed::FieldCount);
    assert_eq!(reason("414243;0(>>4#ib1#>1"), Malformed::NotClosed);
}

#[test]
fn an_image_fuzzy_hash_is_sixteen_hexadecimal_digits_with_distance_zero() {
    assert_eq!(
        logical_outcome("fuzzy_img#af43432fbcb8603c"),
        LineOutcome::Compiled
    );
    assert_eq!(
        logical_outcome("fuzzy_img#af43432fbcb8603c#0#ignored"),
        LineOutcome::Compiled
    );
    for subsignature in ["fuzzy_img#af43432fbcb860", "fuzzy_img#af43432fbcb8603c#1"] {
        assert_eq!(
            malformed_subsignature(subsignature),
            MalformedSubsignature::ImageFuzzyHash
        );
    }
}

fn container_outcomes(text: &str) -> Vec<LineOutcome> {
    compile_file("test.cdb", text).unwrap().1.files[0]
        .lines
        .clone()
}

fn malformed_container(text: &str) -> MalformedContainerLine {
    match compile_file("test.cdb", text) {
        Err(DatabaseError::MalformedContainerLine { reason, .. }) => reason,
        other => panic!("expected a malformed container line, got {other:?}"),
    }
}

#[test]
fn every_container_signature_line_has_one_outcome() {
    let text = "\
# a comment
C.Name:CL_TYPE_ZIP:*:(?i)evil\\.exe$:*:*:*:*:*:*
C.Sizes:*:237:*:10-0:0-17:0:1:ba9f27fb:anything
C.Empty:CL_TYPE_ANY::*:::*::*:*
C.Junk:CL_TYPE_RAR:*:*:10-99999x:*:1:*:*:*
C.Later:CL_TYPE_ZIP:*:*:*:*:*:*:*:*:235
C.Earlier:CL_TYPE_ZIP:*:*:*:*:*:*:*:*:0:233
C.Within:CL_TYPE_ZIP:*:*:*:*:*:*:*:*:0:255
";
    assert_eq!(
        container_outcomes(text),
        [
            LineOutcome::Comment,
            LineOutcome::Compiled,
            LineOutcome::Compiled,
            LineOutcome::Compiled,
            LineOutcome::Compiled,
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::Compiled,
        ]
    );
    let (image, _) = compile_file("test.cdb", text).unwrap();
    let image = Image::open(&image).unwrap();
    assert_eq!(image.container_signatures().unwrap().unwrap().count(), 5);
}

#[test]
fn a_malformed_container_signature_line_fails_the_compile() {
    assert_eq!(
        malformed_container("C.A:CL_TYPE_ZIP:*:*:*:*:*:*:*\n"),
        MalformedContainerLine::FieldCount { found: 9 }
    );
    assert_eq!(
        malformed_container("C.A:CL_TYPE_ZIP:*:*:*:*:*:*:*:*:0:255:1\n"),
        MalformedContainerLine::FieldCount { found: 13 }
    );
    assert_eq!(
        malformed_container("C.A:ZIP:*:*:*:*:*:*:*:*\n"),
        MalformedContainerLine::UnknownContainerType
    );
    assert_eq!(
        malformed_container("C.A:CL_TYPE_ZIP:*:*:10-:*:*:*:*:*\n"),
        MalformedContainerLine::Size
    );
    assert_eq!(
        malformed_container("C.A:CL_TYPE_ZIP:*:*:17x:*:*:*:*:*\n"),
        MalformedContainerLine::Size
    );
    assert_eq!(
        malformed_container("C.A:CL_TYPE_ZIP:*:*:*:*:2:*:*:*\n"),
        MalformedContainerLine::Encrypted
    );
    assert_eq!(
        malformed_container("C.A:CL_TYPE_ZIP:*:*:*:*:*:*:*:*:2x\n"),
        MalformedContainerLine::LevelNotDigits
    );
    assert!(matches!(
        malformed_container("C.A:CL_TYPE_ZIP:*:a(b:*:*:*:*:*:*\n"),
        MalformedContainerLine::EntryName(_)
    ));
}
