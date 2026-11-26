#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use debar_clamav_signatures::{
    Account, DatabaseError, DatabaseFile, LineOutcome, MalformedBody, MalformedExtendedLine,
    compile,
};
use debar_image::{Image, ImageBuilder, PatternSignatureId, Placement};

fn compile_ndb(name: &str, text: &str) -> Result<(Vec<u8>, Account), DatabaseError> {
    let files = [DatabaseFile {
        name,
        contents: text.as_bytes(),
    }];
    let mut builder = ImageBuilder::new();
    let account = compile(&files, &mut builder)?;
    Ok((builder.finish().unwrap(), account))
}

fn outcomes(text: &str) -> Vec<LineOutcome> {
    compile_ndb("test.ndb", text).unwrap().1.files[0]
        .lines
        .clone()
}

fn malformed(text: &str) -> MalformedExtendedLine {
    match compile_ndb("test.ndb", text) {
        Err(DatabaseError::MalformedExtendedLine { reason, .. }) => reason,
        other => panic!("expected a malformed line, got {other:?}"),
    }
}

fn placements(text: &str) -> Vec<Placement> {
    let (bytes, _) = compile_ndb("test.ndb", text).unwrap();
    let image = Image::open(&bytes).unwrap();
    let group = image.pattern_group().unwrap().unwrap();
    (0..group.signature_count())
        .map(|index| {
            group
                .signature(PatternSignatureId(u32::try_from(index).unwrap()))
                .unwrap()
                .placement
        })
        .collect()
}

#[test]
fn a_generic_line_is_compiled_under_its_unofficial_name() {
    let (bytes, account) = compile_ndb("local.ndb", "Test.Body-1:0:*:4142434445\n").unwrap();
    let image = Image::open(&bytes).unwrap();
    let group = image.pattern_group().unwrap().unwrap();
    let record = group.signature(PatternSignatureId(0)).unwrap();

    assert_eq!(account.files[0].lines, [LineOutcome::Compiled]);
    assert_eq!(account.files[0].kind, "extended signatures");
    assert_eq!(
        image.signature_name(record.name).unwrap().text,
        "Test.Body-1.UNOFFICIAL"
    );
}

#[test]
fn every_line_has_one_outcome() {
    let text = "\
#a comment
Test.Level:0:*:41424344:235
Test.Max:0:*:41424344:1:233
Test.EmptyMax:0:*:41424344:1:
Test.Target15:15:*:41424344
Test.Pe:1:*:4142434445
Test.EntryPoint:1:EP+0:4142434445
Test.Macro:0:$3$:4142434445
Test.Generic:*:*:4142434445
";
    assert_eq!(
        outcomes(text),
        [
            LineOutcome::Comment,
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::TargetNotLoaded,
            LineOutcome::NotYetCompiled,
            LineOutcome::NeedsExecutableFacts,
            LineOutcome::NeverReports,
            LineOutcome::Compiled,
        ]
    );
}

#[test]
fn a_line_left_out_by_its_level_is_not_checked_further() {
    assert_eq!(
        outcomes("Test.Skipped:0:*:zz:300:abc\nTest.Skipped2:abc:*:4142:300\n"),
        [
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::OutsideFunctionalityLevel
        ]
    );
}

#[test]
fn a_malformed_line_fails_the_whole_compile() {
    assert_eq!(
        malformed("Test.Few:0:*\n"),
        MalformedExtendedLine::TooFewFields
    );
    assert_eq!(
        malformed("Test.Many:0:*:41424344:1:300:x\n"),
        MalformedExtendedLine::TooManyFields
    );
    assert_eq!(malformed("\n"), MalformedExtendedLine::TooFewFields);
    assert_eq!(
        malformed(":0:*:41424344\n"),
        MalformedExtendedLine::EmptyName
    );
    assert_eq!(
        malformed("Test.Level:0:*:41424344: 5\n"),
        MalformedExtendedLine::LevelNotDigits
    );
    assert_eq!(
        malformed("Test.Target:-1:*:41424344\n"),
        MalformedExtendedLine::TargetNotANumber
    );
    assert_eq!(
        malformed("Test.Ep:0:EP+0:41424344\n"),
        MalformedExtendedLine::ExecutableOffsetOnTarget { target: 0 }
    );
    assert_eq!(
        malformed("Test.Eof:0:EOF+5:41424344\n"),
        MalformedExtendedLine::OffsetMalformed
    );
    assert!(matches!(
        malformed("Test.Space:0:*:41424344 \n"),
        MalformedExtendedLine::Body(MalformedBody::UnfinishedByte { .. })
    ));
}

#[test]
fn bodies_the_format_rejects_fail_the_compile() {
    for (body, reason) in [
        ("4142", MalformedBody::PlainBodyTooShort),
        ("41??42", MalformedBody::NoFixedPairInPart),
        ("????", MalformedBody::NoFixedPairInPart),
        ("4142*43", MalformedBody::PartTooShort),
        ("*41424344", MalformedBody::EmptyPart),
        ("41424344*", MalformedBody::EmptyPart),
        ("4142**4344", MalformedBody::EmptyPart),
        (
            "4142(43|44*45)",
            MalformedBody::UnsupportedInsideAlternatives { at: 10 },
        ),
        (
            "4142!(43|44??)",
            MalformedBody::NegatedGenericAlternatives { at: 4 },
        ),
        (
            "4142434445[0-33]46",
            MalformedBody::MisplacedLoneByteDistance { at: 10 },
        ),
    ] {
        assert_eq!(
            malformed(&format!("Test.Body:0:*:{body}\n")),
            MalformedExtendedLine::Body(reason),
            "{body}"
        );
    }
}

#[test]
fn bodies_using_every_element_compile() {
    let text = "\
Test.Nibbles:0:*:41??4?4??2434445
Test.Star:0:*:41424344*45464748
Test.Gaps:0:*:4142{3}4344{4-6}4546{-5}4748{5-}4950
Test.ZeroGap:0:*:41424344{0}45464748
Test.Brackets:0:*:41[2-3]4243444546[0-1]47
Test.Choices:0:*:4142(43|44)(4546|4748)(49|4a4b|4c??)4d4e
Test.Negated:0:*:4142!(43|44)!(4546|4748)4950
Test.Nested:0:*:4142(43(44|45)|46)4748
Test.Classes:0:*:(B)414243(W)44(L)4546(B)
Test.Negated.Edge:0:*:414243!(B)
";
    assert!(
        outcomes(text)
            .iter()
            .all(|outcome| *outcome == LineOutcome::Compiled)
    );
}

#[test]
fn offsets_are_read_into_placements() {
    let text = "\
Test.Anywhere:0:*:4142434445
Test.At:0:32:4142434445
Test.Range:0:30,2:4142434445
Test.Eof:0:EOF-40:4142434445
Test.EofRange:0:EOF-42,2:4142434445
Test.Empty:0::4142434445
Test.Comma:0:7,:4142434445
";
    assert_eq!(
        placements(text),
        [
            Placement::Anywhere,
            Placement::FromStart {
                distance: 32,
                shift: 0
            },
            Placement::FromStart {
                distance: 30,
                shift: 2
            },
            Placement::BeforeEnd {
                distance: 40,
                shift: 0
            },
            Placement::BeforeEnd {
                distance: 42,
                shift: 2
            },
            Placement::FromStart {
                distance: 0,
                shift: 0
            },
            Placement::FromStart {
                distance: 7,
                shift: 0
            },
        ]
    );
}

#[test]
fn potentially_unwanted_extended_files_compile_into_their_own_category() {
    let (bytes, account) = compile_ndb("local.ndu", "PUA.Test:0:*:4142434445\n").unwrap();
    let image = Image::open(&bytes).unwrap();
    let record = image
        .pattern_group()
        .unwrap()
        .unwrap()
        .signature(PatternSignatureId(0))
        .unwrap();

    assert_eq!(
        account.files[0].kind,
        "extended signatures, potentially unwanted"
    );
    assert_eq!(record.category, debar_image::Category::PotentiallyUnwanted);
}

#[test]
fn an_ignore_list_drops_an_extended_signature_before_it_is_checked() {
    let files = [
        DatabaseFile {
            name: "a.ign2",
            contents: b"Test.Ignored\n",
        },
        DatabaseFile {
            name: "b.ndb",
            contents: b"Test.Ignored:0:*:zz\nTest.Kept:0:*:4142434445\n",
        },
    ];
    let mut builder = ImageBuilder::new();
    let account = compile(&files, &mut builder).unwrap();

    assert_eq!(
        account.files[1].lines,
        [LineOutcome::Ignored, LineOutcome::Compiled]
    );
}

#[test]
fn an_empty_extended_file_fails_the_compile() {
    assert!(matches!(
        compile_ndb("empty.ndb", ""),
        Err(DatabaseError::EmptyDatabaseFile { .. })
    ));
}
