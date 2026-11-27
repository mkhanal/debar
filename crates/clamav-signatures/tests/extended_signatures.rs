#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use debar_clamav_signatures::{
    Account, DatabaseError, DatabaseFile, LineOutcome, MalformedBody, MalformedExtendedLine,
    compile,
};
use debar_image::{
    ExecutableAnchor, Image, ImageBuilder, PatternSignatureId, Placement, RecordedOutcome,
    SignatureGroup,
};

const GENERIC: SignatureGroup = SignatureGroup(0);

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
    placements_in(text, GENERIC)
}

fn placements_in(text: &str, group: SignatureGroup) -> Vec<Placement> {
    let (bytes, _) = compile_ndb("test.ndb", text).unwrap();
    let image = Image::open(&bytes).unwrap();
    let group = image.pattern_group(group).unwrap().unwrap();
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
    let group = image.pattern_group(GENERIC).unwrap().unwrap();
    let record = group.signature(PatternSignatureId(0)).unwrap();
    let RecordedOutcome::Detection(name) = record.outcome else {
        panic!("an extended signature is a detection")
    };

    assert_eq!(account.files[0].lines, [LineOutcome::Compiled]);
    assert_eq!(account.files[0].kind, "extended signatures");
    assert_eq!(
        image.signature_name(name).unwrap().text,
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
            LineOutcome::Compiled,
            LineOutcome::Compiled,
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
        .pattern_group(GENERIC)
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

#[test]
fn each_target_compiles_into_its_own_group() {
    let text = "\
Test.Generic:0:*:4142434445
Test.Pe:1:*:4142434445
Test.Elf:6:*:4142434445
Test.Ascii:7:*:4142434445
Test.Other:14:*:4142434445
";
    let (bytes, account) = compile_ndb("test.ndb", text).unwrap();
    let image = Image::open(&bytes).unwrap();

    assert!(
        account.files[0]
            .lines
            .iter()
            .all(|outcome| *outcome == LineOutcome::Compiled)
    );
    for target in [0, 1, 6, 7, 14] {
        assert_eq!(
            image
                .pattern_group(SignatureGroup(target))
                .unwrap()
                .unwrap()
                .signature_count(),
            1,
            "target {target}"
        );
    }
    assert!(image.pattern_group(SignatureGroup(2)).unwrap().is_none());
}

#[test]
fn executable_offsets_are_read_into_positions_in_an_executable() {
    let text = "\
Test.AfterEp:1:EP+10:4142434445
Test.BeforeEp:1:EP-4,8:4142434445
Test.Section:1:S2+16,4:4142434445
Test.Last:1:SL+0:4142434445
Test.Whole:1:SE3:4142434445
Test.WholeShifted:1:SE0,5:4142434445
Test.VersionInfo:1:VI:4142434445
Test.Eof:1:EOF-20:4142434445
Test.Absolute:1:100:4142434445
";
    let in_executable = |anchor, shift| Placement::InExecutable { anchor, shift };
    assert_eq!(
        placements_in(text, SignatureGroup(1)),
        [
            in_executable(ExecutableAnchor::AfterEntryPoint { distance: 10 }, 0),
            in_executable(ExecutableAnchor::BeforeEntryPoint { distance: 4 }, 8),
            in_executable(
                ExecutableAnchor::SectionStart {
                    section: 2,
                    distance: 16
                },
                4
            ),
            in_executable(ExecutableAnchor::LastSectionStart { distance: 0 }, 0),
            in_executable(
                ExecutableAnchor::WholeSection {
                    section: 3,
                    start_only_from_length: Some(262_144)
                },
                0
            ),
            in_executable(
                ExecutableAnchor::WholeSection {
                    section: 0,
                    start_only_from_length: None
                },
                5
            ),
            in_executable(ExecutableAnchor::VersionInformation, 0),
            in_executable(ExecutableAnchor::BeforeEnd { distance: 20 }, 0),
            Placement::FromStart {
                distance: 100,
                shift: 0
            },
        ]
    );
}

#[test]
fn an_executable_offset_outside_an_executable_target_fails_the_compile() {
    assert_eq!(
        malformed("Test.Ep:0:EP+0:4142434445\n"),
        MalformedExtendedLine::ExecutableOffsetOnTarget { target: 0 }
    );
    assert_eq!(
        malformed("Test.Ep:7:S1+0:4142434445\n"),
        MalformedExtendedLine::ExecutableOffsetOnTarget { target: 7 }
    );
}

#[test]
fn executable_offsets_follow_the_formats_lenient_grammar() {
    let text = "\
Test.EmptyEp:1:EP+:4142434445
Test.EmptySection:1:SE:4142434445
Test.Trailing:1:S1+2junk:4142434445
Test.VersionInfoAnything:1:VIrest:4142434445
Test.WholeSectionChoice:1:SE1:41(42|43)434445
";
    let in_executable = |anchor, shift| Placement::InExecutable { anchor, shift };
    assert_eq!(
        placements_in(text, SignatureGroup(1)),
        [
            in_executable(ExecutableAnchor::AfterEntryPoint { distance: 0 }, 0),
            in_executable(
                ExecutableAnchor::WholeSection {
                    section: 0,
                    start_only_from_length: Some(262_144)
                },
                0
            ),
            in_executable(
                ExecutableAnchor::SectionStart {
                    section: 1,
                    distance: 2
                },
                0
            ),
            in_executable(ExecutableAnchor::VersionInformation, 0),
            in_executable(
                ExecutableAnchor::WholeSection {
                    section: 1,
                    start_only_from_length: None
                },
                0
            ),
        ]
    );
    for offset in ["SE1+5", "S1+", "S+1", "EP+x", "Sx"] {
        assert_eq!(
            malformed(&format!("Test.Bad:1:{offset}:4142434445\n")),
            MalformedExtendedLine::OffsetMalformed,
            "{offset}"
        );
    }
}
