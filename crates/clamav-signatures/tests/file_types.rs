#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use debar_clamav_signatures::{
    DatabaseError, DatabaseFile, LineOutcome, MalformedFileTypeLine, compile,
};
use debar_image::{
    Image, ImageBuilder, MagicTable, ObjectKind, PatternSignatureId, Placement, RecordedOutcome,
    SignatureGroup, TypeFinding,
};

fn compile_ftm(text: &str) -> Result<(Vec<u8>, Vec<LineOutcome>), DatabaseError> {
    let files = [DatabaseFile {
        name: "local.ftm",
        contents: text.as_bytes(),
    }];
    let mut builder = ImageBuilder::new();
    let account = compile(&files, &mut builder)?;
    Ok((builder.finish().unwrap(), account.files[0].lines.clone()))
}

fn magic_kind(bytes: &[u8], table: MagicTable, prefix: &[u8]) -> Option<ObjectKind> {
    let image = Image::open(bytes).unwrap();
    image
        .type_magic()
        .unwrap()
        .unwrap()
        .first_match(table, prefix)
        .unwrap()
}

#[test]
fn magic_lines_are_tried_last_line_first() {
    let text = "\
0:0:5b616c69617365735d:mirc ini:CL_TYPE_ANY:CL_TYPE_SCRIPT
0:0:5b616c69617365735d:TAR-POSIX:CL_TYPE_ANY:CL_TYPE_POSIX_TAR
0:0:4d5a:DOS/W32 executable:CL_TYPE_ANY:CL_TYPE_MSEXE
4:1024:482b0004:HFS+ partition:CL_TYPE_PART_ANY:CL_TYPE_PART_HFSPLUS
";
    let (bytes, outcomes) = compile_ftm(text).unwrap();

    assert!(
        outcomes
            .iter()
            .all(|outcome| *outcome == LineOutcome::Compiled)
    );
    assert_eq!(
        magic_kind(&bytes, MagicTable::Files, b"[aliases]\nx"),
        Some(ObjectKind::PosixTar)
    );
    assert_eq!(
        magic_kind(&bytes, MagicTable::Files, b"MZ\x90\x00"),
        Some(ObjectKind::WindowsExecutable)
    );
    assert_eq!(magic_kind(&bytes, MagicTable::Files, b"ZM"), None);
    let mut partition = vec![0u8; 1028];
    partition[1024..].copy_from_slice(&[0x48, 0x2b, 0x00, 0x04]);
    assert_eq!(
        magic_kind(&bytes, MagicTable::Partitions, &partition),
        Some(ObjectKind::HfsPlusPartition)
    );
    assert_eq!(magic_kind(&bytes, MagicTable::Files, &partition), None);
}

#[test]
fn recognition_lines_compile_into_the_type_recognition_group() {
    let text = "\
1:*:3c68746d6c3e:HTML data:CL_TYPE_ANY:CL_TYPE_HTML
1:510:55aa:Disk Image - Master Boot Record:CL_TYPE_ANY:CL_TYPE_MBR:77
1:0,1024:0a(46|66)726f6d3a20{-1024}0a(43|63)6f6e74656e742d(54|74)7970653a20:Mail file:CL_TYPE_ANY:CL_TYPE_MAIL
";
    let (bytes, outcomes) = compile_ftm(text).unwrap();
    let image = Image::open(&bytes).unwrap();
    let recognition = image
        .object_kinds()
        .unwrap()
        .unwrap()
        .typing_rules()
        .recognition_group
        .unwrap();
    let group = image.pattern_group(recognition).unwrap().unwrap();
    let found = |index| {
        let record = group.signature(PatternSignatureId(index)).unwrap();
        (record.placement, record.outcome)
    };

    assert!(
        outcomes
            .iter()
            .all(|outcome| *outcome == LineOutcome::Compiled)
    );
    assert_eq!(
        found(0),
        (
            Placement::Anywhere,
            RecordedOutcome::TypeFound(TypeFinding {
                found: ObjectKind::Html,
                required: None
            })
        )
    );
    assert_eq!(
        found(1).0,
        Placement::FromStart {
            distance: 510,
            shift: 0
        }
    );
    assert_eq!(
        group
            .signature(PatternSignatureId(2))
            .unwrap()
            .segment_count,
        2
    );
    assert!(image.pattern_group(SignatureGroup(0)).unwrap().is_none());
}

#[test]
fn levels_comments_and_other_modes_are_accounted_for() {
    let text = "\
#comment
0:0:89504e47:PNG:CL_TYPE_ANY:CL_TYPE_GRAPHICS::121
0:0:89504e47:PNG:CL_TYPE_ANY:CL_TYPE_PNG:122
3:0:4142:Other mode:CL_TYPE_ANY:CL_TYPE_ZIP
";
    let (_, outcomes) = compile_ftm(text).unwrap();

    assert_eq!(
        outcomes,
        [
            LineOutcome::Comment,
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::Compiled,
            LineOutcome::NotASignature,
        ]
    );
}

#[test]
fn a_malformed_file_type_line_fails_the_compile() {
    for (line, expected) in [
        (
            "0:0:4142:Too few:CL_TYPE_ANY\n",
            MalformedFileTypeLine::TooFewFields,
        ),
        (
            "0:0:4142:Unknown:CL_TYPE_ANY:CL_TYPE_NOTHING\n",
            MalformedFileTypeLine::UnknownTypeName {
                name: "CL_TYPE_NOTHING".to_owned(),
            },
        ),
        (
            "0:x:4142:Offset:CL_TYPE_ANY:CL_TYPE_ZIP\n",
            MalformedFileTypeLine::OffsetMalformed,
        ),
        (
            "0:0:41zz:Magic:CL_TYPE_ANY:CL_TYPE_ZIP\n",
            MalformedFileTypeLine::MagicNotHex,
        ),
    ] {
        match compile_ftm(line) {
            Err(DatabaseError::MalformedFileTypeLine {
                reason, line: 1, ..
            }) => {
                assert_eq!(reason, expected, "{line}");
            }
            other => panic!("{line}: expected a malformed line, got {other:?}"),
        }
    }
}

#[test]
fn every_group_overlaps_its_windows_by_the_longest_part_loaded_into_it() {
    let files = [
        DatabaseFile {
            name: "a.ndb",
            contents:
                b"Test.Short:0:*:414243444546\nTest.Pe:1:*:41424344{200-300}4142434445464748\n",
        },
        DatabaseFile {
            name: "b.ldb",
            contents: b"Test.Logical;Engine:51-255,Target:0;0;41424344454647484950::w\n",
        },
        DatabaseFile {
            name: "c.ftm",
            contents: b"1:*:414243444546474849:Long type:CL_TYPE_ANY:CL_TYPE_HTML\n",
        },
    ];
    let mut builder = ImageBuilder::new();
    compile(&files, &mut builder).unwrap();
    let bytes = builder.finish().unwrap();
    let image = Image::open(&bytes).unwrap();
    let overlap = |group| {
        image
            .pattern_group(SignatureGroup(group))
            .unwrap()
            .unwrap()
            .report_windows()
            .unwrap()
            .overlap
    };

    assert_eq!(overlap(0), 20);
    assert_eq!(overlap(1), 8);
}
