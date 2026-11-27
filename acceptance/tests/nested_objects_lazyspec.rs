#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::{Path, PathBuf};

use acceptance::{
    CompiledImage, comparison_report_objects, compile, detections, lowercase_hex,
    scratch_directory, write_file,
};
use md5::Md5;
use serde_json::Value;
use sha2::Digest as _;

const ARCHIVE_MARK: &[u8] = b"ARCHIVEMARK";
const SHORT_ARCHIVE_MARK: &[u8] = b"Q@Q@";
const EMBEDDED_BODY: &[u8] = b"EMBEDDEDBODY";
const RESCAN_BODY: &[u8] = b"RESCANBODY";
const INSIDE_BODY: &[u8] = b"INSIDEBINARYBODY";

const FILE_TYPES: &str = "\
0:0:4d5a:DOS/W32 executable:CL_TYPE_ANY:CL_TYPE_MSEXE
0:0:52617221:RAR:CL_TYPE_ANY:CL_TYPE_RAR
1:*:415243484956454d41524b:RAR-SFX:CL_TYPE_ANY:CL_TYPE_RARSFX
1:*:51405140:RAR-SFX short:CL_TYPE_ANY:CL_TYPE_RARSFX
";
const BODIES: &str = "Test.Embedded:0:*:454d424544444544424f4459\n";
const LOGICAL: &str = "\
Test.Rescanned;Engine:51-255,Target:0,HandlerType:CL_TYPE_PDF;0;52455343414e424f4459
Test.InsideBinary;Engine:51-255,Target:0,Container:CL_TYPE_BINARY_DATA;0;494e5349444542494e415259424f4459
";

fn databases(test: &str, extra: &[(&str, String)]) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    let mut files = vec![
        ("types.ftm", FILE_TYPES.to_owned()),
        ("local.ndb", BODIES.to_owned()),
        ("local.ldb", LOGICAL.to_owned()),
    ];
    files.extend(extra.iter().cloned());
    for (name, contents) in files {
        write_file(&databases.join(name), contents.as_bytes()).unwrap();
    }
    let compiled = compile(&databases, &directory, "loose").unwrap();
    (directory, compiled)
}

fn binary_with(parts: &[&[u8]]) -> Vec<u8> {
    holding(b"\x00\x00\x00\x00binary", parts)
}

fn text_with(parts: &[&[u8]]) -> Vec<u8> {
    holding(b"plain text", parts)
}

fn holding(start: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut contents = start.to_vec();
    for part in parts {
        contents.extend_from_slice(b" .... ");
        contents.extend_from_slice(part);
    }
    contents.extend_from_slice(b" ....\n");
    contents
}

fn objects(directory: &Path, image: &Path, contents: &[u8]) -> Vec<Value> {
    objects_with(directory, image, &["--every-match"], contents)
}

fn objects_with(directory: &Path, image: &Path, options: &[&str], contents: &[u8]) -> Vec<Value> {
    let input = directory.join("input");
    write_file(&input, contents).unwrap();
    comparison_report_objects(image, options, &input, directory).unwrap()
}

fn offset_of(contents: &[u8], mark: &[u8], from: usize) -> usize {
    from + contents[from..]
        .windows(mark.len())
        .position(|window| window == mark)
        .unwrap()
}

fn false_positive(contents: &[u8]) -> String {
    format!(
        "{}:{}:Test.Trusted\n",
        lowercase_hex(&Md5::digest(contents)),
        contents.len()
    )
}

#[test]
fn an_archive_found_inside_another_file_is_scanned_as_an_object_of_its_own() {
    const REQUIREMENT: &str =
        "An Archive Found Inside Another File Is Scanned As An Object Of Its Own";
    let (directory, compiled) = databases("embedded-archive", &[]);
    let contents = binary_with(&[ARCHIVE_MARK, EMBEDDED_BODY]);
    let start = offset_of(&contents, ARCHIVE_MARK, 0);

    let found = objects(&directory, &compiled.image, &contents);

    assert_eq!(found.len(), 2, "{REQUIREMENT}");
    let child = &found[1];
    assert_eq!(child["parent"], found[0]["id"], "{REQUIREMENT}");
    assert_eq!(child["depth"], 1, "{REQUIREMENT}");
    assert_eq!(child["type"], "CL_TYPE_RAR", "{REQUIREMENT}");
    assert_eq!(child["size"], contents.len() - start, "{REQUIREMENT}");
    assert_eq!(
        detections(child),
        ["Test.Embedded.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    let at_the_start = [ARCHIVE_MARK, binary_with(&[]).as_slice()].concat();
    assert_eq!(
        objects(&directory, &compiled.image, &at_the_start).len(),
        1,
        "{REQUIREMENT}: at the start"
    );
    let in_an_archive = [b"Rar!".as_slice(), binary_with(&[ARCHIVE_MARK]).as_slice()].concat();
    let archive = objects(&directory, &compiled.image, &in_an_archive);
    assert_eq!(archive.len(), 1, "{REQUIREMENT}: in an archive");
    assert_eq!(archive[0]["type"], "CL_TYPE_RAR", "{REQUIREMENT}");
    let five = [binary_with(&[]).as_slice(), SHORT_ARCHIVE_MARK, b"."].concat();
    let six = [five.as_slice(), b"."].concat();
    assert_eq!(
        objects(&directory, &compiled.image, &five).len(),
        1,
        "{REQUIREMENT}: five bytes"
    );
    assert_eq!(
        objects(&directory, &compiled.image, &six).len(),
        2,
        "{REQUIREMENT}: six bytes"
    );
}

#[test]
fn an_object_found_inside_another_is_not_searched_for_objects_of_its_own() {
    const REQUIREMENT: &str =
        "An Object Found Inside Another Is Not Searched For Objects Of Its Own";
    let (directory, compiled) = databases("embedded-not-searched", &[]);
    let contents = binary_with(&[ARCHIVE_MARK, ARCHIVE_MARK]);
    let first = offset_of(&contents, ARCHIVE_MARK, 0);
    let second = offset_of(&contents, ARCHIVE_MARK, first + 1);

    let found = objects(&directory, &compiled.image, &contents);

    let children: Vec<(&Value, &Value, &Value)> = found[1..]
        .iter()
        .map(|object| (&object["parent"], &object["depth"], &object["size"]))
        .collect();
    assert_eq!(
        children,
        [
            (
                &found[0]["id"],
                &Value::from(1),
                &Value::from(contents.len() - first)
            ),
            (
                &found[0]["id"],
                &Value::from(1),
                &Value::from(contents.len() - second)
            ),
        ],
        "{REQUIREMENT}"
    );
}

#[test]
fn a_handler_type_scans_the_file_again_as_that_kind() {
    const REQUIREMENT: &str = "A Handler Type Scans The File Again As That Kind";
    let (directory, compiled) = databases("handler-type", &[]);
    let contents = text_with(&[RESCAN_BODY]);

    let found = objects(&directory, &compiled.image, &contents);

    assert_eq!(found.len(), 2, "{REQUIREMENT}");
    let again = &found[1];
    assert_eq!(again["parent"], found[0]["id"], "{REQUIREMENT}");
    assert_eq!(again["depth"], 1, "{REQUIREMENT}");
    assert_eq!(again["type"], "CL_TYPE_PDF", "{REQUIREMENT}");
    assert_eq!(again["sha256"], found[0]["sha256"], "{REQUIREMENT}");
    assert!(detections(&found[0]).is_empty(), "{REQUIREMENT}");
    assert_eq!(
        detections(again),
        ["Test.Rescanned.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn a_raw_only_scan_finds_no_object_inside_another_yet_a_handler_type_still_scans_the_file_again() {
    const REQUIREMENT: &str = "A Raw-Only Scan Finds No Object Inside Another, Yet A Handler Type Still Scans The File Again";
    let pdf_only = format!("Test.PdfOnly:10:*:{}\n", lowercase_hex(RESCAN_BODY));
    let (directory, compiled) = databases("raw-only-objects", &[("pdf.ndb", pdf_only)]);
    let raw_only = ["--every-match", "--raw-only"];
    let embedded = binary_with(&[ARCHIVE_MARK, EMBEDDED_BODY]);
    let rescanned = text_with(&[RESCAN_BODY]);

    let found = objects_with(&directory, &compiled.image, &raw_only, &embedded);
    let again = objects_with(&directory, &compiled.image, &raw_only, &rescanned);
    let again_in_full = objects(&directory, &compiled.image, &rescanned);

    assert_eq!(found.len(), 1, "{REQUIREMENT}");
    assert_eq!(
        detections(&found[0]),
        ["Test.Embedded.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(again.len(), 2, "{REQUIREMENT}: handler type");
    assert_eq!(again[1]["type"], "CL_TYPE_PDF", "{REQUIREMENT}");
    assert_eq!(
        detections(&again[1]),
        ["Test.Rescanned.UNOFFICIAL"],
        "{REQUIREMENT}: raw-only again"
    );
    assert_eq!(
        detections(&again_in_full[1]),
        ["Test.PdfOnly.UNOFFICIAL", "Test.Rescanned.UNOFFICIAL"],
        "{REQUIREMENT}: in a full scan"
    );
}

#[test]
fn a_container_condition_is_tested_against_the_object_holding_it() {
    const REQUIREMENT: &str = "A Container Condition Is Tested Against The Object Holding It";
    let (directory, compiled) = databases("container-condition", &[]);
    let contents = binary_with(&[ARCHIVE_MARK, INSIDE_BODY]);

    let found = objects(&directory, &compiled.image, &contents);

    assert!(detections(&found[0]).is_empty(), "{REQUIREMENT}");
    assert_eq!(
        detections(&found[1]),
        ["Test.InsideBinary.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn a_false_positive_hash_of_an_object_inside_another_trusts_only_that_object() {
    const REQUIREMENT: &str =
        "A False-Positive Hash Of An Object Inside Another Trusts Only That Object";
    let contents = text_with(&[ARCHIVE_MARK, EMBEDDED_BODY]);
    let start = offset_of(&contents, ARCHIVE_MARK, 0);
    let (inner_directory, inner) = databases(
        "false-positive-inner",
        &[("local.fp", false_positive(&contents[start..]))],
    );
    let (outer_directory, outer) = databases(
        "false-positive-outer",
        &[("local.fp", false_positive(&contents))],
    );

    let inner_trusted = objects(&inner_directory, &inner.image, &contents);
    let outer_trusted = objects(&outer_directory, &outer.image, &contents);

    assert_eq!(
        detections(&inner_trusted[0]),
        ["Test.Embedded.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert!(detections(&inner_trusted[1]).is_empty(), "{REQUIREMENT}");
    assert_eq!(
        inner_trusted[0]["verdict"], "strong_indicator",
        "{REQUIREMENT}"
    );
    assert!(
        outer_trusted
            .iter()
            .all(|object| detections(object).is_empty()),
        "{REQUIREMENT}"
    );
    assert_eq!(outer_trusted[0]["verdict"], "trusted", "{REQUIREMENT}");
}
