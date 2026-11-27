#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::{Path, PathBuf};

use acceptance::{
    CompiledImage, comparison_report_with, compile, detections, lowercase_hex, scratch_directory,
    write_file,
};
use md5::Md5;
use serde_json::Value;
use sha2::Digest as _;

const LATER_PART: usize = 300 * 1024;
const FIRST: &[u8] = b"FIRSTBODY";
const SECOND: &[u8] = b"SECONDBODY";
const UNWANTED: &[u8] = b"UNWANTEDBODY";
const LATER_UNWANTED: &[u8] = b"LATERUNWANTED";

const DATABASE: &str = "\
Test.First:0:*:4649525354424f4459
Test.Second:0:*:5345434f4e44424f4459
Heuristics.Test.Unwanted:0:*:554e57414e544544424f4459
Heuristics.Test.LaterUnwanted:0:*:4c41544552554e57414e544544
";

fn loose_databases(test: &str, files: &[(&str, &str)]) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    for (name, contents) in files {
        write_file(&databases.join(name), contents.as_bytes()).unwrap();
    }
    let compiled = compile(&databases, &directory, "loose").unwrap();
    (directory, compiled)
}

fn file_with(early: &[u8], later: &[u8]) -> Vec<u8> {
    let mut contents = vec![b'.'; LATER_PART + 1024];
    contents[..early.len()].copy_from_slice(early);
    contents[LATER_PART..LATER_PART + later.len()].copy_from_slice(later);
    contents
}

fn report(directory: &Path, image: &Path, options: &[&str], contents: &[u8]) -> Value {
    let input = directory.join("input");
    write_file(&input, contents).unwrap();
    comparison_report_with(image, options, &input, directory).unwrap()
}

#[test]
fn the_first_strong_detection_ends_the_scan_unless_every_match_is_asked_for() {
    const REQUIREMENT: &str =
        "The First Strong Detection Ends The Scan Unless Every Match Is Asked For";
    let (directory, compiled) = loose_databases("first-match", &[("local.ndb", DATABASE)]);
    let contents = file_with(FIRST, SECOND);

    let first = report(&directory, &compiled.image, &[], &contents);
    let every = report(&directory, &compiled.image, &["--every-match"], &contents);

    assert_eq!(
        detections(&first),
        ["Test.First.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(first["verdict"], "strong_indicator", "{REQUIREMENT}");
    assert_eq!(
        detections(&every),
        ["Test.First.UNOFFICIAL", "Test.Second.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(every["verdict"], "strong_indicator", "{REQUIREMENT}");
}

#[test]
fn a_potentially_unwanted_detection_is_reported_only_when_nothing_strong_is_found() {
    const REQUIREMENT: &str =
        "A Potentially Unwanted Detection Is Reported Only When Nothing Strong Is Found";
    let (directory, compiled) = loose_databases("unwanted-deferred", &[("local.ndb", DATABASE)]);

    let outranked = report(
        &directory,
        &compiled.image,
        &[],
        &file_with(UNWANTED, SECOND),
    );
    let unwanted_only = report(
        &directory,
        &compiled.image,
        &[],
        &file_with(UNWANTED, LATER_UNWANTED),
    );

    assert_eq!(
        detections(&outranked),
        ["Test.Second.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(outranked["verdict"], "strong_indicator", "{REQUIREMENT}");
    assert_eq!(
        detections(&unwanted_only),
        ["Heuristics.Test.LaterUnwanted.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        unwanted_only["verdict"], "potentially_unwanted",
        "{REQUIREMENT}"
    );
}

#[test]
fn with_every_match_potentially_unwanted_detections_are_reported_after_every_strong_one() {
    const REQUIREMENT: &str =
        "With Every Match, Potentially Unwanted Detections Are Reported After Every Strong One";
    let (directory, compiled) = loose_databases("unwanted-after", &[("local.ndb", DATABASE)]);
    let mut contents = file_with(UNWANTED, SECOND);
    contents[100..100 + FIRST.len()].copy_from_slice(FIRST);
    let later = LATER_PART + 200;
    contents[later..later + LATER_UNWANTED.len()].copy_from_slice(LATER_UNWANTED);

    let every = report(&directory, &compiled.image, &["--every-match"], &contents);

    assert_eq!(
        detections(&every),
        [
            "Test.First.UNOFFICIAL",
            "Test.Second.UNOFFICIAL",
            "Heuristics.Test.Unwanted.UNOFFICIAL",
            "Heuristics.Test.LaterUnwanted.UNOFFICIAL"
        ],
        "{REQUIREMENT}"
    );
}

#[test]
fn with_heuristic_precedence_a_potentially_unwanted_detection_is_strong() {
    const REQUIREMENT: &str =
        "With Heuristic Precedence, A Potentially Unwanted Detection Is Strong";
    let (directory, compiled) = loose_databases("heuristic-precedence", &[("local.ndb", DATABASE)]);

    let precedence = report(
        &directory,
        &compiled.image,
        &["--heuristic-precedence"],
        &file_with(UNWANTED, SECOND),
    );

    assert_eq!(
        detections(&precedence),
        ["Heuristics.Test.Unwanted.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(precedence["verdict"], "strong_indicator", "{REQUIREMENT}");
}

#[test]
fn a_file_whose_hash_is_listed_as_a_false_positive_is_trusted_whatever_detected_it() {
    const REQUIREMENT: &str =
        "A File Whose Hash Is Listed As A False Positive Is Trusted, Whatever Detected It";
    let contents = file_with(FIRST, SECOND);
    let false_positive = format!(
        "{}:{}:Test.Trusted\n",
        lowercase_hex(&Md5::digest(&contents)),
        contents.len()
    );
    let (directory, compiled) = loose_databases(
        "false-positive-pattern",
        &[("local.ndb", DATABASE), ("local.fp", &false_positive)],
    );

    for options in [&[][..], &["--every-match"][..]] {
        let trusted = report(&directory, &compiled.image, options, &contents);

        assert_eq!(detections(&trusted), Vec::<String>::new(), "{REQUIREMENT}");
        assert_eq!(trusted["verdict"], "trusted", "{REQUIREMENT}");
    }
}

const GENERIC_BODY: &[u8] = b"GENERICBODY";
const OTHER_DATA_BODY: &[u8] = b"OTHERDATABODY";

const PASS_DATABASE: &str = "\
Test.Generic:0:*:47454e45524943424f4459
Test.OtherData:14:*:4f5448455244415441424f4459
";

const PASS_FILE_TYPES: &str = "\
0:0:3c68746d6c3e:HTML data:CL_TYPE_ANY:CL_TYPE_HTML
0:0:5059434f4d50:compiled Python:CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED
0:0:41494d4f44454c:AI model:CL_TYPE_ANY:CL_TYPE_AI_MODEL
";

fn holding(start: &[u8], separator: &[u8], bodies: &[&[u8]]) -> Vec<u8> {
    let mut contents = start.to_vec();
    for body in bodies {
        contents.extend_from_slice(separator);
        contents.extend_from_slice(body);
    }
    contents.extend_from_slice(separator);
    contents
}

fn binary_holding(start: &[u8], bodies: &[&[u8]]) -> Vec<u8> {
    holding(start, b" \x00\x00\x00\x00 ", bodies)
}

fn listing_hash_of(contents: &[u8]) -> String {
    format!(
        "{}:{}:Test.Hash\n",
        lowercase_hex(&Md5::digest(contents)),
        contents.len()
    )
}

#[test]
fn binary_data_is_matched_twice_as_itself_and_as_other_data() {
    const REQUIREMENT: &str = "Binary Data Is Matched Twice, As Itself And As Other Data";
    let both_bodies: [&[u8]; 2] = [GENERIC_BODY, OTHER_DATA_BODY];
    let binary = binary_holding(b"\x00\x00\x00\x00binary", &both_bodies);
    let python = binary_holding(b"PYCOMP", &both_bodies);
    let model = binary_holding(b"AIMODEL", &both_bodies);
    let text = holding(b"plain text", b" .... ", &both_bodies);
    let hashes: String = [&binary, &python, &model, &text]
        .iter()
        .map(|contents| listing_hash_of(contents))
        .collect();
    let (directory, compiled) = loose_databases(
        "passes-per-kind",
        &[
            ("local.ndb", PASS_DATABASE),
            ("local.hdb", hashes.as_str()),
            ("types.ftm", PASS_FILE_TYPES),
        ],
    );
    let twice = [
        "Test.Generic.UNOFFICIAL",
        "Test.Hash.UNOFFICIAL",
        "Test.OtherData.UNOFFICIAL",
        "Test.Generic.UNOFFICIAL",
        "Test.Hash.UNOFFICIAL",
    ];

    for contents in [&binary, &python, &model] {
        let every = report(&directory, &compiled.image, &["--every-match"], contents);
        assert_eq!(
            detections(&every),
            twice,
            "{REQUIREMENT}: {}",
            every["type"]
        );
    }
    let text_report = report(&directory, &compiled.image, &["--every-match"], &text);
    assert_eq!(
        detections(&text_report),
        ["Test.Generic.UNOFFICIAL", "Test.Hash.UNOFFICIAL"],
        "{REQUIREMENT}: text"
    );
    let other_only = binary_holding(b"\x00\x00\x00\x00binary", &[OTHER_DATA_BODY]);
    assert_eq!(
        detections(&report(&directory, &compiled.image, &[], &other_only)),
        ["Test.OtherData.UNOFFICIAL"],
        "{REQUIREMENT}: without every match"
    );
}

#[test]
fn a_page_typed_as_html_from_its_first_bytes_is_never_detected_by_the_hash_of_its_own_bytes() {
    const REQUIREMENT: &str =
        "A Page Typed As HTML From Its First Bytes Is Never Detected By The Hash Of Its Own Bytes";
    let page = b"<html><body>a page a database lists by its hash</body></html>\n";
    let (directory, compiled) = loose_databases(
        "html-own-hash",
        &[
            ("local.hdb", listing_hash_of(page).as_str()),
            ("types.ftm", PASS_FILE_TYPES),
        ],
    );

    for options in [&[][..], &["--every-match"][..]] {
        let scanned = report(&directory, &compiled.image, options, page);

        assert_eq!(scanned["type"], "CL_TYPE_HTML", "{REQUIREMENT}");
        assert!(detections(&scanned).is_empty(), "{REQUIREMENT}");
    }
}
