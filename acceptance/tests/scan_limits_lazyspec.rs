#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

use acceptance::largest_file::{LARGEST_FILE, expressions_to_the_end, matched_only_to_the_end};
use acceptance::{
    CompiledImage, comparison_report, comparison_report_with, compile, detections,
    scratch_directory, write_file,
};
use serde_json::Value;

const BODY: &[u8] = b"BCDE";
const DATABASE: &str = "Test.Body:0:0:42434445\n";
const DEFAULT_LARGEST_FILE: usize = 100 * 1024 * 1024;

fn loose_databases(test: &str) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    write_file(&databases.join("local.ndb"), DATABASE.as_bytes()).unwrap();
    let compiled = compile(&databases, &directory, "loose").unwrap();
    (directory, compiled)
}

fn report(directory: &Path, image: &Path, length: usize) -> Value {
    let mut contents = vec![b'.'; length];
    contents[..BODY.len()].copy_from_slice(BODY);
    let input = directory.join("input");
    write_file(&input, &contents).unwrap();
    comparison_report(image, &input, directory).unwrap()
}

#[test]
fn a_file_of_five_bytes_or_less_is_never_scanned() {
    const REQUIREMENT: &str = "A File Of Five Bytes Or Less Is Never Scanned";
    let (directory, compiled) = loose_databases("five-bytes");

    let five = report(&directory, &compiled.image, 5);
    let six = report(&directory, &compiled.image, 6);

    assert_eq!(detections(&five), Vec::<String>::new(), "{REQUIREMENT}");
    assert_eq!(five["type"], Value::Null, "{REQUIREMENT}");
    assert_eq!(five["verdict"], "nothing_found", "{REQUIREMENT}");
    assert_eq!(detections(&six), ["Test.Body.UNOFFICIAL"], "{REQUIREMENT}");
}

#[test]
fn a_file_larger_than_the_file_size_limit_is_not_scanned() {
    const REQUIREMENT: &str = "A File Larger Than The File-Size Limit Is Not Scanned";
    let (directory, compiled) = loose_databases("largest-file");

    let larger = report(&directory, &compiled.image, DEFAULT_LARGEST_FILE + 1);
    let at_the_limit = report(&directory, &compiled.image, DEFAULT_LARGEST_FILE);

    assert_eq!(detections(&larger), Vec::<String>::new(), "{REQUIREMENT}");
    assert_eq!(larger["type"], Value::Null, "{REQUIREMENT}");
    assert_eq!(larger["verdict"], "nothing_found", "{REQUIREMENT}");
    assert_eq!(
        detections(&at_the_limit),
        ["Test.Body.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn a_file_up_to_the_file_size_limit_is_scanned_to_its_end() {
    const REQUIREMENT: &str = "A File Up To The File-Size Limit Is Scanned To Its End";
    let directory = scratch_directory("scanned-to-its-end").unwrap();
    let compiled = expressions_to_the_end(&directory).unwrap();
    let input = matched_only_to_the_end(&directory, LARGEST_FILE).unwrap();

    let every =
        comparison_report_with(&compiled.image, &["--every-match"], &input, &directory).unwrap();
    let first = comparison_report(&compiled.image, &input, &directory).unwrap();

    let mut every_detection = detections(&every);
    every_detection.sort();
    let reference = [
        "Test.Backreference.UNOFFICIAL",
        "Test.End.UNOFFICIAL",
        "Test.Large.UNOFFICIAL",
        "Test.Span.UNOFFICIAL",
        "Test.Tail.UNOFFICIAL",
    ];
    assert_eq!(every_detection, reference, "{REQUIREMENT}");
    assert_eq!(every["verdict"], "strong_indicator", "{REQUIREMENT}");
    let one = detections(&first);
    assert_eq!(one.len(), 1, "{REQUIREMENT}");
    assert!(reference.contains(&one[0].as_str()), "{REQUIREMENT}");
}
