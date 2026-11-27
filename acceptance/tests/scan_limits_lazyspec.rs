#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

use acceptance::largest_file::{LARGEST_FILE, expressions_to_the_end, matched_only_to_the_end};
use acceptance::{
    CompiledImage, comparison_report, comparison_report_objects, comparison_report_with, compile,
    detections, scratch_directory, write_file,
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

const ARCHIVE_MARK: &[u8] = b"ARCHIVEMARK";
const NESTED_FILE_TYPES: &str = "\
0:0:4d5a:DOS/W32 executable:CL_TYPE_ANY:CL_TYPE_MSEXE
1:*:415243484956454d41524b:RAR-SFX:CL_TYPE_ANY:CL_TYPE_RARSFX
";
const TOP_LEVEL_BODY: &str = "Test.Top:0:0:706c61696e2074657874\n";
const INSIDE_BODY: &str =
    "Test.Inside;Engine:51-255,Target:0,Container:CL_TYPE_TEXT_ASCII;0;415243484956454d41524b\n";

fn nested_databases(test: &str) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    for (name, contents) in [
        ("types.ftm", NESTED_FILE_TYPES),
        ("local.ndb", TOP_LEVEL_BODY),
        ("local.ldb", INSIDE_BODY),
    ] {
        write_file(&databases.join(name), contents.as_bytes()).unwrap();
    }
    let compiled = compile(&databases, &directory, "nested").unwrap();
    (directory, compiled)
}

fn holding_archives(count: usize, padding_after_first: usize) -> Vec<u8> {
    let mut contents = b"plain text".to_vec();
    for index in 0..count {
        contents.extend_from_slice(b" .... ");
        contents.extend_from_slice(ARCHIVE_MARK);
        if index == 0 {
            contents.extend(std::iter::repeat_n(b'.', padding_after_first));
        }
    }
    contents.extend_from_slice(b" ....\n");
    contents
}

fn objects_with(directory: &Path, image: &Path, options: &[&str], contents: &[u8]) -> Vec<Value> {
    let input = directory.join("input");
    write_file(&input, contents).unwrap();
    comparison_report_objects(image, options, &input, directory).unwrap()
}

fn sizes(objects: &[Value]) -> Vec<u64> {
    objects
        .iter()
        .map(|object| object["size"].as_u64().unwrap())
        .collect()
}

#[test]
fn an_object_deeper_than_the_recursion_limit_is_not_scanned() {
    const REQUIREMENT: &str = "An Object Deeper Than The Recursion Limit Is Not Scanned";
    let (directory, compiled) = nested_databases("recursion-limit");
    let contents = holding_archives(1, 0);

    let one = objects_with(
        &directory,
        &compiled.image,
        &["--every-match", "--max-recursion", "1"],
        &contents,
    );
    let two = objects_with(
        &directory,
        &compiled.image,
        &["--every-match", "--max-recursion", "2"],
        &contents,
    );

    assert_eq!(one.len(), 1, "{REQUIREMENT}");
    assert_eq!(
        detections(&one[0]),
        ["Test.Top.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(two.len(), 2, "{REQUIREMENT}");
    assert_eq!(two[1]["depth"], 1, "{REQUIREMENT}");
    assert_eq!(
        detections(&two[1]),
        ["Test.Inside.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn the_top_level_file_counts_against_the_file_count_limit() {
    const REQUIREMENT: &str = "The Top-Level File Counts Against The File-Count Limit";
    let (directory, compiled) = nested_databases("file-count-limit");
    let contents = holding_archives(2, 0);

    let counted = |most: &str| {
        objects_with(
            &directory,
            &compiled.image,
            &["--every-match", "--max-files", most],
            &contents,
        )
        .len()
    };

    assert_eq!(counted("1"), 1, "{REQUIREMENT}");
    assert_eq!(counted("2"), 2, "{REQUIREMENT}");
    assert_eq!(counted("3"), 3, "{REQUIREMENT}");
}

#[test]
fn an_object_too_large_for_what_remains_of_the_scan_size_limit_is_skipped_and_later_ones_are_still_scanned()
 {
    const REQUIREMENT: &str = "An Object Too Large For What Remains Of The Scan-Size Limit Is Skipped, And Later Ones Are Still Scanned";
    let (directory, compiled) = nested_databases("scan-size-limit");
    let contents = holding_archives(2, 64);
    let unlimited = objects_with(&directory, &compiled.image, &["--every-match"], &contents);
    let all = sizes(&unlimited);
    assert_eq!(all.len(), 3, "{REQUIREMENT}");
    let room_for_the_second = (all[0] + all[2]).to_string();

    let limited = objects_with(
        &directory,
        &compiled.image,
        &["--every-match", "--max-scan-size", &room_for_the_second],
        &contents,
    );

    assert_eq!(sizes(&limited), [all[0], all[2]], "{REQUIREMENT}");
}

#[test]
fn at_most_one_limit_alert_is_reported_and_only_when_asked_for() {
    const REQUIREMENT: &str = "At Most One Limit Alert Is Reported, And Only When Asked For";
    let (directory, compiled) = nested_databases("limit-alert");
    let contents = holding_archives(2, 0);
    let scanned = |options: &[&str]| {
        let objects = objects_with(&directory, &compiled.image, options, &contents);
        detections(&objects[0])
    };

    let files = scanned(&["--every-match", "--max-files", "1", "--alert-exceeds-max"]);
    let deep = scanned(&[
        "--every-match",
        "--max-recursion",
        "1",
        "--alert-exceeds-max",
    ]);
    let quiet = scanned(&["--every-match", "--max-files", "1"]);

    assert_eq!(
        files,
        ["Test.Top.UNOFFICIAL", "Heuristics.Limits.Exceeded.MaxFiles"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        deep,
        [
            "Test.Top.UNOFFICIAL",
            "Heuristics.Limits.Exceeded.MaxRecursion"
        ],
        "{REQUIREMENT}"
    );
    assert_eq!(quiet, ["Test.Top.UNOFFICIAL"], "{REQUIREMENT}");
}
