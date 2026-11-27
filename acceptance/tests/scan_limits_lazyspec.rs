#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use acceptance::largest_file::{LARGEST_FILE, expressions_to_the_end, matched_only_to_the_end};
use acceptance::{
    CompiledImage, comparison_report, comparison_report_objects, comparison_report_with, compile,
    detections, release_binaries, run, scratch_directory, write_file,
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

const TRIGGERED_ELSEWHERE: usize = 400;
const TRIGGERED_FILE_LENGTH: usize = 17 * 1024 * 1024;
const MOST_WORK_FOR_THE_TRIGGERED_FILE: u64 = 2 * 17 * 1024 * 1024;
const LAST_BYTES: &[u8] = b"LASTBYTE";
const LAST_BYTES_BODY: &str = "Test.Last:0:EOF-8:4c41535442595445\n";

fn triggered_only_in_mail(test: &str) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    let mut in_mail = String::new();
    for index in 0..TRIGGERED_ELSEWHERE {
        writeln!(
            in_mail,
            "Test.InMail{index};Engine:81-255,Container:CL_TYPE_MAIL,Target:0;1;0:504b;0/mail{index}[0-9]+end/"
        )
        .unwrap();
    }
    write_file(&databases.join("local.ldb"), in_mail.as_bytes()).unwrap();
    write_file(&databases.join("local.ndb"), LAST_BYTES_BODY.as_bytes()).unwrap();
    let compiled = compile(&databases, &directory, "triggered-only-in-mail").unwrap();
    (directory, compiled)
}

fn triggering_file(directory: &Path, name: &str, ending: &[u8]) -> PathBuf {
    let mut contents = vec![b'.'; TRIGGERED_FILE_LENGTH];
    contents[..2].copy_from_slice(b"PK");
    contents[TRIGGERED_FILE_LENGTH.checked_sub(ending.len()).unwrap()..].copy_from_slice(ending);
    let input = directory.join(name);
    write_file(&input, &contents).unwrap();
    input
}

fn work_units_to_scan(image: &Path, input: &Path) -> u64 {
    let measured = run(Command::new(&release_binaries().unwrap().debar)
        .arg("measure-scan")
        .arg("--image")
        .arg(image)
        .arg(input))
    .unwrap();
    let measured: Value = serde_json::from_slice(&measured).unwrap();
    measured["work_units"].as_u64().unwrap()
}

#[test]
fn a_file_is_scanned_to_its_end_however_many_signatures_it_triggers_that_cannot_report_in_it() {
    const REQUIREMENT: &str =
        "A File Is Scanned To Its End However Many Signatures It Triggers That Cannot Report In It";
    let (directory, compiled) = triggered_only_in_mail("triggered-only-in-mail");
    let ending_detected = triggering_file(&directory, "ending-detected", LAST_BYTES);
    let ending_clean = triggering_file(&directory, "ending-clean", b"........");

    let every = comparison_report_with(
        &compiled.image,
        &["--every-match"],
        &ending_detected,
        &directory,
    )
    .unwrap();
    let work = work_units_to_scan(&compiled.image, &ending_clean);

    assert_eq!(
        detections(&every),
        ["Test.Last.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(every["verdict"], "strong_indicator", "{REQUIREMENT}");
    assert!(
        work < MOST_WORK_FOR_THE_TRIGGERED_FILE,
        "{REQUIREMENT}: {work} work units for {TRIGGERED_FILE_LENGTH} bytes"
    );
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

const FIRST_MARK: &[u8] = b"FIRSTMARK";
const LAST_MARK: &[u8] = b"LASTMARK";
const MARKS_DATABASE: &str = "Test.First:0:0:46495253544d41524b\nTest.Last:0:*:4c4153544d41524b\n";
const MARKED_LENGTH: usize = 16 * 1024 * 1024;
const SCAN_TIME_REACHED_IN_THE_MIDDLE: &str = "100";
const BUSY_THREADS: usize = 8;

fn marked_at_both_ends(test: &str) -> (PathBuf, CompiledImage, PathBuf) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    write_file(&databases.join("local.ndb"), MARKS_DATABASE.as_bytes()).unwrap();
    let compiled = compile(&databases, &directory, "marks").unwrap();
    let mut contents = vec![b'.'; MARKED_LENGTH];
    contents[..FIRST_MARK.len()].copy_from_slice(FIRST_MARK);
    contents[MARKED_LENGTH.saturating_sub(LAST_MARK.len())..].copy_from_slice(LAST_MARK);
    let input = directory.join("input");
    write_file(&input, &contents).unwrap();
    (directory, compiled, input)
}

fn time_limited_report(image: &Path, input: &Path, into: &Path) -> Value {
    std::fs::create_dir_all(into).unwrap();
    comparison_report_with(
        image,
        &[
            "--every-match",
            "--max-scan-time",
            SCAN_TIME_REACHED_IN_THE_MIDDLE,
            "--alert-exceeds-max",
        ],
        input,
        into,
    )
    .unwrap()
}

#[test]
fn a_scans_time_limit_gives_the_same_verdict_at_any_machine_speed() {
    const REQUIREMENT: &str = "A Scan's Time Limit Gives The Same Verdict At Any Machine Speed";
    let (directory, compiled, input) = marked_at_both_ends("scan-time-any-speed");
    let quiet: Vec<Value> = (0..3)
        .map(|run| {
            time_limited_report(
                &compiled.image,
                &input,
                &directory.join(format!("quiet-{run}")),
            )
        })
        .collect();

    let busy = std::sync::atomic::AtomicBool::new(true);
    let loaded: Vec<Value> = std::thread::scope(|scope| {
        for _ in 0..BUSY_THREADS {
            scope.spawn(|| {
                let mut spun = 0u64;
                while busy.load(std::sync::atomic::Ordering::Relaxed) {
                    spun = std::hint::black_box(spun.wrapping_add(1));
                }
            });
        }
        let scans: Vec<_> = (0..3)
            .map(|run| {
                let into = directory.join(format!("loaded-{run}"));
                let (image, input) = (&compiled.image, &input);
                scope.spawn(move || time_limited_report(image, input, &into))
            })
            .collect();
        let reports = scans.into_iter().map(|scan| scan.join().unwrap()).collect();
        busy.store(false, std::sync::atomic::Ordering::Relaxed);
        reports
    });

    assert_eq!(
        detections(&quiet[0]),
        [
            "Test.First.UNOFFICIAL",
            "Heuristics.Limits.Exceeded.MaxScanTime"
        ],
        "{REQUIREMENT}"
    );
    for report in quiet.iter().chain(&loaded) {
        assert_eq!(report, &quiet[0], "{REQUIREMENT}");
    }
}

#[test]
fn a_scan_that_would_exceed_its_time_limit_stops_keeps_what_it_found_and_alerts_only_when_asked() {
    const REQUIREMENT: &str = "A Scan That Would Exceed Its Time Limit Stops, Keeps What It Found, And Alerts Only When Asked";
    let (directory, compiled, input) = marked_at_both_ends("scan-time-stops");
    let scanned = |options: &[&str]| {
        comparison_report_with(&compiled.image, options, &input, &directory).unwrap()
    };

    let quiet = scanned(&[
        "--every-match",
        "--max-scan-time",
        SCAN_TIME_REACHED_IN_THE_MIDDLE,
    ]);
    let alerted = scanned(&[
        "--every-match",
        "--max-scan-time",
        SCAN_TIME_REACHED_IN_THE_MIDDLE,
        "--alert-exceeds-max",
    ]);
    let switched_off = scanned(&["--every-match", "--max-scan-time", "0"]);

    assert_eq!(
        detections(&quiet),
        ["Test.First.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(quiet["verdict"], "strong_indicator", "{REQUIREMENT}");
    assert_eq!(
        detections(&alerted),
        [
            "Test.First.UNOFFICIAL",
            "Heuristics.Limits.Exceeded.MaxScanTime"
        ],
        "{REQUIREMENT}"
    );
    assert_eq!(alerted["verdict"], "strong_indicator", "{REQUIREMENT}");
    assert_eq!(
        detections(&switched_off),
        ["Test.First.UNOFFICIAL", "Test.Last.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}
