#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use acceptance::{
    compile, lowercase_hex, members_of_pinned_databases, official_image, pinned_databases,
    release_binaries, scratch_directory, target_directory, write_file,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const HASH_LINE_OUTCOMES: [&str; 5] = [
    "compiled",
    "outside_functionality_level",
    "ignored",
    "comment",
    "shadowed_by_duplicate",
];

fn is_hash_file(kind: &str) -> bool {
    kind.contains("hashes")
}

fn count(outcomes: &Value, outcome: &str) -> u64 {
    outcomes[outcome].as_u64().unwrap()
}

#[test]
fn every_hash_signature_line_in_the_pinned_databases_is_accounted_for_in_the_image() {
    const REQUIREMENT: &str =
        "Every Hash Signature Line In The Pinned Databases Is Accounted For In The Image";
    let compiled = official_image().unwrap();
    let files = compiled.account["files"].as_array().unwrap();
    let accounted: BTreeMap<(String, String), &Value> = files
        .iter()
        .map(|file| {
            (
                (
                    file["file"].as_str().unwrap().to_owned(),
                    file["member"].as_str().unwrap().to_owned(),
                ),
                file,
            )
        })
        .collect();

    let members = members_of_pinned_databases(&pinned_databases().unwrap()).unwrap();
    assert_eq!(
        accounted.len(),
        members.len(),
        "{REQUIREMENT}: one account per file"
    );
    let mut compiled_hash_lines = 0u64;
    let mut hash_lines = 0u64;
    for member in &members {
        let file = accounted
            .get(&(member.container.clone(), member.member.clone()))
            .unwrap_or_else(|| {
                panic!(
                    "{REQUIREMENT}: {} {} is not accounted for",
                    member.container, member.member
                )
            });
        let lines = u64::try_from(member.lines).unwrap();
        assert_eq!(
            file["lines"].as_u64(),
            Some(lines),
            "{REQUIREMENT}: {}",
            member.member
        );
        let outcomes = &file["outcomes"];
        let total: u64 = outcomes
            .as_object()
            .unwrap()
            .values()
            .map(|value| value.as_u64().unwrap())
            .sum();
        assert_eq!(
            total, lines,
            "{REQUIREMENT}: every line of {} has one outcome",
            member.member
        );
        if is_hash_file(file["kind"].as_str().unwrap()) {
            let hash_outcomes: u64 = HASH_LINE_OUTCOMES
                .iter()
                .map(|outcome| count(outcomes, outcome))
                .sum();
            assert_eq!(
                hash_outcomes, lines,
                "{REQUIREMENT}: no hash line of {} is unsupported",
                member.member
            );
            hash_lines += lines;
            compiled_hash_lines += count(outcomes, "compiled");
        }
    }
    let image_entries: u64 = compiled.account["image"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|section| section["kind"] == "hash entries")
        .map(|section| section["items"].as_u64().unwrap())
        .sum();
    assert!(
        hash_lines > 3_000_000,
        "{REQUIREMENT}: the pinned databases were read"
    );
    assert_eq!(
        image_entries, compiled_hash_lines,
        "{REQUIREMENT}: one image entry per compiled line"
    );
}

#[test]
fn the_same_databases_always_compile_to_the_same_image_byte_for_byte() {
    const REQUIREMENT: &str = "The Same Databases Always Compile To The Same Image, Byte For Byte";
    let databases = pinned_databases().unwrap();
    let directory = scratch_directory("same-image").unwrap();

    let first = compile(&databases, &directory, "first").unwrap();
    let second = compile(&databases, &directory, "second").unwrap();

    let first = std::fs::read(first.image).unwrap();
    let second = std::fs::read(second.image).unwrap();
    assert!(first == second, "{REQUIREMENT}");
    std::fs::write(
        target_directory()
            .join("acceptance")
            .join("official-image.sha256"),
        format!("{}\n", lowercase_hex(&Sha256::digest(&first))),
    )
    .unwrap();
}

const EXTENDED_LINE_OUTCOMES: [&str; 6] = [
    "compiled",
    "outside_functionality_level",
    "ignored",
    "comment",
    "target_not_loaded",
    "never_reports",
];

const FILE_TYPE_LINE_OUTCOMES: [&str; 4] = [
    "compiled",
    "outside_functionality_level",
    "comment",
    "not_a_signature",
];

const FILE_TYPE_LINES_THE_REFERENCE_SCANNER_LOADS: u64 = 256;

#[test]
fn every_extended_signature_line_in_the_pinned_databases_is_accounted_for_in_the_image() {
    const REQUIREMENT: &str =
        "Every Extended Signature Line In The Pinned Databases Is Accounted For In The Image";
    let compiled = official_image().unwrap();
    let files = compiled.account["files"].as_array().unwrap();
    let members = members_of_pinned_databases(&pinned_databases().unwrap()).unwrap();
    let mut compiled_lines = 0u64;
    let mut extended_files = 0;
    for file in files.iter().filter(|file| {
        file["kind"]
            .as_str()
            .unwrap()
            .starts_with("extended signatures")
    }) {
        extended_files += 1;
        let member = members
            .iter()
            .find(|member| member.member == file["member"].as_str().unwrap())
            .unwrap();
        let outcomes = &file["outcomes"];
        let accounted: u64 = EXTENDED_LINE_OUTCOMES
            .iter()
            .map(|outcome| count(outcomes, outcome))
            .sum();
        assert_eq!(
            accounted,
            u64::try_from(member.lines).unwrap(),
            "{REQUIREMENT}: every line of {} has one outcome",
            member.member
        );
        let left_out: Vec<usize> = file["lines_not_compiled"]
            .as_array()
            .unwrap()
            .iter()
            .map(|line| usize::try_from(line["line"].as_u64().unwrap()).unwrap())
            .collect();
        let loaded = member
            .contents
            .split(|byte| *byte == b'\n')
            .zip(1usize..)
            .filter(|(line, number)| !line.is_empty() && !left_out.contains(number))
            .count();
        assert_eq!(
            count(outcomes, "compiled"),
            u64::try_from(loaded).unwrap(),
            "{REQUIREMENT}: every loaded line of {} is compiled",
            member.member
        );
        compiled_lines += count(outcomes, "compiled");
    }
    assert_eq!(
        extended_files, 3,
        "{REQUIREMENT}: main.ndb, daily.ndb and daily.ndu"
    );
    assert!(
        compiled_lines > 30_000,
        "{REQUIREMENT}: the pinned databases were read"
    );
    let image_signatures: u64 = compiled.account["image"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|section| section["kind"] == "pattern signatures")
        .map(|section| section["items"].as_u64().unwrap())
        .sum();
    assert_eq!(
        image_signatures, compiled_lines,
        "{REQUIREMENT}: one image entry per compiled line"
    );
}

#[test]
fn every_file_type_line_in_the_pinned_databases_is_accounted_for_in_the_image() {
    const REQUIREMENT: &str =
        "Every File-Type Line In The Pinned Databases Is Accounted For In The Image";
    let compiled = official_image().unwrap();
    let files = compiled.account["files"].as_array().unwrap();
    let members = members_of_pinned_databases(&pinned_databases().unwrap()).unwrap();
    let mut compiled_lines = 0u64;
    for file in files.iter().filter(|file| file["kind"] == "file types") {
        let member = members
            .iter()
            .find(|member| member.member == file["member"].as_str().unwrap())
            .unwrap();
        let outcomes = &file["outcomes"];
        let accounted: u64 = FILE_TYPE_LINE_OUTCOMES
            .iter()
            .map(|outcome| count(outcomes, outcome))
            .sum();
        assert_eq!(
            accounted,
            u64::try_from(member.lines).unwrap(),
            "{REQUIREMENT}: every line of {} has one outcome",
            member.member
        );
        compiled_lines += count(outcomes, "compiled");
    }
    assert_eq!(
        compiled_lines, FILE_TYPE_LINES_THE_REFERENCE_SCANNER_LOADS,
        "{REQUIREMENT}: every loaded line is compiled"
    );
    let items_in = |kind: &str| -> u64 {
        compiled.account["image"]["sections"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|section| section["kind"] == kind)
            .map(|section| section["items"].as_u64().unwrap())
            .sum()
    };
    assert_eq!(
        items_in("type magic") + items_in("type recognition signatures"),
        compiled_lines,
        "{REQUIREMENT}: one image entry per compiled line"
    );
}

#[test]
fn a_malformed_extended_signature_line_fails_the_compile() {
    const REQUIREMENT: &str = "A Malformed Extended Signature Line Fails The Compile";
    let directory = scratch_directory("malformed-extended").unwrap();
    for (case, line) in [
        ("fields", "Test.Few:0:*\n"),
        ("name", ":0:*:41424344\n"),
        ("level", "Test.Level:0:*:41424344:x\n"),
        ("target", "Test.Target:x:*:41424344\n"),
        ("offset", "Test.Offset:0:EOF+3:41424344\n"),
        ("body", "Test.Body:0:*:4142zz\n"),
    ] {
        let databases = directory.join(case);
        std::fs::create_dir(&databases).unwrap();
        write_file(
            &databases.join("local.ndb"),
            format!("Test.Good:0:*:41424344\n{line}").as_bytes(),
        )
        .unwrap();
        let image = directory.join(format!("{case}.image"));
        let output = std::process::Command::new(&release_binaries().unwrap().compiler)
            .arg("--databases")
            .arg(&databases)
            .arg("--image")
            .arg(&image)
            .arg("--account")
            .arg(directory.join(format!("{case}.json")))
            .output()
            .unwrap();
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{REQUIREMENT}: {case}");
        assert!(
            message.contains("local.ndb line 2"),
            "{REQUIREMENT}: {case}: {message}"
        );
        assert!(!image.exists(), "{REQUIREMENT}: {case}");
    }
}
