#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use acceptance::{
    comparison_report, compile, detections, lowercase_hex, members_of_pinned_databases,
    official_image, pinned_databases, release_binaries, scratch_directory, target_directory,
    write_file,
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
fn every_line_of_every_pinned_database_file_is_accounted_for_and_none_is_left_uncompiled() {
    const REQUIREMENT: &str =
        "Every Line Of Every Pinned Database File Is Accounted For And None Is Left Uncompiled";
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
        assert_eq!(
            count(outcomes, "not_yet_compiled"),
            0,
            "{REQUIREMENT}: no line of {} is left uncompiled",
            member.member
        );
    }
    assert_eq!(
        compiled.account["line_totals"]["not_yet_compiled"].as_u64(),
        Some(0),
        "{REQUIREMENT}"
    );
}

#[test]
fn every_hash_signature_line_in_the_pinned_databases_is_accounted_for_in_the_image() {
    const REQUIREMENT: &str =
        "Every Hash Signature Line In The Pinned Databases Is Accounted For In The Image";
    let compiled = official_image().unwrap();
    let files = compiled.account["files"].as_array().unwrap();
    let mut compiled_hash_lines = 0u64;
    let mut hash_lines = 0u64;
    for file in files
        .iter()
        .filter(|file| is_hash_file(file["kind"].as_str().unwrap()))
    {
        let lines = file["lines"].as_u64().unwrap();
        let outcomes = &file["outcomes"];
        let hash_outcomes: u64 = HASH_LINE_OUTCOMES
            .iter()
            .map(|outcome| count(outcomes, outcome))
            .sum();
        assert_eq!(
            hash_outcomes, lines,
            "{REQUIREMENT}: no hash line of {} is unsupported",
            file["member"]
        );
        hash_lines += lines;
        compiled_hash_lines += count(outcomes, "compiled");
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

const LOGICAL_LINE_OUTCOMES: [&str; 6] = [
    "compiled",
    "outside_functionality_level",
    "ignored",
    "comment",
    "target_not_loaded",
    "not_loaded",
];

#[test]
fn every_logical_signature_line_in_the_pinned_databases_is_accounted_for_in_the_image() {
    const REQUIREMENT: &str =
        "Every Logical Signature Line In The Pinned Databases Is Accounted For In The Image";
    let compiled = official_image().unwrap();
    let files = compiled.account["files"].as_array().unwrap();
    let members = members_of_pinned_databases(&pinned_databases().unwrap()).unwrap();
    let mut compiled_lines = 0u64;
    let mut logical_files = 0;
    for file in files.iter().filter(|file| {
        file["kind"]
            .as_str()
            .unwrap()
            .starts_with("logical signatures")
    }) {
        logical_files += 1;
        let member = members
            .iter()
            .find(|member| member.member == file["member"].as_str().unwrap())
            .unwrap();
        let outcomes = &file["outcomes"];
        let accounted: u64 = LOGICAL_LINE_OUTCOMES
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
        let loaded: Vec<String> = String::from_utf8_lossy(&member.contents)
            .split('\n')
            .zip(1usize..)
            .filter(|(line, number)| !line.is_empty() && !left_out.contains(number))
            .map(|(line, _)| line.to_owned())
            .collect();
        assert_eq!(
            count(outcomes, "compiled"),
            u64::try_from(loaded.len()).unwrap(),
            "{REQUIREMENT}: every other loaded line of {} is compiled",
            member.member
        );
        compiled_lines += count(outcomes, "compiled");
    }
    assert_eq!(
        logical_files, 3,
        "{REQUIREMENT}: main.ldb, daily.ldb and daily.ldu"
    );
    assert!(
        compiled_lines > 300_000,
        "{REQUIREMENT}: the pinned databases were read"
    );
    let image_signatures: u64 = compiled.account["image"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|section| section["kind"] == "logical signatures")
        .map(|section| section["items"].as_u64().unwrap())
        .sum();
    let triggers: u64 = compiled.account["image"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|section| section["triggered_programs"].as_u64())
        .sum();
    assert_eq!(
        image_signatures,
        compiled_lines + triggers,
        "{REQUIREMENT}: one image entry per compiled line, beside the programs' triggers"
    );
}

#[test]
fn a_malformed_logical_signature_line_fails_the_compile() {
    const REQUIREMENT: &str = "A Malformed Logical Signature Line Fails The Compile";
    let directory = scratch_directory("malformed-logical").unwrap();
    for (case, line) in [
        ("fields", "Test.Few;Target:0;0\n"),
        (
            "expression",
            "Test.Expression;Target:0;(0&1;41424344;45464748\n",
        ),
        ("count", "Test.Count;Target:0;0&1;41424344\n"),
        (
            "attribute",
            "Test.Attribute;Engine:51-255,Target:0,FileSize:9;0;41424344\n",
        ),
        ("target", "Test.Target;Engine:51-255;0;41424344\n"),
        ("subsignature", "Test.Body;Target:0;0;4142zz\n"),
    ] {
        let databases = directory.join(case);
        std::fs::create_dir(&databases).unwrap();
        write_file(
            &databases.join("local.ldb"),
            format!("Test.Good;Target:0;0;41424344\n{line}").as_bytes(),
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
            message.contains("local.ldb line 2"),
            "{REQUIREMENT}: {case}: {message}"
        );
        assert!(!image.exists(), "{REQUIREMENT}: {case}");
    }
}

const CONTAINER_LINE_OUTCOMES: [&str; 4] = [
    "compiled",
    "outside_functionality_level",
    "ignored",
    "comment",
];

#[test]
fn every_container_signature_line_in_the_pinned_databases_is_accounted_for_in_the_image() {
    const REQUIREMENT: &str =
        "Every Container Signature Line In The Pinned Databases Is Accounted For In The Image";
    let compiled = official_image().unwrap();
    let files = compiled.account["files"].as_array().unwrap();
    let members = members_of_pinned_databases(&pinned_databases().unwrap()).unwrap();
    let mut compiled_lines = 0u64;
    let mut container_files = 0;
    for file in files
        .iter()
        .filter(|file| file["kind"] == "container signatures")
    {
        container_files += 1;
        let member = members
            .iter()
            .find(|member| member.member == file["member"].as_str().unwrap())
            .unwrap();
        let outcomes = &file["outcomes"];
        let accounted: u64 = CONTAINER_LINE_OUTCOMES
            .iter()
            .map(|outcome| count(outcomes, outcome))
            .sum();
        assert_eq!(
            accounted,
            u64::try_from(member.lines).unwrap(),
            "{REQUIREMENT}: every line of {} has one outcome",
            member.member
        );
        let comments = String::from_utf8_lossy(&member.contents)
            .split('\n')
            .filter(|line| line.starts_with('#'))
            .count();
        let left_out = file["lines_not_compiled"].as_array().unwrap().len();
        assert_eq!(
            count(outcomes, "compiled"),
            u64::try_from(member.lines - comments - left_out).unwrap(),
            "{REQUIREMENT}: every loaded line of {} is compiled",
            member.member
        );
        compiled_lines += count(outcomes, "compiled");
    }
    assert_eq!(container_files, 2, "{REQUIREMENT}: main.cdb and daily.cdb");
    assert!(
        compiled_lines > 100,
        "{REQUIREMENT}: the pinned databases were read"
    );
    let image_signatures: u64 = compiled.account["image"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|section| section["kind"] == "container signatures")
        .map(|section| section["items"].as_u64().unwrap())
        .sum();
    assert_eq!(
        image_signatures, compiled_lines,
        "{REQUIREMENT}: one image entry per compiled line"
    );
}

#[test]
fn a_malformed_container_signature_line_fails_the_compile() {
    const REQUIREMENT: &str = "A Malformed Container Signature Line Fails The Compile";
    let directory = scratch_directory("malformed-container").unwrap();
    for (case, line) in [
        ("few", "C.Few:CL_TYPE_ZIP:*:*:*:*:*:*:*\n"),
        ("many", "C.Many:CL_TYPE_ZIP:*:*:*:*:*:*:*:*:0:255:1\n"),
        ("type", "C.Type:ZIP:*:*:*:*:*:*:*:*\n"),
        ("size", "C.Size:CL_TYPE_ZIP:*:*:10-:*:*:*:*:*\n"),
        ("position", "C.Position:CL_TYPE_ZIP:*:*:*:*:*:2x:*:*\n"),
        ("encrypted", "C.Encrypted:CL_TYPE_ZIP:*:*:*:*:2:*:*:*\n"),
        ("level", "C.Level:CL_TYPE_ZIP:*:*:*:*:*:*:*:*:x\n"),
        ("name", "C.Name:CL_TYPE_ZIP:*:a(b:*:*:*:*:*:*\n"),
    ] {
        let databases = directory.join(case);
        std::fs::create_dir(&databases).unwrap();
        write_file(
            &databases.join("local.cdb"),
            format!("C.Good:CL_TYPE_ZIP:*:*:*:*:*:*:*:*\n{line}").as_bytes(),
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
            message.contains("local.cdb line 2"),
            "{REQUIREMENT}: {case}: {message}"
        );
        assert!(!image.exists(), "{REQUIREMENT}: {case}");
    }
}

fn files_of_kind<'a>(account: &'a Value, kind: &str) -> Vec<&'a Value> {
    account["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|file| file["kind"] == kind)
        .collect()
}

fn compiled_lines_of_kind(account: &Value, kind: &str) -> u64 {
    files_of_kind(account, kind)
        .iter()
        .map(|file| count(&file["outcomes"], "compiled"))
        .sum()
}

fn section_items(account: &Value, kind: &str) -> u64 {
    account["image"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|section| section["kind"] == kind)
        .map(|section| section["items"].as_u64().unwrap())
        .sum()
}

#[test]
fn every_certificate_rule_icon_signature_and_url_rule_in_the_pinned_databases_is_compiled_into_the_image()
 {
    const REQUIREMENT: &str = "Every Certificate Rule, Icon Signature And URL Rule In The Pinned Databases Is Compiled Into The Image";
    let compiled = official_image().unwrap();
    let account = &compiled.account;
    let members = members_of_pinned_databases(&pinned_databases().unwrap()).unwrap();
    let field_counts = |member: &str, separator: char, field: usize| -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        let found = members
            .iter()
            .find(|candidate| candidate.member == member)
            .unwrap();
        for line in String::from_utf8_lossy(&found.contents).lines() {
            if !line.starts_with('#') && !line.is_empty() {
                *counts
                    .entry(
                        line.split(separator)
                            .nth(field)
                            .unwrap_or_default()
                            .to_owned(),
                    )
                    .or_insert(0) += 1;
            }
        }
        counts
    };
    assert_eq!(
        compiled_lines_of_kind(account, "certificate rules"),
        30,
        "{REQUIREMENT}"
    );
    let trust = field_counts("daily.crb", ';', 1);
    assert_eq!((trust["1"], trust["0"]), (8, 22), "{REQUIREMENT}");
    assert_eq!(
        section_items(account, "certificate rules"),
        30,
        "{REQUIREMENT}"
    );
    assert_eq!(
        compiled_lines_of_kind(account, "icon signatures"),
        222,
        "{REQUIREMENT}"
    );
    assert_eq!(field_counts("daily.idb", ':', 1).len(), 22, "{REQUIREMENT}");
    assert_eq!(field_counts("daily.idb", ':', 2).len(), 19, "{REQUIREMENT}");
    assert_eq!(
        section_items(account, "icon signatures"),
        222,
        "{REQUIREMENT}"
    );
    assert_eq!(
        compiled_lines_of_kind(account, "monitored URL rules"),
        263,
        "{REQUIREMENT}"
    );
    assert_eq!(
        compiled_lines_of_kind(account, "allowed URL rules"),
        185,
        "{REQUIREMENT}"
    );
    assert_eq!(
        section_items(account, "URL rules"),
        263 + 185,
        "{REQUIREMENT}"
    );
}

#[test]
fn every_engine_switch_in_the_pinned_databases_is_evaluated_at_the_functionality_level() {
    const REQUIREMENT: &str =
        "Every Engine Switch In The Pinned Databases Is Evaluated At The Functionality Level";
    let compiled = official_image().unwrap();
    let switches = files_of_kind(&compiled.account, "engine switches");
    assert_eq!(switches.len(), 1, "{REQUIREMENT}: daily.cfg");
    let outcomes = &switches[0]["outcomes"];
    assert_eq!(
        count(outcomes, "outside_functionality_level"),
        21,
        "{REQUIREMENT}"
    );
    assert_eq!(count(outcomes, "compiled"), 0, "{REQUIREMENT}");
    let directory = scratch_directory("engine-switches").unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    write_file(
        &databases.join("daily.cfg"),
        b"PE:0x0:51:51\nPHISHING:0x2\n",
    )
    .unwrap();
    write_file(&databases.join("local.pdb"), b"H:example.com\n").unwrap();
    let turned_off = compile(&databases, &directory, "switched").unwrap();
    let outcomes = &files_of_kind(&turned_off.account, "engine switches")[0]["outcomes"];
    assert_eq!(
        (
            count(outcomes, "outside_functionality_level"),
            count(outcomes, "compiled")
        ),
        (1, 1),
        "{REQUIREMENT}: a switch takes effect only within its range"
    );
    assert_eq!(
        count(
            &files_of_kind(&turned_off.account, "monitored URL rules")[0]["outcomes"],
            "not_loaded"
        ),
        1,
        "{REQUIREMENT}: a switch that takes effect turns its feature off"
    );
    let defaults = section_items(&compiled.account, "engine features");
    assert_eq!(
        defaults, 86,
        "{REQUIREMENT}: every engine feature at its default"
    );
    assert_eq!(
        section_items(&turned_off.account, "engine features"),
        defaults - 1,
        "{REQUIREMENT}"
    );
}

#[test]
fn every_signature_program_in_the_pinned_databases_is_verified_and_compiled_into_the_image() {
    const REQUIREMENT: &str =
        "Every Signature Program In The Pinned Databases Is Verified And Compiled Into The Image";
    let compiled = official_image().unwrap();
    let programs = files_of_kind(&compiled.account, "signature programs");
    assert_eq!(programs.len(), 85, "{REQUIREMENT}");
    let left_out: Vec<&str> = programs
        .iter()
        .filter(|file| count(&file["outcomes"], "outside_functionality_level") > 0)
        .map(|file| file["member"].as_str().unwrap())
        .collect();
    assert_eq!(
        left_out,
        ["4510302.cbc", "4553522.cbc", "7086472.cbc"],
        "{REQUIREMENT}"
    );
    for file in &programs {
        let outcomes = &file["outcomes"];
        assert!(
            count(outcomes, "compiled") == file["lines"].as_u64().unwrap()
                || left_out.contains(&file["member"].as_str().unwrap()),
            "{REQUIREMENT}: {}",
            file["member"]
        );
    }
    assert_eq!(
        section_items(&compiled.account, "signature programs"),
        82,
        "{REQUIREMENT}"
    );
    let directory = scratch_directory("program-triggers").unwrap();
    let input = directory.join("input");
    write_file(
        &input,
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();
    let report = comparison_report(&compiled.image, &input, &directory).unwrap();
    assert!(
        !detections(&report)
            .iter()
            .any(|name| name == "Eicar-Signature"),
        "{REQUIREMENT}: a program's trigger reports no detection of its own"
    );
}

#[test]
fn every_pinned_database_is_verified_by_its_digital_signature() {
    const REQUIREMENT: &str = "Every Pinned Database Is Verified By Its Digital Signature";
    let compiled = official_image().unwrap();
    let databases = compiled.account["databases"].as_array().unwrap();
    assert_eq!(databases.len(), 3, "{REQUIREMENT}");
    for database in databases {
        assert_eq!(
            database["provenance"], "signed container, detached signature verified",
            "{REQUIREMENT}: {}",
            database["name"]
        );
    }
    let members = members_of_pinned_databases(&pinned_databases().unwrap()).unwrap();
    assert!(
        members
            .iter()
            .all(|member| std::path::Path::new(&member.container)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("cvd"))),
        "{REQUIREMENT}: every member was loaded from its verified container"
    );
}

fn refused(databases: &std::path::Path, directory: &std::path::Path, case: &str) -> String {
    let image = directory.join(format!("{case}.image"));
    let output = std::process::Command::new(&release_binaries().unwrap().compiler)
        .arg("--databases")
        .arg(databases)
        .arg("--image")
        .arg(&image)
        .arg("--account")
        .arg(directory.join(format!("{case}.json")))
        .output()
        .unwrap();
    assert!(!output.status.success(), "{case} compiled");
    assert!(!image.exists(), "{case} wrote an image");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_database_whose_digital_signature_does_not_verify_is_refused() {
    const REQUIREMENT: &str = "A Database Whose Digital Signature Does Not Verify Is Refused";
    let pinned = pinned_databases().unwrap();
    let directory = scratch_directory("refused-signature").unwrap();
    let mut changed = std::fs::read(pinned.join("bytecode.cvd")).unwrap();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    for (case, with_detached) in [("with-detached", true), ("header-only", false)] {
        let databases = directory.join(case);
        std::fs::create_dir(&databases).unwrap();
        write_file(&databases.join("bytecode.cvd"), &changed).unwrap();
        if with_detached {
            std::fs::copy(
                pinned.join("bytecode-339.cvd.sign"),
                databases.join("bytecode-339.cvd.sign"),
            )
            .unwrap();
        }
        let message = refused(&databases, &directory, case);
        assert!(
            message.contains("bytecode.cvd"),
            "{REQUIREMENT}: {case}: {message}"
        );
    }
}

#[test]
fn a_malformed_certificate_icon_url_rule_or_switch_line_or_a_malformed_signature_program_fails_the_compile()
 {
    const REQUIREMENT: &str = "A Malformed Certificate, Icon, URL-Rule Or Switch Line, Or A Malformed Signature Program, Fails The Compile";
    let directory = scratch_directory("malformed-carried").unwrap();
    for (case, file, contents, named) in [
        (
            "certificate",
            "local.crb",
            "# comment\na;0;b\n",
            "local.crb line 2",
        ),
        (
            "icon",
            "local.idb",
            "# comment\nIcon:MS:IE:00\n",
            "local.idb line 2",
        ),
        (
            "url",
            "local.pdb",
            "H:example.com\nQ:example.com\n",
            "local.pdb line 2",
        ),
        (
            "switch",
            "daily.cfg",
            "# comment\nPE:zz\n",
            "daily.cfg line 2",
        ),
        ("program", "local.cbc", "ClamBX\n", "local.cbc"),
    ] {
        let databases = directory.join(case);
        std::fs::create_dir(&databases).unwrap();
        write_file(&databases.join(file), contents.as_bytes()).unwrap();
        let message = refused(&databases, &directory, case);
        assert!(message.contains(named), "{REQUIREMENT}: {case}: {message}");
    }
}
