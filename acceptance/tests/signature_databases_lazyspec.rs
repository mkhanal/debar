#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use acceptance::{
    compile, lowercase_hex, members_of_pinned_databases, official_image, pinned_databases,
    scratch_directory, target_directory,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const HASH_LINE_OUTCOMES: [&str; 4] = [
    "compiled",
    "outside_functionality_level",
    "ignored",
    "comment",
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
