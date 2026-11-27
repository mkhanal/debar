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
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const FILE_TYPES: &str = "1:*:3c68746d6c3e:HTML data:CL_TYPE_ANY:CL_TYPE_HTML\n";
const SIGNATURES: &str = "\
Test.Text:7:*:68656c6c6f20776f726c64
Test.TextAt5:7:5:68656c6c6f
Test.TextAsWritten:7:*:536f6d65202020
Test.AnyLowercased:0:*:736f6d652068656c6c6f
Test.AnyAsWritten:0:*:536f6d65202020
Test.TwoSpaces:7:*:7820207a
Test.TextNearTheEnd:7:EOF-20:2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
";
const LONGEST_TEXT_PART: usize = 16;
const TEXT_PIECE: usize = 131_072 + LONGEST_TEXT_PART;
const LARGEST_NORMALISED: usize = 20 * 1024 * 1024;

fn databases(test: &str, extra: &[(&str, &str)]) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    let mut files = vec![("types.ftm", FILE_TYPES), ("local.ndb", SIGNATURES)];
    files.extend_from_slice(extra);
    for (name, contents) in files {
        write_file(&databases.join(name), contents.as_bytes()).unwrap();
    }
    let compiled = compile(&databases, &directory, "loose").unwrap();
    (directory, compiled)
}

fn top_level(directory: &Path, image: &Path, contents: &[u8]) -> Value {
    let input = directory.join("input");
    write_file(&input, contents).unwrap();
    comparison_report_objects(image, &["--every-match"], &input, directory)
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
}

fn sorted_detections(object: &Value) -> Vec<String> {
    let mut names = detections(object);
    names.sort();
    names
}

fn unofficial(names: &[&str]) -> Vec<String> {
    let mut names: Vec<String> = names
        .iter()
        .map(|name| format!("{name}.UNOFFICIAL"))
        .collect();
    names.sort();
    names
}

#[test]
fn text_is_matched_through_its_normalised_text() {
    const REQUIREMENT: &str = "Text Is Matched Through Its Normalised Text";
    let (directory, compiled) = databases("plain-text-normalised", &[]);
    let text = b"Some   HELLO \t\r\n  W\xe9ORLD, said the text.\n";

    let scanned = top_level(&directory, &compiled.image, text);

    assert_eq!(scanned["type"], "CL_TYPE_TEXT_ASCII", "{REQUIREMENT}");
    assert_eq!(
        sorted_detections(&scanned),
        unofficial(&[
            "Test.Text",
            "Test.TextAt5",
            "Test.AnyLowercased",
            "Test.AnyAsWritten"
        ]),
        "{REQUIREMENT}"
    );
}

#[test]
fn a_hash_of_the_normalised_text_detects_the_text_file() {
    const REQUIREMENT: &str = "A Hash Of The Normalised Text Detects The Text File";
    let normalised: &[u8] = b"a text file listed by the hash of its normalised text ";
    let listed = format!(
        "{}:{}:Test.NormalisedHash\n",
        lowercase_hex(&Sha256::digest(normalised)),
        normalised.len()
    );
    let (directory, compiled) = databases("plain-text-hash", &[("local.hsb", &listed)]);
    let text = b"A TEXT FILE\tlisted by\t\tthe hash of\r\nits normalised text\n";

    let scanned = top_level(&directory, &compiled.image, text);

    assert_eq!(
        detections(&scanned),
        ["Test.NormalisedHash.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn whitespace_starts_afresh_every_131_072_bytes_plus_the_longest_part_of_a_signature_for_text() {
    const REQUIREMENT: &str = "Whitespace Starts Afresh Every 131,072 Bytes Plus The Longest Part Of A Signature For Text";
    let (directory, compiled) = databases("plain-text-pieces", &[]);
    let run_across = |before: usize| [vec![b'x'; before], b"  z\n".to_vec()].concat();

    let across = top_level(&directory, &compiled.image, &run_across(TEXT_PIECE - 1));
    let before = top_level(&directory, &compiled.image, &run_across(TEXT_PIECE - 2));
    let twice = top_level(
        &directory,
        &compiled.image,
        &[run_across(TEXT_PIECE - 1), run_across(TEXT_PIECE - 4)].concat(),
    );

    assert_eq!(
        detections(&across),
        ["Test.TwoSpaces.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert!(detections(&before).is_empty(), "{REQUIREMENT}");
    assert_eq!(
        detections(&twice),
        ["Test.TwoSpaces.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn text_of_more_than_20_mib_is_not_normalised() {
    const REQUIREMENT: &str = "Text Of More Than 20 MiB Is Not Normalised";
    let (directory, compiled) = databases("plain-text-largest", &[]);
    let text_of = |length: usize| {
        let mut text = b"Some   hello world ".to_vec();
        text.resize(length, b'.');
        text
    };

    let largest = top_level(&directory, &compiled.image, &text_of(LARGEST_NORMALISED));
    let beyond = top_level(
        &directory,
        &compiled.image,
        &text_of(LARGEST_NORMALISED + 1),
    );

    assert_eq!(
        sorted_detections(&largest),
        unofficial(&[
            "Test.Text",
            "Test.TextAt5",
            "Test.AnyLowercased",
            "Test.AnyAsWritten"
        ]),
        "{REQUIREMENT}"
    );
    assert_eq!(
        detections(&beyond),
        ["Test.AnyAsWritten.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn text_found_to_be_a_web_page_is_not_matched_through_normalised_text() {
    const REQUIREMENT: &str = "Text Found To Be A Web Page Is Not Matched Through Normalised Text";
    let (directory, compiled) = databases("plain-text-page", &[]);
    let mut page = b"Some   \xe9 HELLO WORLD ".to_vec();
    page.resize(2_000, b'.');
    page.extend_from_slice(b"<html><body>a page after all</body></html>\n");

    let scanned = top_level(&directory, &compiled.image, &page);

    assert_eq!(scanned["type"], "CL_TYPE_HTML", "{REQUIREMENT}");
    assert_eq!(
        detections(&scanned),
        ["Test.AnyAsWritten.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}
