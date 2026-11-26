#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use acceptance::{
    CompiledImage, comparison_report, compile, detections, lowercase_hex, official_image,
    scratch_directory, write_file,
};
use md5::Md5;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const SAMPLE: &[u8] = b"a file a database lists by its hash\n";
const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

struct Scan {
    report: Value,
}

fn scan(directory: &Path, image: &Path, contents: &[u8]) -> Scan {
    let input = directory.join("input");
    write_file(&input, contents).unwrap();
    Scan {
        report: comparison_report(image, &input, directory).unwrap(),
    }
}

fn loose_databases(test: &str, files: &[(&str, String)]) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    for (name, contents) in files {
        write_file(&databases.join(name), contents.as_bytes()).unwrap();
    }
    let compiled = compile(&databases, &directory, "loose").unwrap();
    (directory, compiled)
}

fn sample_size() -> usize {
    SAMPLE.len()
}

#[test]
fn a_file_whose_md5_is_listed_is_detected_under_the_signatures_name() {
    const REQUIREMENT: &str = "A File Whose MD5 Is Listed Is Detected Under The Signature's Name";
    let line = format!(
        "{}:{}:Debar.Test.Md5\n",
        lowercase_hex(&Md5::digest(SAMPLE)),
        sample_size()
    );
    let (directory, compiled) = loose_databases("md5-listed", &[("listed.hdb", line)]);

    let scanned = scan(&directory, &compiled.image, SAMPLE);

    assert_eq!(
        detections(&scanned.report),
        ["Debar.Test.Md5.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        scanned.report["verdict"], "strong_indicator",
        "{REQUIREMENT}"
    );
}

#[test]
fn a_file_whose_sha_256_is_listed_is_detected_under_the_signatures_name() {
    const REQUIREMENT: &str =
        "A File Whose SHA-256 Is Listed Is Detected Under The Signature's Name";
    let line = format!(
        "{}:{}:Debar.Test.Sha256\n",
        lowercase_hex(&Sha256::digest(SAMPLE)),
        sample_size()
    );
    let (directory, compiled) = loose_databases("sha256-listed", &[("listed.hsb", line)]);

    let scanned = scan(&directory, &compiled.image, SAMPLE);

    assert_eq!(
        detections(&scanned.report),
        ["Debar.Test.Sha256.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn a_listed_false_positive_hash_suppresses_the_detection() {
    const REQUIREMENT: &str = "A Listed False-Positive Hash Suppresses The Detection";
    let md5 = lowercase_hex(&Md5::digest(SAMPLE));
    let size = sample_size();
    let (directory, compiled) = loose_databases(
        "false-positive",
        &[
            ("listed.hdb", format!("{md5}:{size}:Debar.Test.Md5\n")),
            ("trusted.fp", format!("{md5}:{size}:Debar.Test.Trusted\n")),
        ],
    );

    let scanned = scan(&directory, &compiled.image, SAMPLE);

    assert_eq!(
        detections(&scanned.report),
        Vec::<String>::new(),
        "{REQUIREMENT}"
    );
    assert_eq!(scanned.report["verdict"], "trusted", "{REQUIREMENT}");
}

#[test]
fn a_signature_from_a_file_outside_a_signed_container_is_reported_with_unofficial_after_its_name() {
    const REQUIREMENT: &str = "A Signature From A File Outside A Signed Container Is Reported With .UNOFFICIAL After Its Name";
    let official = official_image().unwrap();
    let directory = scratch_directory("official-names").unwrap();

    let scanned = scan(&directory, &official.image, EICAR);

    assert_eq!(
        detections(&scanned.report),
        ["Eicar-Test-Signature", "Eicar-Test-Signature"],
        "{REQUIREMENT}: a signed container's names stand alone, for the MD5 and the SHA-256 entry"
    );
    let line = format!(
        "{}:{}:Debar.Loose.Eicar\n",
        lowercase_hex(&Md5::digest(EICAR)),
        EICAR.len()
    );
    let (directory, loose) = loose_databases("unofficial-names", &[("loose.hdb", line)]);
    assert_eq!(
        detections(&scan(&directory, &loose.image, EICAR).report),
        ["Debar.Loose.Eicar.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn a_hash_listed_twice_is_detected_under_the_name_the_reference_scanner_reports() {
    const REQUIREMENT: &str =
        "A Hash Listed Twice Is Detected Under The Name The Reference Scanner Reports";
    let key = format!("{}:{}", lowercase_hex(&Md5::digest(SAMPLE)), sample_size());
    for (names, reported) in [
        (&["First", "Second"][..], "Second"),
        (&["D1", "D2", "D3"][..], "D3"),
        (&["D1", "D2", "D3", "D4", "D5"][..], "D4"),
        (&["D1", "D2", "D3", "D4", "D5", "D6", "D7"][..], "D5"),
    ] {
        let lines = names.iter().fold(String::new(), |mut lines, name| {
            lines.push_str(&key);
            lines.push_str(":Debar.Test.");
            lines.push_str(name);
            lines.push('\n');
            lines
        });
        let (directory, compiled) = loose_databases("hash-listed-twice", &[("listed.hdb", lines)]);

        let scanned = scan(&directory, &compiled.image, SAMPLE);

        assert_eq!(
            detections(&scanned.report),
            [format!("Debar.Test.{reported}.UNOFFICIAL")],
            "{REQUIREMENT}: {names:?}"
        );
    }
}
