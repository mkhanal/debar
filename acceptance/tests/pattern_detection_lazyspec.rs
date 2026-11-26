#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::{Path, PathBuf};

use acceptance::{
    CompiledImage, comparison_report, compile, detections, scratch_directory, write_file,
};

fn loose_databases(test: &str, ndb: &str) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    write_file(&databases.join("local.ndb"), ndb.as_bytes()).unwrap();
    let compiled = compile(&databases, &directory, "loose").unwrap();
    (directory, compiled)
}

fn detected(directory: &Path, image: &Path, contents: &[u8]) -> Vec<String> {
    let input = directory.join("input");
    write_file(&input, contents).unwrap();
    detections(&comparison_report(image, &input, directory).unwrap())
}

fn file_with(length: usize, at: usize, body: &[u8]) -> Vec<u8> {
    let mut contents = vec![b'.'; length.max(at + body.len())];
    contents[at..at + body.len()].copy_from_slice(body);
    contents
}

const DATABASE: &str = "\
Test.Anywhere:0:*:414243444546
Test.At32:0:32:4a4b4c4d4e4f
Test.Range:0:30,2:505152535455
Test.Eof:0:EOF-40:565758595a5b
Test.Elements:0:*:6162??64(65|7a)66{2-4}6768*696a6b6c
";

#[test]
fn a_file_holding_an_extended_signatures_body_where_its_offset_allows_is_detected_under_the_signatures_name()
 {
    const REQUIREMENT: &str = "A File Holding An Extended Signature's Body Where Its Offset Allows Is Detected Under The Signature's Name";
    let (directory, compiled) = loose_databases("pattern-offsets", DATABASE);
    let image = &compiled.image;
    let scan = |contents: Vec<u8>| detected(&directory, image, &contents);

    assert_eq!(
        scan(file_with(100, 57, b"ABCDEF")),
        ["Test.Anywhere.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(file_with(100, 32, b"JKLMNO")),
        ["Test.At32.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(file_with(100, 33, b"JKLMNO")),
        Vec::<String>::new(),
        "{REQUIREMENT}"
    );
    for at in [30, 31, 32] {
        assert_eq!(
            scan(file_with(100, at, b"PQRSTU")),
            ["Test.Range.UNOFFICIAL"],
            "{REQUIREMENT}: {at}"
        );
    }
    for at in [29, 33] {
        assert_eq!(
            scan(file_with(100, at, b"PQRSTU")),
            Vec::<String>::new(),
            "{REQUIREMENT}: {at}"
        );
    }
    assert_eq!(
        scan(file_with(100, 60, b"VWXYZ[")),
        ["Test.Eof.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(file_with(100, 61, b"VWXYZ[")),
        Vec::<String>::new(),
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(file_with(200, 10, b"ab?dzf...gh--ijkl")),
        ["Test.Elements.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        scan(file_with(200, 10, b"ab?dzf.....gh--ijkl")),
        Vec::<String>::new(),
        "{REQUIREMENT}"
    );
    let input = directory.join("input");
    write_file(&input, &file_with(100, 57, b"ABCDEF")).unwrap();
    assert_eq!(
        comparison_report(image, &input, &directory).unwrap()["verdict"],
        "strong_indicator",
        "{REQUIREMENT}"
    );
}

#[test]
fn a_body_is_detected_wherever_it_lies_in_a_large_file() {
    const REQUIREMENT: &str = "A Body Is Detected Wherever It Lies In A Large File";
    let (directory, compiled) = loose_databases(
        "pattern-boundaries",
        "Test.Long:0:*:3031323334353637383940414243444546474849\nTest.Parts:0:*:616263646566*7071727374{100000-300000}78797a7b\n",
    );
    let body = b"0123456789@ABCDEFGHI";
    for boundary in [65_536usize, 131_072, 262_144, 393_216] {
        for into in 1..body.len() {
            let contents = file_with(400_000, boundary - into, body);
            assert_eq!(
                detected(&directory, &compiled.image, &contents),
                ["Test.Long.UNOFFICIAL"],
                "{REQUIREMENT}: {into} bytes before {boundary}"
            );
        }
    }
    let mut parts = file_with(600_000, 1_000, b"abcdef");
    parts[131_070..131_075].copy_from_slice(b"pqrst");
    parts[400_000..400_004].copy_from_slice(b"xyz{");
    assert_eq!(
        detected(&directory, &compiled.image, &parts),
        ["Test.Parts.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}
