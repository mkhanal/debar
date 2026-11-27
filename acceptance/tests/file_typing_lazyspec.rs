#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

use acceptance::{
    CompiledImage, comparison_report, compile, detections, lowercase_hex, official_image,
    scratch_directory, write_file,
};
use md5::Md5;
use serde_json::Value;
use sha2::Digest as _;

const FILE_TYPES: &str = "\
0:0:5b616c69617365735d:mirc ini:CL_TYPE_ANY:CL_TYPE_SCRIPT
0:0:5b616c69617365735d:TAR-POSIX-CVE-2012-1419:CL_TYPE_ANY:CL_TYPE_POSIX_TAR
0:0:4d5a:DOS/W32 executable:CL_TYPE_ANY:CL_TYPE_MSEXE
0:0:494433:MP3:CL_TYPE_ANY:CL_TYPE_IGNORED
1:*:3c68746d6c3e:HTML data:CL_TYPE_ANY:CL_TYPE_HTML
1:*:255044462d??2e:PDF:CL_TYPE_ANY:CL_TYPE_PDF:55
";

fn databases_with(test: &str, files: &[(&str, String)]) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    for (name, contents) in files {
        write_file(&databases.join(name), contents.as_bytes()).unwrap();
    }
    let compiled = compile(&databases, &directory, "loose").unwrap();
    (directory, compiled)
}

fn report(directory: &Path, image: &Path, contents: &[u8]) -> Value {
    let input = directory.join("input");
    write_file(&input, contents).unwrap();
    comparison_report(image, &input, directory).unwrap()
}

#[test]
fn a_file_is_typed_from_its_first_bytes_as_the_file_type_database_says() {
    const REQUIREMENT: &str = "A File Is Typed From Its First Bytes As The File-Type Database Says";
    let (directory, compiled) = databases_with(
        "typing-first-bytes",
        &[("types.ftm", FILE_TYPES.to_owned())],
    );
    let type_of = |contents: &[u8]| {
        report(&directory, &compiled.image, contents)["type"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let mut binary: Vec<u8> = (0..=255).collect();
    binary.extend(vec![0u8; 100]);
    let mut pdf_in_binary: Vec<u8> = (0..100).collect();
    pdf_in_binary.extend_from_slice(b"%PDF-1.4\n");

    for (contents, expected) in [
        (&b"[aliases]\nnick=x\n"[..], "CL_TYPE_POSIX_TAR"),
        (b"MZ\x90\x00\x03\x00\x00\x00", "CL_TYPE_MSEXE"),
        (b"hello world, nothing to see\n", "CL_TYPE_TEXT_ASCII"),
        (&binary, "CL_TYPE_BINARY_DATA"),
        (b"a page: <html><body>x</body></html>\n", "CL_TYPE_HTML"),
        (&pdf_in_binary, "CL_TYPE_PDF"),
    ] {
        assert_eq!(
            type_of(contents),
            expected,
            "{REQUIREMENT}: {contents:02x?}"
        );
    }
}

fn utf16_little_endian(narrow: &[u8]) -> Vec<u8> {
    narrow.iter().flat_map(|byte| [*byte, 0]).collect()
}

#[test]
fn every_mark_in_a_files_first_bytes_is_weighed_in_the_order_it_is_found() {
    const REQUIREMENT: &str =
        "Every Mark In A File's First Bytes Is Weighed In The Order It Is Found";
    let official = official_image().unwrap();
    let directory = scratch_directory("typing-every-mark").unwrap();
    let filler: &[u8] = b"xxxxxxxxxx";
    let xdp: &[u8] = b"<xdp:xdp";
    let nsis: &[u8] = b"\xef\xbe\xad\xdeNullsoftInst";
    let html: &[u8] = b"<html>";
    let mut pe = b"MZ".to_vec();
    pe.extend([0u8; 60]);
    pe.extend(b"PE\x00\x00");
    let pe = pe.as_slice();
    let between = |marks: &[&[u8]]| {
        let mut contents = filler.to_vec();
        for mark in marks {
            contents.extend_from_slice(mark);
            contents.extend_from_slice(filler);
        }
        contents
    };
    let mail_around = |content_type_after_pe: bool| {
        let mut contents = b"x\nFrom: a@b\n".to_vec();
        contents.extend_from_slice(xdp);
        contents.extend_from_slice(b"\nContent-Type: a\n");
        contents.extend_from_slice(pe);
        if content_type_after_pe {
            contents.extend_from_slice(b"\nContent-Type: b\n");
        }
        contents.extend_from_slice(filler);
        contents
    };

    for (contents, expected) in [
        (between(&[xdp, nsis, xdp]), "CL_TYPE_XDP"),
        (between(&[nsis, xdp, nsis]), "CL_TYPE_NULSFT"),
        (between(&[xdp, nsis]), "CL_TYPE_NULSFT"),
        (between(&[nsis, xdp]), "CL_TYPE_XDP"),
        (between(&[pe, xdp, pe]), "CL_TYPE_MSEXE"),
        (between(&[pe, xdp, b"PE\x00\x00"]), "CL_TYPE_XDP"),
        (mail_around(true), "CL_TYPE_MAIL"),
        (mail_around(false), "CL_TYPE_MSEXE"),
        (
            utf16_little_endian(&between(&[html, xdp, pe, html])),
            "CL_TYPE_HTML_UTF16",
        ),
        (
            utf16_little_endian(&between(&[html, xdp, pe])),
            "CL_TYPE_BINARY_DATA",
        ),
    ] {
        assert_eq!(
            report(&directory, &official.image, &contents)["type"],
            expected,
            "{REQUIREMENT}: {contents:02x?}"
        );
    }
}

#[test]
fn a_file_typed_as_never_scanned_has_no_detection() {
    const REQUIREMENT: &str = "A File Typed As Never Scanned Has No Detection";
    let contents = b"ID3 a file holding NEVERSCANNED bytes\n";
    let (directory, compiled) = databases_with(
        "typing-never-scanned",
        &[
            ("types.ftm", FILE_TYPES.to_owned()),
            ("local.ndb", "Test.Body:0:*:4e45564552534341".to_owned()),
            (
                "local.hdb",
                format!(
                    "{}:{}:Test.Hash\n",
                    lowercase_hex(&Md5::digest(contents)),
                    contents.len()
                ),
            ),
        ],
    );

    let scanned = report(&directory, &compiled.image, contents);

    assert_eq!(scanned["type"], "CL_TYPE_IGNORED", "{REQUIREMENT}");
    assert!(detections(&scanned).is_empty(), "{REQUIREMENT}");
    let mut renamed = contents.to_vec();
    renamed[..3].copy_from_slice(b"XX3");
    assert_eq!(
        detections(&report(&directory, &compiled.image, &renamed)),
        ["Test.Body.UNOFFICIAL"],
        "{REQUIREMENT}: the same bytes typed otherwise are detected"
    );
}
