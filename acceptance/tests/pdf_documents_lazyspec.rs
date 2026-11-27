#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::Write as _;
use std::path::{Path, PathBuf};

use acceptance::{
    CompiledImage, comparison_report_objects, compile, detections, lowercase_hex,
    scratch_directory, write_file,
};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const FILE_TYPES: &str = "0:0:255044462d:PDF document:CL_TYPE_ANY:CL_TYPE_PDF\n";
const STREAM_BODY: &[u8] = b"PDFSTREAMBODY";
const SCRIPT_BODY: &[u8] = b"PDFSCRIPTBODY";
const PAGE_TEXT: &[u8] = b"hello pdf page";
const CONTAINED_BODY: &[u8] = b"CONTAINEDBODY";
const CONTAINED_TEXT: &[u8] = b"contained text";
const OBFUSCATED_NAME: &str = "Heuristics.PDF.ObfuscatedNameObject";

fn databases(test: &str) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    let bodies = format!(
        "Test.Stream:0:*:{}\nTest.Script:0:*:{}\nTest.PageText:7:*:{}\n",
        lowercase_hex(STREAM_BODY),
        lowercase_hex(SCRIPT_BODY),
        lowercase_hex(PAGE_TEXT),
    );
    let contained = format!(
        "Test.InPdf;Engine:51-255,Container:CL_TYPE_PDF,Target:0;0;{}\n\
         Test.InPdfText;Engine:51-255,Container:CL_TYPE_PDF,Target:7;0;{}\n",
        lowercase_hex(CONTAINED_BODY),
        lowercase_hex(CONTAINED_TEXT),
    );
    for (name, contents) in [
        ("types.ftm", FILE_TYPES.to_owned()),
        ("local.ndb", bodies),
        ("local.ldb", contained),
    ] {
        write_file(&databases.join(name), contents.as_bytes()).unwrap();
    }
    let compiled = compile(&databases, &directory, "loose").unwrap();
    (directory, compiled)
}

fn objects(directory: &Path, image: &Path, contents: &[u8], options: &[&str]) -> Vec<Value> {
    let input = directory.join("input.pdf");
    write_file(&input, contents).unwrap();
    let mut all = vec!["--every-match"];
    all.extend_from_slice(options);
    comparison_report_objects(image, &all, &input, directory).unwrap()
}

fn pdf(objects: &[&[u8]]) -> Vec<u8> {
    let mut document = b"%PDF-1.4\n".to_vec();
    for (number, object) in (1..).zip(objects) {
        document.extend_from_slice(format!("{number} 0 obj\n").as_bytes());
        document.extend_from_slice(object);
        document.extend_from_slice(b"\nendobj\n");
    }
    document.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n");
    document
}

fn stream(dictionary: &str, data: &[u8]) -> Vec<u8> {
    [
        format!("<< {dictionary} /Length {}>>\nstream\n", data.len()).as_bytes(),
        data,
        b"\nendstream",
    ]
    .concat()
}

fn zlib(contents: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(contents).unwrap();
    encoder.finish().unwrap()
}

fn hex(contents: &[u8]) -> Vec<u8> {
    [lowercase_hex(contents).as_bytes(), b">"].concat()
}

fn run_length(contents: &[u8]) -> Vec<u8> {
    let mut coded = Vec::new();
    for run in contents.chunks(100) {
        coded.push(u8::try_from(run.len() - 1).unwrap());
        coded.extend_from_slice(run);
    }
    coded.push(128);
    coded
}

fn text_holding(body: &[u8], tag: &str) -> Vec<u8> {
    [
        format!("plain text of {tag} .... ").as_bytes(),
        body,
        b" ....\nmore plain text, line after line.\n",
    ]
    .concat()
}

fn sha256(bytes: &[u8]) -> String {
    lowercase_hex(&Sha256::digest(bytes))
}

fn children_of<'v>(found: &'v [Value], parent: &Value) -> Vec<&'v Value> {
    found
        .iter()
        .filter(|object| object["parent"] == *parent)
        .collect()
}

fn holding<'v>(found: &'v [Value], bytes: &[u8]) -> Option<&'v Value> {
    found
        .iter()
        .find(|object| object["sha256"] == sha256(bytes))
}

fn all_detections(found: &[Value]) -> Vec<String> {
    found.iter().flat_map(detections).collect()
}

#[test]
fn a_pdfs_streams_are_scanned_as_their_decoded_bytes() {
    const REQUIREMENT: &str = "A PDF's Streams Are Scanned As Their Decoded Bytes";
    let (directory, compiled) = databases("pdf-streams");
    let flated = text_holding(STREAM_BODY, "a flate stream");
    let chained = text_holding(STREAM_BODY, "a chain of filters");
    let run = text_holding(STREAM_BODY, "a run-length stream");
    let run_alone = text_holding(STREAM_BODY, "a stream only run-length coded");
    let plain = text_holding(STREAM_BODY, "a stream with no filter");
    let broken_hex: Vec<u8> = lowercase_hex(&text_holding(STREAM_BODY, "broken hex"))
        .as_bytes()
        .chunks(40)
        .collect::<Vec<_>>()
        .join(&b'\n');
    let image = text_holding(STREAM_BODY, "an image");
    let document = pdf(&[
        &stream("/Filter /FlateDecode", &zlib(&flated)),
        &stream(
            "/Filter [/ASCIIHexDecode /FlateDecode]",
            &hex(&zlib(&chained)),
        ),
        &stream(
            "/Filter [/FlateDecode /RunLengthDecode]",
            &zlib(&run_length(&run)),
        ),
        &stream("/Filter /RunLengthDecode", &run_length(&run_alone)),
        &stream("/Type /XObject", &plain),
        &stream("/Filter /ASCIIHexDecode", &broken_hex),
        &stream("/Subtype /Image /Filter /FlateDecode", &zlib(&image)),
    ]);

    let found = objects(&directory, &compiled.image, &document, &[]);

    assert_eq!(found[0]["type"], "CL_TYPE_PDF", "{REQUIREMENT}");
    let children = children_of(&found, &found[0]["id"]);
    for decoded in [&flated, &chained, &run, &plain] {
        let object = holding(&found, decoded).expect(REQUIREMENT);
        assert_eq!(object["depth"], 1, "{REQUIREMENT}");
        assert_eq!(object["type"], "CL_TYPE_TEXT_ASCII", "{REQUIREMENT}");
        assert_eq!(
            detections(object),
            ["Test.Stream.UNOFFICIAL"],
            "{REQUIREMENT}"
        );
    }
    assert!(holding(&found, &broken_hex).is_some(), "{REQUIREMENT}");
    assert!(holding(&found, &image).is_none(), "{REQUIREMENT}");
    assert!(holding(&found, &run_alone).is_none(), "{REQUIREMENT}");
    assert_eq!(children.len(), 5, "{REQUIREMENT}");
}

#[test]
fn a_pdfs_scripts_are_scanned_as_objects_of_their_own() {
    const REQUIREMENT: &str = "A PDF's Scripts Are Scanned As Objects Of Their Own";
    let (directory, compiled) = databases("pdf-scripts");
    let document = pdf(&[
        b"<< /Type /Catalog >>",
        b"<< /S /JavaScript /JS <50444653435249505442> >>",
        b"<< /S /JavaScript /JS (app.alert\\(1\\); PDFSCRIPTBODY) >>",
    ]);

    let found = objects(&directory, &compiled.image, &document, &[]);

    let scripts: Vec<&Value> = children_of(&found, &found[0]["id"]);
    assert_eq!(scripts.len(), 2, "{REQUIREMENT}");
    let script = scripts
        .iter()
        .find(|object| detections(object) == ["Test.Script.UNOFFICIAL"])
        .expect(REQUIREMENT);
    assert_eq!(script["depth"], 1, "{REQUIREMENT}");
}

#[test]
fn objects_inside_a_pdf_object_stream_are_scanned_like_any_other_object() {
    const REQUIREMENT: &str =
        "Objects Inside A PDF Object Stream Are Scanned Like Any Other Object";
    let (directory, compiled) = databases("pdf-object-streams");
    let held = b"7 0 << /S /JavaScript /JS (var body = 'PDFSCRIPTBODY';) >>";
    let document = pdf(&[
        b"<< /Type /Catalog >>",
        &stream(
            "/Type/ObjStm /N 1 /First 4 /Filter /FlateDecode",
            &zlib(held),
        ),
    ]);

    let found = objects(&directory, &compiled.image, &document, &[]);

    let detected: Vec<&Value> = children_of(&found, &found[0]["id"])
        .into_iter()
        .filter(|object| detections(object) == ["Test.Script.UNOFFICIAL"])
        .collect();
    assert_eq!(detected.len(), 2, "{REQUIREMENT}");
    assert!(holding(&found, held).is_some(), "{REQUIREMENT}");
    for object in detected {
        assert_eq!(object["depth"], 1, "{REQUIREMENT}");
    }
}

#[test]
fn a_pdf_pages_text_is_scanned_as_an_object_of_its_own() {
    const REQUIREMENT: &str = "A PDF Page's Text Is Scanned As An Object Of Its Own";
    let (directory, compiled) = databases("pdf-page-text");
    let content = b"BT /F1 12 Tf 72 712 Td\n[(Hello) -250 ( PDF   Page)] TJ\nET\n";
    let document = pdf(&[
        b"<< /Type /Page /Contents 2 0 R >>",
        &stream("/Filter /FlateDecode", &zlib(content)),
    ]);

    let found = objects(&directory, &compiled.image, &document, &[]);

    let text = holding(&found, PAGE_TEXT).expect(REQUIREMENT);
    assert_eq!(text["depth"], 1, "{REQUIREMENT}");
    assert_eq!(
        detections(text),
        ["Test.PageText.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert!(holding(&found, content).is_some(), "{REQUIREMENT}");
}

#[test]
fn a_signature_naming_a_pdf_as_its_container_matches_what_is_extracted_from_it() {
    const REQUIREMENT: &str =
        "A Signature Naming A PDF As Its Container Matches What Is Extracted From It";
    let (directory, compiled) = databases("pdf-container");
    let raw = text_holding(CONTAINED_BODY, "a contained stream");
    let text = text_holding(b"Contained   Text", "contained words");
    let document = pdf(&[
        &stream("/Filter /FlateDecode", &zlib(&raw)),
        &stream("/Filter /FlateDecode", &zlib(&text)),
    ]);

    let found = objects(&directory, &compiled.image, &document, &[]);
    let alone = objects(&directory, &compiled.image, &raw, &[]);

    assert_eq!(
        detections(holding(&found, &raw).expect(REQUIREMENT)),
        ["Test.InPdf.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        detections(holding(&found, &text).expect(REQUIREMENT)),
        ["Test.InPdfText.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert!(all_detections(&alone).is_empty(), "{REQUIREMENT}");
}

#[test]
fn a_pdf_name_written_with_escapes_is_reported_as_an_obfuscated_name() {
    const REQUIREMENT: &str = "A PDF Name Written With Escapes Is Reported As An Obfuscated Name";
    let (directory, compiled) = databases("pdf-escaped-names");
    let escaped = pdf(&[b"<< /S /J#61vaScript /JS (var x = 1;) >>"]);
    let plain = pdf(&[b"<< /S /JavaScript /JS (var x = 1;) >>"]);

    let found = objects(&directory, &compiled.image, &escaped, &[]);
    let found_plain = objects(&directory, &compiled.image, &plain, &[]);

    assert!(
        all_detections(&found)
            .iter()
            .any(|name| name.starts_with(OBFUSCATED_NAME)),
        "{REQUIREMENT}"
    );
    assert!(all_detections(&found_plain).is_empty(), "{REQUIREMENT}");
}

#[test]
fn an_object_refused_by_a_limit_ends_the_scan_of_a_pdfs_objects() {
    const REQUIREMENT: &str = "An Object Refused By A Limit Ends The Scan Of A PDF's Objects";
    let (directory, compiled) = databases("pdf-refused");
    let large: Vec<u8> = [
        b"<< /OpenAction [3 0 R] /Note (".as_slice(),
        &[b'x'; 3000],
        b") >>",
    ]
    .concat();
    let later = text_holding(STREAM_BODY, "a later stream");
    let refusing = pdf(&[&large, &stream("/Type /XObject", &later)]);
    let admitting = pdf(&[b"<< /Note (small) >>", &stream("/Type /XObject", &later)]);
    let limit = (refusing.len() + 1000).to_string();

    let refused = objects(
        &directory,
        &compiled.image,
        &refusing,
        &["--max-scan-size", &limit],
    );
    let admitted = objects(
        &directory,
        &compiled.image,
        &admitting,
        &["--max-scan-size", &limit],
    );

    assert!(holding(&refused, &later).is_none(), "{REQUIREMENT}");
    assert!(holding(&admitted, &later).is_some(), "{REQUIREMENT}");
}
