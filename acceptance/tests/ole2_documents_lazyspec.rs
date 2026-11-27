#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::Write as _;
use std::path::{Path, PathBuf};

use acceptance::ole2_document::{
    Layout, Node, directory_entry_offset, ole2_document, ole2_document_with_layout, sector_offset,
};
use acceptance::{
    CompiledImage, comparison_report_objects, compile, detections, lowercase_hex,
    scratch_directory, write_file,
};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const FILE_TYPES: &str = "0:0:d0cf11e0a1b11ae1:OLE2 container:CL_TYPE_ANY:CL_TYPE_MSOLE2\n";
const MEMBER_BODY: &[u8] = b"MEMBERBODY";
const INNER_BODY: &[u8] = b"INNERBODYTEXT";
const BODIES: &str = "\
Test.Member:0:*:4d454d424552424f4459
Test.Inner:0:*:494e4e4552424f445954455854
";
const MAX_RECURSION: &str = "Heuristics.Limits.Exceeded.MaxRecursion";
const DIRECTORY_START_FIELD: usize = 116;
const DIRECTORY_RIGHT_FIELD: usize = 72;
const SECTOR_SHIFT_FIELD: usize = 0x1e;
const FIRST_FAT_SECTOR_OFFSET: usize = 512;

fn databases(test: &str) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    for (name, contents) in [("types.ftm", FILE_TYPES), ("local.ndb", BODIES)] {
        write_file(&databases.join(name), contents.as_bytes()).unwrap();
    }
    let compiled = compile(&databases, &directory, "loose").unwrap();
    (directory, compiled)
}

fn text_holding(body: &[u8], tag: &str, length: usize) -> Vec<u8> {
    let mut text = [
        format!("plain text of {tag} .... ").as_bytes(),
        body,
        b" ....\n".as_slice(),
    ]
    .concat();
    let mut filler = b"more plain text, line after line.\n".iter().cycle();
    while text.len() < length {
        text.push(*filler.next().unwrap());
    }
    text
}

fn objects(directory: &Path, image: &Path, contents: &[u8], options: &[&str]) -> Vec<Value> {
    let input = directory.join("input");
    write_file(&input, contents).unwrap();
    let mut all = vec!["--every-match"];
    all.extend_from_slice(options);
    comparison_report_objects(image, &all, &input, directory).unwrap()
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

fn sorted_hashes(objects: &[&Value]) -> Vec<String> {
    let mut hashes: Vec<String> = objects
        .iter()
        .map(|object| object["sha256"].as_str().unwrap().to_owned())
        .collect();
    hashes.sort();
    hashes
}

fn sorted(hashes: &[&[u8]]) -> Vec<String> {
    let mut sorted: Vec<String> = hashes.iter().map(|bytes| sha256(bytes)).collect();
    sorted.sort();
    sorted
}

fn zlib(contents: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(contents).unwrap();
    encoder.finish().unwrap()
}

fn entry_field(document: &[u8], layout: Layout, index: usize, field: usize) -> u32 {
    let at = directory_entry_offset(layout, index) + field;
    u32::from_le_bytes(document[at..at + 4].try_into().unwrap())
}

fn set_entry_field(document: &mut [u8], layout: Layout, index: usize, field: usize, value: u32) {
    let at = directory_entry_offset(layout, index) + field;
    document[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn set_fat_entry(document: &mut [u8], sector: u32, next: u32) {
    let at = FIRST_FAT_SECTOR_OFFSET + usize::try_from(sector).unwrap() * 4;
    document[at..at + 4].copy_from_slice(&next.to_le_bytes());
}

#[test]
fn an_ole2_documents_streams_are_scanned_as_objects_of_their_own() {
    const REQUIREMENT: &str = "An OLE2 Document's Streams Are Scanned As Objects Of Their Own";
    let (directory, compiled) = databases("ole2-streams");
    let small = text_holding(MEMBER_BODY, "a mini stream", 100);
    let large = text_holding(b"nothing", "a large stream", 5000);
    let deep = text_holding(b"nothing", "a stream in a storage", 200);
    let innermost = text_holding(INNER_BODY, "a stream of a stream", 300);
    let nested = ole2_document(&[Node::stream("Innermost", &innermost)]);
    let tiny = b"tiny!".to_vec();
    let document = ole2_document(&[
        Node::stream("Small", &small),
        Node::stream("Large", &large),
        Node::storage("Inner", vec![Node::stream("Deep", &deep)]),
        Node::stream("Nested", &nested),
        Node::stream("Tiny", &tiny),
    ]);

    let found = objects(&directory, &compiled.image, &document, &[]);

    assert_eq!(found[0]["type"], "CL_TYPE_MSOLE2", "{REQUIREMENT}");
    let streams = children_of(&found, &found[0]["id"]);
    assert_eq!(
        sorted_hashes(&streams),
        sorted(&[&small, &large, &deep, &nested]),
        "{REQUIREMENT}"
    );
    for stream in &streams {
        assert_eq!(stream["depth"], 1, "{REQUIREMENT}");
    }
    let small_object = streams
        .iter()
        .find(|object| object["sha256"] == sha256(&small))
        .unwrap();
    assert_eq!(small_object["type"], "CL_TYPE_TEXT_ASCII", "{REQUIREMENT}");
    assert_eq!(
        detections(small_object),
        ["Test.Member.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    let nested_object = streams
        .iter()
        .find(|object| object["sha256"] == sha256(&nested))
        .unwrap();
    assert_eq!(nested_object["type"], "CL_TYPE_MSOLE2", "{REQUIREMENT}");
    let deeper = children_of(&found, &nested_object["id"]);
    assert_eq!(
        sorted_hashes(&deeper),
        sorted(&[&innermost]),
        "{REQUIREMENT}"
    );
    assert_eq!(deeper[0]["depth"], 2, "{REQUIREMENT}");
    assert_eq!(
        detections(deeper[0]),
        ["Test.Inner.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn a_compressed_ole2_stream_is_scanned_as_its_inflated_bytes() {
    const REQUIREMENT: &str = "A Compressed OLE2 Stream Is Scanned As Its Inflated Bytes";
    let (directory, compiled) = databases("ole2-compressed");
    let inflated = text_holding(MEMBER_BODY, "a compressed stream", 3000);
    let compressed = [&3000u32.to_le_bytes()[..], &zlib(&inflated)].concat();
    let broken = [&[0u8, 0, 0, 0, 0x78, 0x9c][..], b"not deflate data at all"].concat();
    let plain = text_holding(b"nothing", "a plain stream", 120);
    let document = ole2_document(&[
        Node::stream("Compressed", &compressed),
        Node::stream("Broken", &broken),
        Node::stream("Plain", &plain),
    ]);

    let found = objects(&directory, &compiled.image, &document, &[]);

    let streams = children_of(&found, &found[0]["id"]);
    assert_eq!(
        sorted_hashes(&streams),
        sorted(&[&inflated, &plain]),
        "{REQUIREMENT}"
    );
    let inflated_object = streams
        .iter()
        .find(|object| object["sha256"] == sha256(&inflated))
        .unwrap();
    assert_eq!(
        detections(inflated_object),
        ["Test.Member.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn a_word_powerpoint_or_macro_document_scans_a_stream_once_more_for_each_storage_holding_it() {
    const REQUIREMENT: &str =
        "A Word, PowerPoint Or Macro Document Scans A Stream Once More For Each Storage Holding It";
    let (directory, compiled) = databases("ole2-folders");
    let word = text_holding(b"nothing", "a word document stream", 150);
    let first = text_holding(b"nothing", "one storage deep", 160);
    let second = text_holding(MEMBER_BODY, "two storages deep", 170);
    let storages = Node::storage(
        "Macros",
        vec![
            Node::stream("First", &first),
            Node::storage("VBA", vec![Node::stream("Second", &second)]),
        ],
    );

    for (word_stream, expected) in [
        (Some("WordDocument"), vec![1, 2, 3]),
        (Some("PowerPoint Document"), vec![1, 2, 3]),
        (Some("WordDocumentX"), vec![1, 1, 1]),
        (None, vec![0, 1, 1]),
    ] {
        let mut nodes = Vec::new();
        if let Some(name) = word_stream {
            nodes.push(Node::stream(name, &word));
        }
        nodes.push(storages.clone());
        let found = objects(&directory, &compiled.image, &ole2_document(&nodes), &[]);
        let streams = children_of(&found, &found[0]["id"]);
        let counts: Vec<usize> = [&word, &first, &second]
            .iter()
            .map(|bytes| {
                streams
                    .iter()
                    .filter(|object| object["sha256"] == sha256(bytes))
                    .count()
            })
            .collect();
        assert_eq!(counts, expected, "{REQUIREMENT}: {word_stream:?}");
        for stream in &streams {
            assert_eq!(stream["depth"], 1, "{REQUIREMENT}");
        }
    }
}

#[test]
fn a_loop_in_an_ole2_directory_ends_the_walk() {
    const REQUIREMENT: &str = "A Loop In An OLE2 Directory Ends The Walk";
    let (directory, compiled) = databases("ole2-loop");
    let bodies: Vec<Vec<u8>> = ["A", "B", "C", "D"]
        .iter()
        .map(|name| text_holding(b"nothing", &format!("stream {name}"), 110))
        .collect();
    let nodes: Vec<Node> = ["A", "B", "C", "D"]
        .iter()
        .zip(&bodies)
        .map(|(name, body)| Node::stream(name, body))
        .collect();
    let (mut document, layout) = ole2_document_with_layout(&nodes);
    set_entry_field(&mut document, layout, 2, DIRECTORY_RIGHT_FIELD, 1);

    let found = objects(&directory, &compiled.image, &document, &[]);

    let streams = children_of(&found, &found[0]["id"]);
    assert_eq!(
        sorted_hashes(&streams),
        sorted(&[&bodies[0], &bodies[1]]),
        "{REQUIREMENT}"
    );
}

#[test]
fn a_damaged_ole2_stream_yields_the_bytes_its_chain_still_holds() {
    const REQUIREMENT: &str = "A Damaged OLE2 Stream Yields The Bytes Its Chain Still Holds";
    let (directory, compiled) = databases("ole2-damaged");
    let large = text_holding(b"nothing", "a looping stream", 5000);
    let (mut looping, layout) = ole2_document_with_layout(&[Node::stream("Large", &large)]);
    let start = entry_field(&looping, layout, 1, DIRECTORY_START_FIELD);
    set_fat_entry(&mut looping, start + 1, start);

    let found = objects(&directory, &compiled.image, &looping, &[]);

    let streams = children_of(&found, &found[0]["id"]);
    assert_eq!(
        sorted_hashes(&streams),
        sorted(&[&large[..1024]]),
        "{REQUIREMENT}: a loop in the chain"
    );

    let cut = text_holding(b"nothing", "a stream cut short", 4500);
    let (whole, layout) = ole2_document_with_layout(&[Node::stream("Cut", &cut)]);
    let start = entry_field(&whole, layout, 1, DIRECTORY_START_FIELD);
    let kept = 4396;
    let truncated = whole[..sector_offset(start) + kept].to_vec();
    let mut expected = cut[..kept].to_vec();
    expected.resize(cut.len(), 0);

    let found = objects(&directory, &compiled.image, &truncated, &[]);

    let streams = children_of(&found, &found[0]["id"]);
    assert_eq!(
        sorted_hashes(&streams),
        sorted(&[&expected]),
        "{REQUIREMENT}: a last sector cut short"
    );
}

#[test]
fn ole2_storages_nested_beyond_the_recursion_limit_end_the_walk() {
    const REQUIREMENT: &str = "OLE2 Storages Nested Beyond The Recursion Limit End The Walk";
    let (directory, compiled) = databases("ole2-deep");
    let levels: Vec<Vec<u8>> = (1..=8)
        .map(|level| text_holding(b"nothing", &format!("storage level {level}"), 120))
        .collect();
    let mut nested = Node::storage("S8", vec![Node::stream("L8", &levels[7])]);
    for level in (1..8).rev() {
        nested = Node::storage(
            &format!("S{level}"),
            vec![
                Node::stream(&format!("L{level}"), &levels[level - 1]),
                nested,
            ],
        );
    }
    let top = text_holding(b"nothing", "the first top-level stream", 130);
    let last = text_holding(b"nothing", "the last top-level stream", 140);
    let document = ole2_document(&[
        Node::stream("Top", &top),
        nested,
        Node::stream("Last", &last),
    ]);

    let found = objects(
        &directory,
        &compiled.image,
        &document,
        &["--max-recursion", "5", "--alert-exceeds-max"],
    );

    let streams = children_of(&found, &found[0]["id"]);
    assert_eq!(
        sorted_hashes(&streams),
        sorted(&[&top, &levels[0], &levels[1], &levels[2], &levels[3]]),
        "{REQUIREMENT}"
    );
    assert!(
        found
            .iter()
            .any(|object| detections(object).iter().any(|name| name == MAX_RECURSION)),
        "{REQUIREMENT}"
    );
}

#[test]
fn an_ole2_document_with_an_invalid_header_is_matched_on_its_own_bytes_only() {
    const REQUIREMENT: &str =
        "An OLE2 Document With An Invalid Header Is Matched On Its Own Bytes Only";
    let (directory, compiled) = databases("ole2-invalid-header");
    let body = text_holding(MEMBER_BODY, "a stream of a broken document", 150);
    let valid = ole2_document(&[Node::stream("Body", &body)]);
    for (field, value) in [
        (SECTOR_SHIFT_FIELD, 5u8),
        (SECTOR_SHIFT_FIELD, 29),
        (0x20, 0),
        (0x20, 10),
    ] {
        let mut broken = valid.clone();
        broken[field] = value;

        let found = objects(&directory, &compiled.image, &broken, &[]);

        assert_eq!(found.len(), 1, "{REQUIREMENT}: byte {field:#x} = {value}");
        assert_eq!(found[0]["type"], "CL_TYPE_MSOLE2", "{REQUIREMENT}");
        assert_eq!(
            detections(&found[0]),
            ["Test.Member.UNOFFICIAL"],
            "{REQUIREMENT}"
        );
    }
}
