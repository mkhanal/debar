#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::{Path, PathBuf};

use acceptance::zip_archive::{Member, zip_archive, zip_archive_listing};
use acceptance::{
    CompiledImage, comparison_report_objects, compile, detections, lowercase_hex,
    scratch_directory, write_file,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const FILE_TYPES: &str = "\
0:0:504b0304:ZIP:CL_TYPE_ANY:CL_TYPE_ZIP
1:*:504b0304:ZIP-SFX:CL_TYPE_ANY:CL_TYPE_ZIPSFX
";
const MEMBER_BODY: &[u8] = b"MEMBERBODY";
const INNER_BODY: &[u8] = b"INNERBODYTEXT";
const BODIES: &str = "\
Test.Member:0:*:4d454d424552424f4459
Test.Inner:0:*:494e4e4552424f445954455854
";
const OVERLAPPING_FILES: &str = "Heuristics.Zip.OverlappingFiles";

fn databases(test: &str, container_signatures: &str) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    let mut files = vec![("types.ftm", FILE_TYPES), ("local.ndb", BODIES)];
    if !container_signatures.is_empty() {
        files.push(("local.cdb", container_signatures));
    }
    for (name, contents) in files {
        write_file(&databases.join(name), contents.as_bytes()).unwrap();
    }
    let compiled = compile(&databases, &directory, "loose").unwrap();
    (directory, compiled)
}

fn text_holding(body: &[u8], tag: &str) -> Vec<u8> {
    [
        format!("plain text of {tag} .... ").as_bytes(),
        body,
        b" ....\n".as_slice(),
    ]
    .concat()
}

fn objects(directory: &Path, image: &Path, contents: &[u8], options: &[&str]) -> Vec<Value> {
    let input = directory.join("input");
    write_file(&input, contents).unwrap();
    let mut all = vec!["--every-match"];
    all.extend_from_slice(options);
    comparison_report_objects(image, &all, &input, directory).unwrap()
}

fn distinct(object: &Value) -> Vec<String> {
    let mut names = detections(object);
    names.dedup();
    names
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

fn hashes(objects: &[&Value]) -> Vec<String> {
    objects
        .iter()
        .map(|object| object["sha256"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_zips_members_are_scanned_as_objects_of_their_own() {
    const REQUIREMENT: &str = "A ZIP's Members Are Scanned As Objects Of Their Own";
    let (directory, compiled) = databases("zip-members", "");
    let stored = text_holding(MEMBER_BODY, "a stored member");
    let deflated = text_holding(
        b"nothing",
        "a deflated member, repeated, repeated, repeated",
    );
    let innermost = text_holding(INNER_BODY, "a member of a member");
    let inner = zip_archive(&[Member::deflated("c.txt", &innermost)]);
    let archive = zip_archive(&[
        Member::stored("a.txt", &stored),
        Member::deflated("b.txt", &deflated),
        Member::stored("inner.zip", &inner),
    ]);

    let found = objects(&directory, &compiled.image, &archive, &[]);

    assert_eq!(found[0]["type"], "CL_TYPE_ZIP", "{REQUIREMENT}");
    let members = children_of(&found, &found[0]["id"]);
    assert_eq!(
        hashes(&members),
        [sha256(&stored), sha256(&deflated), sha256(&inner)],
        "{REQUIREMENT}"
    );
    for member in &members {
        assert_eq!(member["depth"], 1, "{REQUIREMENT}");
    }
    assert_eq!(members[0]["type"], "CL_TYPE_TEXT_ASCII", "{REQUIREMENT}");
    assert_eq!(
        detections(members[0]),
        ["Test.Member.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(members[2]["type"], "CL_TYPE_ZIP", "{REQUIREMENT}");
    let deeper = children_of(&found, &members[2]["id"]);
    assert_eq!(hashes(&deeper), [sha256(&innermost)], "{REQUIREMENT}");
    assert_eq!(deeper[0]["depth"], 2, "{REQUIREMENT}");
    assert_eq!(
        detections(deeper[0]),
        ["Test.Inner.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn an_office_open_xml_document_is_typed_as_its_kind_and_its_members_are_scanned() {
    const REQUIREMENT: &str =
        "An Office Open XML Document Is Typed As Its Kind And Its Members Are Scanned";
    let (directory, compiled) = databases("office-open", "");
    let content_types = b"<?xml version=\"1.0\"?><Types/>".to_vec();
    let part = text_holding(MEMBER_BODY, "a document part");
    for (folder, kind) in [
        ("word/", "CL_TYPE_OOXML_WORD"),
        ("xl/", "CL_TYPE_OOXML_XL"),
        ("ppt/", "CL_TYPE_OOXML_PPT"),
    ] {
        let document = zip_archive(&[
            Member::deflated("[Content_Types].xml", &content_types),
            Member::deflated(&format!("{folder}document.xml"), &part),
        ]);

        let found = objects(&directory, &compiled.image, &document, &[]);

        assert_eq!(found[0]["type"], kind, "{REQUIREMENT}: {folder}");
        let members = children_of(&found, &found[0]["id"]);
        assert_eq!(
            hashes(&members),
            [sha256(&content_types), sha256(&part)],
            "{REQUIREMENT}: {folder}"
        );
        assert_eq!(
            detections(members[1]),
            ["Test.Member.UNOFFICIAL"],
            "{REQUIREMENT}: {folder}"
        );
    }
}

#[test]
fn each_zip_entry_is_tested_against_container_signatures_by_its_name_sizes_encryption_and_position()
{
    const REQUIREMENT: &str = "Each ZIP Entry Is Tested Against Container Signatures By Its Name, Sizes, Encryption And Position";
    let evil = b"seventeen bytes!\n";
    let size = evil.len();
    let signatures = format!(
        "\
Test.Entry:CL_TYPE_ZIP:*:^dir/evil\\.exe$:{size}:{size}:0:2:*:
Test.Basename:CL_TYPE_ZIP:*:^evil\\.exe$:*:*:*:*:*:
Test.FirstPosition:CL_TYPE_ZIP:*:evil:*:*:*:1:*:
Test.Encrypted:CL_TYPE_ZIP:*:^locked\\.txt$:*:*:1:1:*:
Test.Document:CL_TYPE_OOXML_WORD:*:^word/:*:*:0:*:*:
Test.DocumentAsZip:CL_TYPE_ZIP:*:^word/:*:*:*:*:*:
"
    );
    let (directory, compiled) = databases("container-signatures", &signatures);
    let archive = zip_archive(&[
        Member::stored("readme.txt", b"a readme to come first\n"),
        Member::stored("dir/evil.exe", evil),
    ]);
    let locked =
        zip_archive(&[Member::stored("locked.txt", b"locked away inside\n").flagged_encrypted()]);
    let document = zip_archive(&[Member::deflated(
        "word/document.xml",
        b"<document>words</document>",
    )]);

    let named = objects(&directory, &compiled.image, &archive, &[]);
    let encrypted = objects(&directory, &compiled.image, &locked, &[]);
    let in_a_document = objects(&directory, &compiled.image, &document, &[]);

    assert_eq!(
        distinct(&named[0]),
        ["Test.Entry.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        distinct(&encrypted[0]),
        ["Test.Encrypted.UNOFFICIAL"],
        "{REQUIREMENT}: encrypted"
    );
    assert_eq!(
        in_a_document[0]["type"], "CL_TYPE_OOXML_WORD",
        "{REQUIREMENT}"
    );
    assert_eq!(
        distinct(&in_a_document[0]),
        ["Test.Document.UNOFFICIAL"],
        "{REQUIREMENT}: a document"
    );
}

#[test]
fn a_zip_member_over_the_file_size_limit_is_cut_to_it() {
    const REQUIREMENT: &str = "A ZIP Member Over The File-Size Limit Is Cut To It";
    let (directory, compiled) = databases("member-cut", "");
    let lines: Vec<u8> = (0..700)
        .flat_map(|line| {
            format!("line {line:05} of a long member with nothing in it\n").into_bytes()
        })
        .collect();
    let archive = zip_archive(&[Member::deflated("long.txt", &lines)]);
    assert!(archive.len() < 10_000 && lines.len() > 30_000);

    let found = objects(
        &directory,
        &compiled.image,
        &archive,
        &["--max-file-size", "20000"],
    );

    let members = children_of(&found, &found[0]["id"]);
    assert_eq!(members.len(), 1, "{REQUIREMENT}");
    assert_eq!(members[0]["size"], 16_384, "{REQUIREMENT}");
    assert_eq!(
        members[0]["sha256"],
        sha256(&lines[..16_384]),
        "{REQUIREMENT}"
    );
}

#[test]
fn a_zip_stops_extracting_at_the_file_count_limit() {
    const REQUIREMENT: &str = "A ZIP Stops Extracting At The File-Count Limit";
    let (directory, compiled) = databases("member-count", "");
    let contents: Vec<Vec<u8>> = (0..5)
        .map(|member| text_holding(b"nothing", &format!("member {member}")))
        .collect();
    let members: Vec<Member> = contents
        .iter()
        .enumerate()
        .map(|(index, contents)| Member::deflated(&format!("m{index}.txt"), contents))
        .collect();
    let archive = zip_archive(&members);

    let found = objects(&directory, &compiled.image, &archive, &["--max-files", "3"]);

    let scanned = children_of(&found, &found[0]["id"]);
    assert_eq!(
        hashes(&scanned),
        [sha256(&contents[0]), sha256(&contents[1])],
        "{REQUIREMENT}"
    );
}

#[test]
fn a_zip_inside_another_file_is_an_object_for_each_of_its_local_headers() {
    const REQUIREMENT: &str =
        "A ZIP Inside Another File Is An Object For Each Of Its Local Headers";
    let (directory, compiled) = databases("zip-inside", "");
    let members: Vec<Member> = (0..12)
        .map(|member| {
            Member::stored(
                &format!("m{member:02}.txt"),
                &text_holding(MEMBER_BODY, &format!("member {member}")),
            )
        })
        .collect();
    let host = [
        b"\x00\x00\x00\x00binary data before an archive ".as_slice(),
        &zip_archive(&members),
    ]
    .concat();

    let found = objects(&directory, &compiled.image, &host, &[]);

    let archives = children_of(&found, &found[0]["id"]);
    let expected: Vec<String> = members
        .iter()
        .map(|member| sha256(&member.local_record()))
        .collect();
    assert_eq!(hashes(&archives), expected, "{REQUIREMENT}");
    for (archive, member) in archives.iter().zip(&members) {
        assert_eq!(archive["type"], "CL_TYPE_ZIP", "{REQUIREMENT}");
        let held = children_of(&found, &archive["id"]);
        assert_eq!(hashes(&held), [sha256(&member.contents)], "{REQUIREMENT}");
    }
}

#[test]
fn a_zip_with_a_duplicate_or_overlapping_record_has_no_member_scanned() {
    const REQUIREMENT: &str = "A ZIP With A Duplicate Or Overlapping Record Has No Member Scanned";
    let (directory, compiled) = databases("zip-duplicates", "");
    let members = [
        Member::deflated("a.txt", &text_holding(MEMBER_BODY, "a")),
        Member::deflated("b.txt", &text_holding(MEMBER_BODY, "b")),
    ];
    let duplicated = zip_archive_listing(&members, &[0, 0, 1]);
    let overlapping = chain_of_overlapping_records(3);

    for (archive, case) in [(duplicated, "a duplicate"), (overlapping, "two overlaps")] {
        let found = objects(&directory, &compiled.image, &archive, &[]);
        assert_eq!(found.len(), 1, "{REQUIREMENT}: {case}");
        assert!(detections(&found[0]).is_empty(), "{REQUIREMENT}: {case}");
    }
}

#[test]
fn more_than_five_overlapping_zip_records_raise_an_alert_and_are_read_from_their_local_headers() {
    const REQUIREMENT: &str = "More Than Five Overlapping ZIP Records Raise An Alert And Are Read From Their Local Headers";
    let (directory, compiled) = databases("zip-overlaps", "");
    let archive = chain_of_overlapping_records(7);

    let found = objects(&directory, &compiled.image, &archive, &[]);

    assert_eq!(detections(&found[0]), [OVERLAPPING_FILES], "{REQUIREMENT}");
    let outer = children_of(&found, &found[0]["id"]);
    let outer_data_starts = 30 + "link0".len();
    let outer_ends = archive.len() - central_directory_length(&archive);
    assert_eq!(
        hashes(&outer),
        [sha256(&archive[outer_data_starts..outer_ends])],
        "{REQUIREMENT}"
    );
}

#[test]
fn a_damaged_zip_yields_the_members_its_local_headers_still_hold() {
    const REQUIREMENT: &str = "A Damaged ZIP Yields The Members Its Local Headers Still Hold";
    let (directory, compiled) = databases("zip-damaged", "");
    let first = text_holding(MEMBER_BODY, "the first member");
    let second = text_holding(
        b"nothing",
        "the second member, which is longer than the first",
    );
    let members = [
        Member::stored("first.txt", &first),
        Member::stored("second.txt", &second),
    ];
    let archive = zip_archive(&members);
    let local_records = members[0].local_record().len() + members[1].local_record().len();
    let without_a_directory = archive[..local_records].to_vec();
    let cut_short = archive[..local_records - 10].to_vec();
    let mut corrupt = Member::deflated("corrupt.txt", &first).local_record();
    corrupt[30 + "corrupt.txt".len()] = 0x07;
    let corrupt_archive = [
        corrupt,
        Member::stored("second.txt", &second).local_record(),
    ]
    .concat();

    for (damaged, expected, case) in [
        (
            without_a_directory,
            vec![sha256(&first), sha256(&second)],
            "no central directory",
        ),
        (cut_short, vec![sha256(&first)], "cut short"),
        (corrupt_archive, vec![sha256(&second)], "corrupt"),
    ] {
        let found = objects(&directory, &compiled.image, &damaged, &[]);
        let members = children_of(&found, &found[0]["id"]);
        assert_eq!(hashes(&members), expected, "{REQUIREMENT}: {case}");
    }
}

#[test]
fn an_encrypted_zip_member_is_scanned_as_the_bytes_it_stores() {
    const REQUIREMENT: &str = "An Encrypted ZIP Member Is Scanned As The Bytes It Stores";
    let (directory, compiled) = databases("zip-encrypted", "");
    let stored = text_holding(MEMBER_BODY, "a member flagged as encrypted");
    let archive = zip_archive(&[Member::stored("locked.txt", &stored).flagged_encrypted()]);

    let found = objects(&directory, &compiled.image, &archive, &[]);

    let members = children_of(&found, &found[0]["id"]);
    assert_eq!(hashes(&members), [sha256(&stored)], "{REQUIREMENT}");
    assert_eq!(
        detections(members[0]),
        ["Test.Member.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

fn chain_of_overlapping_records(records: usize) -> Vec<u8> {
    let mut members = Vec::new();
    let mut held = text_holding(b"nothing", "the innermost link");
    for link in (0..records).rev() {
        let member = Member::stored(&format!("link{link}"), &held);
        held = member.local_record();
        members.push(member);
    }
    members.reverse();
    let chain = held;
    let mut central = Vec::new();
    let mut offset = 0u32;
    for member in &members {
        central.extend_from_slice(&member.central_record(offset));
        offset += u32::try_from(30 + member.name.len()).unwrap();
    }
    let central_offset = u32::try_from(chain.len()).unwrap();
    [
        chain,
        central.clone(),
        acceptance::zip_archive::end_record(members.len(), &central, central_offset),
    ]
    .concat()
}

fn central_directory_length(archive: &[u8]) -> usize {
    let end = archive.len() - 22;
    let offset = u32::from_le_bytes(archive[end + 16..end + 20].try_into().unwrap());
    archive.len() - usize::try_from(offset).unwrap()
}
