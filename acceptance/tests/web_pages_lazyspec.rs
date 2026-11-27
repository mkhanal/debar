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

const TYPED_FROM_FIRST_BYTES: &str = "0:0:3c68746d6c3e:HTML data:CL_TYPE_ANY:CL_TYPE_HTML\n";
const FOUND_WHILE_MATCHED: &str = "1:*:3c68746d6c3e:HTML data:CL_TYPE_ANY:CL_TYPE_HTML\n";
const EVERY_MATCH: &[&str] = &["--every-match"];
const FIRST_MATCH: &[&str] = &[];
const LARGEST_PAGE_NORMALISED: usize = 40 * 1024 * 1024;
const LARGEST_PAGE_WITHOUT_TAGS: usize = 8 * 1024 * 1024;

fn signature(name: &str, target: u8, offset: &str, bytes: &[u8]) -> String {
    format!("{name}:{target}:{offset}:{}\n", lowercase_hex(bytes))
}

fn databases(test: &str, file_types: &str, files: &[(&str, String)]) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    write_file(&databases.join("types.ftm"), file_types.as_bytes()).unwrap();
    for (name, contents) in files {
        write_file(&databases.join(name), contents.as_bytes()).unwrap();
    }
    let compiled = compile(&databases, &directory, "loose").unwrap();
    (directory, compiled)
}

fn pattern_databases(
    test: &str,
    file_types: &str,
    signatures: &[String],
) -> (PathBuf, CompiledImage) {
    databases(test, file_types, &[("local.ndb", signatures.concat())])
}

fn top_level(directory: &Path, image: &Path, options: &[&str], contents: &[u8]) -> Value {
    let input = directory.join("input");
    write_file(&input, contents).unwrap();
    comparison_report_objects(image, options, &input, directory)
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

const PAGE: &[u8] = b"<html><BODY>Alpha  <B>Beta</B> <!-- hidden --> Gamma</BODY></HTML>\n";
const PAGE_WITHOUT_COMMENTS: &[u8] = b"<html><body>alpha <b>beta</b>gamma</body></html>";
const PAGE_WITHOUT_TAGS: &[u8] = b" alpha beta gamma ";

#[test]
fn a_web_page_is_matched_through_its_page_without_comments_and_its_page_without_tags() {
    const REQUIREMENT: &str =
        "A Web Page Is Matched Through Its Page Without Comments And Its Page Without Tags";
    let (directory, compiled) = pattern_databases(
        "web-pages-views",
        TYPED_FROM_FIRST_BYTES,
        &[
            signature("Test.WithoutComments", 3, "*", b"<b>beta</b>gamma"),
            signature("Test.WithoutTags", 3, "*", b" beta gamma "),
            signature("Test.AnyWithoutTags", 0, "*", b"alpha beta"),
            signature("Test.AtTheStart", 3, "0", b"<html><body>alpha"),
            signature("Test.AtTheStartWithoutTags", 3, "0", b" alpha"),
            signature("Test.OwnBytes", 0, "*", b"<BODY>"),
        ],
    );

    let scanned = top_level(&directory, &compiled.image, EVERY_MATCH, PAGE);

    assert_eq!(scanned["type"], "CL_TYPE_HTML", "{REQUIREMENT}");
    assert_eq!(
        sorted_detections(&scanned),
        unofficial(&[
            "Test.WithoutComments",
            "Test.WithoutTags",
            "Test.AnyWithoutTags",
            "Test.AtTheStart",
            "Test.AtTheStartWithoutTags",
        ]),
        "{REQUIREMENT}"
    );
}

#[test]
fn the_page_without_comments_is_the_page_lowercased_with_comments_left_out_and_references_decoded()
{
    const REQUIREMENT: &str = "The Page Without Comments Is The Page Lowercased, With Comments Left Out And References Decoded";
    let page = b"<html><P CLASS='Big'>Fish   &amp; Chips &#65;&#x42;</P><!DOCTYPE x>\n\
<SCRIPT> var a = 'b'; </SCRIPT><STYLE> p { } </STYLE>";
    let expected: &[u8] =
        b"<html><p class=\"big\">fish & chips ab</p><script>vara=\"b\";</script><style>p{}</style>";
    let (directory, compiled) = pattern_databases(
        "web-pages-without-comments",
        TYPED_FROM_FIRST_BYTES,
        &[
            signature("Test.WithoutComments", 3, "0", expected),
            signature("Test.Comment", 3, "*", b"doctype"),
        ],
    );

    let scanned = top_level(&directory, &compiled.image, EVERY_MATCH, page);

    assert_eq!(
        detections(&scanned),
        ["Test.WithoutComments.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn the_page_without_tags_holds_the_pages_text_and_its_links() {
    const REQUIREMENT: &str = "The Page Without Tags Holds The Page's Text And Its Links";
    let page = b"<html><a HREF=\"Http://Example.COM/x\">Click</a> <SCRIPT>secret()</SCRIPT> \
<img src=Pic.gif> End &amp; MORE</html>";
    let expected: &[u8] = b" Http://Example.COM/x click Pic.gif end more ";
    let listed = format!(
        "{}:{}:Test.WithoutTagsHash\n",
        lowercase_hex(&Sha256::digest(expected)),
        expected.len()
    );
    let (directory, compiled) = databases(
        "web-pages-without-tags",
        TYPED_FROM_FIRST_BYTES,
        &[("local.hsb", listed)],
    );

    let scanned = top_level(&directory, &compiled.image, EVERY_MATCH, page);

    assert_eq!(
        detections(&scanned),
        ["Test.WithoutTagsHash.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn bytes_at_or_above_0x80_reach_the_page_without_tags_as_the_supported_format_writes_them() {
    const REQUIREMENT: &str =
        "Bytes At Or Above 0x80 Reach The Page Without Tags As The Supported Format Writes Them";
    let page = b"<html>caf\xc3\xa9 \xe4\xb8\xad x</html>";
    let (directory, compiled) = pattern_databases(
        "web-pages-high-bytes",
        TYPED_FROM_FIRST_BYTES,
        &[
            signature("Test.WithoutTags", 3, "0", b" caf\xc3\xc3 \xe4\xb8\xb8x "),
            signature(
                "Test.WithoutComments",
                3,
                "*",
                b"caf\xc3\xa9 \xe4\xb8\xad x",
            ),
        ],
    );

    let scanned = top_level(&directory, &compiled.image, EVERY_MATCH, page);

    assert_eq!(
        sorted_detections(&scanned),
        unofficial(&["Test.WithoutTags", "Test.WithoutComments"]),
        "{REQUIREMENT}"
    );
}

#[test]
fn a_hash_of_a_pages_view_detects_the_page() {
    const REQUIREMENT: &str = "A Hash Of A Page's View Detects The Page";
    let listed: String = [
        ("Test.WithoutCommentsHash", PAGE_WITHOUT_COMMENTS),
        ("Test.WithoutTagsHash", PAGE_WITHOUT_TAGS),
        ("Test.OwnHash", PAGE),
    ]
    .iter()
    .map(|(name, bytes)| {
        format!(
            "{}:{}:{name}\n",
            lowercase_hex(&Sha256::digest(bytes)),
            bytes.len()
        )
    })
    .collect::<Vec<String>>()
    .concat();
    let (directory, compiled) = databases(
        "web-pages-hashes",
        TYPED_FROM_FIRST_BYTES,
        &[("local.hsb", listed)],
    );

    let scanned = top_level(&directory, &compiled.image, EVERY_MATCH, PAGE);

    assert_eq!(
        sorted_detections(&scanned),
        unofficial(&["Test.WithoutCommentsHash", "Test.WithoutTagsHash"]),
        "{REQUIREMENT}"
    );
}

fn padded_page(length: usize) -> Vec<u8> {
    let mut page = b"<html>alpha <b>beta</b> ".to_vec();
    while page.len() < length {
        page.extend_from_slice(b"pad ");
    }
    page.truncate(length);
    page
}

fn padded_page_signatures() -> [String; 2] {
    [
        signature("Test.WithoutComments", 3, "*", b"alpha <b>beta"),
        signature("Test.WithoutTags", 3, "*", b"alpha beta"),
    ]
}

#[test]
fn a_page_of_more_than_40_mib_is_not_matched_at_all() {
    const REQUIREMENT: &str = "A Page Of More Than 40 MiB Is Not Matched At All";
    let (directory, compiled) = pattern_databases(
        "web-pages-largest",
        TYPED_FROM_FIRST_BYTES,
        &[
            padded_page_signatures().concat(),
            signature("Test.Any", 0, "*", b"<html>alpha"),
        ],
    );

    let beyond = top_level(
        &directory,
        &compiled.image,
        EVERY_MATCH,
        &padded_page(LARGEST_PAGE_NORMALISED + 1),
    );

    assert_eq!(beyond["type"], "CL_TYPE_HTML", "{REQUIREMENT}");
    assert!(detections(&beyond).is_empty(), "{REQUIREMENT}");
}

#[test]
fn a_page_of_more_than_8_mib_is_matched_only_through_its_page_without_comments() {
    const REQUIREMENT: &str =
        "A Page Of More Than 8 MiB Is Matched Only Through Its Page Without Comments";
    let (directory, compiled) = pattern_databases(
        "web-pages-without-tags-largest",
        TYPED_FROM_FIRST_BYTES,
        &padded_page_signatures(),
    );

    let largest = top_level(
        &directory,
        &compiled.image,
        EVERY_MATCH,
        &padded_page(LARGEST_PAGE_WITHOUT_TAGS),
    );
    let beyond = top_level(
        &directory,
        &compiled.image,
        EVERY_MATCH,
        &padded_page(LARGEST_PAGE_WITHOUT_TAGS + 1),
    );

    assert_eq!(
        sorted_detections(&largest),
        unofficial(&["Test.WithoutComments", "Test.WithoutTags"]),
        "{REQUIREMENT}"
    );
    assert_eq!(
        detections(&beyond),
        ["Test.WithoutComments.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn text_found_to_be_a_web_page_is_matched_through_its_views() {
    const REQUIREMENT: &str = "Text Found To Be A Web Page Is Matched Through Its Views";
    let (directory, compiled) = pattern_databases(
        "web-pages-found-in-text",
        FOUND_WHILE_MATCHED,
        &[
            signature("Test.OwnBytes", 0, "*", b"Plain WORDS"),
            signature("Test.WithoutComments", 3, "*", b"<html>alpha <b>beta</b>"),
            signature("Test.WithoutTags", 3, "*", b" alpha beta "),
        ],
    );
    let mut text = b"Plain WORDS ".repeat(100);
    text.extend_from_slice(b"<html>Alpha  <b>Beta</b></html>\n");

    let scanned = top_level(&directory, &compiled.image, EVERY_MATCH, &text);

    assert_eq!(scanned["type"], "CL_TYPE_HTML", "{REQUIREMENT}");
    assert_eq!(
        sorted_detections(&scanned),
        unofficial(&["Test.OwnBytes", "Test.WithoutComments", "Test.WithoutTags"]),
        "{REQUIREMENT}"
    );
}

#[test]
fn without_every_match_a_detection_in_the_page_without_comments_ends_the_pages_matching() {
    const REQUIREMENT: &str =
        "Without Every Match, A Detection In The Page Without Comments Ends The Page's Matching";
    let (directory, compiled) = pattern_databases(
        "web-pages-first-match",
        TYPED_FROM_FIRST_BYTES,
        &[
            signature("Test.WithoutComments", 3, "*", b"<b>beta</b>gamma"),
            signature("Test.WithoutTags", 3, "*", b" beta gamma "),
        ],
    );

    let scanned = top_level(&directory, &compiled.image, FIRST_MATCH, PAGE);

    assert_eq!(
        detections(&scanned),
        ["Test.WithoutComments.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}
