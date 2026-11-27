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

const FILE_TYPES: &str = "\
0:0:46726f6d3a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL
0:0:46726f6d20:MBox:CL_TYPE_ANY:CL_TYPE_MAIL
0:0:5375626a6563743a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL
1:0,1024:0a(46|66)726f6d3a20{-2048}0a(43|63)6f6e74656e742d(54|74)7970653a20:Mail file:CL_TYPE_ANY:CL_TYPE_MAIL
";
const SIGNATURES: &str = "\
Test.InPart:0:*:50415254424f4459
Test.ForMail:4:*:4d41494c424f4459
";

fn databases(test: &str) -> (PathBuf, CompiledImage) {
    let directory = scratch_directory(test).unwrap();
    let databases = directory.join("databases");
    std::fs::create_dir(&databases).unwrap();
    for (name, contents) in [("types.ftm", FILE_TYPES), ("local.ndb", SIGNATURES)] {
        write_file(&databases.join(name), contents.as_bytes()).unwrap();
    }
    let compiled = compile(&databases, &directory, "loose").unwrap();
    (directory, compiled)
}

fn objects(directory: &Path, image: &Path, contents: &[u8]) -> Vec<Value> {
    let input = directory.join("input");
    write_file(&input, contents).unwrap();
    comparison_report_objects(image, &["--every-match"], &input, directory).unwrap()
}

fn distinct(object: &Value) -> Vec<String> {
    let mut names = detections(object);
    names.sort();
    names.dedup();
    names
}

fn sha256(bytes: &[u8]) -> String {
    lowercase_hex(&Sha256::digest(bytes))
}

fn children_of<'v>(found: &'v [Value], parent: &Value) -> Vec<&'v Value> {
    found
        .iter()
        .filter(|object| object["parent"] == parent["id"])
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

fn sorted_sha256(contents: &[&[u8]]) -> Vec<String> {
    let mut hashes: Vec<String> = contents.iter().map(|bytes| sha256(bytes)).collect();
    hashes.sort();
    hashes
}

#[test]
fn a_mail_messages_parts_are_scanned_as_objects_of_their_own() {
    const REQUIREMENT: &str = "A Mail Message's Parts Are Scanned As Objects Of Their Own";
    let (directory, compiled) = databases("mail-parts");
    let message = b"From: a@b.c\r\n\
Content-Type: multipart/mixed; boundary=\"outer\"\r\n\
\r\n\
preamble\r\n\
--outer\r\n\
Content-Type: text/plain\r\n\
\r\n\
Hello plain part.\r\n\
--outer\r\n\
Content-Type: multipart/alternative; boundary=inner\r\n\
\r\n\
--inner\r\n\
Content-Type: text/html\r\n\
\r\n\
<html><body>Hi there</body></html>\r\n\
--inner--\r\n\
--outer\r\n\
Content-Type: application/octet-stream; name=\"a.bin\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
YW4gYXR0YWNobWVudCBjYXJyeWluZyBQQVJUQk9EWSBpbnNpZGUK\r\n\
--outer--\r\n";

    let found = objects(&directory, &compiled.image, message);

    assert_eq!(found[0]["type"], "CL_TYPE_MAIL", "{REQUIREMENT}");
    assert!(detections(&found[0]).is_empty(), "{REQUIREMENT}");
    let parts = children_of(&found, &found[0]);
    let attachment: &[u8] = b"an attachment carrying PARTBODY inside\n";
    assert_eq!(
        sorted_hashes(&parts),
        sorted_sha256(&[
            b"Hello plain part.\n",
            b"<html><body>Hi there</body></html>\n",
            attachment,
        ]),
        "{REQUIREMENT}"
    );
    for part in &parts {
        assert_eq!(part["depth"], 1, "{REQUIREMENT}");
    }
    let detected = parts
        .iter()
        .find(|part| part["sha256"] == sha256(attachment))
        .unwrap();
    assert_eq!(
        distinct(detected),
        ["Test.InPart.UNOFFICIAL"],
        "{REQUIREMENT}"
    );

    let single = objects(
        &directory,
        &compiled.image,
        b"From: a@b.c\nContent-Type: text/html\n\n<p>one body</p>\n",
    );
    assert_eq!(
        sorted_hashes(&children_of(&single, &single[0])),
        sorted_sha256(&[b"<p>one body</p>\n"]),
        "{REQUIREMENT}"
    );
}

#[test]
fn a_mail_part_is_scanned_as_its_decoded_bytes() {
    const REQUIREMENT: &str = "A Mail Part Is Scanned As Its Decoded Bytes";
    let (directory, compiled) = databases("mail-decoded");

    let quoted = objects(
        &directory,
        &compiled.image,
        b"From: a@b.c\nContent-Type: text/plain\nContent-Transfer-Encoding: quoted-printable\n\n\
Soft =\nbreak and =3D equals =41=42 end\nnext line\n",
    );
    assert_eq!(
        sorted_hashes(&children_of(&quoted, &quoted[0])),
        sorted_sha256(&[b"Soft break and = equals AB end\nnext line\n"]),
        "{REQUIREMENT}"
    );

    let lines = objects(
        &directory,
        &compiled.image,
        b"From: a@b.c\nContent-Type: text/html\r\rfirst line   \r\nsecond line",
    );
    assert_eq!(
        sorted_hashes(&children_of(&lines, &lines[0])),
        sorted_sha256(&[b"first line   \nsecond line\n"]),
        "{REQUIREMENT}"
    );

    let named = objects(
        &directory,
        &compiled.image,
        b"From: a@b.c\nContent-Type: multipart/mixed; boundary=q\n\n--q\n\
Content-Type: text/plain\nContent-Transfer-Encoding: 7bit\n\
Content-Disposition: attachment; filename=\"t.txt\"\n\n\
c2V2ZW4gYml0IHBsYWluIHdvcmRzIGhlcmUK\n--q--\n",
    );
    assert_eq!(
        sorted_hashes(&children_of(&named, &named[0])),
        sorted_sha256(&[
            b"c2V2ZW4gYml0IHBsYWluIHdvcmRzIGhlcmUK\n",
            b"seven bit plain words here\n",
        ]),
        "{REQUIREMENT}"
    );
}

#[test]
fn a_message_attached_to_a_message_is_scanned_as_a_message_of_its_own() {
    const REQUIREMENT: &str = "A Message Attached To A Message Is Scanned As A Message Of Its Own";
    let (directory, compiled) = databases("mail-attached");
    let inner: &[u8] = b"From: x@y.z\nContent-Type: application/octet-stream\n\
Content-Transfer-Encoding: base64\n\n\
aW5uZXIgYXR0YWNobWVudCBvZiB0aGUgYXR0YWNoZWQgbWVzc2FnZQo=\n";
    let message = [
        b"From: a@b.c\nContent-Type: multipart/mixed; boundary=b1\n\n--b1\n\
Content-Type: message/rfc822\n\n"
            .as_slice(),
        inner,
        b"--b1--\n",
    ]
    .concat();

    let found = objects(&directory, &compiled.image, &message);

    let attached = children_of(&found, &found[0]);
    assert_eq!(
        sorted_hashes(&attached),
        sorted_sha256(&[inner]),
        "{REQUIREMENT}"
    );
    assert_eq!(attached[0]["type"], "CL_TYPE_MAIL", "{REQUIREMENT}");
    assert_eq!(
        sorted_hashes(&children_of(&found, attached[0])),
        sorted_sha256(&[b"inner attachment of the attached message\n"]),
        "{REQUIREMENT}"
    );
    assert_eq!(
        children_of(&found, attached[0])[0]["depth"],
        2,
        "{REQUIREMENT}"
    );
}

#[test]
fn a_message_without_a_content_header_or_sender_yields_no_parts() {
    const REQUIREMENT: &str = "A Message Without A Content Header Or Sender Yields No Parts";
    let (directory, compiled) = databases("mail-no-headers");

    let found = objects(
        &directory,
        &compiled.image,
        b"Subject: plain note\n\nhello PARTBODY in the body\n",
    );

    assert_eq!(found[0]["type"], "CL_TYPE_MAIL", "{REQUIREMENT}");
    assert_eq!(found.len(), 1, "{REQUIREMENT}");
    assert_eq!(
        distinct(&found[0]),
        ["Test.InPart.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
}

#[test]
fn each_message_of_a_mailbox_is_opened() {
    const REQUIREMENT: &str = "Each Message Of A Mailbox Is Opened";
    let (directory, compiled) = databases("mail-mailbox");
    let mailbox = b"From someone@x Sat Jan  3 01:05:34 1996\n\
From: a@b.c\nContent-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\n\
Zmlyc3QgbWFpbGJveCBhdHRhY2htZW50IFBBUlRCT0RZCg==\n\n\
From other@y Sat Jan  3 01:05:34 1996\n\
From: c@d.e\nContent-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\n\
c2Vjb25kIG1haWxib3ggYXR0YWNobWVudAo=\n";

    let found = objects(&directory, &compiled.image, mailbox);

    assert_eq!(
        sorted_hashes(&children_of(&found, &found[0])),
        sorted_sha256(&[
            b"first mailbox attachment PARTBODY\n",
            b"second mailbox attachment\n",
        ]),
        "{REQUIREMENT}"
    );
}

#[test]
fn a_uuencoded_block_in_a_message_body_is_scanned_as_its_decoded_bytes() {
    const REQUIREMENT: &str = "A Uuencoded Block In A Message Body Is Scanned As Its Decoded Bytes";
    let (directory, compiled) = databases("mail-uuencoded");

    let found = objects(
        &directory,
        &compiled.image,
        b"From: a@b.c\nContent-Type: text/plain\n\nsome text before\nbegin 644 f.txt\n\
>=75E;F-O9&5D('!A>6QO860@;V8@=&AI<G1Y(&(N\n`\nend\nafter text\n",
    );

    assert_eq!(
        sorted_hashes(&children_of(&found, &found[0])),
        sorted_sha256(&[
            b"some text before\nend\nafter text\n",
            b"uuencoded payload of thirty b.",
        ]),
        "{REQUIREMENT}"
    );
}

#[test]
fn text_found_to_be_mail_is_matched_as_mail() {
    const REQUIREMENT: &str = "Text Found To Be Mail Is Matched As Mail";
    let (directory, compiled) = databases("mail-found-in-text");
    let filler = "filler words here ".repeat(62);
    let text = format!(
        "preface line one\nsome more text\nFrom: a@b.c\n{filler}\n\
Content-Type: text/plain\n\nthe body says MAILBODY\n"
    );

    let found = objects(&directory, &compiled.image, text.as_bytes());

    assert_eq!(found[0]["type"], "CL_TYPE_MAIL", "{REQUIREMENT}");
    assert_eq!(
        distinct(&found[0]),
        ["Test.ForMail.UNOFFICIAL"],
        "{REQUIREMENT}"
    );
    assert_eq!(
        sorted_hashes(&children_of(&found, &found[0])),
        sorted_sha256(&[b"the body says MAILBODY\n"]),
        "{REQUIREMENT}"
    );
}
