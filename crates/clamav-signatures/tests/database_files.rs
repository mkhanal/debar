#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects,
    clippy::format_collect,
    clippy::format_push_string
)]

use std::io::Write;

use debar_clamav_signatures::{Account, DatabaseError, DatabaseFile, LineOutcome, compile};
use debar_image::{
    Category, DigestAlgorithm, HashPurpose, Image, ImageBuilder, Indicator, PartitionKey,
    Provenance,
};
use md5::{Digest as _, Md5};
use sha2::Sha256;

const SAMPLE: &[u8] = b"hello debar target\n";

fn md5_hex(bytes: &[u8]) -> String {
    hex(&Md5::digest(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Compiled {
    image: Vec<u8>,
    account: Account,
}

fn compile_files(files: &[(&str, &[u8])]) -> Result<Compiled, DatabaseError> {
    let files: Vec<DatabaseFile<'_>> = files
        .iter()
        .map(|(name, contents)| DatabaseFile { name, contents })
        .collect();
    let mut builder = ImageBuilder::new();
    let account = compile(&files, &mut builder)?;
    Ok(Compiled {
        image: builder.finish().unwrap(),
        account,
    })
}

fn key(purpose: HashPurpose, algorithm: DigestAlgorithm) -> PartitionKey {
    PartitionKey {
        purpose,
        category: Category::Malware,
        algorithm,
    }
}

fn found(image: &[u8], key: PartitionKey, size: u32, digest_hex: &str) -> Option<String> {
    let image = Image::open(image).unwrap();
    let digest: Vec<u8> = (0..digest_hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digest_hex[at..at + 2], 16).unwrap())
        .collect();
    let partition = image.hash_partition(key).unwrap()?;
    let name = partition
        .lookup_exact_size(size, &digest)
        .unwrap()
        .or_else(|| partition.lookup_any_size(&digest).unwrap())?;
    Some(image.signature_name(name).unwrap().text)
}

fn whole_object(algorithm: DigestAlgorithm) -> PartitionKey {
    key(HashPurpose::WholeObjectDetection, algorithm)
}

#[test]
fn a_loose_whole_file_md5_is_compiled_under_its_unofficial_name() {
    let line = format!("{}:19:Test.Sample-1\n", md5_hex(SAMPLE));
    let compiled = compile_files(&[("local.hdb", line.as_bytes())]).unwrap();

    assert_eq!(
        found(
            &compiled.image,
            whole_object(DigestAlgorithm::Md5),
            19,
            &md5_hex(SAMPLE)
        ),
        Some("Test.Sample-1.UNOFFICIAL".to_owned())
    );
    assert_eq!(compiled.account.files[0].lines, [LineOutcome::Compiled]);
}

#[test]
fn the_hash_length_chooses_the_algorithm_in_every_hash_file() {
    let sha256 = sha256_hex(SAMPLE);
    let sha1 = "a".repeat(40);
    let text = format!("{sha256}:19:By.Sha256\n{sha1}:19:By.Sha1\n");
    let compiled = compile_files(&[("local.hdb", text.as_bytes())]).unwrap();

    assert_eq!(
        found(
            &compiled.image,
            whole_object(DigestAlgorithm::Sha256),
            19,
            &sha256
        ),
        Some("By.Sha256.UNOFFICIAL".to_owned())
    );
    assert_eq!(
        found(
            &compiled.image,
            whole_object(DigestAlgorithm::Sha1),
            19,
            &sha1
        ),
        Some("By.Sha1.UNOFFICIAL".to_owned())
    );
}

#[test]
fn section_hashes_put_the_size_first() {
    let text = format!("4096:{}:Section.Hash\n", md5_hex(b"section"));
    let compiled = compile_files(&[("local.mdb", text.as_bytes())]).unwrap();

    assert_eq!(
        found(
            &compiled.image,
            key(
                HashPurpose::ExecutableSectionDetection,
                DigestAlgorithm::Md5
            ),
            4096,
            &md5_hex(b"section")
        ),
        Some("Section.Hash.UNOFFICIAL".to_owned())
    );
}

#[test]
fn false_positive_hashes_go_to_the_trust_table() {
    let text = format!("{}:19:Trusted.Sample\n", md5_hex(SAMPLE));
    let compiled = compile_files(&[("local.fp", text.as_bytes())]).unwrap();

    assert!(
        found(
            &compiled.image,
            key(HashPurpose::WholeObjectTrust, DigestAlgorithm::Md5),
            19,
            &md5_hex(SAMPLE)
        )
        .is_some()
    );
    assert_eq!(
        found(
            &compiled.image,
            whole_object(DigestAlgorithm::Md5),
            19,
            &md5_hex(SAMPLE)
        ),
        None
    );
}

#[test]
fn potentially_unwanted_files_compile_into_their_own_category() {
    let text = format!("{}:19:PUA.Test.Sample\n", md5_hex(SAMPLE));
    let compiled = compile_files(&[("local.hdu", text.as_bytes())]).unwrap();
    let image = Image::open(&compiled.image).unwrap();
    let partition = image
        .hash_partition(PartitionKey {
            category: Category::PotentiallyUnwanted,
            ..whole_object(DigestAlgorithm::Md5)
        })
        .unwrap()
        .unwrap();

    let name = partition
        .lookup_exact_size(19, &Md5::digest(SAMPLE))
        .unwrap()
        .unwrap();

    assert_eq!(
        image.signature_name(name).unwrap().indicator,
        Indicator::PotentiallyUnwanted
    );
}

#[test]
fn a_name_is_cut_before_its_trailer_and_comments_are_accounted() {
    let text = format!("# a comment\n{}:19:Cut.Here (Clam) rest\n", md5_hex(SAMPLE));
    let compiled = compile_files(&[("local.hdb", text.as_bytes())]).unwrap();

    assert_eq!(
        found(
            &compiled.image,
            whole_object(DigestAlgorithm::Md5),
            19,
            &md5_hex(SAMPLE)
        ),
        Some("Cut.Here.UNOFFICIAL".to_owned())
    );
    assert_eq!(
        compiled.account.files[0].lines,
        [LineOutcome::Comment, LineOutcome::Compiled]
    );
}

#[test]
fn lines_outside_the_functionality_level_are_left_out() {
    let digest = md5_hex(SAMPLE);
    let text = format!(
        "{digest}:19:Too.New:999\n{digest}:19:Too.Old:1:100\n{digest}:19:Text.Maximum:1:abc\n{digest}:19:In.Range:73:300\n"
    );
    let compiled = compile_files(&[("local.hdb", text.as_bytes())]).unwrap();

    assert_eq!(
        compiled.account.files[0].lines,
        [
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::OutsideFunctionalityLevel,
            LineOutcome::Compiled
        ]
    );
}

#[test]
fn a_hash_for_any_size_needs_level_seventy_three() {
    let digest = md5_hex(SAMPLE);
    let with_level = format!("{digest}:*:Any.Size:73\n");
    let compiled = compile_files(&[("local.hdb", with_level.as_bytes())]).unwrap();
    assert_eq!(
        found(
            &compiled.image,
            whole_object(DigestAlgorithm::Md5),
            12_345,
            &digest
        ),
        Some("Any.Size.UNOFFICIAL".to_owned())
    );

    for refused in [
        format!("{digest}:*:Any.Size\n"),
        format!("{digest}:*:Any.Size:72\n"),
    ] {
        assert!(matches!(
            compile_files(&[("local.hdb", refused.as_bytes())]),
            Err(DatabaseError::MalformedLine { line: 1, .. })
        ));
    }
}

#[test]
fn a_malformed_hash_line_fails_the_whole_compile() {
    let digest = md5_hex(SAMPLE);
    let malformed = [
        format!("{digest}:19:Fine\n\n{digest}:19:After.Blank\n"),
        "junk\n".to_owned(),
        format!("{digest}0:19:Long.Hash\n"),
        format!("{}z:19:Not.Hex\n", &digest[..31]),
        format!("{digest}:0:Size.Zero\n"),
        format!("{digest}:4294967295:Size.Too.Large\n"),
        format!("{digest}:19:\n"),
        format!("{digest}:19:Six:1:2:3\n"),
    ];
    for text in malformed {
        assert!(
            matches!(
                compile_files(&[("local.hdb", text.as_bytes())]),
                Err(DatabaseError::MalformedLine { .. })
            ),
            "{text}"
        );
    }
    assert!(matches!(
        compile_files(&[("local.hdb", b"")]),
        Err(DatabaseError::EmptyHashFile { .. })
    ));
}

#[test]
fn sizes_with_a_leading_space_or_plus_are_read() {
    let digest = md5_hex(SAMPLE);
    let text = format!("{digest}:+19:Plus\n{}: 7:Space\n", md5_hex(b"seven"));
    let compiled = compile_files(&[("local.hdb", text.as_bytes())]).unwrap();

    assert_eq!(
        found(
            &compiled.image,
            whole_object(DigestAlgorithm::Md5),
            19,
            &digest
        ),
        Some("Plus.UNOFFICIAL".to_owned())
    );
}

#[test]
fn an_ignore_list_drops_a_signature_by_its_whole_name_loaded_after_it() {
    let digest = md5_hex(SAMPLE);
    let signatures = format!(
        "{digest}:19:Win.Test.Foo-1\n{}:7:Win.Test.Kept\n",
        md5_hex(b"seven")
    );
    let compiled = compile_files(&[
        ("a.hdb", signatures.as_bytes()),
        ("z.ign2", b"Win.Test.Foo-1\nFoo\nWin.Test\n"),
    ])
    .unwrap();

    let hashes = compiled
        .account
        .files
        .iter()
        .find(|file| file.file == "a.hdb")
        .unwrap();
    assert_eq!(hashes.lines, [LineOutcome::Ignored, LineOutcome::Compiled]);
}

#[test]
fn an_ignore_entry_with_a_digest_needs_the_digest_of_the_line() {
    let line = format!("{}:19:Win.Test.Foo-1", md5_hex(SAMPLE));
    let ignore = format!("Win.Test.Foo-1:{}\n", md5_hex(line.as_bytes()));
    let wrong = format!(
        "Win.Test.Foo-1:{}\n",
        md5_hex(format!("{line}\n").as_bytes())
    );
    let text = format!("{line}\r\n");

    let ignored =
        compile_files(&[("a.hdb", text.as_bytes()), ("a.ign2", ignore.as_bytes())]).unwrap();
    let kept = compile_files(&[("a.hdb", text.as_bytes()), ("a.ign2", wrong.as_bytes())]).unwrap();

    let outcome = |compiled: &Compiled| {
        compiled
            .account
            .files
            .iter()
            .find(|file| file.file == "a.hdb")
            .unwrap()
            .lines
            .clone()
    };
    assert_eq!(outcome(&ignored), [LineOutcome::Ignored]);
    assert_eq!(outcome(&kept), [LineOutcome::Compiled]);
}

#[test]
fn of_two_entries_with_one_key_the_later_loaded_name_is_kept_for_lookup() {
    let digest = md5_hex(SAMPLE);
    let first = format!("{digest}:19:Dup.A\n");
    let second = format!("{digest}:19:Dup.B\n");
    let compiled =
        compile_files(&[("b.hdb", second.as_bytes()), ("a.hdb", first.as_bytes())]).unwrap();

    assert_eq!(
        found(
            &compiled.image,
            whole_object(DigestAlgorithm::Md5),
            19,
            &digest
        ),
        Some("Dup.B.UNOFFICIAL".to_owned())
    );
}

#[test]
fn files_that_are_not_databases_are_listed_and_other_kinds_are_not_yet_compiled() {
    let compiled = compile_files(&[
        (".bashrc", b"export A=1\n"),
        ("daily-1.cvd.sign", b"signature"),
        (
            "local.ldb",
            b"Logical.One;Target:0;0;41424344\nLogical.Two;Target:0;0;45464748\n",
        ),
    ])
    .unwrap();

    assert_eq!(
        compiled.account.not_databases,
        [".bashrc", "daily-1.cvd.sign"]
    );
    assert_eq!(
        compiled.account.files[0].lines,
        [LineOutcome::NotYetCompiled, LineOutcome::NotYetCompiled]
    );
}

fn tar_member(name: &str, contents: &[u8]) -> Vec<u8> {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    let size = format!("{:011o}\0", contents.len());
    header[124..136].copy_from_slice(size.as_bytes());
    let mut member = header.to_vec();
    member.extend_from_slice(contents);
    member.resize(member.len().next_multiple_of(512), 0);
    member
}

fn container(stem: &str, members: &[(&str, Vec<u8>)], compress: bool) -> Vec<u8> {
    let fields = |md5: &str| {
        format!("ClamAV-VDB:01 Jan 2026 00-00 +0000:42:2:90:{md5}:sig:builder:1700000000")
    };
    let mut info = format!("{}\n", fields("X"));
    for (name, contents) in members {
        info.push_str(&format!(
            "{name}:{}:{}\n",
            contents.len(),
            sha256_hex(contents)
        ));
    }
    info.push_str("DSIG:unverified\n");
    let mut tar = tar_member("COPYING", b"licence text\nsecond line\n");
    tar.extend(tar_member(&format!("{stem}.info"), info.as_bytes()));
    for (name, contents) in members {
        tar.extend(tar_member(name, contents));
    }
    let payload = if compress {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar).unwrap();
        encoder.finish().unwrap()
    } else {
        tar
    };
    let mut header = fields(&md5_hex(&payload)).into_bytes();
    header.resize(512, b' ');
    header.extend(payload);
    header
}

#[test]
fn a_container_compiles_its_members_under_their_official_names() {
    let line = format!("{}:19:Official.Sample\n", md5_hex(SAMPLE)).into_bytes();
    for compress in [true, false] {
        let cvd = container("daily", &[("daily.hdb", line.clone())], compress);
        let compiled = compile_files(&[("daily.cvd", &cvd)]).unwrap();
        let image = Image::open(&compiled.image).unwrap();

        assert_eq!(
            found(
                &compiled.image,
                whole_object(DigestAlgorithm::Md5),
                19,
                &md5_hex(SAMPLE)
            ),
            Some("Official.Sample".to_owned())
        );
        let databases = image.databases().unwrap();
        assert_eq!(databases[0].name, "daily");
        assert_eq!(databases[0].version, 42);
        assert_eq!(
            databases[0].provenance,
            Provenance::SignedContainerNotYetVerified
        );
        let members: Vec<(Option<&str>, &[LineOutcome])> = compiled
            .account
            .files
            .iter()
            .map(|file| (file.member.as_deref(), file.lines.as_slice()))
            .collect();
        assert_eq!(
            members,
            [
                (Some("COPYING"), &[LineOutcome::NotASignature; 2][..]),
                (Some("daily.info"), &[LineOutcome::NotASignature; 3][..]),
                (Some("daily.hdb"), &[LineOutcome::Compiled][..]),
            ]
        );
    }
}

#[test]
fn a_container_whose_payload_or_member_was_changed_is_refused() {
    let line = format!("{}:19:Official.Sample\n", md5_hex(SAMPLE)).into_bytes();
    let mut changed_payload = container("daily", &[("daily.hdb", line.clone())], true);
    let last = changed_payload.len() - 1;
    changed_payload[last] ^= 1;
    assert!(matches!(
        compile_files(&[("daily.cvd", &changed_payload)]),
        Err(DatabaseError::Container { .. })
    ));

    let mut changed_member = container("daily", &[("daily.hdb", line)], false);
    let position = changed_member
        .windows(15)
        .position(|window| window == b"Official.Sample")
        .unwrap();
    changed_member[position] = b'X';
    let payload_md5 = md5_hex(&changed_member[512..]);
    let header = String::from_utf8(changed_member[..512].to_vec()).unwrap();
    let old_md5 = header.split(':').nth(5).unwrap().to_owned();
    changed_member[..512].copy_from_slice(header.replace(&old_md5, &payload_md5).as_bytes());
    assert!(matches!(
        compile_files(&[("daily.cvd", &changed_member)]),
        Err(DatabaseError::Container { .. })
    ));
}

#[test]
fn an_ignore_list_inside_a_container_applies_to_containers_loaded_after_it() {
    let digest = md5_hex(SAMPLE);
    let main_line = format!(
        "{digest}:19:Main.Ignored\n{}:7:Main.Kept\n",
        md5_hex(b"seven")
    )
    .into_bytes();
    let main = container("main", &[("main.hdb", main_line)], true);
    let daily = container("daily", &[("daily.ign2", b"Main.Ignored\n".to_vec())], true);

    let compiled = compile_files(&[("main.cvd", &main), ("daily.cvd", &daily)]).unwrap();

    let hashes = compiled
        .account
        .files
        .iter()
        .find(|file| file.member.as_deref() == Some("main.hdb"))
        .unwrap();
    assert_eq!(hashes.lines, [LineOutcome::Ignored, LineOutcome::Compiled]);
}
