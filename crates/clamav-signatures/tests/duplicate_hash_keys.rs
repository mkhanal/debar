#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use debar_clamav_signatures::{DatabaseFile, LineOutcome, compile};
use debar_image::{Category, DigestAlgorithm, HashPurpose, Image, ImageBuilder, PartitionKey};

fn image_of(name: &str, text: &str) -> (Vec<u8>, Vec<LineOutcome>) {
    let files = [DatabaseFile {
        name,
        contents: text.as_bytes(),
    }];
    let mut builder = ImageBuilder::new();
    let account = compile(&files, &mut builder).unwrap();
    (builder.finish().unwrap(), account.files[0].lines.clone())
}

fn reported(image: &Image<'_>, hex: &str, size: u32) -> String {
    let digest: Vec<u8> = hex
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let algorithm = if digest.len() == 16 {
        DigestAlgorithm::Md5
    } else {
        DigestAlgorithm::Sha256
    };
    let partition = image
        .hash_partition(PartitionKey {
            purpose: HashPurpose::WholeObjectDetection,
            category: Category::Malware,
            algorithm,
        })
        .unwrap()
        .unwrap();
    let name = partition.lookup_exact_size(size, &digest).unwrap().unwrap();
    image.signature_name(name).unwrap().text
}

fn same_key_lines(names: &[&str]) -> String {
    names.iter().fold(String::new(), |mut text, name| {
        text.push_str("44d88612fea8a8f36de82e1278abb02f:68:");
        text.push_str(name);
        text.push('\n');
        text
    })
}

#[test]
fn two_equal_keys_alone_report_the_one_loaded_later() {
    for names in [["A", "B"], ["B", "A"]] {
        let (bytes, outcomes) = image_of("local.hdb", &same_key_lines(&names));
        let image = Image::open(&bytes).unwrap();

        assert_eq!(
            reported(&image, "44d88612fea8a8f36de82e1278abb02f", 68),
            format!("{}.UNOFFICIAL", names[1])
        );
        assert_eq!(
            outcomes,
            [LineOutcome::ShadowedByDuplicate, LineOutcome::Compiled]
        );
    }
}

#[test]
fn three_to_seven_equal_keys_report_the_name_the_reference_measured() {
    let measured = [(3, "D3"), (4, "D3"), (5, "D4"), (6, "D4"), (7, "D5")];
    for (count, expected) in measured {
        let names: Vec<String> = (1..=count).map(|index| format!("D{index}")).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let (bytes, _) = image_of("local.hdb", &same_key_lines(&names));
        let image = Image::open(&bytes).unwrap();

        assert_eq!(
            reported(&image, "44d88612fea8a8f36de82e1278abb02f", 68),
            format!("{expected}.UNOFFICIAL"),
            "{count} equal keys"
        );
    }
}

#[test]
fn every_duplicated_key_reports_the_name_the_written_rule_predicts_in_a_crowded_bucket() {
    let scenarios = include_str!("duplicate_hash_keys/scenarios.hdb");
    let expected = include_str!("duplicate_hash_keys/expected.tsv");
    let (bytes, _) = image_of("scenarios.hdb", scenarios);
    let image = Image::open(&bytes).unwrap();

    let mut checked = 0;
    for line in expected.lines() {
        let [digest, size, name] = line.split('\t').collect::<Vec<_>>()[..] else {
            panic!("{line:?} is not digest, size and name")
        };
        assert_eq!(
            reported(&image, digest, size.parse().unwrap()),
            format!("{name}.UNOFFICIAL"),
            "{digest} at {size}"
        );
        checked += 1;
    }
    assert_eq!(checked, 400);
}
