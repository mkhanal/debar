#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use debar_image::{
    Category, DatabaseRecord, Digest, DigestAlgorithm, HashPurpose, HashSignature, HashedSize,
    Image, ImageBuilder, ImageError, Indicator, PartitionKey, Provenance,
};

fn md5(seed: u32) -> Digest {
    let mut bytes = [0u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let index = u32::try_from(index).unwrap();
        *byte = (seed.wrapping_mul(2_654_435_761).rotate_left(index) ^ index.wrapping_mul(97))
            .to_le_bytes()[0];
    }
    Digest::Md5(bytes)
}

fn signature(size: HashedSize, digest: Digest, name: &str) -> HashSignature<'_> {
    HashSignature {
        purpose: HashPurpose::WholeObjectDetection,
        category: Category::Malware,
        size,
        digest,
        name,
        indicator: Indicator::Strong,
    }
}

const WHOLE_OBJECT_MD5: PartitionKey = PartitionKey {
    purpose: HashPurpose::WholeObjectDetection,
    category: Category::Malware,
    algorithm: DigestAlgorithm::Md5,
};

fn image_of(signatures: &[HashSignature<'_>]) -> Vec<u8> {
    let mut builder = ImageBuilder::new();
    builder
        .add_database(DatabaseRecord {
            name: "first".to_owned(),
            version: 7,
            declared_signature_count: 3,
            functionality_level: 90,
            provenance: Provenance::DetachedSignatureVerified,
        })
        .unwrap();
    for signature in signatures {
        builder.add_hash_signature(signature).unwrap();
    }
    builder.finish().unwrap()
}

#[test]
fn every_added_hash_is_found_at_its_size_under_its_name() {
    let names: Vec<String> = (0..5_000)
        .map(|index| format!("Test.Hash-{index}"))
        .collect();
    let signatures: Vec<HashSignature<'_>> = names
        .iter()
        .zip(0u32..)
        .map(|(name, index)| signature(HashedSize::Exactly(100 + index % 300), md5(index), name))
        .collect();
    let bytes = image_of(&signatures);
    let image = Image::open(&bytes).unwrap();
    let partition = image.hash_partition(WHOLE_OBJECT_MD5).unwrap().unwrap();

    for signature in &signatures {
        let HashedSize::Exactly(size) = signature.size else {
            panic!("every signature here has an exact size")
        };
        let found = partition
            .lookup_exact_size(size, signature.digest.bytes())
            .unwrap()
            .unwrap();
        assert_eq!(image.signature_name(found).unwrap().text, signature.name);
    }
}

#[test]
fn a_hash_at_another_size_or_an_unlisted_hash_is_not_found() {
    let bytes = image_of(&[signature(HashedSize::Exactly(68), md5(1), "Listed")]);
    let image = Image::open(&bytes).unwrap();
    let partition = image.hash_partition(WHOLE_OBJECT_MD5).unwrap().unwrap();

    assert_eq!(
        partition.lookup_exact_size(69, md5(1).bytes()).unwrap(),
        None
    );
    assert_eq!(
        partition.lookup_exact_size(68, md5(2).bytes()).unwrap(),
        None
    );
    assert!(partition.has_size(68));
    assert!(!partition.has_size(69));
}

#[test]
fn a_hash_listed_for_any_size_is_found_at_every_size() {
    let bytes = image_of(&[signature(HashedSize::Any, md5(9), "Anywhere")]);
    let image = Image::open(&bytes).unwrap();
    let partition = image.hash_partition(WHOLE_OBJECT_MD5).unwrap().unwrap();

    assert!(partition.has_any_size_entries());
    let found = partition.lookup_any_size(md5(9).bytes()).unwrap().unwrap();
    assert_eq!(image.signature_name(found).unwrap().text, "Anywhere");
    assert_eq!(
        partition.lookup_exact_size(5, md5(9).bytes()).unwrap(),
        None
    );
}

#[test]
fn of_two_entries_with_one_key_the_one_added_last_is_found() {
    let bytes = image_of(&[
        signature(HashedSize::Exactly(10), md5(3), "Added.First"),
        signature(HashedSize::Exactly(10), md5(3), "Added.Last"),
    ]);
    let image = Image::open(&bytes).unwrap();
    let partition = image.hash_partition(WHOLE_OBJECT_MD5).unwrap().unwrap();

    let found = partition
        .lookup_exact_size(10, md5(3).bytes())
        .unwrap()
        .unwrap();

    assert_eq!(image.signature_name(found).unwrap().text, "Added.Last");
}

#[test]
fn a_name_keeps_the_kind_of_indicator_it_was_added_with() {
    let mut unwanted = signature(HashedSize::Exactly(10), md5(4), "Unwanted.Thing");
    unwanted.indicator = Indicator::PotentiallyUnwanted;
    let bytes = image_of(&[unwanted]);
    let image = Image::open(&bytes).unwrap();
    let partition = image.hash_partition(WHOLE_OBJECT_MD5).unwrap().unwrap();

    let found = partition
        .lookup_exact_size(10, md5(4).bytes())
        .unwrap()
        .unwrap();

    assert_eq!(
        image.signature_name(found).unwrap().indicator,
        Indicator::PotentiallyUnwanted
    );
}

#[test]
fn a_partition_nothing_was_added_to_is_absent() {
    let bytes = image_of(&[signature(HashedSize::Exactly(10), md5(4), "Only.Md5")]);
    let image = Image::open(&bytes).unwrap();

    let sha256 = PartitionKey {
        algorithm: DigestAlgorithm::Sha256,
        ..WHOLE_OBJECT_MD5
    };

    assert!(image.hash_partition(sha256).unwrap().is_none());
}

#[test]
fn the_databases_are_recorded_in_the_image() {
    let bytes = image_of(&[]);
    let image = Image::open(&bytes).unwrap();

    let databases = image.databases().unwrap();

    assert_eq!(databases.len(), 1);
    assert_eq!(databases[0].name, "first");
    assert_eq!(databases[0].version, 7);
    assert_eq!(
        databases[0].provenance,
        Provenance::DetachedSignatureVerified
    );
}

#[test]
fn the_same_signatures_build_the_same_bytes() {
    let names: Vec<String> = (0..2_000).map(|index| format!("Same-{index}")).collect();
    let signatures: Vec<HashSignature<'_>> = names
        .iter()
        .zip(0u32..)
        .map(|(name, index)| signature(HashedSize::Exactly(index % 50 + 1), md5(index), name))
        .collect();

    assert_eq!(image_of(&signatures), image_of(&signatures));
}

#[test]
fn sections_start_on_page_boundaries_and_pass_their_checksums() {
    let bytes = image_of(&[signature(HashedSize::Exactly(10), md5(4), "Checked")]);
    let image = Image::open(&bytes).unwrap();

    assert!(
        image
            .sections()
            .iter()
            .all(|section| section.range.start % 4096 == 0)
    );
    assert_eq!(image.verify_sections(), Ok(()));
}

#[test]
fn a_changed_byte_in_a_section_fails_verification_but_not_opening() {
    let mut bytes = image_of(&[signature(HashedSize::Exactly(10), md5(4), "Checked")]);
    let last_section = Image::open(&bytes)
        .unwrap()
        .sections()
        .last()
        .unwrap()
        .range
        .clone();
    bytes[last_section.start] ^= 0xff;

    let image = Image::open(&bytes).unwrap();

    assert!(matches!(
        image.verify_sections(),
        Err(ImageError::SectionChecksumMismatch { .. })
    ));
}

#[test]
fn a_changed_byte_in_the_header_is_refused_at_opening() {
    let mut bytes = image_of(&[]);
    bytes[40] ^= 1;

    assert_eq!(
        Image::open(&bytes).err(),
        Some(ImageError::HeaderChecksumMismatch)
    );
}

#[test]
fn a_truncated_image_is_refused() {
    let bytes = image_of(&[]);

    assert!(matches!(
        Image::open(&bytes[..bytes.len() - 1]),
        Err(ImageError::LengthDisagrees { .. })
    ));
    assert_eq!(Image::open(&bytes[..10]).err(), Some(ImageError::TooShort));
}

#[test]
fn a_file_that_is_not_an_image_is_refused() {
    assert_eq!(
        Image::open(&[0u8; 8192]).err(),
        Some(ImageError::NotAnImage)
    );
}

#[test]
fn every_single_byte_change_to_an_image_is_answered_without_a_panic() {
    let names: Vec<String> = (0..40).map(|index| format!("Mutated-{index}")).collect();
    let mut signatures: Vec<HashSignature<'_>> = names
        .iter()
        .zip(0u32..)
        .map(|(name, index)| signature(HashedSize::Exactly(index % 7 + 1), md5(index), name))
        .collect();
    signatures.push(signature(HashedSize::Any, md5(99), "Any"));
    let original = image_of(&signatures);
    let sections = Image::open(&original).unwrap().sections().to_vec();

    for section in &sections {
        for offset in section.range.clone() {
            for flip in [0x01u8, 0x80, 0xff] {
                let mut bytes = original.clone();
                bytes[offset] ^= flip;
                let Ok(image) = Image::open(&bytes) else {
                    continue;
                };
                let _ = image.databases();
                if let Ok(Some(partition)) = image.hash_partition(WHOLE_OBJECT_MD5) {
                    for index in 0..41u32 {
                        if let Ok(Some(name)) =
                            partition.lookup_exact_size(index % 7 + 1, md5(index).bytes())
                        {
                            let _ = image.signature_name(name);
                        }
                        let _ = partition.lookup_any_size(md5(index).bytes());
                    }
                }
            }
        }
    }
}
