#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use debar_image::{
    Category, Digest, HashPurpose, HashSignature, HashedSize, Image, ImageBuilder, Indicator,
};
use debar_matching::{
    DigestNeed, HashSettings, ObjectDigests, Trust, UnwantedCategories,
    executable_section_detections, executable_section_digest_need, whole_object_detections,
    whole_object_digest_need, whole_object_trust,
};
use md5::{Digest as _, Md5};
use sha1::Sha1;
use sha2::Sha256;

const OBJECT: &[u8] = b"an object to look up\n";

fn size() -> u64 {
    u64::try_from(OBJECT.len()).unwrap()
}

fn listed(purpose: HashPurpose, size: HashedSize, digest: Digest, name: &str) -> HashSignature<'_> {
    HashSignature {
        purpose,
        category: Category::Malware,
        size,
        digest,
        name,
        indicator: Indicator::Strong,
    }
}

fn md5() -> Digest {
    Digest::Md5(Md5::digest(OBJECT).into())
}

fn sha1() -> Digest {
    Digest::Sha1(Sha1::digest(OBJECT).into())
}

fn sha256() -> Digest {
    Digest::Sha256(Sha256::digest(OBJECT).into())
}

fn exact() -> HashedSize {
    HashedSize::Exactly(u32::try_from(OBJECT.len()).unwrap())
}

fn image_of(signatures: &[HashSignature<'_>]) -> Vec<u8> {
    let mut builder = ImageBuilder::new();
    for signature in signatures {
        builder.add_hash_signature(signature).unwrap();
    }
    builder.finish().unwrap()
}

fn names(image: &Image<'_>, settings: HashSettings) -> Vec<String> {
    let need = whole_object_digest_need(image, size(), settings).unwrap();
    let digests = ObjectDigests::of(OBJECT, need);
    whole_object_detections(image, size(), &digests, settings)
        .unwrap()
        .into_iter()
        .map(|detection| detection.name)
        .collect()
}

#[test]
fn only_the_digests_some_entry_lists_at_the_object_size_are_needed() {
    let bytes = image_of(&[
        listed(
            HashPurpose::WholeObjectDetection,
            exact(),
            md5(),
            "Md5.Here",
        ),
        listed(
            HashPurpose::WholeObjectDetection,
            HashedSize::Exactly(3),
            sha1(),
            "Sha1.Elsewhere",
        ),
    ]);
    let image = Image::open(&bytes).unwrap();

    assert_eq!(
        whole_object_digest_need(&image, size(), HashSettings::default()).unwrap(),
        DigestNeed {
            md5: true,
            sha1: false,
            sha256: false
        }
    );
}

#[test]
fn an_entry_for_any_size_makes_its_digest_needed_at_every_size() {
    let bytes = image_of(&[listed(
        HashPurpose::WholeObjectDetection,
        HashedSize::Any,
        sha256(),
        "Any",
    )]);
    let image = Image::open(&bytes).unwrap();

    assert!(
        whole_object_digest_need(&image, 999_999, HashSettings::default())
            .unwrap()
            .sha256
    );
}

#[test]
fn nothing_is_needed_without_any_whole_object_detection_entry() {
    let bytes = image_of(&[listed(
        HashPurpose::WholeObjectTrust,
        exact(),
        md5(),
        "Trust.Only",
    )]);
    let image = Image::open(&bytes).unwrap();

    assert!(
        whole_object_digest_need(&image, size(), HashSettings::default())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn detections_come_in_digest_order_exact_size_before_any_size() {
    let bytes = image_of(&[
        listed(
            HashPurpose::WholeObjectDetection,
            HashedSize::Any,
            sha256(),
            "Sha256.Any",
        ),
        listed(
            HashPurpose::WholeObjectDetection,
            exact(),
            sha256(),
            "Sha256.Exact",
        ),
        listed(
            HashPurpose::WholeObjectDetection,
            HashedSize::Any,
            sha1(),
            "Sha1.Any",
        ),
        listed(
            HashPurpose::WholeObjectDetection,
            HashedSize::Any,
            md5(),
            "Md5.Any",
        ),
        listed(
            HashPurpose::WholeObjectDetection,
            exact(),
            md5(),
            "Md5.Exact",
        ),
        listed(
            HashPurpose::WholeObjectDetection,
            exact(),
            sha1(),
            "Sha1.Exact",
        ),
    ]);
    let image = Image::open(&bytes).unwrap();

    assert_eq!(
        names(&image, HashSettings::default()),
        [
            "Md5.Exact",
            "Md5.Any",
            "Sha1.Exact",
            "Sha1.Any",
            "Sha256.Exact",
            "Sha256.Any"
        ]
    );
}

#[test]
fn potentially_unwanted_entries_count_only_when_asked_for() {
    let mut unwanted = listed(
        HashPurpose::WholeObjectDetection,
        exact(),
        md5(),
        "PUA.Thing",
    );
    unwanted.category = Category::PotentiallyUnwanted;
    unwanted.indicator = Indicator::PotentiallyUnwanted;
    let bytes = image_of(&[unwanted]);
    let image = Image::open(&bytes).unwrap();

    assert_eq!(names(&image, HashSettings::default()), Vec::<String>::new());
    assert_eq!(
        names(
            &image,
            HashSettings {
                potentially_unwanted: true,
                unwanted_categories: UnwantedCategories::Every,
            }
        ),
        ["PUA.Thing"]
    );
}

#[test]
fn a_false_positive_entry_trusts_the_object() {
    let bytes = image_of(&[
        listed(
            HashPurpose::WholeObjectDetection,
            exact(),
            md5(),
            "Detected",
        ),
        listed(HashPurpose::WholeObjectTrust, exact(), md5(), "Trusted"),
    ]);
    let image = Image::open(&bytes).unwrap();
    let need = whole_object_digest_need(&image, size(), HashSettings::default()).unwrap();
    let digests = ObjectDigests::of(OBJECT, need);

    assert_eq!(
        whole_object_trust(&image, size(), &digests).unwrap(),
        Trust::Trusted
    );
    assert_eq!(
        whole_object_trust(&image, size(), &ObjectDigests::of(b"other", need)).unwrap(),
        Trust::NotTrusted
    );
}

#[test]
fn section_hashes_are_looked_up_apart_from_whole_object_hashes() {
    let bytes = image_of(&[listed(
        HashPurpose::ExecutableSectionDetection,
        exact(),
        md5(),
        "Section",
    )]);
    let image = Image::open(&bytes).unwrap();
    let need = executable_section_digest_need(&image, size(), HashSettings::default()).unwrap();
    let digests = ObjectDigests::of(OBJECT, need);

    let found =
        executable_section_detections(&image, size(), &digests, HashSettings::default()).unwrap();

    assert_eq!(found[0].name, "Section");
    assert_eq!(names(&image, HashSettings::default()), Vec::<String>::new());
}
