#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use debar_image::{
    ByteSet, Category, Digest, HashPurpose, HashSignature, HashedSize, Image, ImageBuilder,
    Indicator, KindDescription, MagicTable, MaskedByte, ObjectKind, OwnBytes, Pattern,
    PatternElement, PatternOutcome, PatternSignature, Placement, RecognitionRank, SignatureGroup,
    TypeFinding, TypingRules,
};
use debar_matching::{DigestNeed, ObjectDigests};
use debar_platform::input::InputError;
use debar_scan::{
    Completion, FinishedObject, Matching, ObjectBytes, ObjectObserver, ScanSettings, Unobserved,
    Verdict, scan,
};

const GENERIC: SignatureGroup = SignatureGroup(0);
const OTHER_DATA: SignatureGroup = SignatureGroup(14);
const RECOGNITION: SignatureGroup = SignatureGroup(15);
const RETYPING_MARK: &[u8] = b"RETYPINGMARK";
const TYPING_PREFIX_LENGTH: u32 = 1024;
const BYTES_NEVER_IN_TEXT: std::ops::RangeInclusive<u8> = 0x00..=0x08;
const GENERIC_BODY: &[u8] = b"GENERICBODY";
const OTHER_DATA_BODY: &[u8] = b"OTHERDATABODY";

fn exact(text: &[u8]) -> Pattern {
    Pattern {
        before: None,
        elements: text
            .iter()
            .map(|byte| PatternElement::Byte(MaskedByte::exactly(*byte)))
            .collect(),
        after: None,
    }
}

fn describe(
    builder: &mut ImageBuilder,
    kind: ObjectKind,
    groups: Vec<SignatureGroup>,
    own_bytes: OwnBytes,
    matched_again_as: Option<ObjectKind>,
) {
    describe_retyping(
        builder,
        kind,
        groups,
        own_bytes,
        matched_again_as,
        Vec::new(),
    );
}

fn describe_retyping(
    builder: &mut ImageBuilder,
    kind: ObjectKind,
    groups: Vec<SignatureGroup>,
    own_bytes: OwnBytes,
    matched_again_as: Option<ObjectKind>,
    found_in_full_scan_retypes: Vec<ObjectKind>,
) {
    builder.describe_object_kind(
        kind,
        KindDescription {
            format_name: format!("{kind:?}"),
            groups,
            recognition: RecognitionRank::default(),
            own_bytes,
            matched_again_as,
            found_in_full_scan_retypes,
            found_at_an_offset: None,
            executable: false,
        },
    );
}

fn matched_as_itself() -> OwnBytes {
    OwnBytes::Matched {
        as_kind: None,
        recognising_types: false,
    }
}

fn add_body(builder: &mut ImageBuilder, group: SignatureGroup, name: &str, body: &[u8]) {
    builder
        .add_pattern_signature(&PatternSignature {
            group,
            category: Category::Malware,
            placement: Placement::Anywhere,
            report_rank: 0,
            pattern: &exact(body),
            outcome: PatternOutcome::Detection {
                name,
                indicator: Indicator::Strong,
            },
        })
        .unwrap();
}

fn sha256_of(object: &[u8]) -> Digest {
    let need = DigestNeed {
        sha256: true,
        ..DigestNeed::default()
    };
    Digest::Sha256(ObjectDigests::of(object, need).sha256.unwrap())
}

fn image(hashed: &[&[u8]]) -> Vec<u8> {
    let mut builder = ImageBuilder::new();
    builder.set_typing(TypingRules {
        prefix_length: TYPING_PREFIX_LENGTH,
        recognition_group: Some(RECOGNITION),
        text_bytes: ByteSet::of((0..=u8::MAX).filter(|byte| !BYTES_NEVER_IN_TEXT.contains(byte))),
        wide_text_retry: None,
        most_found_at_offsets: 10,
    });
    builder.add_type_magic(MagicTable::Files, 0, b"<html>", ObjectKind::Html);
    describe(
        &mut builder,
        ObjectKind::Text,
        vec![GENERIC],
        matched_as_itself(),
        None,
    );
    describe(
        &mut builder,
        ObjectKind::BinaryData,
        vec![GENERIC],
        OwnBytes::Matched {
            as_kind: None,
            recognising_types: true,
        },
        Some(ObjectKind::Other),
    );
    describe_retyping(
        &mut builder,
        ObjectKind::AppleDiskImage,
        vec![GENERIC],
        matched_as_itself(),
        None,
        vec![ObjectKind::BinaryData],
    );
    builder
        .add_pattern_signature(&PatternSignature {
            group: RECOGNITION,
            category: Category::Malware,
            placement: Placement::Anywhere,
            report_rank: 0,
            pattern: &exact(RETYPING_MARK),
            outcome: PatternOutcome::TypeFound(TypeFinding {
                found: ObjectKind::AppleDiskImage,
                required: None,
            }),
        })
        .unwrap();
    describe(
        &mut builder,
        ObjectKind::Other,
        vec![OTHER_DATA, GENERIC],
        matched_as_itself(),
        None,
    );
    describe(
        &mut builder,
        ObjectKind::Html,
        vec![GENERIC],
        OwnBytes::NotMatched,
        None,
    );
    add_body(&mut builder, GENERIC, "Test.Generic", GENERIC_BODY);
    add_body(&mut builder, OTHER_DATA, "Test.OtherData", OTHER_DATA_BODY);
    for object in hashed {
        builder
            .add_hash_signature(&HashSignature {
                purpose: HashPurpose::WholeObjectDetection,
                category: Category::Malware,
                size: HashedSize::Exactly(u32::try_from(object.len()).unwrap()),
                digest: sha256_of(object),
                name: "Test.Hash",
                indicator: Indicator::Strong,
            })
            .unwrap();
    }
    builder.finish().unwrap()
}

fn holding(start: &[u8], bodies: &[&[u8]]) -> Vec<u8> {
    let mut object = start.to_vec();
    for body in bodies {
        object.extend_from_slice(b" .... ");
        object.extend_from_slice(body);
    }
    object.extend_from_slice(b" ....\n");
    object
}

fn binary_holding(bodies: &[&[u8]]) -> Vec<u8> {
    holding(b"\x00\x00\x00\x00binary", bodies)
}

fn text_holding(bodies: &[&[u8]]) -> Vec<u8> {
    holding(b"plain text", bodies)
}

struct Held<'b>(&'b [u8]);

impl ObjectBytes for Held<'_> {
    fn length(&self) -> u64 {
        ObjectBytes::length(self.0)
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        self.0.read_at(offset, into)
    }
}

struct Scanned {
    verdict: Verdict,
    names: Vec<String>,
}

fn scanned(image: &[u8], object: &[u8], matching: Matching) -> Scanned {
    let image = Image::open(image).unwrap();
    let settings = ScanSettings {
        matching,
        ..ScanSettings::default()
    };
    let report = scan(&image, &Held(object), &settings, &mut Unobserved);
    assert!(
        matches!(report.completion, Completion::Complete),
        "{:?}",
        report.completion
    );
    Scanned {
        verdict: report.verdict,
        names: report
            .reported
            .into_iter()
            .map(|reported| reported.name)
            .collect(),
    }
}

#[test]
fn binary_data_is_matched_again_as_the_kind_the_image_names() {
    let object = binary_holding(&[GENERIC_BODY, OTHER_DATA_BODY]);
    let image = image(&[&object]);

    let every = scanned(&image, &object, Matching::EveryMatch);

    assert_eq!(
        every.names,
        [
            "Test.Generic",
            "Test.Hash",
            "Test.OtherData",
            "Test.Generic",
            "Test.Hash"
        ]
    );
}

#[test]
fn a_kind_the_image_matches_once_gets_one_pass() {
    let object = text_holding(&[GENERIC_BODY, OTHER_DATA_BODY]);
    let image = image(&[&object]);

    let every = scanned(&image, &object, Matching::EveryMatch);

    assert_eq!(every.names, ["Test.Generic", "Test.Hash"]);
}

#[test]
fn without_every_match_the_extra_pass_detects_what_the_object_s_own_pass_did_not() {
    let object = binary_holding(&[OTHER_DATA_BODY]);
    let image = image(&[]);

    let first = scanned(&image, &object, Matching::FirstMatch);

    assert_eq!(first.names, ["Test.OtherData"]);
    assert_eq!(first.verdict, Verdict::StrongIndicator);
}

#[test]
fn without_every_match_a_detection_in_the_object_s_own_pass_ends_the_scan_before_the_extra_pass() {
    let object = binary_holding(&[GENERIC_BODY, OTHER_DATA_BODY]);
    let image = image(&[&object]);

    let first = scanned(&image, &object, Matching::FirstMatch);

    assert_eq!(first.names, ["Test.Generic"]);
}

#[test]
fn a_kind_whose_own_bytes_are_never_matched_is_neither_matched_nor_hash_checked() {
    let object = holding(b"<html>", &[GENERIC_BODY]);
    let image = image(&[&object]);

    let every = scanned(&image, &object, Matching::EveryMatch);

    assert!(every.names.is_empty(), "{:?}", every.names);
    assert_eq!(every.verdict, Verdict::NothingFound);
}

#[test]
fn the_extra_pass_follows_the_kind_typed_from_the_first_bytes_even_when_the_object_is_retyped() {
    let mut object = binary_holding(&[OTHER_DATA_BODY]);
    object.resize(usize::try_from(TYPING_PREFIX_LENGTH).unwrap() + 64, b'.');
    object.extend_from_slice(RETYPING_MARK);
    object.extend_from_slice(b" ....\n");
    let image_bytes = image(&[]);
    let image = Image::open(&image_bytes).unwrap();
    let settings = ScanSettings {
        matching: Matching::EveryMatch,
        ..ScanSettings::default()
    };
    let mut kinds = FinalKinds(Vec::new());

    let report = scan(&image, &Held(&object), &settings, &mut kinds);

    assert_eq!(kinds.0, [Some(ObjectKind::AppleDiskImage)]);
    let names: Vec<String> = report
        .reported
        .into_iter()
        .map(|reported| reported.name)
        .collect();
    assert_eq!(names, ["Test.OtherData"]);
}

struct FinalKinds(Vec<Option<ObjectKind>>);

impl ObjectObserver for FinalKinds {
    fn object_finished(&mut self, object: &FinishedObject<'_>) {
        self.0.push(object.kind);
    }
}
