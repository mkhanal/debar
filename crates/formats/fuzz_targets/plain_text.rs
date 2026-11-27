#![forbid(unsafe_code)]
#![no_main]

use std::alloc::System;
use std::sync::OnceLock;

use cap::Cap;
use debar_image::{
    ByteSet, Category, Image, ImageBuilder, Indicator, KindDescription, MaskedByte,
    ObjectKind, OwnBytes, Pattern, PatternElement, PatternOutcome, PatternSignature, Placement,
    RecognitionRank, SignatureGroup, TextNormalisation, TypingRules,
};
use debar_scan::{
    Facts, FinishedObject, FormatModules, Limits, Matching, ObjectObserver, ScanSettings, ScanTime,
    scan_with_modules,
};
use libfuzzer_sys::fuzz_target;

#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, usize::MAX);

const MEMORY_BOUND_BYTES: usize = 32 * 1024 * 1024;
const SETTINGS_BYTES: usize = 2;
const PIECE_STEP: u32 = 64;
const GENERIC: SignatureGroup = SignatureGroup(0);
const TEXT: SignatureGroup = SignatureGroup(7);

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

fn describe(builder: &mut ImageBuilder, kind: ObjectKind, groups: Vec<SignatureGroup>) {
    builder.describe_object_kind(
        kind,
        KindDescription {
            format_name: format!("{kind:?}"),
            groups,
            recognition: RecognitionRank::default(),
            own_bytes: OwnBytes::Matched {
                as_kind: (kind == ObjectKind::Text).then_some(ObjectKind::Untyped),
                recognising_types: false,
            },
            matched_again_as: None,
            found_in_full_scan_retypes: Vec::new(),
            found_at_an_offset: None,
            executable: false,
        },
    );
}

fn image(piece: u32) -> Vec<u8> {
    let mut builder = ImageBuilder::new();
    builder.set_typing(TypingRules {
        prefix_length: 1024,
        recognition_group: None,
        text_bytes: ByteSet::of(0x09..=0xff),
        wide_text_retry: None,
        most_found_at_offsets: 10,
    });
    builder.set_text_normalisation(TextNormalisation {
        normalised_in_pieces_of: piece,
    });
    describe(&mut builder, ObjectKind::Text, vec![GENERIC, TEXT]);
    describe(&mut builder, ObjectKind::Untyped, vec![GENERIC]);
    describe(&mut builder, ObjectKind::BinaryData, vec![GENERIC]);
    for (group, body, name) in [
        (TEXT, b"a b".as_slice(), "Test.Text"),
        (GENERIC, b"ab  c".as_slice(), "Test.TwoSpaces"),
    ] {
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
    builder.finish().unwrap()
}

fn images() -> &'static [Vec<u8>] {
    static IMAGES: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    IMAGES.get_or_init(|| (1..=4).map(|step| image(step * PIECE_STEP)).collect())
}

struct Bounds {
    deepest_level: u32,
}

impl ObjectObserver for Bounds {
    fn object_finished(&mut self, object: &FinishedObject<'_>) {
        assert!(
            object.depth <= self.deepest_level,
            "an object at depth {} is beyond the deepest level {}",
            object.depth,
            self.deepest_level
        );
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((chosen, object)) = input.split_first_chunk::<SETTINGS_BYTES>() else {
        return;
    };
    let [flags, scan_kilobytes] = *chosen;
    let limits = Limits {
        longest_scan: Some(ScanTime::from_milliseconds(1_000)),
        largest_scan: Some(1024 * (u64::from(scan_kilobytes) + 1)),
        deepest_level: u32::from(flags >> 4) % 4,
        ..Limits::default()
    };
    let settings = ScanSettings {
        matching: if flags & 1 == 1 {
            Matching::EveryMatch
        } else {
            Matching::FirstMatch
        },
        facts: Facts::Gathered,
        limits,
        ..ScanSettings::default()
    };
    let chosen_image = images()
        .get(usize::from(flags >> 1) % images().len())
        .unwrap();
    let image = Image::open(chosen_image).unwrap();
    let mut bounds = Bounds {
        deepest_level: limits.deepest_level,
    };
    ALLOCATOR
        .set_limit(ALLOCATOR.allocated().saturating_add(MEMORY_BOUND_BYTES))
        .unwrap();
    let report = scan_with_modules(
        &image,
        &object,
        &settings,
        FormatModules::built_in(),
        &mut bounds,
    );
    ALLOCATOR.set_limit(usize::MAX).unwrap();
    drop(report);
});
