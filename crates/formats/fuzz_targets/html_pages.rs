#![forbid(unsafe_code)]
#![no_main]

use std::alloc::System;
use std::sync::OnceLock;

use cap::Cap;
use debar_image::{
    ByteSet, Category, Image, ImageBuilder, Indicator, KindDescription, MagicTable, MaskedByte,
    ObjectKind, OwnBytes, Pattern, PatternElement, PatternOutcome, PatternSignature, Placement,
    RecognitionRank, SignatureGroup, TypingRules,
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
const PAGE_START: &[u8] = b"<html>";
const GENERIC: SignatureGroup = SignatureGroup(0);
const WEB_PAGES: SignatureGroup = SignatureGroup(3);

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
            own_bytes: if kind == ObjectKind::Html {
                OwnBytes::NotMatched
            } else {
                OwnBytes::Matched {
                    as_kind: None,
                    recognising_types: false,
                }
            },
            matched_again_as: None,
            found_in_full_scan_retypes: Vec::new(),
            found_at_an_offset: None,
            executable: false,
        },
    );
}

fn image() -> &'static [u8] {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        let mut builder = ImageBuilder::new();
        builder.set_typing(TypingRules {
            prefix_length: 1024,
            recognition_group: None,
            text_bytes: ByteSet::of(0x09..=0xff),
            wide_text_retry: None,
            most_found_at_offsets: 10,
        });
        builder.add_type_magic(MagicTable::Files, 0, PAGE_START, ObjectKind::Html);
        describe(&mut builder, ObjectKind::Html, vec![GENERIC, WEB_PAGES]);
        describe(&mut builder, ObjectKind::Untyped, vec![GENERIC]);
        describe(&mut builder, ObjectKind::BinaryData, vec![GENERIC]);
        for (group, body, name) in [
            (WEB_PAGES, b"<b>x</b>".as_slice(), "Test.WithoutComments"),
            (GENERIC, b" a b ".as_slice(), "Test.WithoutTags"),
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
    })
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
    let Some((chosen, rest)) = input.split_first_chunk::<SETTINGS_BYTES>() else {
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
    let page = [PAGE_START, rest].concat();
    let image = Image::open(image()).unwrap();
    let mut bounds = Bounds {
        deepest_level: limits.deepest_level,
    };
    ALLOCATOR
        .set_limit(ALLOCATOR.allocated().saturating_add(MEMORY_BOUND_BYTES))
        .unwrap();
    let report = scan_with_modules(
        &image,
        &page.as_slice(),
        &settings,
        FormatModules::built_in(),
        &mut bounds,
    );
    ALLOCATOR.set_limit(usize::MAX).unwrap();
    drop(report);
});
