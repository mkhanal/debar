#![forbid(unsafe_code)]
#![no_main]

use std::alloc::System;
use std::sync::OnceLock;

use cap::Cap;
use debar_image::{
    ByteSet, Category, Image, ImageBuilder, Indicator,
    KindDescription, MagicTable, MaskedByte, ObjectKind, OwnBytes, Pattern, PatternElement,
    PatternOutcome, PatternSignature, Placement, RecognitionRank, SignatureGroup,
    TypingRules,
};
use debar_scan::{
    Facts, FinishedObject, FormatModules, Limits, Matching, ObjectObserver, ScanSettings, ScanTime,
    scan_with_modules,
};
use libfuzzer_sys::fuzz_target;

#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, usize::MAX);

const MEMORY_BOUND_BYTES: usize = 32 * 1024 * 1024;
const FILE_SIZE_STEP: u64 = 4 * 1024;
const SCAN_SIZE_STEP: u64 = 16 * 1024;
const SETTINGS_BYTES: usize = 4;
const MAIL_HEADER: &[u8] = b"From: ";
const MAILBOX_SEPARATOR: &[u8] = b"From ";
const A_MAIL_START: &[u8] = b"From: a\nContent-Type: multipart/mixed; boundary=b\n\n--b\n";
const GENERIC: SignatureGroup = SignatureGroup(0);
const RECOGNITION: SignatureGroup = SignatureGroup(15);

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

fn describe(builder: &mut ImageBuilder, kind: ObjectKind) {
    builder.describe_object_kind(
        kind,
        KindDescription {
            format_name: format!("{kind:?}"),
            groups: vec![GENERIC],
            recognition: RecognitionRank {
                priority: u32::from(kind.code()),
                ..RecognitionRank::default()
            },
            own_bytes: OwnBytes::Matched {
                as_kind: None,
                recognising_types: true,
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
            recognition_group: Some(RECOGNITION),
            text_bytes: ByteSet::of(0x20..=0x7e),
            wide_text_retry: None,
            most_found_at_offsets: 10,
        });
        builder.add_type_magic(MagicTable::Files, 0, MAIL_HEADER, ObjectKind::Mail);
        builder.add_type_magic(MagicTable::Files, 0, MAILBOX_SEPARATOR, ObjectKind::Mail);
        for kind in [ObjectKind::Text, ObjectKind::BinaryData, ObjectKind::Mail] {
            describe(&mut builder, kind);
        }
        builder
            .add_pattern_signature(&PatternSignature {
                group: GENERIC,
                category: Category::Malware,
                placement: Placement::Anywhere,
                report_rank: 0,
                pattern: &exact(b"BODY"),
                outcome: PatternOutcome::Detection {
                    name: "Test.Body",
                    indicator: Indicator::Strong,
                },
            })
            .unwrap();
        builder.finish().unwrap()
    })
}

struct Bounds {
    deepest_level: u32,
    most_files: u64,
    finished: u64,
}

impl ObjectObserver for Bounds {
    fn object_finished(&mut self, object: &FinishedObject<'_>) {
        assert!(
            object.depth <= self.deepest_level,
            "an object at depth {} is beyond the deepest level {}",
            object.depth,
            self.deepest_level
        );
        self.finished = self.finished.saturating_add(1);
        assert!(
            self.finished <= self.most_files,
            "{} objects finished where {} files are allowed",
            self.finished,
            self.most_files
        );
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((chosen, object)) = input.split_first_chunk::<SETTINGS_BYTES>() else {
        return;
    };
    let [flags, file_steps, scan_steps, files] = *chosen;
    let object = if flags & 1 == 1 {
        [A_MAIL_START, object].concat()
    } else {
        object.to_vec()
    };
    let limits = Limits {
        longest_scan: Some(ScanTime::from_milliseconds(u64::from(files).saturating_add(1))),
        largest_file: Some(FILE_SIZE_STEP.saturating_mul(u64::from(file_steps) + 1)),
        largest_scan: Some(SCAN_SIZE_STEP.saturating_mul(u64::from(scan_steps) + 1)),
        most_files: Some(u64::from(files % 64) + 1),
        deepest_level: u32::from(flags >> 3) % 8,
    };
    let settings = ScanSettings {
        matching: if flags & 2 == 2 {
            Matching::EveryMatch
        } else {
            Matching::FirstMatch
        },
        alert_on_limits: flags & 4 == 4,
        facts: Facts::Gathered,
        limits,
        ..ScanSettings::default()
    };
    let image = Image::open(image()).unwrap();
    let mut bounds = Bounds {
        deepest_level: limits.deepest_level,
        most_files: limits.most_files.unwrap_or(u64::MAX),
        finished: 0,
    };
    ALLOCATOR
        .set_limit(ALLOCATOR.allocated().saturating_add(MEMORY_BOUND_BYTES))
        .unwrap();
    let report = scan_with_modules(
        &image,
        &object.as_slice(),
        &settings,
        FormatModules::built_in(),
        &mut bounds,
    );
    ALLOCATOR.set_limit(usize::MAX).unwrap();
    drop(report);
});
