#![forbid(unsafe_code)]
#![no_main]

use std::alloc::System;
use std::sync::OnceLock;

use cap::Cap;
use debar_image::{
    ByteSet, Category, EmbeddedObject, FoundAtAnOffset, Hosts, Image, ImageBuilder, Indicator,
    KindDescription, MagicTable, MaskedByte, ObjectKind, OwnBytes, Pattern, PatternElement,
    PatternOutcome, PatternSignature, Placement, RecognitionRank, SignatureGroup, TypeFinding,
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
const LOCAL_HEADER: &[u8] = b"PK\x03\x04";
const CODED_METHODS: [(u16, u16); 4] = [(9, 0), (12, 0), (6, 0x0006), (6, 0)];
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

fn describe(builder: &mut ImageBuilder, kind: ObjectKind, found: Option<FoundAtAnOffset>) {
    builder.describe_object_kind(
        kind,
        KindDescription {
            format_name: format!("{kind:?}"),
            groups: vec![GENERIC],
            recognition: RecognitionRank {
                priority: u32::from(kind.code()),
                always_replaces: found.is_some(),
                ..RecognitionRank::default()
            },
            own_bytes: OwnBytes::Matched {
                as_kind: None,
                recognising_types: kind != ObjectKind::Zip,
            },
            matched_again_as: None,
            found_in_full_scan_retypes: Vec::new(),
            found_at_an_offset: found,
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
        builder.add_type_magic(MagicTable::Files, 0, LOCAL_HEADER, ObjectKind::Zip);
        for kind in [
            ObjectKind::Text,
            ObjectKind::BinaryData,
            ObjectKind::Zip,
            ObjectKind::OfficeOpenWord,
            ObjectKind::OfficeOpenSpreadsheet,
            ObjectKind::OfficeOpenPresentation,
        ] {
            describe(&mut builder, kind, None);
        }
        describe(
            &mut builder,
            ObjectKind::ZipSelfExtracting,
            Some(FoundAtAnOffset::Embedded {
                object: EmbeddedObject {
                    scanned_as: ObjectKind::Zip,
                    starts_before_the_match: 0,
                    recorded_up_to_the_file_count: true,
                },
                hosts: Hosts::NotIn(vec![ObjectKind::Zip]),
            }),
        );
        builder
            .add_pattern_signature(&PatternSignature {
                group: RECOGNITION,
                category: Category::Malware,
                placement: Placement::Anywhere,
                report_rank: 0,
                pattern: &exact(LOCAL_HEADER),
                outcome: PatternOutcome::TypeFound(TypeFinding {
                    found: ObjectKind::ZipSelfExtracting,
                    required: None,
                }),
            })
            .unwrap();
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

fn one_coded_member(data: &[u8], method: u16, flags: u16, real_size: u32) -> Vec<u8> {
    let compressed = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let name = b"m";
    let mut archive = Vec::new();
    archive.extend_from_slice(LOCAL_HEADER);
    for value in [20u16, flags, method, 0, 0] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    for value in [0u32, compressed, real_size] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    for value in [1u16, 0] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(name);
    archive.extend_from_slice(data);
    let central_offset = u32::try_from(archive.len()).unwrap_or(u32::MAX);
    archive.extend_from_slice(b"PK\x01\x02");
    for value in [20u16, 20, flags, method, 0, 0] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    for value in [0u32, compressed, real_size] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    for value in [1u16, 0, 0, 0, 0] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    for value in [0u32, 0] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(name);
    archive.extend_from_slice(b"PK\x05\x06");
    for value in [0u16, 0, 1, 1] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    for value in [47u32, central_offset] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive
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
    let coded;
    let object = if flags & 1 == 1 {
        let (method, method_flags) = CODED_METHODS[usize::from(files >> 6)];
        let real_size = u32::from(file_steps).saturating_add(1).saturating_mul(4096);
        coded = one_coded_member(object, method, method_flags, real_size);
        coded.as_slice()
    } else {
        object
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
        &object,
        &settings,
        FormatModules::built_in(),
        &mut bounds,
    );
    ALLOCATOR.set_limit(usize::MAX).unwrap();
    drop(report);
});
