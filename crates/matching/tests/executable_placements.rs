#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use std::cell::Cell;

use debar_image::{
    Category, ExecutableAnchor, Image, ImageBuilder, Indicator, KindDescription, MaskedByte,
    ObjectKind, OwnBytes, PartMemory, Pattern, PatternElement, PatternOutcome, PatternSignature,
    Placement, RecognitionRank, SignatureGroup,
};
use debar_matching::{
    ExecutableLayout, ExecutableSection, GroupSelection, PatternRequest, PatternScan,
    PatternSettings,
};

const GENERIC: SignatureGroup = SignatureGroup(0);
const EXECUTABLES: SignatureGroup = SignatureGroup(1);
const MARKER: &[u8] = b"MARK";

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
    executable: bool,
) {
    builder.describe_object_kind(
        kind,
        KindDescription {
            format_name: format!("{kind:?}"),
            groups,
            recognition: RecognitionRank::default(),
            own_bytes: OwnBytes::Matched {
                as_kind: None,
                recognising_types: false,
            },
            found_in_full_scan_retypes: Vec::new(),
            executable,
        },
    );
}

fn image_with(signatures: &[(SignatureGroup, Placement, Pattern)]) -> Vec<u8> {
    let names: Vec<String> = (0..signatures.len())
        .map(|index| format!("Test.{index}"))
        .collect();
    let mut builder = ImageBuilder::new();
    for ((group, placement, pattern), name) in signatures.iter().zip(&names) {
        builder
            .add_pattern_signature(&PatternSignature {
                group: *group,
                category: Category::Malware,
                placement: *placement,
                report_rank: 0,
                pattern,
                outcome: PatternOutcome::Detection {
                    name,
                    indicator: Indicator::Strong,
                },
            })
            .unwrap();
    }
    describe(
        &mut builder,
        ObjectKind::WindowsExecutable,
        vec![EXECUTABLES, GENERIC],
        true,
    );
    describe(&mut builder, ObjectKind::BinaryData, vec![GENERIC], false);
    builder.finish().unwrap()
}

fn layout() -> ExecutableLayout {
    ExecutableLayout {
        entry_point: 0x210,
        sections: vec![
            ExecutableSection {
                start: 0x100,
                length: 0x100,
            },
            ExecutableSection {
                start: 0x400,
                length: 0x200,
            },
        ],
        version_information: vec![0x700],
    }
}

fn object_with_marker_at(length: usize, at: usize) -> Vec<u8> {
    let mut object = vec![0u8; length];
    object[at..at + MARKER.len()].copy_from_slice(MARKER);
    object
}

fn detected(
    image: &[u8],
    kind: ObjectKind,
    object: &[u8],
    layout: Option<ExecutableLayout>,
) -> bool {
    let image = Image::open(image).unwrap();
    let request = PatternRequest {
        selection: GroupSelection::ForKind(kind),
        settings: PatternSettings {
            potentially_unwanted: false,
            every_match: true,
        },
        object_length: object.len() as u64,
    };
    let mut scan = PatternScan::new(&image, request, || layout).unwrap();
    scan.feed(object).unwrap();
    !scan.finish().unwrap().detections.is_empty()
}

fn in_executable(anchor: ExecutableAnchor, shift: u32) -> Placement {
    Placement::InExecutable { anchor, shift }
}

fn matches_only_at(placement: Placement, expected: &[usize]) {
    let image = image_with(&[(EXECUTABLES, placement, exact(MARKER))]);
    for at in (0..0x800).step_by(8).chain(expected.iter().copied()) {
        let object = object_with_marker_at(0x800, at);
        assert_eq!(
            detected(
                &image,
                ObjectKind::WindowsExecutable,
                &object,
                Some(layout())
            ),
            expected.contains(&at),
            "{placement:?} with the marker at {at:#x}"
        );
    }
}

#[test]
fn an_entry_point_offset_matches_at_its_resolved_position() {
    matches_only_at(
        in_executable(ExecutableAnchor::AfterEntryPoint { distance: 0x10 }, 0),
        &[0x220],
    );
    matches_only_at(
        in_executable(ExecutableAnchor::BeforeEntryPoint { distance: 0x10 }, 0),
        &[0x200],
    );
}

#[test]
fn a_shift_widens_the_resolved_position_into_a_range() {
    matches_only_at(
        in_executable(ExecutableAnchor::AfterEntryPoint { distance: 0 }, 8),
        &[0x210, 0x211, 0x215, 0x218],
    );
}

#[test]
fn section_offsets_resolve_against_the_section_table() {
    matches_only_at(
        in_executable(
            ExecutableAnchor::SectionStart {
                section: 1,
                distance: 0x10,
            },
            0,
        ),
        &[0x410],
    );
    matches_only_at(
        in_executable(ExecutableAnchor::LastSectionStart { distance: 0x20 }, 0),
        &[0x420],
    );
    matches_only_at(
        in_executable(
            ExecutableAnchor::SectionStart {
                section: 2,
                distance: 0,
            },
            0,
        ),
        &[],
    );
}

#[test]
fn a_whole_section_offset_matches_from_the_section_start_to_its_end_plus_the_shift() {
    let placement = in_executable(
        ExecutableAnchor::WholeSection {
            section: 0,
            start_only_from_length: None,
        },
        8,
    );
    let image = image_with(&[(EXECUTABLES, placement, exact(MARKER))]);
    for (at, expected) in [
        (0xff, false),
        (0x100, true),
        (0x180, true),
        (0x208, true),
        (0x209, false),
    ] {
        let object = object_with_marker_at(0x800, at);
        assert_eq!(
            detected(
                &image,
                ObjectKind::WindowsExecutable,
                &object,
                Some(layout())
            ),
            expected,
            "marker at {at:#x}"
        );
    }
}

#[test]
fn a_whole_section_offset_matches_only_at_the_section_start_in_a_large_object() {
    let placement = in_executable(
        ExecutableAnchor::WholeSection {
            section: 1,
            start_only_from_length: Some(0x1000),
        },
        0,
    );
    let image = image_with(&[(EXECUTABLES, placement, exact(MARKER))]);
    for (length, at, expected) in [
        (0x800, 0x410, true),
        (0x1000, 0x410, false),
        (0x1000, 0x400, true),
    ] {
        let object = object_with_marker_at(length, at);
        assert_eq!(
            detected(
                &image,
                ObjectKind::WindowsExecutable,
                &object,
                Some(layout())
            ),
            expected,
            "{length:#x} bytes, marker at {at:#x}"
        );
    }
}

#[test]
fn version_information_offsets_match_only_at_the_listed_positions() {
    matches_only_at(
        in_executable(ExecutableAnchor::VersionInformation, 0),
        &[0x700],
    );
}

#[test]
fn an_offset_that_wraps_below_zero_or_a_shift_that_wraps_never_matches() {
    matches_only_at(
        in_executable(ExecutableAnchor::BeforeEntryPoint { distance: 0x211 }, 0),
        &[],
    );
    matches_only_at(
        in_executable(ExecutableAnchor::BeforeEntryPoint { distance: 0x21a }, 20),
        &[],
    );
    matches_only_at(
        in_executable(ExecutableAnchor::AfterEntryPoint { distance: 0 }, u32::MAX),
        &[],
    );
}

#[test]
fn without_an_executable_layout_only_absolute_and_unplaced_signatures_match() {
    let image = image_with(&[
        (
            EXECUTABLES,
            in_executable(ExecutableAnchor::AfterEntryPoint { distance: 0 }, 0),
            exact(b"EPEP"),
        ),
        (
            GENERIC,
            Placement::BeforeEnd {
                distance: 4,
                shift: 0,
            },
            exact(b"TAIL"),
        ),
        (
            EXECUTABLES,
            Placement::FromStart {
                distance: 0,
                shift: 0,
            },
            exact(b"HEAD"),
        ),
    ]);
    let mut object = vec![0u8; 0x400];
    object[..4].copy_from_slice(b"HEAD");
    object[0x210..0x214].copy_from_slice(b"EPEP");
    object[0x3fc..].copy_from_slice(b"TAIL");
    let names = |layout: Option<ExecutableLayout>, kind| {
        let image = Image::open(&image).unwrap();
        let request = PatternRequest {
            selection: GroupSelection::ForKind(kind),
            settings: PatternSettings {
                potentially_unwanted: false,
                every_match: true,
            },
            object_length: object.len() as u64,
        };
        let mut scan = PatternScan::new(&image, request, || layout).unwrap();
        scan.feed(&object).unwrap();
        let mut names: Vec<String> = scan
            .finish()
            .unwrap()
            .detections
            .into_iter()
            .map(|detection| detection.name)
            .collect();
        names.sort();
        names
    };

    assert_eq!(
        names(Some(layout()), ObjectKind::WindowsExecutable),
        ["Test.0", "Test.1", "Test.2"]
    );
    assert_eq!(names(None, ObjectKind::WindowsExecutable), ["Test.2"]);
    assert_eq!(names(None, ObjectKind::BinaryData), ["Test.1"]);
}

#[test]
fn the_executable_layout_is_asked_for_only_for_an_executable_kind() {
    let image = image_with(&[(
        EXECUTABLES,
        in_executable(ExecutableAnchor::AfterEntryPoint { distance: 0 }, 0),
        exact(MARKER),
    )]);
    let image = Image::open(&image).unwrap();
    let asked = Cell::new(0);
    for kind in [ObjectKind::BinaryData, ObjectKind::WindowsExecutable] {
        let request = PatternRequest {
            selection: GroupSelection::ForKind(kind),
            settings: PatternSettings::default(),
            object_length: 16,
        };
        let scan = PatternScan::new(&image, request, || {
            asked.set(asked.get() + 1);
            None
        })
        .unwrap();
        drop(scan);
    }
    assert_eq!(asked.get(), 1);
}

#[test]
fn a_body_split_by_a_bounded_gap_is_lost_when_nine_later_parts_overwrite_its_predecessor() {
    let mut elements = exact(b"ABCD").elements;
    elements.push(PatternElement::PartBreak {
        minimum: 40,
        maximum: Some(100),
    });
    elements.extend(exact(b"ZZZZ").elements);
    let pattern = Pattern {
        before: None,
        elements,
        after: None,
    };
    let mut builder = ImageBuilder::new();
    builder
        .add_pattern_signature(&PatternSignature {
            group: GENERIC,
            category: Category::Malware,
            placement: Placement::Anywhere,
            report_rank: 0,
            pattern: &pattern,
            outcome: PatternOutcome::Detection {
                name: "Test.Ring",
                indicator: Indicator::Strong,
            },
        })
        .unwrap();
    builder.set_part_memory(GENERIC, PartMemory::FirstAndLatestEnds { latest: 8 });
    describe(&mut builder, ObjectKind::BinaryData, vec![GENERIC], false);
    let image = builder.finish().unwrap();
    for (too_close, expected) in [(6, true), (7, true), (8, false), (9, false), (10, false)] {
        let mut object = b"ABCD".to_vec();
        object.extend(vec![b'.'; 300]);
        object.extend_from_slice(b"ABCD");
        let zzzz = object.len() + 90;
        object.resize(zzzz - 4 * too_close, b'.');
        for _ in 0..too_close {
            object.extend_from_slice(b"ABCD");
        }
        object.extend_from_slice(b"ZZZZ");
        object.extend(vec![b'.'; 10]);
        assert_eq!(
            detected(&image, ObjectKind::BinaryData, &object, None),
            expected,
            "{too_close} too-close predecessors"
        );
    }
}
