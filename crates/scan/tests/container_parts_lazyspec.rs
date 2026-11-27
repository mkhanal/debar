#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

#[path = "modules/test_container.rs"]
mod test_container;

use std::alloc::System;
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use cap::Cap;
use debar_formats::{EncryptedContent, Fact, FormatModule, Limit, MacroLanguage};
use debar_image::{
    ContainerSignature, Image, ImageBuilder, Indicator, KindCondition, ObjectKind, SizeCondition,
};
use debar_platform::input::InputError;
use debar_scan::{
    Completion, Facts, FinishedObject, FormatModules, Limits, Matching, ObjectBytes, ObjectFact,
    ObjectObserver, ScanReport, ScanSettings, scan_with_modules,
};
use test_container::{
    ContainerWriter, HEADER_LENGTH, TEST_CONTAINER, TEST_CONTAINER_MODULE, add_body,
    test_container_image_builder,
};

#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, usize::MAX);

static MEASURING: RwLock<()> = RwLock::new(());

const MEMORY_BOUND_BYTES: u64 = 32 * 1024 * 1024;
const DECODED_PART_BYTES: u64 = 24 * 1024 * 1024;
const MODULES: &[&dyn FormatModule] = &[&TEST_CONTAINER_MODULE];

const ONE_BODY: &[u8] = b"PARTONEBODY";
const TWO_BODY: &[u8] = b"PARTTWOBODY";
const OWN_BODY: &[u8] = b"OWNBYTESBODY";
const VIEW_BODY: &[u8] = b"VIEWEDBODY";
const INNERMOST_BODY: &[u8] = b"INNERMOSTBODY";
const ENTRY_SIZE: u32 = 77;

fn alongside_others() -> RwLockReadGuard<'static, ()> {
    MEASURING.read().unwrap_or_else(PoisonError::into_inner)
}

fn alone() -> RwLockWriteGuard<'static, ()> {
    MEASURING.write().unwrap_or_else(PoisonError::into_inner)
}

fn image() -> Vec<u8> {
    let mut builder: ImageBuilder = test_container_image_builder().unwrap();
    for (name, body) in [
        ("Test.One", ONE_BODY),
        ("Test.Two", TWO_BODY),
        ("Test.Own", OWN_BODY),
        ("Test.View", VIEW_BODY),
        ("Test.Innermost", INNERMOST_BODY),
    ] {
        add_body(&mut builder, name, body).unwrap();
    }
    builder
        .add_container_signature(&ContainerSignature {
            name: "Test.Entry",
            indicator: Indicator::Strong,
            container: KindCondition::Kind(TEST_CONTAINER),
            container_size: SizeCondition::Any,
            entry_name: None,
            compressed_size: SizeCondition::Exactly(ENTRY_SIZE),
            real_size: SizeCondition::Any,
            encrypted: None,
            position: SizeCondition::Any,
        })
        .unwrap();
    builder.finish().unwrap()
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct Finished {
    id: u64,
    parent: Option<u64>,
    depth: u32,
    kind: Option<ObjectKind>,
    length: u64,
}

#[derive(Default)]
struct Objects(Vec<Finished>);

impl ObjectObserver for Objects {
    fn object_finished(&mut self, object: &FinishedObject<'_>) {
        self.0.push(Finished {
            id: object.layer.0,
            parent: object.parent.map(|parent| parent.0),
            depth: object.depth,
            kind: object.kind,
            length: object.bytes.length(),
        });
    }
}

struct Scanned {
    report: ScanReport,
    finished: Vec<Finished>,
}

impl Scanned {
    fn names(&self) -> Vec<&str> {
        self.report
            .reported
            .iter()
            .map(|reported| reported.name.as_str())
            .collect()
    }

    fn layer_of(&self, name: &str) -> u64 {
        self.report
            .reported
            .iter()
            .find(|reported| reported.name == name)
            .unwrap()
            .layer
            .0
    }

    fn finished(&self, id: u64) -> &Finished {
        self.finished.iter().find(|object| object.id == id).unwrap()
    }

    fn limits(&self) -> Vec<Limit> {
        self.report.limits.iter().map(|event| event.limit).collect()
    }
}

fn scanned_with(object: &[u8], settings: &ScanSettings<'_>) -> Scanned {
    scanned_in(&image(), object, settings)
}

fn scanned_in(image: &[u8], object: &[u8], settings: &ScanSettings<'_>) -> Scanned {
    let image = Image::open(image).unwrap();
    let mut objects = Objects::default();
    let report = scan_with_modules(
        &image,
        &Held(object),
        settings,
        FormatModules::new(MODULES),
        &mut objects,
    );
    assert!(
        matches!(report.completion, Completion::Complete),
        "{:?}",
        report.completion
    );
    Scanned {
        report,
        finished: objects.0,
    }
}

fn every_match() -> ScanSettings<'static> {
    ScanSettings {
        matching: Matching::EveryMatch,
        ..ScanSettings::default()
    }
}

fn first_match() -> ScanSettings<'static> {
    ScanSettings::default()
}

fn with_limits(limits: Limits) -> ScanSettings<'static> {
    ScanSettings {
        limits,
        ..every_match()
    }
}

fn binary(body: &[u8]) -> Vec<u8> {
    let mut bytes = b"\x00\x00\x00\x00binary part ".to_vec();
    bytes.extend_from_slice(body);
    bytes
}

fn two_parts_then_own_bytes() -> Vec<u8> {
    ContainerWriter::new()
        .inverted(&binary(ONE_BODY))
        .inverted(&binary(TWO_BODY))
        .end()
        .raw(OWN_BODY)
        .finish()
}

#[test]
fn each_part_of_a_container_is_scanned_whole_before_the_next_part_is_read() {
    const REQUIREMENT: &str =
        "Each Part Of A Container Is Scanned Whole Before The Next Part Is Read";
    let _shared = alongside_others();
    let container = two_parts_then_own_bytes();

    let every = scanned_with(&container, &every_match());
    let first = scanned_with(&container, &first_match());

    assert_eq!(
        every.names(),
        ["Test.One", "Test.Two", "Test.Own"],
        "{REQUIREMENT}"
    );
    assert_eq!(first.names(), ["Test.One"], "{REQUIREMENT}");
    let parts_read = first
        .finished
        .iter()
        .filter(|object| object.parent.is_some())
        .count();
    assert_eq!(parts_read, 1, "{REQUIREMENT}: no later part is read");
}

#[test]
fn a_containers_parts_are_scanned_before_its_own_bytes() {
    const REQUIREMENT: &str = "A Container's Parts Are Scanned Before Its Own Bytes";
    let _shared = alongside_others();
    let container = ContainerWriter::new()
        .inverted(&binary(ONE_BODY))
        .end()
        .raw(OWN_BODY)
        .finish();

    let every = scanned_with(&container, &every_match());
    let first = scanned_with(&container, &first_match());

    assert_eq!(every.names(), ["Test.One", "Test.Own"], "{REQUIREMENT}");
    assert_eq!(every.layer_of("Test.Own"), 0, "{REQUIREMENT}");
    assert_eq!(first.names(), ["Test.One"], "{REQUIREMENT}");
}

#[test]
fn a_part_is_an_object_one_level_deeper_than_its_container_under_the_same_limits() {
    const REQUIREMENT: &str =
        "A Part Is An Object One Level Deeper Than Its Container, Under The Same Limits";
    let _shared = alongside_others();
    let inner = ContainerWriter::new()
        .inverted(&binary(TWO_BODY))
        .end()
        .finish();
    let nested = ContainerWriter::new()
        .inverted(&binary(ONE_BODY))
        .produced(&inner)
        .end()
        .finish();

    let scanned = scanned_with(&nested, &every_match());
    let one = scanned.finished(scanned.layer_of("Test.One"));
    let two = scanned.finished(scanned.layer_of("Test.Two"));
    assert_eq!(
        (one.depth, one.kind, two.depth),
        (1, Some(ObjectKind::BinaryData), 2),
        "{REQUIREMENT}"
    );

    let shallow = scanned_with(
        &nested,
        &with_limits(Limits {
            deepest_level: 1,
            ..Limits::default()
        }),
    );
    assert_eq!(shallow.names(), ["Test.One"], "{REQUIREMENT}");
    assert_eq!(shallow.limits(), [Limit::DeepestLevel], "{REQUIREMENT}");

    let container = two_parts_then_own_bytes();
    let two_files = scanned_with(
        &container,
        &with_limits(Limits {
            most_files: Some(2),
            ..Limits::default()
        }),
    );
    assert_eq!(two_files.names(), ["Test.One", "Test.Own"], "{REQUIREMENT}");
    assert_eq!(two_files.limits(), [Limit::MostFiles], "{REQUIREMENT}");

    let large = vec![0u8; 4096];
    let large_then_small = ContainerWriter::new()
        .inverted(&large)
        .inverted(&binary(TWO_BODY))
        .end()
        .finish();
    let length = ObjectBytes::length(large_then_small.as_slice());
    let small = ObjectBytes::length(binary(TWO_BODY).as_slice());
    let skipped = scanned_with(
        &large_then_small,
        &with_limits(Limits {
            largest_scan: Some(length.checked_add(small).unwrap()),
            ..Limits::default()
        }),
    );
    assert_eq!(skipped.names(), ["Test.Two"], "{REQUIREMENT}");
    assert_eq!(skipped.limits(), [Limit::LargestScan], "{REQUIREMENT}");
}

#[test]
fn a_damaged_container_keeps_what_its_earlier_parts_found_and_its_own_bytes_are_still_matched() {
    const REQUIREMENT: &str = "A Damaged Container Keeps What Its Earlier Parts Found, And Its Own Bytes Are Still Matched";
    let _shared = alongside_others();
    let damaged = ContainerWriter::new()
        .inverted(&binary(ONE_BODY))
        .raw(b"?")
        .inverted(&binary(TWO_BODY))
        .end()
        .raw(OWN_BODY)
        .finish();

    let scanned = scanned_with(&damaged, &every_match());

    assert_eq!(scanned.names(), ["Test.One", "Test.Own"], "{REQUIREMENT}");
}

#[test]
fn a_normalised_view_is_matched_as_its_kind_uses_a_level_and_is_never_counted() {
    const REQUIREMENT: &str =
        "A Normalised View Is Matched As Its Kind, Uses A Level, And Is Never Counted";
    let _shared = alongside_others();
    let container = ContainerWriter::new()
        .inverted_view(VIEW_BODY)
        .inverted(&binary(ONE_BODY))
        .end()
        .finish();

    let two_files = scanned_with(
        &container,
        &with_limits(Limits {
            most_files: Some(2),
            ..Limits::default()
        }),
    );
    let no_level = scanned_with(
        &container,
        &with_limits(Limits {
            deepest_level: 0,
            ..Limits::default()
        }),
    );

    assert_eq!(
        two_files.names(),
        ["Test.View", "Test.One"],
        "{REQUIREMENT}"
    );
    assert_ne!(two_files.layer_of("Test.View"), 0, "{REQUIREMENT}");
    assert!(two_files.limits().is_empty(), "{REQUIREMENT}");
    assert!(no_level.names().is_empty(), "{REQUIREMENT}");
    assert_eq!(no_level.limits(), [Limit::DeepestLevel], "{REQUIREMENT}");
}

#[test]
fn a_container_entry_is_tested_against_container_signatures_before_its_part_is_scanned() {
    const REQUIREMENT: &str =
        "A Container Entry Is Tested Against Container Signatures Before Its Part Is Scanned";
    let _shared = alongside_others();
    let container = ContainerWriter::new()
        .entry(b"member", ENTRY_SIZE)
        .inverted(&binary(ONE_BODY))
        .end()
        .finish();

    let every = scanned_with(&container, &every_match());
    let first = scanned_with(&container, &first_match());

    assert_eq!(every.names(), ["Test.Entry", "Test.One"], "{REQUIREMENT}");
    assert_eq!(every.layer_of("Test.Entry"), 0, "{REQUIREMENT}");
    assert_eq!(first.names(), ["Test.Entry"], "{REQUIREMENT}");
    assert_eq!(
        first.finished.len(),
        1,
        "{REQUIREMENT}: the part is never read"
    );
}

#[test]
fn an_archive_found_inside_another_file_spans_only_the_length_its_header_gives() {
    const REQUIREMENT: &str =
        "An Archive Found Inside Another File Spans Only The Length Its Header Gives";
    let _shared = alongside_others();
    let first_archive = ContainerWriter::new()
        .end()
        .raw(b"padding TOYC\x40\x00\x00\x00 inside the first archive")
        .finish();
    let second_archive = ContainerWriter::new()
        .end()
        .raw(b"the second archive")
        .finish();
    let mut host = binary(b"host");
    host.resize(100, b' ');
    host.extend_from_slice(&first_archive);
    host.extend_from_slice(b" between the archives ");
    host.extend_from_slice(&second_archive);
    host.extend_from_slice(b" then TOYC\x02\x00\x00\x00 fails its header check");

    let scanned = scanned_with(&host, &every_match());

    let children: Vec<(u64, Option<ObjectKind>)> = scanned
        .finished
        .iter()
        .filter(|object| object.parent == Some(0))
        .map(|object| (object.length, object.kind))
        .collect();
    let first_length = ObjectBytes::length(first_archive.as_slice());
    let second_length = ObjectBytes::length(second_archive.as_slice());
    assert_eq!(
        children,
        [
            (first_length, Some(TEST_CONTAINER)),
            (second_length, Some(TEST_CONTAINER)),
        ],
        "{REQUIREMENT}"
    );
    assert!(first_length > HEADER_LENGTH, "{REQUIREMENT}");
}

fn nested_repeating(innermost_unit: &[u8], levels: u32) -> Vec<u8> {
    let mut unit = innermost_unit.to_vec();
    for _ in 0..levels {
        let times = u32::try_from(
            DECODED_PART_BYTES
                .checked_div(ObjectBytes::length(unit.as_slice()))
                .unwrap(),
        )
        .unwrap();
        unit = ContainerWriter::new().repeated(&unit, times).end().finish();
    }
    unit
}

#[test]
fn scanning_a_container_holds_at_most_32_mib_of_memory_however_large_its_parts_decode_to() {
    const REQUIREMENT: &str =
        "Scanning A Container Holds At Most 32 MiB Of Memory, However Large Its Parts Decode To";
    let _alone = alone();
    let image = image();
    let mut innermost = vec![b'.'; 4096];
    innermost.splice(100..100, INNERMOST_BODY.iter().copied());
    let container = nested_repeating(&innermost, 3);
    let settings = every_match();

    let held_before = u64::try_from(ALLOCATOR.allocated()).unwrap();
    let scanned = scanned_in(&image, &container, &settings);
    let peak = u64::try_from(ALLOCATOR.max_allocated()).unwrap();
    let held_for_the_scan = peak.saturating_sub(held_before);

    println!("{REQUIREMENT}: peak heap bytes held for the scan: {held_for_the_scan}");
    let decoded: Vec<u32> = scanned
        .finished
        .iter()
        .filter(|object| object.length >= DECODED_PART_BYTES.checked_sub(64 * 1024).unwrap())
        .map(|object| object.depth)
        .collect();
    assert_eq!(decoded.len(), 3, "{REQUIREMENT}: {:?}", scanned.finished);
    assert!(scanned.names().contains(&"Test.Innermost"), "{REQUIREMENT}");
    assert!(
        held_for_the_scan <= MEMORY_BOUND_BYTES,
        "{REQUIREMENT}: {held_for_the_scan} bytes"
    );
}

#[test]
fn a_containers_facts_are_reported_with_the_object_they_describe_only_when_asked_for() {
    const REQUIREMENT: &str =
        "A Container's Facts Are Reported With The Object They Describe, Only When Asked For";
    let _shared = alongside_others();
    let inner = ContainerWriter::new().fact(1).end().finish();
    let builder = ContainerWriter::new().fact(0).inverted(&inner);
    let damaged_at = builder.length();
    let container = builder.raw(b"?").finish();

    let gathered = scanned_with(
        &container,
        &ScanSettings {
            facts: Facts::Gathered,
            ..every_match()
        },
    );
    let not_gathered = scanned_with(&container, &every_match());

    let inner_layer = gathered
        .finished
        .iter()
        .find(|object| object.parent == Some(0))
        .unwrap()
        .id;
    let encrypted = Fact::Encrypted {
        content: EncryptedContent::Archive,
        decryptable: false,
    };
    let facts: Vec<(u64, Fact)> = gathered
        .report
        .facts
        .iter()
        .map(|ObjectFact { layer, fact }| (layer.0, *fact))
        .collect();
    assert_eq!(
        facts,
        [
            (0, Fact::Macros(MacroLanguage::VisualBasic)),
            (inner_layer, encrypted),
            (0, Fact::BrokenStructure { at: damaged_at }),
        ],
        "{REQUIREMENT}"
    );
    assert!(not_gathered.report.facts.is_empty(), "{REQUIREMENT}");
}
