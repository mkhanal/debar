#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use debar_image::{
    ByteSet, Category, ContentSubsignature, Digest, EmbeddedObject, EngineAlert, Expression,
    FoundAtAnOffset, HashPurpose, HashSignature, HashedSize, Hosts, Image, ImageBuilder, Indicator,
    KindCondition, KindDescription, LogicalConditions, LogicalOutcome, LogicalSignature,
    MagicTable, MaskedByte, ObjectKind, OwnBytes, Pattern, PatternElement, PatternOutcome,
    PatternSignature, Placement, RecognitionRank, SignatureGroup, Subsignature, TypeFinding,
    TypingRules,
};
use debar_matching::{DigestNeed, ObjectDigests};
use debar_platform::input::InputError;
use debar_scan::{
    Completion, FinishedObject, Limit, Limits, Matching, ObjectBytes, ObjectObserver, ScanReport,
    ScanSettings, Verdict, scan,
};

const GENERIC: SignatureGroup = SignatureGroup(0);
const RECOGNITION: SignatureGroup = SignatureGroup(15);
const MOST_FOUND_AT_OFFSETS: u32 = 3;
const BINARY_START: &[u8] = b"\x00\x00\x00\x00binary";
const ARCHIVE_MARK: &[u8] = b"ARCHIVEMARK";
const SHORT_ARCHIVE_MARK: &[u8] = b"Q@Q@";
const ARCHIVE_HEAD: &[u8] = b"ARCHIVEHEAD";
const INSTALLER_MARK: &[u8] = b"INSTALLERMARK";
const DISK_MARK: &[u8] = b"DISKIMAGEMARK";
const RECORDED_MARK: &[u8] = b"RECORDEDMARK";
const EMBEDDED_BODY: &[u8] = b"EMBEDDEDBODY";
const RESCAN_BODY: &[u8] = b"RESCANBODY";
const INSIDE_BODY: &[u8] = b"INSIDEBINARYBODY";
const INSTALLER_SHIFT: u16 = 4;

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
                recognising_types: true,
            },
            matched_again_as: None,
            found_in_full_scan_retypes: Vec::new(),
            found_at_an_offset: found,
            executable: false,
        },
    );
}

fn recognise(builder: &mut ImageBuilder, mark: &[u8], found: ObjectKind) {
    builder
        .add_pattern_signature(&PatternSignature {
            group: RECOGNITION,
            category: Category::Malware,
            placement: Placement::Anywhere,
            report_rank: 0,
            pattern: &exact(mark),
            outcome: PatternOutcome::TypeFound(TypeFinding {
                found,
                required: None,
            }),
        })
        .unwrap();
}

fn add_body(builder: &mut ImageBuilder, name: &str, body: &[u8]) {
    builder
        .add_pattern_signature(&PatternSignature {
            group: GENERIC,
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

fn add_logical(
    builder: &mut ImageBuilder,
    name: &str,
    body: &[u8],
    conditions: &LogicalConditions,
) {
    builder
        .add_logical_signature(&LogicalSignature {
            group: GENERIC,
            category: Category::Malware,
            name,
            indicator: Indicator::Strong,
            outcome: LogicalOutcome::Detection,
            expression: &Expression::Subsignature {
                index: 0,
                count: None,
            },
            subsignatures: &[Subsignature::Content(ContentSubsignature {
                placement: Placement::Anywhere,
                patterns: vec![exact(body)],
            })],
            conditions,
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

fn describe_found_at_offsets(builder: &mut ImageBuilder) {
    let any_but_archives = Hosts::NotIn(vec![ObjectKind::Rar]);
    describe(
        builder,
        ObjectKind::RarSelfExtracting,
        Some(FoundAtAnOffset::Embedded {
            object: EmbeddedObject {
                scanned_as: ObjectKind::Rar,
                starts_before_the_match: 0,
            },
            hosts: any_but_archives,
        }),
    );
    describe(
        builder,
        ObjectKind::NullsoftInstaller,
        Some(FoundAtAnOffset::Embedded {
            object: EmbeddedObject {
                scanned_as: ObjectKind::NullsoftInstaller,
                starts_before_the_match: INSTALLER_SHIFT,
            },
            hosts: Hosts::OnlyIn(vec![ObjectKind::WindowsExecutable]),
        }),
    );
    describe(
        builder,
        ObjectKind::AppleDiskImage,
        Some(FoundAtAnOffset::RetypesTheObject { hosts: Hosts::Any }),
    );
    describe(
        builder,
        ObjectKind::ZipSelfExtracting,
        Some(FoundAtAnOffset::Recorded),
    );
}

fn image(trusted: &[&[u8]]) -> Vec<u8> {
    let mut builder = ImageBuilder::new();
    builder.set_typing(TypingRules {
        prefix_length: 16,
        recognition_group: Some(RECOGNITION),
        text_bytes: ByteSet::of(0x20..=0x7e),
        wide_text_retry: None,
        most_found_at_offsets: MOST_FOUND_AT_OFFSETS,
    });
    builder.add_type_magic(MagicTable::Files, 0, b"MZ", ObjectKind::WindowsExecutable);
    builder.add_type_magic(MagicTable::Files, 0, ARCHIVE_HEAD, ObjectKind::Rar);
    for kind in [
        ObjectKind::Text,
        ObjectKind::BinaryData,
        ObjectKind::WindowsExecutable,
        ObjectKind::Rar,
        ObjectKind::Pdf,
    ] {
        describe(&mut builder, kind, None);
    }
    describe_found_at_offsets(&mut builder);
    recognise(&mut builder, ARCHIVE_MARK, ObjectKind::RarSelfExtracting);
    recognise(
        &mut builder,
        SHORT_ARCHIVE_MARK,
        ObjectKind::RarSelfExtracting,
    );
    recognise(&mut builder, INSTALLER_MARK, ObjectKind::NullsoftInstaller);
    recognise(&mut builder, DISK_MARK, ObjectKind::AppleDiskImage);
    recognise(&mut builder, RECORDED_MARK, ObjectKind::ZipSelfExtracting);
    add_body(&mut builder, "Test.Embedded", EMBEDDED_BODY);
    add_logical(
        &mut builder,
        "Test.Rescanned",
        RESCAN_BODY,
        &LogicalConditions {
            handler_type: Some(ObjectKind::Pdf),
            ..LogicalConditions::default()
        },
    );
    add_logical(
        &mut builder,
        "Test.InsideBinary",
        INSIDE_BODY,
        &LogicalConditions {
            container: Some(KindCondition::Kind(ObjectKind::BinaryData)),
            ..LogicalConditions::default()
        },
    );
    builder
        .name_engine_alert(
            EngineAlert::RecursionLimitExceeded,
            "Test.Limits.Recursion",
            Indicator::PotentiallyUnwanted,
        )
        .unwrap();
    builder
        .name_engine_alert(
            EngineAlert::FileCountLimitExceeded,
            "Test.Limits.Files",
            Indicator::PotentiallyUnwanted,
        )
        .unwrap();
    for object in trusted {
        builder
            .add_hash_signature(&HashSignature {
                purpose: HashPurpose::WholeObjectTrust,
                category: Category::Malware,
                size: HashedSize::Exactly(u32::try_from(object.len()).unwrap()),
                digest: sha256_of(object),
                name: "Test.Trusted",
                indicator: Indicator::Strong,
            })
            .unwrap();
    }
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
struct Object {
    id: u64,
    parent: Option<u64>,
    depth: u32,
    kind: Option<ObjectKind>,
    length: u64,
}

#[derive(Default)]
struct Objects(Vec<Object>);

impl ObjectObserver for Objects {
    fn object_finished(&mut self, object: &FinishedObject<'_>) {
        self.0.push(Object {
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
    objects: Vec<Object>,
}

impl Scanned {
    fn names_on(&self, id: u64) -> Vec<&str> {
        self.report
            .reported
            .iter()
            .filter(|reported| reported.layer.0 == id)
            .map(|reported| reported.name.as_str())
            .collect()
    }

    fn children(&self) -> Vec<&Object> {
        self.objects
            .iter()
            .filter(|object| object.parent.is_some() && object.kind.is_some())
            .collect()
    }
}

fn scanned_with(image: &[u8], object: &[u8], settings: &ScanSettings<'_>) -> Scanned {
    let image = Image::open(image).unwrap();
    let mut objects = Objects::default();
    let report = scan(&image, &Held(object), settings, &mut objects);
    assert!(
        matches!(report.completion, Completion::Complete),
        "{:?}",
        report.completion
    );
    objects.0.sort_by_key(|object| object.id);
    Scanned {
        report,
        objects: objects.0,
    }
}

fn every_match() -> ScanSettings<'static> {
    ScanSettings {
        matching: Matching::EveryMatch,
        ..ScanSettings::default()
    }
}

fn scanned(object: &[u8]) -> Scanned {
    scanned_with(&image(&[]), object, &every_match())
}

fn binary_with(parts: &[&[u8]]) -> Vec<u8> {
    let mut object = BINARY_START.to_vec();
    for part in parts {
        object.extend_from_slice(b" .... ");
        object.extend_from_slice(part);
    }
    object.extend_from_slice(b" ....\n");
    object
}

fn offset_of(object: &[u8], mark: &[u8]) -> u64 {
    object
        .windows(mark.len())
        .position(|window| window == mark)
        .map(|position| u64::try_from(position).unwrap())
        .unwrap()
}

#[test]
fn an_archive_found_at_an_offset_is_scanned_as_a_child_from_there_to_the_end() {
    let object = binary_with(&[ARCHIVE_MARK, EMBEDDED_BODY]);
    let start = offset_of(&object, ARCHIVE_MARK);

    let scanned = scanned(&object);

    assert_eq!(
        scanned.children(),
        [&Object {
            id: 1,
            parent: Some(0),
            depth: 1,
            kind: Some(ObjectKind::Rar),
            length: u64::try_from(object.len()).unwrap() - start,
        }]
    );
    assert_eq!(scanned.names_on(0), ["Test.Embedded"]);
    assert_eq!(scanned.names_on(1), ["Test.Embedded"]);
}

#[test]
fn an_embedded_object_finds_no_objects_inside_it_but_later_offsets_in_its_parent_are_still_taken() {
    let object = binary_with(&[ARCHIVE_MARK, ARCHIVE_MARK]);
    let first = offset_of(&object, ARCHIVE_MARK);
    let second =
        offset_of(&object[usize::try_from(first).unwrap() + 1..], ARCHIVE_MARK) + first + 1;
    let length = u64::try_from(object.len()).unwrap();

    let scanned = scanned(&object);

    let children: Vec<(Option<u64>, u64)> = scanned
        .children()
        .iter()
        .map(|child| (child.parent, child.length))
        .collect();
    assert_eq!(
        children,
        [(Some(0), length - first), (Some(0), length - second)]
    );
}

#[test]
fn without_every_match_a_detection_in_the_object_s_own_pass_ends_the_scan_before_its_children() {
    let object = binary_with(&[ARCHIVE_MARK, EMBEDDED_BODY]);

    let scanned = scanned_with(&image(&[]), &object, &ScanSettings::default());

    assert_eq!(scanned.children(), Vec::<&Object>::new());
    assert_eq!(scanned.names_on(0), ["Test.Embedded"]);
}

#[test]
fn an_object_found_at_the_start_is_not_an_embedded_object() {
    let mut object = ARCHIVE_MARK.to_vec();
    object.extend_from_slice(&binary_with(&[]));

    let scanned = scanned(&object);

    assert_eq!(scanned.children(), Vec::<&Object>::new());
}

#[test]
fn an_embedded_object_of_five_bytes_or_less_is_never_pushed() {
    let five = [binary_with(&[]).as_slice(), SHORT_ARCHIVE_MARK, b"."].concat();
    let six = [five.as_slice(), b"."].concat();

    let scanned_at_five = scanned(&five);
    let scanned_at_six = scanned(&six);

    assert_eq!(scanned_at_five.objects.len(), 1);
    assert_eq!(scanned_at_six.children().len(), 1);
}

#[test]
fn an_installer_is_embedded_only_in_an_executable_and_starts_before_its_mark() {
    let in_binary = binary_with(&[INSTALLER_MARK]);
    let mut in_executable = b"MZ".to_vec();
    in_executable.extend_from_slice(&binary_with(&[INSTALLER_MARK]));
    let mark = offset_of(&in_executable, INSTALLER_MARK);

    let from_binary = scanned(&in_binary);
    let from_executable = scanned(&in_executable);

    assert_eq!(from_binary.children(), Vec::<&Object>::new());
    assert_eq!(
        from_executable
            .children()
            .iter()
            .map(|child| (child.kind, child.length))
            .collect::<Vec<_>>(),
        [(
            Some(ObjectKind::NullsoftInstaller),
            u64::try_from(in_executable.len()).unwrap() - mark + u64::from(INSTALLER_SHIFT)
        )]
    );
}

#[test]
fn an_archive_is_not_embedded_in_an_archive_of_its_own_kind() {
    let object = [ARCHIVE_HEAD, binary_with(&[ARCHIVE_MARK]).as_slice()].concat();

    let scanned = scanned(&object);

    assert_eq!(scanned.objects[0].kind, Some(ObjectKind::Rar));
    assert_eq!(scanned.children(), Vec::<&Object>::new());
}

#[test]
fn a_kind_that_retypes_its_host_changes_the_object_s_own_kind() {
    let object = binary_with(&[DISK_MARK]);

    let scanned = scanned(&object);

    assert_eq!(scanned.children(), Vec::<&Object>::new());
    assert_eq!(scanned.objects[0].kind, Some(ObjectKind::AppleDiskImage));
}

#[test]
fn only_the_first_offsets_recorded_up_to_the_image_s_count_are_taken() {
    let object = binary_with(&[RECORDED_MARK, RECORDED_MARK, RECORDED_MARK, ARCHIVE_MARK]);

    let scanned = scanned(&object);

    assert_eq!(scanned.children(), Vec::<&Object>::new());
}

#[test]
fn a_handler_type_rescans_the_object_as_a_retyped_child_which_reports_it_by_name() {
    let object = binary_with(&[RESCAN_BODY]);

    let scanned = scanned(&object);

    assert_eq!(
        scanned.children(),
        [&Object {
            id: 1,
            parent: Some(0),
            depth: 1,
            kind: Some(ObjectKind::Pdf),
            length: u64::try_from(object.len()).unwrap(),
        }]
    );
    assert_eq!(scanned.names_on(0), Vec::<&str>::new());
    assert_eq!(scanned.names_on(1), ["Test.Rescanned"]);
}

#[test]
fn a_container_condition_is_tested_against_the_parent_s_kind() {
    let object = binary_with(&[ARCHIVE_MARK, INSIDE_BODY]);

    let scanned = scanned(&object);

    assert_eq!(scanned.names_on(0), Vec::<&str>::new());
    assert_eq!(scanned.names_on(1), ["Test.InsideBinary"]);
}

#[test]
fn a_child_beyond_the_deepest_level_is_not_scanned_and_raises_the_one_limit_alert() {
    let object = binary_with(&[ARCHIVE_MARK, ARCHIVE_MARK, EMBEDDED_BODY]);
    let settings = ScanSettings {
        limits: Limits {
            deepest_level: 0,
            ..Limits::default()
        },
        alert_on_limits: true,
        ..every_match()
    };

    let scanned = scanned_with(&image(&[]), &object, &settings);

    assert_eq!(scanned.children(), Vec::<&Object>::new());
    let limits: Vec<Limit> = scanned
        .report
        .limits
        .iter()
        .map(|event| event.limit)
        .collect();
    assert_eq!(limits, [Limit::DeepestLevel]);
    assert_eq!(
        scanned.names_on(0),
        ["Test.Embedded", "Test.Limits.Recursion"]
    );
    assert_eq!(scanned.report.verdict, Verdict::StrongIndicator);
}

#[test]
fn a_refused_rescan_ends_the_object_s_logical_outcomes_and_loses_its_embedded_objects() {
    let object = binary_with(&[RESCAN_BODY, ARCHIVE_MARK]);
    let settings = ScanSettings {
        limits: Limits {
            deepest_level: 0,
            ..Limits::default()
        },
        ..every_match()
    };

    let scanned = scanned_with(&image(&[]), &object, &settings);

    assert_eq!(scanned.objects.len(), 1);
    let limits: Vec<Limit> = scanned
        .report
        .limits
        .iter()
        .map(|event| event.limit)
        .collect();
    assert_eq!(limits, [Limit::DeepestLevel]);
}

#[test]
fn the_top_level_object_counts_against_the_file_count() {
    let object = binary_with(&[ARCHIVE_MARK]);
    let settings = ScanSettings {
        limits: Limits {
            most_files: Some(1),
            ..Limits::default()
        },
        alert_on_limits: true,
        ..every_match()
    };

    let scanned = scanned_with(&image(&[]), &object, &settings);

    assert_eq!(scanned.children(), Vec::<&Object>::new());
    assert_eq!(scanned.names_on(0), ["Test.Limits.Files"]);
    assert_eq!(scanned.report.verdict, Verdict::PotentiallyUnwanted);
}

#[test]
fn a_false_positive_hash_of_the_parent_suppresses_its_children_s_detections() {
    let object = binary_with(&[ARCHIVE_MARK, EMBEDDED_BODY]);

    let scanned = scanned_with(&image(&[&object]), &object, &every_match());

    assert_eq!(scanned.report.reported.len(), 0);
    assert_eq!(scanned.report.verdict, Verdict::Trusted);
}

#[test]
fn a_false_positive_hash_of_a_child_suppresses_only_its_own_detections() {
    let object = binary_with(&[ARCHIVE_MARK, EMBEDDED_BODY]);
    let start = usize::try_from(offset_of(&object, ARCHIVE_MARK)).unwrap();

    let scanned = scanned_with(&image(&[&object[start..]]), &object, &every_match());

    assert_eq!(scanned.names_on(0), ["Test.Embedded"]);
    assert_eq!(scanned.names_on(1), Vec::<&str>::new());
    assert_eq!(scanned.report.verdict, Verdict::StrongIndicator);
}
