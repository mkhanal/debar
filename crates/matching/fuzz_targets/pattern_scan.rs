#![forbid(unsafe_code)]
#![no_main]

use debar_image::{
    ByteSet, Category, ContextTest, ExecutableAnchor, Image, ImageBuilder, Indicator,
    KindDescription, MaskedByte, ObjectKind, OwnBytes, Pattern, PatternElement, PatternOutcome,
    PatternSignature, Placement, RecognitionRank, SignatureGroup,
};
use debar_matching::{ObjectContext, UnwantedCategories, 
    ExecutableLayout, ExecutableSection, GroupSelection, PatternRequest, PatternScan,
    PatternSettings,
};

const GENERIC: SignatureGroup = SignatureGroup(0);
use libfuzzer_sys::fuzz_target;

fn exact(text: &[u8]) -> Vec<PatternElement> {
    text.iter()
        .map(|byte| PatternElement::Byte(MaskedByte::exactly(*byte)))
        .collect()
}

fn patterns() -> Vec<(Pattern, Placement)> {
    let word_edge = ContextTest {
        sequences: vec![vec![ByteSet::of(*b" .")]],
        negated: false,
        satisfied_at_object_edge: true,
    };
    let mut gapped = exact(b"MZ");
    gapped.push(PatternElement::Gap {
        minimum: 2,
        maximum: Some(40),
    });
    gapped.extend(exact(b"PE"));
    let mut chained = exact(b"alpha");
    chained.push(PatternElement::Gap {
        minimum: 0,
        maximum: None,
    });
    chained.extend(exact(b"beta"));
    chained.push(PatternElement::Gap {
        minimum: 3,
        maximum: None,
    });
    chained.extend(exact(b"gamma"));
    let mut mixed = exact(b"ab");
    mixed.push(PatternElement::Choice(vec![
        vec![MaskedByte::exactly(b'c')],
        vec![MaskedByte::exactly(b'd'), MaskedByte::ANY],
    ]));
    mixed.push(PatternElement::NoneOf {
        width: 1,
        excluded: vec![vec![MaskedByte::exactly(b'x')]],
    });
    mixed.push(PatternElement::OneOf(ByteSet::of(*b"0123456789")));
    mixed.push(PatternElement::Byte(MaskedByte {
        value: 0x40,
        mask: 0xf0,
    }));
    vec![
        (
            Pattern {
                before: None,
                elements: exact(b"EICAR-LIKE"),
                after: None,
            },
            Placement::Anywhere,
        ),
        (
            Pattern {
                before: None,
                elements: gapped,
                after: None,
            },
            Placement::Anywhere,
        ),
        (
            Pattern {
                before: None,
                elements: chained,
                after: None,
            },
            Placement::Anywhere,
        ),
        (
            Pattern {
                before: Some(word_edge.clone()),
                elements: mixed,
                after: Some(word_edge),
            },
            Placement::Anywhere,
        ),
        (
            Pattern {
                before: None,
                elements: exact(b"%PDF"),
                after: None,
            },
            Placement::FromStart {
                distance: 0,
                shift: 8,
            },
        ),
        (
            Pattern {
                before: None,
                elements: exact(b"END"),
                after: None,
            },
            Placement::BeforeEnd {
                distance: 16,
                shift: 13,
            },
        ),
        (
            Pattern {
                before: None,
                elements: exact(b"q"),
                after: None,
            },
            Placement::Anywhere,
        ),
        (
            Pattern {
                before: None,
                elements: exact(b"EP"),
                after: None,
            },
            Placement::InExecutable {
                anchor: ExecutableAnchor::BeforeEntryPoint { distance: 3 },
                shift: 9,
            },
        ),
        (
            Pattern {
                before: None,
                elements: exact(b"S1"),
                after: None,
            },
            Placement::InExecutable {
                anchor: ExecutableAnchor::SectionStart {
                    section: 1,
                    distance: 2,
                },
                shift: 4,
            },
        ),
        (
            Pattern {
                before: None,
                elements: exact(b"SE"),
                after: None,
            },
            Placement::InExecutable {
                anchor: ExecutableAnchor::WholeSection {
                    section: 0,
                    start_only_from_length: Some(40),
                },
                shift: 6,
            },
        ),
        (
            Pattern {
                before: None,
                elements: exact(b"VI"),
                after: None,
            },
            Placement::InExecutable {
                anchor: ExecutableAnchor::VersionInformation,
                shift: 0,
            },
        ),
        (
            Pattern {
                before: None,
                elements: exact(b"LAST"),
                after: None,
            },
            Placement::InExecutable {
                anchor: ExecutableAnchor::LastSectionStart { distance: 0 },
                shift: 0,
            },
        ),
        (
            Pattern {
                before: None,
                elements: exact(b"TAIL"),
                after: None,
            },
            Placement::InExecutable {
                anchor: ExecutableAnchor::BeforeEnd { distance: 4 },
                shift: 0,
            },
        ),
    ]
}

fn image() -> Vec<u8> {
    let names: Vec<String> = (0..patterns().len())
        .map(|index| format!("Fuzz.Pattern-{index}"))
        .collect();
    let patterns = patterns();
    let mut builder = ImageBuilder::new();
    for ((pattern, placement), name) in patterns.iter().zip(&names) {
        builder
            .add_pattern_signature(&PatternSignature {
                group: GENERIC,
                category: Category::Malware,
                placement: *placement,
                report_rank: 0,
                pattern,
                outcome: PatternOutcome::Detection {
                    name,
                    indicator: Indicator::Strong,
                },
            })
            .expect("every fixed pattern compiles");
    }
    builder.describe_object_kind(
        ObjectKind::WindowsExecutable,
        KindDescription {
            format_name: "executable".to_owned(),
            groups: vec![GENERIC],
            recognition: RecognitionRank::default(),
            own_bytes: OwnBytes::Matched {
                as_kind: None,
                recognising_types: false,
            },
            matched_again_as: None,
            found_in_full_scan_retypes: Vec::new(),
            executable: true,
        },
    );
    builder.finish().expect("the fixed image builds")
}

fn detections(image: &Image<'_>, object: &[u8], chunk: usize) -> Vec<String> {
    let settings = PatternSettings {
        potentially_unwanted: false,
        unwanted_categories: UnwantedCategories::Every,
        every_match: true,
        largest_object_for_regular_expressions: None,
    };
    let request = PatternRequest {
        selection: GroupSelection::ForKind(ObjectKind::WindowsExecutable),
        settings,
        object_length: object.len() as u64,
        context: ObjectContext::TOP_LEVEL,
        image_fuzzy_hash: None,
    };
    let layout = ExecutableLayout {
        entry_point: u32::from(object.first().copied().unwrap_or(0)),
        sections: vec![
            ExecutableSection {
                start: 4,
                length: 20,
            },
            ExecutableSection {
                start: 30,
                length: 0,
            },
        ],
        version_information: vec![2, 40],
    };
    let mut scan = PatternScan::new(image, request, || Some(layout)).expect("the scan starts");
    for piece in object.chunks(chunk.max(1)) {
        scan.feed(piece).expect("a chunk is accepted");
    }
    scan.finish()
        .and_then(debar_matching::ScanEnd::into_outcomes)
        .expect("the scan finishes")
        .detections
        .into_iter()
        .map(|detection| detection.name)
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&chunk, object)) = data.split_first() else {
        return;
    };
    let bytes = image();
    let image = Image::open(&bytes).expect("the fixed image opens");
    let whole = detections(&image, object, object.len());
    assert_eq!(detections(&image, object, usize::from(chunk)), whole);
});
