#![forbid(unsafe_code)]
#![no_main]

use debar_image::{
    LogicalOutcome,
    Category, ContentSubsignature, Subsignature, CountComparison, CountTest, Expression, Image, ImageBuilder,
    Indicator, KindDescription, LogicalConditions, LogicalSignature, MaskedByte, ObjectKind,
    OwnBytes, Pattern, PatternElement, Placement, RecognitionRank, SignatureGroup,
};
use debar_matching::{
    GroupSelection, ObjectContext, PatternRequest, PatternScan, PatternSettings, ScanEnd,
    UnwantedCategories,
};
use libfuzzer_sys::fuzz_target;

const GENERIC: SignatureGroup = SignatureGroup(0);
const SUBSIGNATURES: [&[u8]; 4] = [b"abc", b"bcab", b"cabca", b"ABC"];
const DEEPEST: u32 = 6;

struct Choices<'d> {
    bytes: &'d [u8],
}

impl Choices<'_> {
    fn next(&mut self) -> u8 {
        match self.bytes.split_first() {
            Some((first, rest)) => {
                self.bytes = rest;
                *first
            }
            None => 0,
        }
    }
}

fn count(choices: &mut Choices<'_>) -> CountTest {
    let threshold = u32::from(choices.next() % 4);
    CountTest {
        comparison: match choices.next() % 3 {
            0 => CountComparison::Exactly(threshold),
            1 => CountComparison::MoreThan(threshold),
            _ => CountComparison::FewerThan(threshold),
        },
        distinct_at_least: u32::from(choices.next() % 3),
    }
}

fn expression(choices: &mut Choices<'_>, depth: u32) -> Expression {
    let choice = if depth >= DEEPEST { 0 } else { choices.next() % 5 };
    let index = u16::from(choices.next() % 4);
    match choice {
        0 => Expression::Subsignature { index, count: None },
        1 => Expression::Subsignature {
            index,
            count: Some(count(choices)),
        },
        2 => Expression::All(
            Box::new(expression(choices, depth + 1)),
            Box::new(expression(choices, depth + 1)),
        ),
        3 => Expression::Any(
            Box::new(expression(choices, depth + 1)),
            Box::new(expression(choices, depth + 1)),
        ),
        _ => Expression::Block {
            inner: Box::new(expression(choices, depth + 1)),
            count: count(choices),
        },
    }
}

fn subsignature(bytes: &[u8], folded: bool) -> ContentSubsignature {
    ContentSubsignature {
        placement: Placement::Anywhere,
        patterns: vec![Pattern {
            before: None,
            elements: bytes
                .iter()
                .map(|byte| {
                    PatternElement::Byte(if folded && byte.is_ascii_alphabetic() {
                        MaskedByte {
                            value: byte & !0x20,
                            mask: !0x20,
                        }
                    } else {
                        MaskedByte::exactly(*byte)
                    })
                })
                .collect(),
            after: None,
        }],
    }
}

fn image(choices: &mut Choices<'_>) -> Option<Vec<u8>> {
    let mut builder = ImageBuilder::new();
    let names: Vec<String> = (0..4).map(|index| format!("Fuzz.Logical-{index}")).collect();
    let subsignatures: Vec<Subsignature> = SUBSIGNATURES
        .iter()
        .map(|bytes| Subsignature::Content(subsignature(bytes, choices.next() % 2 == 0)))
        .collect();
    let conditions = LogicalConditions::default();
    for name in &names {
        let expression = expression(choices, 0);
        builder
            .add_logical_signature(&LogicalSignature {
                outcome: LogicalOutcome::Detection,
                group: GENERIC,
                category: Category::Malware,
                name,
                indicator: Indicator::Strong,
                expression: &expression,
                subsignatures: &subsignatures,
                conditions: &conditions,
            })
            .ok()?;
    }
    builder.describe_object_kind(
        ObjectKind::BinaryData,
        KindDescription {
            format_name: "binary data".to_owned(),
            groups: vec![GENERIC],
            recognition: RecognitionRank::default(),
            own_bytes: OwnBytes::Matched {
                as_kind: None,
                recognising_types: false,
            },
            matched_again_as: None,
            found_in_full_scan_retypes: Vec::new(),
            executable: false,
        },
    );
    builder.finish().ok()
}

fn detections(image: &Image<'_>, object: &[u8], chunk: usize) -> Vec<String> {
    let request = PatternRequest {
        selection: GroupSelection::ForKind(ObjectKind::BinaryData),
        settings: PatternSettings {
            potentially_unwanted: false,
            unwanted_categories: UnwantedCategories::Every,
            every_match: true,
            largest_object_for_regular_expressions: None,
        },
        object_length: object.len() as u64,
        context: ObjectContext::TOP_LEVEL,
        image_fuzzy_hash: None,
    };
    let mut scan = PatternScan::new(image, request, || None).expect("the scan starts");
    let outcomes = loop {
        for piece in object.chunks(chunk.max(1)) {
            scan.feed(piece).expect("a chunk is accepted");
        }
        match scan.finish().expect("the scan finishes") {
            ScanEnd::Complete(outcomes) => break outcomes,
            ScanEnd::SecondPassNeeded(second) => scan = *second,
            ScanEnd::WholeObjectNeeded(waiting) => {
                break waiting
                    .match_whole_object(object)
                    .expect("the whole object is matched")
                    .into_outcomes()
                    .expect("the scan completes");
            }
        }
    };
    outcomes
        .logical
        .detections
        .into_iter()
        .map(|detection| detection.name)
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&shape_length, rest)) = data.split_first() else {
        return;
    };
    let shape_length = usize::from(shape_length % 64).min(rest.len());
    let (shape, object) = rest.split_at(shape_length);
    let mut choices = Choices { bytes: shape };
    let Some(bytes) = image(&mut choices) else {
        return;
    };
    let image = Image::open(&bytes).expect("the built image opens");
    let whole = detections(&image, object, object.len());
    let chunk = usize::from(choices.next()).max(1);
    assert_eq!(detections(&image, object, chunk), whole);
});
