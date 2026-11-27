#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::range_plus_one
)]

use std::collections::BTreeSet;

use debar_image::{
    ByteSet, Category, ContextTest, Image, ImageBuilder, Indicator, KindDescription, MaskedByte,
    ObjectKind, OwnBytes, Pattern, PatternElement, PatternOutcome, PatternSignature, Placement,
    RecognitionRank, SignatureGroup,
};
use debar_matching::{
    GroupSelection, ObjectContext, PatternRequest, PatternScan, PatternSettings, ScanProgress,
    UnwantedCategories,
};

const GENERIC: SignatureGroup = SignatureGroup(0);

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^ (mixed >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }

    fn chance(&mut self, per_hundred: u64) -> bool {
        self.below(100) < per_hundred
    }
}

const ALPHABET: [u8; 4] = [0x41, 0x42, 0x0a, 0x20];

fn random_byte(random: &mut Random) -> u8 {
    ALPHABET[random.below(4) as usize]
}

fn random_masked(random: &mut Random) -> MaskedByte {
    match random.below(10) {
        0 => MaskedByte::ANY,
        1 => MaskedByte {
            value: random_byte(random) & 0xf0,
            mask: 0xf0,
        },
        2 => MaskedByte {
            value: random_byte(random) & 0x0f,
            mask: 0x0f,
        },
        _ => MaskedByte::exactly(random_byte(random)),
    }
}

fn random_set(random: &mut Random) -> ByteSet {
    ByteSet::of(ALPHABET.into_iter().filter(|_| random.chance(50)))
}

fn random_context(random: &mut Random) -> Option<ContextTest> {
    random.chance(20).then(|| ContextTest {
        sequences: (0..1 + random.below(2))
            .map(|_| {
                (0..1 + random.below(2))
                    .map(|_| random_set(random))
                    .collect()
            })
            .collect(),
        negated: random.chance(30),
        satisfied_at_object_edge: random.chance(50),
    })
}

fn random_run(random: &mut Random, length: u64) -> Vec<MaskedByte> {
    (0..length)
        .map(|_| MaskedByte::exactly(random_byte(random)))
        .collect()
}

fn random_pattern(random: &mut Random) -> Pattern {
    let mut elements: Vec<PatternElement> = (0..1 + random.below(4))
        .map(|_| PatternElement::Byte(MaskedByte::exactly(random_byte(random))))
        .collect();
    for _ in 0..random.below(6) {
        let element = match random.below(9) {
            0 => PatternElement::Gap {
                minimum: random.below(3) as u32,
                maximum: None,
            },
            1 => {
                let minimum = random.below(3) as u32;
                PatternElement::Gap {
                    minimum,
                    maximum: Some(minimum + 1 + random.below(4) as u32),
                }
            }
            2 => PatternElement::Choice(
                (0..2 + random.below(2))
                    .map(|_| {
                        let length = 1 + random.below(3);
                        random_run(random, length)
                    })
                    .collect(),
            ),
            3 => {
                let width = 1 + random.below(2);
                PatternElement::NoneOf {
                    width: width as u32,
                    excluded: (0..1 + random.below(2))
                        .map(|_| random_run(random, width))
                        .collect(),
                }
            }
            4 => PatternElement::OneOf(random_set(random)),
            _ => PatternElement::Byte(random_masked(random)),
        };
        elements.push(element);
        for _ in 0..random.below(3) {
            elements.push(PatternElement::Byte(random_masked(random)));
        }
    }
    if matches!(elements.last(), Some(PatternElement::Gap { .. })) {
        elements.push(PatternElement::Byte(MaskedByte::exactly(random_byte(
            random,
        ))));
    }
    Pattern {
        before: random_context(random),
        elements,
        after: random_context(random),
    }
}

fn random_placement(random: &mut Random) -> Placement {
    match random.below(6) {
        0 => Placement::FromStart {
            distance: random.below(40) as u32,
            shift: random.below(10) as u32,
        },
        1 => Placement::BeforeEnd {
            distance: random.below(40) as u32,
            shift: random.below(10) as u32,
        },
        _ => Placement::Anywhere,
    }
}

struct Model {
    names: Vec<String>,
    patterns: Vec<Pattern>,
    placements: Vec<Placement>,
}

impl Model {
    fn random(random: &mut Random, count: usize) -> Self {
        let patterns: Vec<Pattern> = (0..count).map(|_| random_pattern(random)).collect();
        Self {
            names: (0..count)
                .map(|index| format!("Test.Pattern-{index}"))
                .collect(),
            placements: (0..count).map(|_| random_placement(random)).collect(),
            patterns,
        }
    }

    fn image(&self) -> Vec<u8> {
        let mut builder = ImageBuilder::new();
        for ((name, pattern), placement) in
            self.names.iter().zip(&self.patterns).zip(&self.placements)
        {
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
                .unwrap();
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
                found_in_full_scan_retypes: Vec::new(),
                executable: false,
            },
        );
        builder.finish().unwrap()
    }
}

fn context_holds(test: Option<&ContextTest>, object: &[u8], position: usize, before: bool) -> bool {
    let Some(test) = test else { return true };
    let at_edge = if before {
        position == 0
    } else {
        position >= object.len()
    };
    if at_edge {
        return test.satisfied_at_object_edge;
    }
    let seen = test.sequences.iter().any(|sequence| {
        let start = if before {
            position.checked_sub(sequence.len())
        } else {
            Some(position)
        };
        start.is_some_and(|start| {
            object
                .get(start..start + sequence.len())
                .is_some_and(|window| {
                    window
                        .iter()
                        .zip(sequence)
                        .all(|(byte, set)| set.contains(*byte))
                })
        })
    });
    seen != test.negated
}

fn run_matches(run: &[MaskedByte], object: &[u8], position: usize) -> bool {
    object
        .get(position..position + run.len())
        .is_some_and(|window| {
            window
                .iter()
                .zip(run)
                .all(|(byte, masked)| masked.accepts(*byte))
        })
}

fn matches_from(
    pattern: &Pattern,
    elements: &[PatternElement],
    object: &[u8],
    position: usize,
) -> bool {
    let Some((first, rest)) = elements.split_first() else {
        return context_holds(pattern.after.as_ref(), object, position, false);
    };
    let next = |at: usize| matches_from(pattern, rest, object, at);
    match first {
        PatternElement::Byte(masked) => {
            object
                .get(position)
                .is_some_and(|byte| masked.accepts(*byte))
                && next(position + 1)
        }
        PatternElement::OneOf(set) => {
            object.get(position).is_some_and(|byte| set.contains(*byte)) && next(position + 1)
        }
        PatternElement::Gap { minimum, maximum }
        | PatternElement::PartBreak { minimum, maximum } => {
            let minimum = *minimum as usize;
            let longest = maximum.map_or(object.len(), |maximum| maximum as usize);
            (minimum..=longest)
                .map(|length| position + length)
                .take_while(|at| *at <= object.len())
                .any(next)
        }
        PatternElement::Choice(alternatives) => alternatives
            .iter()
            .any(|run| run_matches(run, object, position) && next(position + run.len())),
        PatternElement::NoneOf { width, excluded } => {
            let width = *width as usize;
            position + width <= object.len()
                && !excluded
                    .iter()
                    .any(|run| run.len() == width && run_matches(run, object, position))
                && next(position + width)
        }
    }
}

fn naive_detections(model: &Model, object: &[u8]) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for ((name, pattern), placement) in model
        .names
        .iter()
        .zip(&model.patterns)
        .zip(&model.placements)
    {
        let starts: Vec<usize> = match placement {
            Placement::Anywhere => (0..object.len()).collect(),
            Placement::FromStart { distance, shift } => {
                (*distance as usize..=(*distance + *shift) as usize).collect()
            }
            Placement::BeforeEnd { distance, shift } => {
                match object.len().checked_sub(*distance as usize) {
                    Some(first) => (first..=first + *shift as usize).collect(),
                    None => Vec::new(),
                }
            }
            Placement::InExecutable { .. } => Vec::new(),
        };
        let hit = starts
            .into_iter()
            .filter(|start| *start < object.len())
            .any(|start| {
                context_holds(pattern.before.as_ref(), object, start, true)
                    && matches_from(pattern, &pattern.elements, object, start)
            });
        if hit {
            found.insert(name.clone());
        }
    }
    found
}

fn engine_detections(
    image: &Image<'_>,
    object: &[u8],
    chunks: &[usize],
    every_match: bool,
) -> Vec<String> {
    let settings = PatternSettings {
        potentially_unwanted: false,
        unwanted_categories: UnwantedCategories::Every,
        every_match,
        largest_object_for_regular_expressions: None,
    };
    let request = PatternRequest {
        selection: GroupSelection::ForKind(ObjectKind::BinaryData),
        settings,
        object_length: object.len() as u64,
        context: ObjectContext::TOP_LEVEL,
        image_fuzzy_hash: None,
    };
    let mut scan = PatternScan::new(image, request, || None).unwrap();
    let mut rest = object;
    let mut sizes = chunks.iter().cycle();
    while !rest.is_empty() {
        let size = (*sizes.next().unwrap()).clamp(1, rest.len());
        let (chunk, after) = rest.split_at(size);
        if scan.feed(chunk).unwrap() == ScanProgress::Stopped {
            let mut remaining = after;
            while !remaining.is_empty() {
                let (skipped, later) = remaining.split_at(remaining.len().min(4096));
                scan.feed(skipped).unwrap();
                remaining = later;
            }
            break;
        }
        rest = after;
    }
    scan.finish()
        .unwrap()
        .into_outcomes()
        .unwrap()
        .detections
        .into_iter()
        .map(|detection| detection.name)
        .collect()
}

fn random_object(random: &mut Random) -> Vec<u8> {
    (0..random.below(300))
        .map(|_| random_byte(random))
        .collect()
}

#[test]
fn every_match_reports_what_a_naive_matcher_finds_over_random_patterns_and_objects() {
    let mut random = Random(1);
    for _ in 0..300 {
        let count = 1 + random.below(12) as usize;
        let model = Model::random(&mut random, count);
        let bytes = model.image();
        let image = Image::open(&bytes).unwrap();
        for _ in 0..10 {
            let object = random_object(&mut random);
            let expected = naive_detections(&model, &object);
            let found: BTreeSet<String> =
                engine_detections(&image, &object, &[object.len().max(1)], true)
                    .into_iter()
                    .collect();
            assert_eq!(found, expected, "object {object:02x?}");
        }
    }
}

#[test]
fn a_signature_is_reported_once_however_often_it_matches() {
    let pattern = Pattern {
        before: None,
        elements: b"AB"
            .iter()
            .map(|byte| PatternElement::Byte(MaskedByte::exactly(*byte)))
            .collect(),
        after: None,
    };
    let model = Model {
        names: vec!["Test.Twice".to_owned()],
        patterns: vec![pattern],
        placements: vec![Placement::Anywhere],
    };
    let bytes = model.image();
    let image = Image::open(&bytes).unwrap();

    assert_eq!(
        engine_detections(&image, b"xxABxxABxx", &[3], true),
        ["Test.Twice"]
    );
}

#[test]
fn every_split_of_an_object_into_chunks_gives_the_same_detections_in_the_same_order() {
    let mut random = Random(2);
    for _ in 0..2_000 {
        let count = 1 + random.below(12) as usize;
        let model = Model::random(&mut random, count);
        let bytes = model.image();
        let image = Image::open(&bytes).unwrap();
        let object = random_object(&mut random);
        for every_match in [true, false] {
            let whole = engine_detections(&image, &object, &[object.len().max(1)], every_match);
            for _ in 0..8 {
                let chunks: Vec<usize> = (0..1 + random.below(5))
                    .map(|_| 1 + random.below(40) as usize)
                    .collect();
                assert_eq!(
                    engine_detections(&image, &object, &chunks, every_match),
                    whole,
                    "chunks {chunks:?}, object {object:02x?}"
                );
            }
        }
    }
}

#[test]
fn a_match_far_beyond_the_first_chunks_is_found_whatever_the_chunk_size() {
    let mut pattern_bytes = b"DEBAR-PATTERN".to_vec();
    pattern_bytes.extend([0x00, 0xff]);
    let pattern = Pattern {
        before: None,
        elements: pattern_bytes
            .iter()
            .map(|byte| PatternElement::Byte(MaskedByte::exactly(*byte)))
            .chain([PatternElement::Gap {
                minimum: 1000,
                maximum: Some(3000),
            }])
            .chain(
                b"END"
                    .iter()
                    .map(|byte| PatternElement::Byte(MaskedByte::exactly(*byte))),
            )
            .collect(),
        after: None,
    };
    let model = Model {
        names: vec!["Test.Far".to_owned()],
        patterns: vec![pattern],
        placements: vec![Placement::Anywhere],
    };
    let bytes = model.image();
    let image = Image::open(&bytes).unwrap();
    let mut object = vec![b'.'; 300_000];
    let at = 131_072 - 7;
    object[at..at + pattern_bytes.len()].copy_from_slice(&pattern_bytes);
    object[at + pattern_bytes.len() + 2500..at + pattern_bytes.len() + 2503]
        .copy_from_slice(b"END");

    for chunk in [1, 7, 4096, 65_536, 131_072, 300_000] {
        assert_eq!(
            engine_detections(&image, &object, &[chunk], true),
            ["Test.Far"],
            "chunk {chunk}"
        );
    }
}

#[test]
fn a_later_part_waiting_beyond_the_probed_bytes_keeps_the_bytes_earlier_candidates_need() {
    let exactly = |byte: u8| PatternElement::Byte(MaskedByte::exactly(byte));
    let pattern = Pattern {
        before: None,
        elements: vec![
            exactly(b'A'),
            PatternElement::Gap {
                minimum: 1,
                maximum: None,
            },
            exactly(b'\n'),
            PatternElement::Gap {
                minimum: 0,
                maximum: None,
            },
            exactly(b'A'),
            exactly(b'B'),
        ],
        after: None,
    };
    let model = Model {
        names: vec!["Test.Chained".to_owned()],
        patterns: vec![pattern],
        placements: vec![Placement::Anywhere],
    };
    let bytes = model.image();
    let image = Image::open(&bytes).unwrap();
    let object = b"ABBB BBBB\nBBBB BBAB";

    for every_match in [true, false] {
        assert_eq!(
            engine_detections(&image, object, &[1], every_match),
            ["Test.Chained"],
            "every_match {every_match}"
        );
    }
}

#[test]
fn detections_at_one_position_are_reported_in_signature_table_order_whatever_the_chunks() {
    let exactly = |byte: u8| PatternElement::Byte(MaskedByte::exactly(byte));
    let plain = Pattern {
        before: None,
        elements: vec![exactly(b'A')],
        after: None,
    };
    let chained = Pattern {
        before: None,
        elements: vec![
            exactly(b'\n'),
            exactly(b'\n'),
            PatternElement::Gap {
                minimum: 2,
                maximum: None,
            },
            exactly(b'A'),
            exactly(b' '),
        ],
        after: None,
    };
    let model = Model {
        names: vec!["Test.Plain".to_owned(), "Test.Chained".to_owned()],
        patterns: vec![plain, chained],
        placements: vec![Placement::Anywhere, Placement::Anywhere],
    };
    let bytes = model.image();
    let image = Image::open(&bytes).unwrap();
    let object = b"\n\nBBBBBBBBA BB";

    for chunk in [1, 2, 5, object.len()] {
        assert_eq!(
            engine_detections(&image, object, &[chunk], true),
            ["Test.Plain", "Test.Chained"],
            "chunk {chunk}"
        );
    }
}
