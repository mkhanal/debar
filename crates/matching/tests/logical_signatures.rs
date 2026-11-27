#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use std::collections::BTreeSet;

use debar_image::{
    Category, ContentSubsignature, CountComparison, CountTest, Expression, Image, ImageBuilder,
    InclusiveRange, Indicator, KindCondition, KindDescription, LogicalConditions, LogicalOutcome,
    LogicalSignature, MaskedByte, ObjectKind, OwnBytes, PartMemory, Pattern, PatternElement,
    Placement, RecognitionRank, SignatureGroup, Subsignature as ModelSubsignature,
    UnwantedCategory,
};
use debar_matching::{
    GroupSelection, ObjectContext, PatternRequest, PatternScan, PatternSettings, ScanEnd,
    UnwantedCategories, scan_object,
};

const GENERIC: SignatureGroup = SignatureGroup(0);
const ALPHABET: [u8; 3] = *b"ABc";

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
}

#[derive(Clone)]
struct Subsignature {
    bytes: Vec<u8>,
    folded: bool,
}

impl Subsignature {
    fn pattern(&self) -> Pattern {
        Pattern {
            before: None,
            elements: self
                .bytes
                .iter()
                .map(|byte| {
                    if self.folded && byte.is_ascii_alphabetic() {
                        PatternElement::Byte(MaskedByte {
                            value: byte & !0x20,
                            mask: !0x20,
                        })
                    } else {
                        PatternElement::Byte(MaskedByte::exactly(*byte))
                    }
                })
                .collect(),
            after: None,
        }
    }

    fn distinct_starts(&self, object: &[u8]) -> u64 {
        let same = |window: &[u8]| {
            window.iter().zip(&self.bytes).all(|(byte, wanted)| {
                if self.folded {
                    byte.eq_ignore_ascii_case(wanted)
                } else {
                    byte == wanted
                }
            })
        };
        object
            .windows(self.bytes.len())
            .filter(|window| same(window))
            .count() as u64
    }
}

struct Evaluated {
    satisfied: bool,
    matches: u64,
    matched: BTreeSet<u16>,
}

fn evaluate(expression: &Expression, counts: &[u64]) -> Evaluated {
    let unsatisfied = || Evaluated {
        satisfied: false,
        matches: 0,
        matched: BTreeSet::new(),
    };
    match expression {
        Expression::Subsignature { index, count } => {
            let matches = counts[usize::from(*index)];
            let satisfied = count.map_or(matches > 0, |test| test.comparison.holds_for(matches));
            if satisfied {
                Evaluated {
                    satisfied,
                    matches,
                    matched: BTreeSet::from([*index]),
                }
            } else {
                unsatisfied()
            }
        }
        Expression::All(left, right) | Expression::Any(left, right) => {
            let left = evaluate(left, counts);
            let right = evaluate(right, counts);
            let satisfied = if matches!(expression, Expression::All(..)) {
                left.satisfied && right.satisfied
            } else {
                left.satisfied || right.satisfied
            };
            if !satisfied {
                return unsatisfied();
            }
            let mut sum = 0;
            let mut indices = BTreeSet::new();
            for side in [left, right] {
                if side.satisfied {
                    sum += side.matches;
                    indices.extend(side.matched);
                }
            }
            Evaluated {
                satisfied,
                matches: sum,
                matched: indices,
            }
        }
        Expression::Block { inner, count } => {
            let inner = evaluate(inner, counts);
            let (matches, distinct) = if inner.satisfied {
                (inner.matches, inner.matched.len() as u32)
            } else {
                (0, 0)
            };
            if count.comparison.holds_for(matches) && distinct >= count.distinct_at_least {
                Evaluated {
                    satisfied: true,
                    matches,
                    matched: BTreeSet::new(),
                }
            } else {
                unsatisfied()
            }
        }
    }
}

fn random_comparison(random: &mut Random) -> CountComparison {
    let threshold = random.below(4) as u32;
    match random.below(3) {
        0 => CountComparison::Exactly(threshold),
        1 => CountComparison::MoreThan(threshold),
        _ => CountComparison::FewerThan(threshold + 1),
    }
}

fn random_expression(random: &mut Random, subsignatures: u16, depth: u32) -> Expression {
    let index = random.below(u64::from(subsignatures)) as u16;
    let choice = if depth == 0 { 0 } else { random.below(6) };
    match choice {
        0 | 1 => Expression::Subsignature {
            index,
            count: (random.below(4) == 0).then(|| CountTest {
                comparison: random_comparison(random),
                distinct_at_least: 0,
            }),
        },
        2 => Expression::All(
            Box::new(random_expression(random, subsignatures, depth - 1)),
            Box::new(random_expression(random, subsignatures, depth - 1)),
        ),
        3 => Expression::Any(
            Box::new(random_expression(random, subsignatures, depth - 1)),
            Box::new(random_expression(random, subsignatures, depth - 1)),
        ),
        _ => Expression::Block {
            inner: Box::new(random_expression(random, subsignatures, depth - 1)),
            count: CountTest {
                comparison: random_comparison(random),
                distinct_at_least: random.below(3) as u32,
            },
        },
    }
}

struct Signature {
    name: String,
    subsignatures: Vec<Subsignature>,
    expression: Expression,
    conditions: LogicalConditions,
}

fn all_indices_used(expression: &Expression, count: u16) -> Expression {
    let mut used = BTreeSet::new();
    collect(expression, &mut used);
    let mut whole = expression.clone();
    for index in 0..count {
        if !used.contains(&index) {
            whole = Expression::Any(
                Box::new(whole),
                Box::new(Expression::Subsignature { index, count: None }),
            );
        }
    }
    whole
}

fn collect(expression: &Expression, used: &mut BTreeSet<u16>) {
    match expression {
        Expression::Subsignature { index, .. } => {
            used.insert(*index);
        }
        Expression::All(left, right) | Expression::Any(left, right) => {
            collect(left, used);
            collect(right, used);
        }
        Expression::Block { inner, .. } => collect(inner, used),
    }
}

fn random_signature(random: &mut Random, number: usize) -> Signature {
    let count = 1 + random.below(4) as u16;
    let subsignatures = (0..count)
        .map(|_| {
            let length = 3 + random.below(3) as usize;
            Subsignature {
                bytes: (0..length)
                    .map(|_| ALPHABET[random.below(3) as usize])
                    .collect(),
                folded: random.below(4) == 0,
            }
        })
        .collect();
    let expression = all_indices_used(&random_expression(random, count, 3), count);
    Signature {
        name: format!("Test.Logical-{number}"),
        subsignatures,
        expression,
        conditions: LogicalConditions::default(),
    }
}

fn binary_data() -> KindDescription {
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
    }
}

fn image_of(signatures: &[Signature], category: Category) -> Vec<u8> {
    let mut builder = ImageBuilder::new();
    for signature in signatures {
        let subsignatures: Vec<ModelSubsignature> = signature
            .subsignatures
            .iter()
            .map(|subsignature| {
                ModelSubsignature::Content(ContentSubsignature {
                    placement: Placement::Anywhere,
                    patterns: vec![subsignature.pattern()],
                })
            })
            .collect();
        if category == Category::PotentiallyUnwanted {
            builder.set_unwanted_category(&signature.name, UnwantedCategory::Named(".Win.Packer."));
        }
        builder
            .add_logical_signature(&LogicalSignature {
                outcome: LogicalOutcome::Detection,
                group: GENERIC,
                category,
                name: &signature.name,
                indicator: Indicator::Strong,
                expression: &signature.expression,
                subsignatures: &subsignatures,
                conditions: &signature.conditions,
            })
            .unwrap();
    }
    builder.describe_object_kind(ObjectKind::BinaryData, binary_data());
    builder.finish().unwrap()
}

fn settings(potentially_unwanted: bool, categories: UnwantedCategories<'_>) -> PatternSettings<'_> {
    PatternSettings {
        potentially_unwanted,
        unwanted_categories: categories,
        every_match: true,
        largest_object_for_regular_expressions: None,
    }
}

fn detected_with(
    image: &Image<'_>,
    object: &[u8],
    settings: PatternSettings<'_>,
    context: ObjectContext<'_>,
) -> Vec<String> {
    let request = PatternRequest {
        selection: GroupSelection::ForKind(ObjectKind::BinaryData),
        settings,
        object_length: object.len() as u64,
        context,
        image_fuzzy_hash: None,
    };
    scan_object(image, request, || None, object)
        .unwrap()
        .logical
        .detections
        .into_iter()
        .map(|detection| detection.name)
        .collect()
}

fn detected(image: &Image<'_>, object: &[u8]) -> Vec<String> {
    detected_with(
        image,
        object,
        settings(false, UnwantedCategories::Every),
        ObjectContext::TOP_LEVEL,
    )
}

fn random_object(random: &mut Random) -> Vec<u8> {
    let length = random.below(300) as usize;
    (0..length)
        .map(|_| {
            let byte = ALPHABET[random.below(3) as usize];
            if random.below(5) == 0 {
                byte.to_ascii_lowercase()
            } else {
                byte
            }
        })
        .collect()
}

#[test]
fn a_logical_signature_is_reported_exactly_when_its_expression_holds_over_the_counted_matches() {
    let mut random = Random(41);
    for round in 0..120 {
        let signatures: Vec<Signature> = (0..=(random.below(12) as usize))
            .map(|number| random_signature(&mut random, number))
            .collect();
        let bytes = image_of(&signatures, Category::Malware);
        let image = Image::open(&bytes).unwrap();
        for _ in 0..12 {
            let object = random_object(&mut random);
            let expected: Vec<String> = signatures
                .iter()
                .filter(|signature| {
                    let counts: Vec<u64> = signature
                        .subsignatures
                        .iter()
                        .map(|subsignature| subsignature.distinct_starts(&object))
                        .collect();
                    evaluate(&signature.expression, &counts).satisfied
                })
                .map(|signature| signature.name.clone())
                .collect();
            assert_eq!(
                detected(&image, &object),
                expected,
                "round {round}, object {:?}",
                String::from_utf8_lossy(&object)
            );
        }
    }
}

#[test]
fn every_split_of_an_object_into_chunks_gives_the_same_logical_detections() {
    let mut random = Random(7);
    for _ in 0..30 {
        let signatures: Vec<Signature> = (0..8)
            .map(|number| random_signature(&mut random, number))
            .collect();
        let bytes = image_of(&signatures, Category::Malware);
        let image = Image::open(&bytes).unwrap();
        let object = random_object(&mut random);
        let whole = detected(&image, &object);
        for chunk in [1usize, 2, 3, 7, 64] {
            let request = PatternRequest {
                selection: GroupSelection::ForKind(ObjectKind::BinaryData),
                settings: settings(false, UnwantedCategories::Every),
                object_length: object.len() as u64,
                context: ObjectContext::TOP_LEVEL,
                image_fuzzy_hash: None,
            };
            let mut scan = PatternScan::new(&image, request, || None).unwrap();
            let outcomes = loop {
                for piece in object.chunks(chunk) {
                    scan.feed(piece).unwrap();
                }
                match scan.finish().unwrap() {
                    ScanEnd::Complete(outcomes) => break outcomes,
                    ScanEnd::SecondPassNeeded(second) => scan = *second,
                    ScanEnd::WholeObjectNeeded(waiting) => {
                        break waiting
                            .match_whole_object(&object)
                            .unwrap()
                            .into_outcomes()
                            .unwrap();
                    }
                }
            };
            let names: Vec<String> = outcomes
                .logical
                .detections
                .into_iter()
                .map(|detection| detection.name)
                .collect();
            assert_eq!(names, whole, "chunk {chunk}");
        }
    }
}

fn single(bytes: &[u8], conditions: LogicalConditions) -> Signature {
    Signature {
        name: "Test.Conditioned".to_owned(),
        subsignatures: vec![Subsignature {
            bytes: bytes.to_vec(),
            folded: false,
        }],
        expression: Expression::Subsignature {
            index: 0,
            count: None,
        },
        conditions,
    }
}

#[test]
fn a_file_size_condition_holds_only_inside_its_inclusive_range() {
    let bytes = image_of(
        &[single(
            b"ABCD",
            LogicalConditions {
                file_size: Some(InclusiveRange {
                    lowest: 10,
                    highest: 12,
                }),
                ..LogicalConditions::default()
            },
        )],
        Category::Malware,
    );
    let image = Image::open(&bytes).unwrap();
    for (length, reported) in [(9, false), (10, true), (12, true), (13, false)] {
        let mut object = vec![b'.'; length];
        object[..4].copy_from_slice(b"ABCD");
        assert_eq!(!detected(&image, &object).is_empty(), reported, "{length}");
    }
}

#[test]
fn a_container_condition_compares_the_nearest_enclosing_kind() {
    let bytes = image_of(
        &[single(
            b"ABCD",
            LogicalConditions {
                container: Some(KindCondition::Kind(ObjectKind::Zip)),
                ..LogicalConditions::default()
            },
        )],
        Category::Malware,
    );
    let image = Image::open(&bytes).unwrap();
    let object = b"..ABCD..";
    let inside = |ancestors: &[ObjectKind]| {
        detected_with(
            &image,
            object,
            settings(false, UnwantedCategories::Every),
            ObjectContext {
                ancestors,
                retyped: false,
            },
        )
    };
    assert_eq!(inside(&[]), Vec::<String>::new());
    assert_eq!(inside(&[ObjectKind::Zip]), ["Test.Conditioned"]);
    assert_eq!(
        inside(&[ObjectKind::Pdf, ObjectKind::Zip]),
        Vec::<String>::new()
    );
}

#[test]
fn intermediates_name_the_ancestors_from_the_outermost_to_the_parent() {
    let bytes = image_of(
        &[single(
            b"ABCD",
            LogicalConditions {
                intermediates: vec![KindCondition::Kind(ObjectKind::Zip), KindCondition::AnyKind],
                ..LogicalConditions::default()
            },
        )],
        Category::Malware,
    );
    let image = Image::open(&bytes).unwrap();
    let inside = |ancestors: &[ObjectKind]| {
        !detected_with(
            &image,
            b"..ABCD..",
            settings(false, UnwantedCategories::Every),
            ObjectContext {
                ancestors,
                retyped: false,
            },
        )
        .is_empty()
    };
    assert!(inside(&[ObjectKind::Pdf, ObjectKind::Zip]));
    assert!(!inside(&[ObjectKind::Zip, ObjectKind::Pdf]));
    assert!(!inside(&[ObjectKind::Pdf]));
}

#[test]
fn a_handler_type_asks_for_a_rescan_instead_of_a_detection_unless_already_retyped() {
    let bytes = image_of(
        &[single(
            b"ABCD",
            LogicalConditions {
                handler_type: Some(ObjectKind::Pdf),
                ..LogicalConditions::default()
            },
        )],
        Category::Malware,
    );
    let image = Image::open(&bytes).unwrap();
    let scan = |retyped| {
        let request = PatternRequest {
            selection: GroupSelection::ForKind(ObjectKind::BinaryData),
            settings: settings(false, UnwantedCategories::Every),
            object_length: 8,
            context: ObjectContext {
                ancestors: &[],
                retyped,
            },
            image_fuzzy_hash: None,
        };
        scan_object(&image, request, || None, b"..ABCD..")
            .unwrap()
            .logical
    };
    let first = scan(false);
    assert_eq!(first.detections, []);
    assert_eq!(first.rescans, [ObjectKind::Pdf]);
    let again = scan(true);
    assert_eq!(again.detections.len(), 1);
    assert_eq!(again.rescans, []);
}

#[test]
fn potentially_unwanted_logical_signatures_need_the_setting_and_an_admitted_category() {
    let bytes = image_of(
        &[single(b"ABCD", LogicalConditions::default())],
        Category::PotentiallyUnwanted,
    );
    let image = Image::open(&bytes).unwrap();
    let object = b"..ABCD..";
    let with = |on, categories| {
        detected_with(
            &image,
            object,
            settings(on, categories),
            ObjectContext::TOP_LEVEL,
        )
        .len()
    };
    assert_eq!(with(false, UnwantedCategories::Every), 0);
    assert_eq!(with(true, UnwantedCategories::Every), 1);
    assert_eq!(with(true, UnwantedCategories::Containing(".Packer.")), 1);
    assert_eq!(with(true, UnwantedCategories::Containing(".Tool.")), 0);
    assert_eq!(with(true, UnwantedCategories::NotContaining(".Win.")), 0);
    assert_eq!(with(true, UnwantedCategories::NotContaining(".Tool.")), 1);
}

#[test]
fn a_subsignature_in_parts_counts_every_completed_occurrence() {
    let mut elements: Vec<PatternElement> = b"ABCD"
        .iter()
        .map(|byte| PatternElement::Byte(MaskedByte::exactly(*byte)))
        .collect();
    elements.push(PatternElement::PartBreak {
        minimum: 2,
        maximum: Some(6),
    });
    elements.extend(
        b"xy"
            .iter()
            .map(|byte| PatternElement::Byte(MaskedByte::exactly(*byte))),
    );
    let pattern = Pattern {
        before: None,
        elements,
        after: None,
    };
    let subsignatures = [ModelSubsignature::Content(ContentSubsignature {
        placement: Placement::Anywhere,
        patterns: vec![pattern],
    })];
    let expression = Expression::Subsignature {
        index: 0,
        count: Some(CountTest {
            comparison: CountComparison::MoreThan(2),
            distinct_at_least: 0,
        }),
    };
    let mut builder = ImageBuilder::new();
    builder
        .add_logical_signature(&LogicalSignature {
            outcome: LogicalOutcome::Detection,
            group: GENERIC,
            category: Category::Malware,
            name: "Test.Parts",
            indicator: Indicator::Strong,
            expression: &expression,
            subsignatures: &subsignatures,
            conditions: &LogicalConditions::default(),
        })
        .unwrap();
    builder.set_part_memory(GENERIC, PartMemory::FirstAndLatestEnds { latest: 8 });
    builder.describe_object_kind(ObjectKind::BinaryData, binary_data());
    let bytes = builder.finish().unwrap();
    let image = Image::open(&bytes).unwrap();
    let occurrence = b"ABCD...xy";
    let spaced = |count: usize| {
        let mut object = Vec::new();
        for _ in 0..count {
            object.extend_from_slice(occurrence);
            object.extend_from_slice(&[b'.'; 9000]);
        }
        object
    };
    assert_eq!(detected(&image, &spaced(2)), Vec::<String>::new());
    assert_eq!(detected(&image, &spaced(3)), ["Test.Parts"]);
}
