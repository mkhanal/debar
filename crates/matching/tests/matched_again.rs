#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use debar_image::{
    ByteSet, Category, ContentSubsignature, Expression, Image, ImageBuilder, Indicator,
    KindDescription, LogicalConditions, LogicalOutcome, LogicalSignature, MaskedByte, ObjectKind,
    OwnBytes, Pattern, PatternElement, PatternOutcome, PatternSignature, Placement,
    RecognitionRank, ReportWindows, SignatureGroup, Subsignature, TypeFinding, TypingRules,
};
use debar_matching::{
    GroupSelection, MatchedGroups, ObjectContext, PatternOutcomes, PatternRequest, PatternScan,
    PatternSettings, ScanEnd, UnwantedCategories,
};

const GENERIC: SignatureGroup = SignatureGroup(0);
const OTHER_DATA: SignatureGroup = SignatureGroup(14);
const RECOGNITION: SignatureGroup = SignatureGroup(15);
const GROUPS: [SignatureGroup; 3] = [GENERIC, OTHER_DATA, RECOGNITION];
const ALPHABET: [u8; 3] = *b"ABC";

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

fn random_pattern(random: &mut Random) -> Pattern {
    let mut elements: Vec<PatternElement> = (0..2 + random.below(3))
        .map(|_| PatternElement::Byte(MaskedByte::exactly(ALPHABET[random.below(3) as usize])))
        .collect();
    if random.chance(30) {
        let minimum = random.below(3) as u32;
        elements.push(PatternElement::Gap {
            minimum,
            maximum: Some(minimum + 1 + random.below(3) as u32),
        });
        elements.push(PatternElement::Byte(MaskedByte::exactly(
            ALPHABET[random.below(3) as usize],
        )));
    }
    Pattern {
        before: None,
        elements,
        after: None,
    }
}

fn random_indicator(random: &mut Random) -> Indicator {
    match random.below(4) {
        0 => Indicator::Weak,
        1 => Indicator::PotentiallyUnwanted,
        _ => Indicator::Strong,
    }
}

fn random_image(random: &mut Random) -> Vec<u8> {
    let mut builder = ImageBuilder::new();
    for number in 0..=random.below(10) {
        let group = GROUPS[random.below(3) as usize];
        let name = format!("Test.Pattern-{number}");
        let outcome = if group == RECOGNITION || random.chance(5) {
            PatternOutcome::TypeFound(TypeFinding {
                found: ObjectKind::Rar,
                required: None,
            })
        } else {
            PatternOutcome::Detection {
                name: &name,
                indicator: random_indicator(random),
            }
        };
        builder
            .add_pattern_signature(&PatternSignature {
                group,
                category: Category::Malware,
                placement: Placement::Anywhere,
                report_rank: random.below(2) as u8,
                pattern: &random_pattern(random),
                outcome,
            })
            .unwrap();
    }
    for number in 0..random.below(4) {
        let group = GROUPS[random.below(2) as usize];
        let name = format!("Test.Logical-{number}");
        let subsignatures: Vec<Subsignature> = (0..2)
            .map(|_| {
                Subsignature::Content(ContentSubsignature {
                    placement: Placement::Anywhere,
                    patterns: vec![random_pattern(random)],
                })
            })
            .collect();
        let first = Box::new(Expression::Subsignature {
            index: 0,
            count: None,
        });
        let second = Box::new(Expression::Subsignature {
            index: 1,
            count: None,
        });
        let expression = if random.chance(50) {
            Expression::All(first, second)
        } else {
            Expression::Any(first, second)
        };
        builder
            .add_logical_signature(&LogicalSignature {
                group,
                category: Category::Malware,
                name: &name,
                indicator: random_indicator(random),
                outcome: LogicalOutcome::Detection,
                expression: &expression,
                subsignatures: &subsignatures,
                conditions: &LogicalConditions::default(),
            })
            .unwrap();
    }
    for group in [GENERIC, OTHER_DATA] {
        if random.chance(50) {
            builder.set_report_windows(
                group,
                ReportWindows {
                    length: 8 + random.below(24) as u32,
                    overlap: random.below(8) as u32,
                },
            );
        }
    }
    builder.set_typing(TypingRules {
        prefix_length: 16,
        recognition_group: Some(RECOGNITION),
        text_bytes: ByteSet::of(0x20..=0x7e),
        wide_text_retry: None,
        most_found_at_offsets: 10,
    });
    builder.describe_object_kind(
        ObjectKind::BinaryData,
        kind("binary data", vec![GENERIC], Some(ObjectKind::Other)),
    );
    builder.describe_object_kind(
        ObjectKind::Other,
        kind("other data", vec![OTHER_DATA, GENERIC], None),
    );
    builder.finish().unwrap()
}

fn kind(
    format_name: &str,
    groups: Vec<SignatureGroup>,
    matched_again_as: Option<ObjectKind>,
) -> KindDescription {
    KindDescription {
        format_name: format_name.to_owned(),
        groups,
        recognition: RecognitionRank::default(),
        own_bytes: OwnBytes::Matched {
            as_kind: None,
            recognising_types: true,
        },
        matched_again_as,
        found_in_full_scan_retypes: Vec::new(),
        found_at_an_offset: None,
        executable: false,
    }
}

fn request(selection: GroupSelection, every_match: bool, object: &[u8]) -> PatternRequest<'static> {
    PatternRequest {
        selection,
        settings: PatternSettings {
            potentially_unwanted: true,
            unwanted_categories: UnwantedCategories::Every,
            every_match,
            largest_object_for_regular_expressions: None,
        },
        object_length: object.len() as u64,
        context: ObjectContext::TOP_LEVEL,
        image_fuzzy_hash: None,
    }
}

fn matched(mut scan: PatternScan<'_, '_, '_>, object: &[u8]) -> PatternOutcomes {
    loop {
        for chunk in object.chunks(5) {
            scan.feed(chunk).unwrap();
        }
        match scan.finish().unwrap() {
            ScanEnd::Complete(outcomes) => return outcomes,
            ScanEnd::SecondPassNeeded(second) => scan = *second,
            ScanEnd::WholeObjectNeeded(waiting) => {
                return waiting
                    .match_whole_object(&object)
                    .unwrap()
                    .into_outcomes()
                    .unwrap();
            }
        }
    }
}

fn random_object(random: &mut Random) -> Vec<u8> {
    (0..random.below(120))
        .map(|_| ALPHABET[random.below(3) as usize])
        .collect()
}

fn as_matched_alone(outcomes: &PatternOutcomes) -> impl PartialEq + std::fmt::Debug + '_ {
    (
        &outcomes.detections,
        &outcomes.types_found,
        &outcomes.logical,
    )
}

#[test]
fn matching_again_with_the_groups_an_earlier_pass_matched_gives_what_matching_them_again_gives() {
    let mut random = Random(30);
    for round in 0..300 {
        let bytes = random_image(&mut random);
        let image = Image::open(&bytes).unwrap();
        for _ in 0..8 {
            let object = random_object(&mut random);
            let every_match = random.chance(50);
            let first_selection = if random.chance(50) {
                GroupSelection::ForKindRecognisingTypes(ObjectKind::BinaryData)
            } else {
                GroupSelection::ForKind(ObjectKind::BinaryData)
            };
            let first_request = request(first_selection, every_match, &object);
            let first = matched(
                PatternScan::new(&image, first_request, || None).unwrap(),
                &object,
            );
            let again = request(
                GroupSelection::ForKind(ObjectKind::Other),
                every_match,
                &object,
            );

            let alone = matched(PatternScan::new(&image, again, || None).unwrap(), &object);
            let reusing = matched(
                PatternScan::reusing(&image, again, || None, &first.matched_groups).unwrap(),
                &object,
            );

            assert_eq!(
                as_matched_alone(&reusing),
                as_matched_alone(&alone),
                "round {round}, object {:?}, every match {every_match}",
                String::from_utf8_lossy(&object)
            );
        }
    }
}

#[test]
fn groups_matched_for_another_object_length_are_matched_again() {
    let mut random = Random(31);
    for _ in 0..100 {
        let bytes = random_image(&mut random);
        let image = Image::open(&bytes).unwrap();
        let object = random_object(&mut random);
        let shorter = &object[..object.len() / 2];
        let first = matched(
            PatternScan::new(
                &image,
                request(
                    GroupSelection::ForKind(ObjectKind::BinaryData),
                    true,
                    shorter,
                ),
                || None,
            )
            .unwrap(),
            shorter,
        );
        let again = request(GroupSelection::ForKind(ObjectKind::Other), true, &object);

        let alone = matched(PatternScan::new(&image, again, || None).unwrap(), &object);
        let reusing = matched(
            PatternScan::reusing(&image, again, || None, &first.matched_groups).unwrap(),
            &object,
        );

        assert_eq!(as_matched_alone(&reusing), as_matched_alone(&alone));
    }
}

#[test]
fn nothing_matched_before_reuses_nothing() {
    let mut random = Random(32);
    let bytes = random_image(&mut random);
    let image = Image::open(&bytes).unwrap();
    let object = random_object(&mut random);
    let again = request(GroupSelection::ForKind(ObjectKind::Other), true, &object);

    let alone = matched(PatternScan::new(&image, again, || None).unwrap(), &object);
    let reusing = matched(
        PatternScan::reusing(&image, again, || None, &MatchedGroups::default()).unwrap(),
        &object,
    );

    assert_eq!(as_matched_alone(&reusing), as_matched_alone(&alone));
}
