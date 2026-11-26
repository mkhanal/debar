#![no_main]

use debar_image::{
    ByteSet, Category, ContextTest, Image, ImageBuilder, Indicator, MaskedByte, Pattern,
    PatternElement, PatternSignature, Placement,
};
use debar_matching::{PatternScan, PatternSettings};
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
    gapped.push(PatternElement::Gap { minimum: 2, maximum: Some(40) });
    gapped.extend(exact(b"PE"));
    let mut chained = exact(b"alpha");
    chained.push(PatternElement::Gap { minimum: 0, maximum: None });
    chained.extend(exact(b"beta"));
    chained.push(PatternElement::Gap { minimum: 3, maximum: None });
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
    mixed.push(PatternElement::Byte(MaskedByte { value: 0x40, mask: 0xf0 }));
    vec![
        (
            Pattern { before: None, elements: exact(b"EICAR-LIKE"), after: None },
            Placement::Anywhere,
        ),
        (
            Pattern { before: None, elements: gapped, after: None },
            Placement::Anywhere,
        ),
        (
            Pattern { before: None, elements: chained, after: None },
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
            Pattern { before: None, elements: exact(b"%PDF"), after: None },
            Placement::FromStart { distance: 0, shift: 8 },
        ),
        (
            Pattern { before: None, elements: exact(b"END"), after: None },
            Placement::BeforeEnd { distance: 16, shift: 13 },
        ),
        (
            Pattern { before: None, elements: exact(b"q"), after: None },
            Placement::Anywhere,
        ),
    ]
}

fn image() -> Vec<u8> {
    let names: Vec<String> = (0..patterns().len()).map(|index| format!("Fuzz.Pattern-{index}")).collect();
    let patterns = patterns();
    let mut builder = ImageBuilder::new();
    for ((pattern, placement), name) in patterns.iter().zip(&names) {
        builder
            .add_pattern_signature(&PatternSignature {
                category: Category::Malware,
                placement: *placement,
                report_rank: 0,
                pattern,
                name,
                indicator: Indicator::Strong,
            })
            .expect("every fixed pattern compiles");
    }
    builder.finish().expect("the fixed image builds")
}

fn detections(image: &Image<'_>, object: &[u8], chunk: usize) -> Vec<String> {
    let settings = PatternSettings { potentially_unwanted: false, every_match: true };
    let mut scan = PatternScan::new(image, settings, object.len() as u64).expect("the scan starts");
    for piece in object.chunks(chunk.max(1)) {
        scan.feed(piece).expect("a chunk is accepted");
    }
    scan.finish()
        .expect("the scan finishes")
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
