#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use debar_image::{
    ByteSet, Category, Image, ImageBuilder, KindDescription, MagicTable, MaskedByte, ObjectKind,
    OwnBytes, Pattern, PatternElement, PatternOutcome, PatternSignature, Placement,
    RecognitionRank, SignatureGroup, TypeFinding, TypingRules, WideTextRetry,
};
use debar_matching::TypeFound;
use debar_scan::{kind_after_full_scan, kind_from_first_bytes};

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

fn rank(priority: u32) -> RecognitionRank {
    RecognitionRank {
        priority,
        ..RecognitionRank::default()
    }
}

fn describe(
    builder: &mut ImageBuilder,
    kind: ObjectKind,
    recognition: RecognitionRank,
    retypes: Vec<ObjectKind>,
) {
    builder.describe_object_kind(
        kind,
        KindDescription {
            format_name: format!("{kind:?}"),
            groups: vec![GENERIC],
            recognition,
            own_bytes: OwnBytes::Matched {
                as_kind: None,
                recognising_types: true,
            },
            found_in_full_scan_retypes: retypes,
            executable: false,
        },
    );
}

fn image() -> Vec<u8> {
    let mut builder = ImageBuilder::new();
    for (text, found) in [
        (&b"<html>"[..], ObjectKind::Html),
        (b"From: ", ObjectKind::Mail),
        (b"PK\x03\x04", ObjectKind::ZipSelfExtracting),
        (b"%PDF-", ObjectKind::Pdf),
        (b"/RGB\nID", ObjectKind::Ignored),
    ] {
        builder
            .add_pattern_signature(&PatternSignature {
                group: RECOGNITION,
                category: Category::Malware,
                placement: Placement::Anywhere,
                report_rank: 0,
                pattern: &exact(text),
                outcome: PatternOutcome::TypeFound(TypeFinding {
                    found,
                    required: None,
                }),
            })
            .unwrap();
    }
    builder.add_type_magic(MagicTable::Files, 0, b"MZ", ObjectKind::WindowsExecutable);
    for kind in [
        ObjectKind::Text,
        ObjectKind::BinaryData,
        ObjectKind::TextUtf16BigEndian,
        ObjectKind::TextUtf16LittleEndian,
        ObjectKind::WindowsExecutable,
    ] {
        describe(&mut builder, kind, rank(500), Vec::new());
    }
    describe(&mut builder, ObjectKind::Pdf, rank(536), Vec::new());
    describe(
        &mut builder,
        ObjectKind::Html,
        rank(561),
        vec![ObjectKind::Text],
    );
    describe(
        &mut builder,
        ObjectKind::Mail,
        rank(562),
        vec![ObjectKind::Text],
    );
    describe(
        &mut builder,
        ObjectKind::ZipSelfExtracting,
        RecognitionRank {
            priority: 564,
            always_replaces: true,
            left_for_the_full_scan: true,
            ends_recognition: false,
        },
        Vec::new(),
    );
    describe(
        &mut builder,
        ObjectKind::Ignored,
        RecognitionRank {
            priority: 587,
            always_replaces: true,
            left_for_the_full_scan: false,
            ends_recognition: true,
        },
        Vec::new(),
    );
    builder.set_typing(TypingRules {
        prefix_length: 1024,
        recognition_group: Some(RECOGNITION),
        text_bytes: ByteSet::of(
            (0..=u8::MAX).filter(
                |byte| !matches!(byte, 0x00..=0x06 | 0x0b | 0x0e..=0x1a | 0x1c..=0x1f | 0x7f),
            ),
        ),
        wide_text_retry: Some(WideTextRetry {
            found: ObjectKind::Html,
            becomes: ObjectKind::HtmlUtf16,
        }),
    });
    builder.finish().unwrap()
}

fn kind_of(object: &[u8]) -> ObjectKind {
    let bytes = image();
    kind_from_first_bytes(&Image::open(&bytes).unwrap(), object).unwrap()
}

fn utf16_little_endian(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn magic_types_an_object_before_its_bytes_are_classed() {
    assert_eq!(kind_of(b"MZ <html> text"), ObjectKind::WindowsExecutable);
}

#[test]
fn text_and_binary_are_told_apart_by_the_bytes_text_never_holds() {
    assert_eq!(kind_of(b"hello world\n\x80\xff"), ObjectKind::Text);
    assert_eq!(kind_of(&[0, 0, 0, 0, 1, 2, 3, 0]), ObjectKind::BinaryData);
}

#[test]
fn wide_text_is_judged_from_its_third_byte_and_its_order_mark() {
    assert_eq!(
        kind_of(b"hello\x01world and more text"),
        ObjectKind::TextUtf16BigEndian
    );
    let mut marked = vec![0xff, 0xfe];
    marked.extend(utf16_little_endian("plain words"));
    assert_eq!(kind_of(&marked), ObjectKind::TextUtf16LittleEndian);
}

#[test]
fn a_recognised_type_in_the_first_bytes_replaces_text_unless_it_is_left_for_the_full_scan() {
    assert_eq!(kind_of(b"text <html> more"), ObjectKind::Html);
    assert_eq!(kind_of(b"<html>\nFrom: x\n"), ObjectKind::Mail);
    assert_eq!(kind_of(b"From: x\n<html>\n"), ObjectKind::Mail);
    assert_eq!(
        kind_of(b"<html> then PK\x03\x04 later"),
        ObjectKind::TextUtf16BigEndian
    );
    assert_eq!(kind_of(b"\x00\x01binary %PDF-1.4"), ObjectKind::Pdf);
    assert_eq!(kind_of(b"/RGB\nID\n<html>"), ObjectKind::Ignored);
}

#[test]
fn little_endian_wide_html_is_recognised_after_narrowing() {
    assert_eq!(
        kind_of(&utf16_little_endian("<html><body>hi</body></html>")),
        ObjectKind::HtmlUtf16
    );
}

#[test]
fn a_kind_found_in_the_full_scan_retypes_only_the_kinds_it_names() {
    let bytes = image();
    let image = Image::open(&bytes).unwrap();
    let found = |kind| TypeFound { kind, offset: 2100 };

    assert_eq!(
        kind_after_full_scan(&image, ObjectKind::Text, &[found(ObjectKind::Html)]).unwrap(),
        ObjectKind::Html
    );
    assert_eq!(
        kind_after_full_scan(&image, ObjectKind::BinaryData, &[found(ObjectKind::Html)]).unwrap(),
        ObjectKind::BinaryData
    );
    assert_eq!(
        kind_after_full_scan(
            &image,
            ObjectKind::Text,
            &[found(ObjectKind::Mail), found(ObjectKind::Html)]
        )
        .unwrap(),
        ObjectKind::Mail
    );
}
