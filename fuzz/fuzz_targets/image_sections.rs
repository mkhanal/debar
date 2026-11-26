#![no_main]

use debar_image::{
    Category, Digest, DigestAlgorithm, HashPurpose, HashSignature, HashedSize, Image,
    ImageBuilder, Indicator, MaskedByte, PartitionKey, Pattern, PatternElement, PatternSignature,
    Placement,
};
use debar_matching::{PatternScan, PatternSettings};
use libfuzzer_sys::fuzz_target;

const SIGNATURE_COUNT: u8 = 24;

fn digest(seed: u8) -> [u8; 16] {
    let mut bytes = [seed; 16];
    bytes[0] = seed.wrapping_mul(37);
    bytes
}

fn valid_image() -> Vec<u8> {
    let names: Vec<String> = (0..SIGNATURE_COUNT).map(|index| format!("Fuzz.Name-{index}")).collect();
    let mut builder = ImageBuilder::new();
    for (index, name) in (0..SIGNATURE_COUNT).zip(&names) {
        let size = if index % 5 == 0 {
            HashedSize::Any
        } else {
            HashedSize::Exactly(u32::from(index % 4) + 1)
        };
        let _ = builder.add_hash_signature(&HashSignature {
            purpose: HashPurpose::WholeObjectDetection,
            category: Category::Malware,
            size,
            digest: Digest::Md5(digest(index)),
            name,
            indicator: Indicator::Strong,
        });
    }
    let exact = |text: &[u8]| -> Vec<PatternElement> {
        text.iter().map(|byte| PatternElement::Byte(MaskedByte::exactly(*byte))).collect()
    };
    let mut chained = exact(b"fuzz");
    chained.push(PatternElement::Gap { minimum: 0, maximum: None });
    chained.extend(exact(b"zzuf"));
    chained.push(PatternElement::Gap { minimum: 1, maximum: Some(9) });
    chained.extend(exact(b"ab"));
    let patterns = [
        (Pattern { before: None, elements: chained, after: None }, Placement::Anywhere),
        (
            Pattern { before: None, elements: exact(b"head"), after: None },
            Placement::FromStart { distance: 0, shift: 4 },
        ),
        (
            Pattern { before: None, elements: exact(b"xy"), after: None },
            Placement::BeforeEnd { distance: 2, shift: 0 },
        ),
    ];
    for ((pattern, placement), name) in patterns.iter().zip(["Fuzz.A", "Fuzz.B", "Fuzz.C"]) {
        let _ = builder.add_pattern_signature(&PatternSignature {
            category: Category::Malware,
            placement: *placement,
            report_rank: 0,
            pattern,
            name,
            indicator: Indicator::Strong,
        });
    }
    builder.finish().unwrap_or_default()
}

const OBJECT: &[u8] = b"head of a fuzz object, zzuf, a-ab and more; it ends xy";

fuzz_target!(|data: &[u8]| {
    let mut bytes = valid_image();
    let Ok(sections) = Image::open(&bytes).map(|image| image.sections().to_vec()) else {
        return;
    };
    let section_bytes: Vec<usize> = sections.iter().flat_map(|section| section.range.clone()).collect();
    for pair in data.chunks_exact(3) {
        let at = usize::from(u16::from_le_bytes([pair[0], pair[1]]));
        if let Some(offset) = section_bytes.get(at % section_bytes.len().max(1)) {
            bytes[*offset] ^= pair[2];
        }
    }
    let Ok(image) = Image::open(&bytes) else {
        return;
    };
    let key = PartitionKey {
        purpose: HashPurpose::WholeObjectDetection,
        category: Category::Malware,
        algorithm: DigestAlgorithm::Md5,
    };
    let _ = image.databases();
    let settings = PatternSettings { potentially_unwanted: true, every_match: true };
    if let Ok(mut scan) = PatternScan::new(&image, settings, OBJECT.len() as u64) {
        for chunk in OBJECT.chunks(5) {
            if scan.feed(chunk).is_err() {
                break;
            }
        }
        let _ = scan.finish();
    }
    if let Ok(Some(partition)) = image.hash_partition(key) {
        for index in 0..SIGNATURE_COUNT {
            if let Ok(Some(name)) = partition.lookup_exact_size(u32::from(index % 4) + 1, &digest(index)) {
                let _ = image.signature_name(name);
            }
            if let Ok(Some(name)) = partition.lookup_any_size(&digest(index)) {
                let _ = image.signature_name(name);
            }
        }
    }
});
