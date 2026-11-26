#![no_main]

use debar_image::{
    Category, Digest, DigestAlgorithm, HashPurpose, HashSignature, HashedSize, Image,
    ImageBuilder, Indicator, PartitionKey,
};
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
    builder.finish().unwrap_or_default()
}

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
