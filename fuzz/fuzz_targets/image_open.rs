#![no_main]

use debar_image::{Category, DigestAlgorithm, HashPurpose, Image, NameId, PartitionKey};
use libfuzzer_sys::fuzz_target;

const PURPOSES: [HashPurpose; 3] = [
    HashPurpose::WholeObjectDetection,
    HashPurpose::ExecutableSectionDetection,
    HashPurpose::WholeObjectTrust,
];

fuzz_target!(|data: &[u8]| {
    let Ok(image) = Image::open(data) else {
        return;
    };
    let _ = image.databases();
    let _ = image.verify_sections();
    let _ = image.signature_name(NameId(0));
    for purpose in PURPOSES {
        for category in [Category::Malware, Category::PotentiallyUnwanted] {
            for algorithm in DigestAlgorithm::ALL {
                let key = PartitionKey { purpose, category, algorithm };
                if let Ok(Some(partition)) = image.hash_partition(key) {
                    let digest = vec![0u8; algorithm.digest_length()];
                    let _ = partition.lookup_exact_size(68, &digest);
                    let _ = partition.lookup_any_size(&digest);
                }
            }
        }
    }
});
