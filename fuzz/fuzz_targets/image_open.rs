#![no_main]

use debar_image::{
    Category, DigestAlgorithm, HashPurpose, Image, MagicTable, NameId, ObjectKind, PartitionKey,
    SignatureGroup,
};
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
    if let Ok(Some(kinds)) = image.object_kinds() {
        for kind in ObjectKind::ALL {
            let _ = kinds.describe(kind);
        }
        let _ = kinds.described().count();
    }
    if let Ok(Some(magic)) = image.type_magic() {
        let _ = magic.first_match(MagicTable::Files, data);
        let _ = magic.first_match(MagicTable::Partitions, data);
    }
    for group in 0..20 {
        if let Ok(Some(group)) = image.pattern_group(SignatureGroup(group)) {
            let _ = group.signature_count();
        }
    }
    for purpose in PURPOSES {
        for category in [Category::Malware, Category::PotentiallyUnwanted] {
            for algorithm in DigestAlgorithm::ALL {
                let key = PartitionKey {
                    purpose,
                    category,
                    algorithm,
                };
                if let Ok(Some(partition)) = image.hash_partition(key) {
                    let digest = vec![0u8; algorithm.digest_length()];
                    let _ = partition.lookup_exact_size(68, &digest);
                    let _ = partition.lookup_any_size(&digest);
                }
            }
        }
    }
});
