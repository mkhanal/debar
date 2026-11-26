use debar_image::{
    Category, DigestAlgorithm, HashPartition, HashPurpose, Image, ImageError, Indicator,
    PartitionKey,
};

use crate::digests::{DigestNeed, ObjectDigests};
use crate::logical_state::UnwantedCategories;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HashSettings<'s> {
    pub potentially_unwanted: bool,
    pub unwanted_categories: UnwantedCategories<'s>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashDetection {
    pub name: String,
    pub indicator: Indicator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    Trusted,
    NotTrusted,
}

pub fn whole_object_digest_need(
    image: &Image<'_>,
    size: u64,
    settings: HashSettings<'_>,
) -> Result<DigestNeed, ImageError> {
    let detection = partitions(image, HashPurpose::WholeObjectDetection, settings)?;
    if detection.is_empty() {
        return Ok(DigestNeed::default());
    }
    let trust = partitions(image, HashPurpose::WholeObjectTrust, settings)?;
    Ok(need_at(size, detection.iter().chain(&trust)))
}

pub fn executable_section_digest_need(
    image: &Image<'_>,
    size: u64,
    settings: HashSettings<'_>,
) -> Result<DigestNeed, ImageError> {
    let detection = partitions(image, HashPurpose::ExecutableSectionDetection, settings)?;
    Ok(need_at(size, detection.iter()))
}

pub fn whole_object_detections(
    image: &Image<'_>,
    size: u64,
    digests: &ObjectDigests,
    settings: HashSettings<'_>,
) -> Result<Vec<HashDetection>, ImageError> {
    detections(
        image,
        HashPurpose::WholeObjectDetection,
        size,
        digests,
        settings,
    )
}

pub fn executable_section_detections(
    image: &Image<'_>,
    size: u64,
    digests: &ObjectDigests,
    settings: HashSettings<'_>,
) -> Result<Vec<HashDetection>, ImageError> {
    detections(
        image,
        HashPurpose::ExecutableSectionDetection,
        size,
        digests,
        settings,
    )
}

pub fn whole_object_trust(
    image: &Image<'_>,
    size: u64,
    digests: &ObjectDigests,
) -> Result<Trust, ImageError> {
    let found = detections(
        image,
        HashPurpose::WholeObjectTrust,
        size,
        digests,
        HashSettings::default(),
    )?;
    Ok(if found.is_empty() {
        Trust::NotTrusted
    } else {
        Trust::Trusted
    })
}

struct LivePartition<'m> {
    algorithm: DigestAlgorithm,
    category: Category,
    table: HashPartition<'m>,
}

fn partitions<'m>(
    image: &Image<'m>,
    purpose: HashPurpose,
    settings: HashSettings<'_>,
) -> Result<Vec<LivePartition<'m>>, ImageError> {
    let mut live = Vec::new();
    for algorithm in DigestAlgorithm::ALL {
        for category in live_categories(settings) {
            let key = PartitionKey {
                purpose,
                category,
                algorithm,
            };
            if let Some(table) = image.hash_partition(key)? {
                live.push(LivePartition {
                    algorithm,
                    category,
                    table,
                });
            }
        }
    }
    Ok(live)
}

fn live_categories(settings: HashSettings<'_>) -> Vec<Category> {
    if settings.potentially_unwanted {
        vec![Category::PotentiallyUnwanted, Category::Malware]
    } else {
        vec![Category::Malware]
    }
}

fn need_at<'p, 'm: 'p>(
    size: u64,
    partitions: impl Iterator<Item = &'p LivePartition<'m>>,
) -> DigestNeed {
    let exact_size = u32::try_from(size).ok();
    let mut need = DigestNeed::default();
    for partition in partitions {
        let needed = partition.table.has_any_size_entries()
            || exact_size.is_some_and(|size| partition.table.has_size(size));
        if needed {
            match partition.algorithm {
                DigestAlgorithm::Md5 => need.md5 = true,
                DigestAlgorithm::Sha1 => need.sha1 = true,
                DigestAlgorithm::Sha256 => need.sha256 = true,
            }
        }
    }
    need
}

fn digest_for(digests: &ObjectDigests, algorithm: DigestAlgorithm) -> Option<&[u8]> {
    match algorithm {
        DigestAlgorithm::Md5 => digests.md5.as_ref().map(|digest| &digest[..]),
        DigestAlgorithm::Sha1 => digests.sha1.as_ref().map(|digest| &digest[..]),
        DigestAlgorithm::Sha256 => digests.sha256.as_ref().map(|digest| &digest[..]),
    }
}

fn detections(
    image: &Image<'_>,
    purpose: HashPurpose,
    size: u64,
    digests: &ObjectDigests,
    settings: HashSettings<'_>,
) -> Result<Vec<HashDetection>, ImageError> {
    let live = partitions(image, purpose, settings)?;
    let exact_size = u32::try_from(size).ok();
    let mut found = Vec::new();
    for algorithm in DigestAlgorithm::ALL {
        let Some(digest) = digest_for(digests, algorithm) else {
            continue;
        };
        let tables: Vec<&LivePartition<'_>> = live
            .iter()
            .filter(|partition| partition.algorithm == algorithm)
            .collect();
        let malformed = |reason| ImageError::HashPartitionMalformed {
            key: PartitionKey {
                purpose,
                category: Category::Malware,
                algorithm,
            },
            reason,
        };
        let admitted = |partition: &LivePartition<'_>, name| -> Result<bool, ImageError> {
            if partition.category == Category::PotentiallyUnwanted {
                settings.unwanted_categories.admit(image, name)
            } else {
                Ok(true)
            }
        };
        let mut at_exact_size = None;
        let mut at_any_size = None;
        for partition in &tables {
            if at_exact_size.is_none()
                && let Some(size) = exact_size
                && let Some(name) = partition
                    .table
                    .lookup_exact_size(size, digest)
                    .map_err(malformed)?
                && admitted(partition, name)?
            {
                at_exact_size = Some(name);
            }
            if at_any_size.is_none()
                && let Some(name) = partition.table.lookup_any_size(digest).map_err(malformed)?
                && admitted(partition, name)?
            {
                at_any_size = Some(name);
            }
        }
        for name in [at_exact_size, at_any_size].into_iter().flatten() {
            let signature = image.signature_name(name)?;
            found.push(HashDetection {
                name: signature.text,
                indicator: signature.indicator,
            });
        }
    }
    Ok(found)
}
