use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest as _, Sha256};
use zerocopy::IntoBytes;
use zerocopy::little_endian::{U32, U64};

use crate::hash_partition::{self, PartitionKey, PartitionNotBuilt, PendingEntry};
use crate::layout::{
    BYTE_ORDER_MARK, CHECKSUM_LENGTH, DATABASE_NAME_LENGTH, DatabaseEntry, DirectoryEntry, Header,
    LAYOUT_VERSION, MAGIC, SECTION_ALIGNMENT, SectionKind,
};
use crate::model::{DatabaseRecord, Digest, HashSignature, HashedSize, Indicator, Provenance};
use crate::names::{self, NameId};

#[derive(Debug, PartialEq, Eq)]
pub enum BuildError {
    DatabaseNameTooLong { name: String },
    NameWithTwoIndicators { name: String },
    TooManySignatures,
    HashPartition { key: PartitionKey, reason: String },
    Names,
    TooManySections,
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseNameTooLong { name } => write!(
                formatter,
                "the database name {name:?} is longer than the image's {DATABASE_NAME_LENGTH} bytes"
            ),
            Self::NameWithTwoIndicators { name } => write!(
                formatter,
                "the signature name {name:?} is given two different kinds of indicator"
            ),
            Self::TooManySignatures => write!(
                formatter,
                "more signatures than an image can number with 32 bits"
            ),
            Self::HashPartition { key, reason } => {
                write!(formatter, "cannot build the hash table {key:?}: {reason}")
            }
            Self::Names => write!(formatter, "cannot build the names section"),
            Self::TooManySections => write!(
                formatter,
                "more sections than the image's first page can list"
            ),
        }
    }
}

impl std::error::Error for BuildError {}

struct PendingHash {
    size: HashedSize,
    digest: Digest,
    name: u32,
}

#[derive(Default)]
pub struct ImageBuilder {
    databases: Vec<DatabaseRecord>,
    name_text: String,
    name_spans: Vec<NameSpan>,
    partitions: BTreeMap<PartitionKey, Vec<PendingHash>>,
}

struct NameSpan {
    start: usize,
    end: usize,
    indicator: Indicator,
}

struct Section {
    kind: SectionKind,
    qualifier: u32,
    item_count: u64,
    bytes: Vec<u8>,
}

impl ImageBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_database(&mut self, database: DatabaseRecord) -> Result<(), BuildError> {
        if database.name.len() > DATABASE_NAME_LENGTH {
            return Err(BuildError::DatabaseNameTooLong {
                name: database.name,
            });
        }
        self.databases.push(database);
        Ok(())
    }

    pub fn add_hash_signature(&mut self, signature: &HashSignature<'_>) -> Result<(), BuildError> {
        let name =
            u32::try_from(self.name_spans.len()).map_err(|_| BuildError::TooManySignatures)?;
        let start = self.name_text.len();
        self.name_text.push_str(signature.name);
        self.name_spans.push(NameSpan {
            start,
            end: self.name_text.len(),
            indicator: signature.indicator,
        });
        let key = PartitionKey {
            purpose: signature.purpose,
            category: signature.category,
            algorithm: signature.digest.algorithm(),
        };
        self.partitions.entry(key).or_default().push(PendingHash {
            size: signature.size,
            digest: signature.digest,
            name,
        });
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<u8>, BuildError> {
        let Self {
            databases,
            name_text,
            name_spans,
            partitions,
        } = self;
        let (sorted_names, name_ids) = distinct_sorted_names(&name_text, &name_spans)?;
        let mut size_sections = Vec::new();
        let mut filter_sections = Vec::new();
        let mut entry_sections = Vec::new();
        for (key, pending) in partitions {
            let entries = pending
                .into_iter()
                .map(|hash| {
                    Ok(PendingEntry {
                        size: hash.size,
                        digest: hash.digest.bytes().to_vec(),
                        name: *usize::try_from(hash.name)
                            .ok()
                            .and_then(|index| name_ids.get(index))
                            .ok_or(BuildError::Names)?,
                    })
                })
                .collect::<Result<Vec<_>, BuildError>>()?;
            let built = hash_partition::build(key.algorithm, entries).map_err(|reason| {
                BuildError::HashPartition {
                    key,
                    reason: match reason {
                        PartitionNotBuilt::TooLarge => "too many entries".to_owned(),
                        PartitionNotBuilt::Filter(_) => {
                            "the filter could not be constructed".to_owned()
                        }
                    },
                }
            })?;
            let item_count =
                u64::try_from(built.entry_count).map_err(|_| BuildError::TooManySignatures)?;
            let qualifier = key.qualifier();
            size_sections.push(Section {
                kind: SectionKind::HashSizes,
                qualifier,
                item_count,
                bytes: built.sizes,
            });
            filter_sections.push(Section {
                kind: SectionKind::HashFilter,
                qualifier,
                item_count,
                bytes: built.filter,
            });
            entry_sections.push(Section {
                kind: SectionKind::HashEntries,
                qualifier,
                item_count,
                bytes: built.entries,
            });
        }
        let names_section = Section {
            kind: SectionKind::Names,
            qualifier: 0,
            item_count: u64::try_from(sorted_names.len()).map_err(|_| BuildError::Names)?,
            bytes: names::build(&sorted_names).map_err(|_| BuildError::Names)?,
        };
        let mut sections = vec![databases_section(&databases)?];
        sections.extend(size_sections);
        sections.extend(filter_sections);
        sections.extend(entry_sections);
        sections.push(names_section);
        assemble(&sections)
    }
}

type DistinctNames<'a> = (Vec<(&'a str, Indicator)>, Vec<NameId>);

fn distinct_sorted_names<'a>(
    name_text: &'a str,
    name_spans: &[NameSpan],
) -> Result<DistinctNames<'a>, BuildError> {
    let text = |index: usize| {
        let span = name_spans.get(index)?;
        name_text.get(span.start..span.end)
    };
    let mut order: Vec<usize> = (0..name_spans.len()).collect();
    order.sort_by(|left, right| text(*left).cmp(&text(*right)));
    let mut sorted: Vec<(&str, Indicator)> = Vec::new();
    let mut ids = vec![NameId(0); name_spans.len()];
    for index in order {
        let name = text(index).ok_or(BuildError::Names)?;
        let indicator = name_spans.get(index).ok_or(BuildError::Names)?.indicator;
        match sorted.last() {
            Some((last, last_indicator)) if *last == name => {
                if *last_indicator != indicator {
                    return Err(BuildError::NameWithTwoIndicators {
                        name: name.to_owned(),
                    });
                }
            }
            _ => sorted.push((name, indicator)),
        }
        let id = sorted
            .len()
            .checked_sub(1)
            .and_then(|id| u32::try_from(id).ok())
            .ok_or(BuildError::Names)?;
        *ids.get_mut(index).ok_or(BuildError::Names)? = NameId(id);
    }
    Ok((sorted, ids))
}

fn databases_section(databases: &[DatabaseRecord]) -> Result<Section, BuildError> {
    let mut sorted: Vec<&DatabaseRecord> = databases.iter().collect();
    sorted.sort_by(|left, right| left.name.cmp(&right.name));
    let mut bytes = Vec::new();
    for database in &sorted {
        let mut name = [0u8; DATABASE_NAME_LENGTH];
        for (slot, byte) in name.iter_mut().zip(database.name.bytes()) {
            *slot = byte;
        }
        let entry = DatabaseEntry {
            name,
            version: U32::new(database.version),
            declared_signature_count: U32::new(database.declared_signature_count),
            functionality_level: U32::new(database.functionality_level),
            provenance: U32::new(provenance_code(database.provenance)),
        };
        bytes.extend_from_slice(entry.as_bytes());
    }
    Ok(Section {
        kind: SectionKind::Databases,
        qualifier: 0,
        item_count: u64::try_from(sorted.len()).map_err(|_| BuildError::TooManySections)?,
        bytes,
    })
}

#[must_use]
pub(crate) const fn provenance_code(provenance: Provenance) -> u32 {
    match provenance {
        Provenance::SignedContainerNotYetVerified => 1,
        Provenance::UnsignedFile => 2,
    }
}

fn assemble(sections: &[Section]) -> Result<Vec<u8>, BuildError> {
    let header_length = std::mem::size_of::<Header>();
    let entry_length = std::mem::size_of::<DirectoryEntry>();
    let first_page_needed = sections
        .len()
        .checked_mul(entry_length)
        .and_then(|directory| directory.checked_add(header_length))
        .and_then(|used| used.checked_add(CHECKSUM_LENGTH))
        .ok_or(BuildError::TooManySections)?;
    if first_page_needed > SECTION_ALIGNMENT {
        return Err(BuildError::TooManySections);
    }
    let mut image = vec![0u8; SECTION_ALIGNMENT];
    let mut directory = Vec::with_capacity(sections.len());
    for section in sections {
        let offset = image.len();
        image.extend_from_slice(&section.bytes);
        let padded = image.len().next_multiple_of(SECTION_ALIGNMENT);
        image.resize(padded, 0);
        directory.push(DirectoryEntry {
            kind: U32::new(section.kind.code()),
            qualifier: U32::new(section.qualifier),
            offset: U64::new(u64::try_from(offset).map_err(|_| BuildError::TooManySections)?),
            length: U64::new(
                u64::try_from(section.bytes.len()).map_err(|_| BuildError::TooManySections)?,
            ),
            item_count: U64::new(section.item_count),
            checksum: Sha256::digest(&section.bytes).into(),
        });
    }
    let header = Header {
        magic: MAGIC,
        layout_version: U32::new(LAYOUT_VERSION),
        byte_order: U32::new(BYTE_ORDER_MARK),
        file_length: U64::new(u64::try_from(image.len()).map_err(|_| BuildError::TooManySections)?),
        section_count: U32::new(
            u32::try_from(sections.len()).map_err(|_| BuildError::TooManySections)?,
        ),
        reserved: U32::new(0),
    };
    let mut first_page = header.as_bytes().to_vec();
    first_page.extend_from_slice(directory.as_bytes());
    let checksum: [u8; CHECKSUM_LENGTH] = Sha256::digest(&first_page).into();
    first_page.extend_from_slice(&checksum);
    image
        .get_mut(..first_page.len())
        .ok_or(BuildError::TooManySections)?
        .copy_from_slice(&first_page);
    Ok(image)
}
