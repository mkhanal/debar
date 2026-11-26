use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest as _, Sha256};
use zerocopy::IntoBytes;
use zerocopy::little_endian::{U32, U64};

use crate::hash_partition::{self, PartitionKey, PartitionNotBuilt, PendingEntry};
use crate::layout::{
    BYTE_ORDER_MARK, CHECKSUM_LENGTH, DATABASE_NAME_LENGTH, DatabaseEntry, DirectoryEntry, Header,
    LAYOUT_VERSION, MAGIC, SECTION_ALIGNMENT, SectionKind,
};
use crate::model::{
    Category, DatabaseRecord, Digest, HashSignature, HashedSize, Indicator, PartMemory,
    PatternOutcome, PatternSignature, Placement, Provenance, ReportWindows, SignatureGroup,
    TypeFinding,
};
use crate::names::{self, NameId};
use crate::object_kind::ObjectKind;
use crate::object_kinds::{self, KindDescription, KindsNotBuilt, TypingRules};
use crate::pattern_group::{self, GroupNotBuilt, PendingPatternSignature, RecordedOutcome};
use crate::pattern_program::{PatternNotCompiled, Segment, segments_of};
use crate::type_magic::{self, MagicTable, PendingMagic};

#[derive(Debug, PartialEq, Eq)]
pub enum BuildError {
    DatabaseNameTooLong {
        name: String,
    },
    NameWithTwoIndicators {
        name: String,
    },
    TooManySignatures,
    HashPartition {
        key: PartitionKey,
        reason: String,
    },
    Pattern {
        name: String,
        reason: PatternNotCompiled,
    },
    PatternGroup {
        group: SignatureGroup,
        reason: GroupNotBuilt,
    },
    ObjectKinds(KindsNotBuilt),
    TypeMagicTooLarge,
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
            Self::Pattern { name, reason } => {
                write!(
                    formatter,
                    "cannot compile the pattern of {name:?}: {reason:?}"
                )
            }
            Self::PatternGroup { group, reason } => write!(
                formatter,
                "cannot build the pattern signatures of group {}: {reason:?}",
                group.0
            ),
            Self::ObjectKinds(reason) => {
                write!(formatter, "cannot build the object kinds: {reason:?}")
            }
            Self::TypeMagicTooLarge => {
                write!(
                    formatter,
                    "the type magic is larger than the image can hold"
                )
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
    id: HashEntryId,
    size: HashedSize,
    digest: Digest,
    name: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HashEntryId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashBucket {
    pub key: PartitionKey,
    pub size: HashedSize,
    pub entries_in_load_order: Vec<(HashEntryId, Digest)>,
}

#[derive(Default)]
pub struct ImageBuilder {
    databases: Vec<DatabaseRecord>,
    name_text: String,
    name_spans: Vec<NameSpan>,
    partitions: BTreeMap<PartitionKey, Vec<PendingHash>>,
    hash_count: u32,
    withdrawn_hashes: BTreeSet<HashEntryId>,
    groups: BTreeMap<SignatureGroup, PendingGroup>,
    kinds: BTreeMap<ObjectKind, KindDescription>,
    typing: Option<TypingRules>,
    magic: Vec<PendingMagic>,
}

struct PendingGroup {
    patterns: Vec<PendingPattern>,
    report_windows: Option<ReportWindows>,
    part_memory: PartMemory,
}

impl Default for PendingGroup {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            report_windows: None,
            part_memory: PartMemory::EarliestEnd,
        }
    }
}

enum PendingOutcome {
    Detection(u32),
    TypeFound(TypeFinding),
}

struct PendingPattern {
    outcome: PendingOutcome,
    category: Category,
    placement: Placement,
    report_rank: u8,
    segments: Vec<Segment>,
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

    fn add_name(&mut self, name: &str, indicator: Indicator) -> Result<u32, BuildError> {
        let id = u32::try_from(self.name_spans.len()).map_err(|_| BuildError::TooManySignatures)?;
        let start = self.name_text.len();
        self.name_text.push_str(name);
        self.name_spans.push(NameSpan {
            start,
            end: self.name_text.len(),
            indicator,
        });
        Ok(id)
    }

    pub fn add_pattern_signature(
        &mut self,
        signature: &PatternSignature<'_>,
    ) -> Result<(), BuildError> {
        let segments = segments_of(signature.pattern).map_err(|reason| BuildError::Pattern {
            name: match signature.outcome {
                PatternOutcome::Detection { name, .. } => name.to_owned(),
                PatternOutcome::TypeFound(finding) => format!("{finding:?}"),
            },
            reason,
        })?;
        let outcome = match signature.outcome {
            PatternOutcome::Detection { name, indicator } => {
                PendingOutcome::Detection(self.add_name(name, indicator)?)
            }
            PatternOutcome::TypeFound(finding) => PendingOutcome::TypeFound(finding),
        };
        self.groups
            .entry(signature.group)
            .or_default()
            .patterns
            .push(PendingPattern {
                outcome,
                category: signature.category,
                placement: signature.placement,
                report_rank: signature.report_rank,
                segments,
            });
        Ok(())
    }

    pub fn set_report_windows(&mut self, group: SignatureGroup, windows: ReportWindows) {
        self.groups.entry(group).or_default().report_windows = Some(windows);
    }

    pub fn set_part_memory(&mut self, group: SignatureGroup, memory: PartMemory) {
        self.groups.entry(group).or_default().part_memory = memory;
    }

    pub fn describe_object_kind(&mut self, kind: ObjectKind, description: KindDescription) {
        self.kinds.insert(kind, description);
    }

    pub fn set_typing(&mut self, rules: TypingRules) {
        self.typing = Some(rules);
    }

    pub fn add_type_magic(
        &mut self,
        table: MagicTable,
        offset: u32,
        bytes: &[u8],
        found: ObjectKind,
    ) {
        self.magic.push(PendingMagic {
            table,
            offset,
            bytes: bytes.to_vec(),
            found,
        });
    }

    pub fn add_hash_signature(
        &mut self,
        signature: &HashSignature<'_>,
    ) -> Result<HashEntryId, BuildError> {
        let name = self.add_name(signature.name, signature.indicator)?;
        let key = PartitionKey {
            purpose: signature.purpose,
            category: signature.category,
            algorithm: signature.digest.algorithm(),
        };
        let id = HashEntryId(self.hash_count);
        self.hash_count = self
            .hash_count
            .checked_add(1)
            .ok_or(BuildError::TooManySignatures)?;
        self.partitions.entry(key).or_default().push(PendingHash {
            id,
            size: signature.size,
            digest: signature.digest,
            name,
        });
        Ok(id)
    }

    #[must_use]
    pub fn hash_buckets_with_repeated_keys(&self) -> Vec<HashBucket> {
        let mut buckets = Vec::new();
        for (key, pending) in &self.partitions {
            let mut by_key: Vec<&PendingHash> = pending.iter().collect();
            by_key.sort_by_key(|hash| (hash.size, hash.digest));
            let mut sizes_with_repeats: Vec<HashedSize> = by_key
                .windows(2)
                .filter_map(|pair| match pair {
                    [earlier, later]
                        if earlier.size == later.size && earlier.digest == later.digest =>
                    {
                        Some(earlier.size)
                    }
                    _ => None,
                })
                .collect();
            sizes_with_repeats.dedup();
            for size in sizes_with_repeats {
                buckets.push(HashBucket {
                    key: *key,
                    size,
                    entries_in_load_order: pending
                        .iter()
                        .filter(|hash| hash.size == size)
                        .map(|hash| (hash.id, hash.digest))
                        .collect(),
                });
            }
        }
        buckets
    }

    pub fn withdraw_hash_signatures(&mut self, ids: impl IntoIterator<Item = HashEntryId>) {
        self.withdrawn_hashes.extend(ids);
    }

    pub fn finish(self) -> Result<Vec<u8>, BuildError> {
        let Self {
            databases,
            name_text,
            name_spans,
            partitions,
            hash_count: _,
            withdrawn_hashes,
            groups,
            kinds,
            typing,
            magic,
        } = self;
        let (sorted_names, name_ids) = distinct_sorted_names(&name_text, &name_spans)?;
        let hash_sections = hash_sections(partitions, &withdrawn_hashes, &name_ids)?;
        let pattern_sections = pattern_sections(groups, &name_ids)?;
        let mut sections = vec![databases_section(&databases)?];
        if !kinds.is_empty() || typing.is_some() {
            sections.push(Section {
                kind: SectionKind::ObjectKinds,
                qualifier: 0,
                item_count: u64::try_from(kinds.len()).map_err(|_| BuildError::TooManySections)?,
                bytes: object_kinds::build(&kinds, typing).map_err(BuildError::ObjectKinds)?,
            });
        }
        if !magic.is_empty() {
            sections.push(Section {
                kind: SectionKind::TypeMagic,
                qualifier: 0,
                item_count: u64::try_from(magic.len())
                    .map_err(|_| BuildError::TypeMagicTooLarge)?,
                bytes: type_magic::build(&magic).map_err(|_| BuildError::TypeMagicTooLarge)?,
            });
        }
        sections.extend(pattern_sections);
        sections.extend(hash_sections);
        sections.push(Section {
            kind: SectionKind::Names,
            qualifier: 0,
            item_count: u64::try_from(sorted_names.len()).map_err(|_| BuildError::Names)?,
            bytes: names::build(&sorted_names).map_err(|_| BuildError::Names)?,
        });
        assemble(&sections)
    }
}

fn name_id(name_ids: &[NameId], pending: u32) -> Result<NameId, BuildError> {
    usize::try_from(pending)
        .ok()
        .and_then(|index| name_ids.get(index))
        .copied()
        .ok_or(BuildError::Names)
}

fn hash_sections(
    partitions: BTreeMap<PartitionKey, Vec<PendingHash>>,
    withdrawn: &BTreeSet<HashEntryId>,
    name_ids: &[NameId],
) -> Result<Vec<Section>, BuildError> {
    let mut size_sections = Vec::new();
    let mut filter_sections = Vec::new();
    let mut entry_sections = Vec::new();
    for (key, pending) in partitions {
        let entries = pending
            .into_iter()
            .filter(|hash| !withdrawn.contains(&hash.id))
            .map(|hash| {
                Ok(PendingEntry {
                    size: hash.size,
                    digest: hash.digest.bytes().to_vec(),
                    name: name_id(name_ids, hash.name)?,
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
        let section = |kind, bytes| Section {
            kind,
            qualifier,
            item_count,
            bytes,
        };
        size_sections.push(section(SectionKind::HashSizes, built.sizes));
        filter_sections.push(section(SectionKind::HashFilter, built.filter));
        entry_sections.push(section(SectionKind::HashEntries, built.entries));
    }
    size_sections.extend(filter_sections);
    size_sections.extend(entry_sections);
    Ok(size_sections)
}

fn pattern_sections(
    groups: BTreeMap<SignatureGroup, PendingGroup>,
    name_ids: &[NameId],
) -> Result<Vec<Section>, BuildError> {
    let mut sections = Vec::with_capacity(groups.len());
    for (group, pending_group) in groups {
        if pending_group.patterns.is_empty() {
            continue;
        }
        let pending = pending_group
            .patterns
            .into_iter()
            .map(|pattern| {
                Ok(PendingPatternSignature {
                    outcome: match pattern.outcome {
                        PendingOutcome::Detection(name) => {
                            RecordedOutcome::Detection(name_id(name_ids, name)?)
                        }
                        PendingOutcome::TypeFound(finding) => RecordedOutcome::TypeFound(finding),
                    },
                    category: pattern.category,
                    placement: pattern.placement,
                    report_rank: pattern.report_rank,
                    segments: pattern.segments,
                })
            })
            .collect::<Result<Vec<_>, BuildError>>()?;
        let built = pattern_group::build(
            &pending,
            pending_group.report_windows,
            pending_group.part_memory,
        )
        .map_err(|reason| BuildError::PatternGroup { group, reason })?;
        sections.push(Section {
            kind: SectionKind::PatternGroup,
            qualifier: group.0,
            item_count: u64::try_from(built.signature_count)
                .map_err(|_| BuildError::TooManySignatures)?,
            bytes: built.bytes,
        });
    }
    Ok(sections)
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
