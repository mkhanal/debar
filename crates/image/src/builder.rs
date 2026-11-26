use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest as _, Sha256};
use zerocopy::IntoBytes;
use zerocopy::little_endian::{U32, U64};

use crate::byte_rarity::rarity_of;
use crate::certificate_rules::{self, CertificateRule};
use crate::container_signatures::{self, ContainerSignaturesNotBuilt, PendingContainerSignature};
use crate::engine_features::{self, EngineFeature};
use crate::hash_partition::{self, PartitionKey, PartitionNotBuilt, PendingEntry};
use crate::icon_signatures::{self, IconGroups};
use crate::layout::{
    BYTE_ORDER_MARK, CHECKSUM_LENGTH, DATABASE_NAME_LENGTH, DatabaseEntry, DirectoryEntry, Header,
    LAYOUT_VERSION, MAGIC, SECTION_ALIGNMENT, SectionKind,
};
use crate::logical_expression::{
    ExpressionNotCompiled, count_ceilings, gate_of, holds_with_no_matches, postfix_steps,
};
use crate::logical_group::{
    self, LogicalGroupNotBuilt, LogicalSignatureId, MatchingPass, PendingLogicalSignature,
    PendingSubsignature,
};
use crate::model::SignatureProgramId;
use crate::model::{
    Category, ContainerSignature, DatabaseRecord, Digest, Expression, HashSignature, HashedSize,
    Indicator, LogicalConditions, LogicalOutcome, LogicalSignature, PartMemory, PatternOutcome,
    PatternSignature, Placement, Provenance, ReportWindows, SignatureGroup, Subsignature,
    TypeFinding, UnwantedCategory,
};
use crate::names::{self, NameId};
use crate::object_kind::ObjectKind;
use crate::object_kinds::{self, KindDescription, KindsNotBuilt, TypingRules};
use crate::pattern_group::{
    self, GroupNotBuilt, PatternSignatureId, PendingPatternSignature, RecordedOutcome,
};
use crate::pattern_program::{Anchor, PatternNotCompiled, Segment, segments_of};
use crate::plug_in_subsignatures::{
    self, PendingComparison, PendingExpression, PendingImageHash, PendingPlugIns, PlugInsNotBuilt,
};
use crate::selection_filters::{self, GroupAnchors};
use crate::signature_programs::{self, SignatureProgram};
use crate::type_magic::{self, MagicTable, PendingMagic};
use crate::unwanted_categories;
use crate::url_rules::{self, UrlRule, UrlRulesNotBuilt};

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
    Expression {
        name: String,
        reason: ExpressionNotCompiled,
    },
    LogicalGroup {
        group: SignatureGroup,
        reason: LogicalGroupNotBuilt,
    },
    PlugIns {
        group: SignatureGroup,
        reason: PlugInsNotBuilt,
    },
    ContainerSignatures(ContainerSignaturesNotBuilt),
    CarriedSection(SectionKind),
    UrlRules(UrlRulesNotBuilt),
    ObjectKinds(KindsNotBuilt),
    TypeMagicTooLarge,
    UnwantedCategories,
    SelectionFilters,
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
            Self::Expression { name, reason } => write!(
                formatter,
                "cannot compile the logical expression of {name:?}: {reason:?}"
            ),
            Self::LogicalGroup { group, reason } => write!(
                formatter,
                "cannot build the logical signatures of group {}: {reason:?}",
                group.0
            ),
            Self::PlugIns { group, reason } => write!(
                formatter,
                "cannot build the regular expressions, byte comparisons and image hashes of group {}: {reason:?}",
                group.0
            ),
            Self::CarriedSection(kind) => write!(formatter, "the {kind:?} section is too large"),
            Self::UrlRules(reason) => write!(formatter, "cannot build the URL rules: {reason:?}"),
            Self::ContainerSignatures(reason) => {
                write!(
                    formatter,
                    "cannot build the container signatures: {reason:?}"
                )
            }
            Self::ObjectKinds(reason) => {
                write!(formatter, "cannot build the object kinds: {reason:?}")
            }
            Self::TypeMagicTooLarge => {
                write!(
                    formatter,
                    "the type magic is larger than the image can hold"
                )
            }
            Self::UnwantedCategories => write!(
                formatter,
                "cannot build the categories of potentially unwanted signatures"
            ),
            Self::SelectionFilters => {
                write!(formatter, "cannot build the filters of the selected groups")
            }
            Self::Names => write!(formatter, "cannot build the names section"),
            Self::TooManySections => write!(formatter, "more sections than an image can number"),
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
    unwanted_categories: BTreeMap<String, Option<String>>,
    containers: Vec<PendingContainer>,
    engine_features: Option<Vec<EngineFeature>>,
    certificate_rules: Vec<CertificateRule>,
    icon_groups: Option<IconGroups>,
    url_rules: Vec<UrlRule>,
    programs: Vec<SignatureProgram>,
}

struct PendingContainer {
    name: u32,
    signature: PendingContainerSignature,
}

struct PendingGroup {
    patterns: Vec<PendingPattern>,
    logical: Vec<PendingLogical>,
    plug_ins: PendingPlugIns,
    report_windows: Option<ReportWindows>,
    part_memory: PartMemory,
}

impl Default for PendingGroup {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            logical: Vec::new(),
            plug_ins: PendingPlugIns::default(),
            report_windows: None,
            part_memory: PartMemory::EarliestEnd,
        }
    }
}

enum PendingOutcome {
    Detection(u32),
    TypeFound(TypeFinding),
    Subsignature {
        logical: LogicalSignatureId,
        index: u16,
    },
}

struct PendingPattern {
    outcome: PendingOutcome,
    category: Category,
    placement: Placement,
    report_rank: u8,
    pass: MatchingPass,
    segments: Vec<Segment>,
}

struct PendingLogical {
    name: u32,
    outcome: LogicalOutcome,
    category: Category,
    steps: Vec<crate::logical_expression::ExpressionStep>,
    subsignatures: Vec<PendingSubsignature>,
    conditions: LogicalConditions,
    holds_with_no_matches: bool,
}

const HITS_SCALE_BITS: u32 = 48;
const RECORDED_STARTS_OF_A_COMPARED_SUBSIGNATURE: u32 = 1024;
const SIXTEENTHS_PER_BIT: u32 = 16;

fn expected_hits_of_anchor(anchor: &Anchor) -> u64 {
    let rarity_bits = match anchor {
        Anchor::Long { bytes, .. } => rarity_of(bytes),
        Anchor::Short { bytes, .. } => rarity_of(bytes),
        Anchor::Everywhere => 0,
    } / SIXTEENTHS_PER_BIT;
    1u64.checked_shl(HITS_SCALE_BITS.saturating_sub(rarity_bits.min(HITS_SCALE_BITS)))
        .unwrap_or(u64::MAX)
}

fn expected_hits(placement: Placement, segments: &[Segment]) -> u64 {
    segments
        .iter()
        .enumerate()
        .filter(|(index, _)| *index > 0 || placement == Placement::Anywhere)
        .fold(0u64, |hits, (_, segment)| {
            hits.saturating_add(expected_hits_of_anchor(&segment.anchor))
        })
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
                pass: MatchingPass::Main,
                segments,
            });
        Ok(())
    }

    pub fn add_logical_signature(
        &mut self,
        signature: &LogicalSignature<'_>,
    ) -> Result<(), BuildError> {
        let described = || signature.name.to_owned();
        let subsignature_count = signature.subsignatures.len();
        let steps = postfix_steps(signature.expression, subsignature_count).map_err(|reason| {
            BuildError::Expression {
                name: described(),
                reason,
            }
        })?;
        let segmented = segmented_contents(signature)?;
        let has_plug_ins = segmented.iter().any(Option::is_none);
        let hits = expected_hits_of_subsignatures(signature.subsignatures, &segmented);
        let holds_without_matches = holds_with_no_matches(&steps);
        let gate = if holds_without_matches || has_plug_ins {
            None
        } else {
            gate_of(signature.expression, &|index| {
                hits.get(usize::from(index)).copied().unwrap_or(u64::MAX)
            })
        };
        let ceilings = plug_in_aware_ceilings(signature.expression, signature.subsignatures);
        let name = self.add_name(signature.name, signature.indicator)?;
        let group = self.groups.entry(signature.group).or_default();
        let logical = LogicalSignatureId(
            u32::try_from(group.logical.len()).map_err(|_| BuildError::TooManySignatures)?,
        );
        let mut subsignatures = Vec::with_capacity(subsignature_count);
        for (index, (subsignature, patterns)) in
            signature.subsignatures.iter().zip(segmented).enumerate()
        {
            let index = u16::try_from(index).map_err(|_| BuildError::TooManySignatures)?;
            let ceiling = ceilings.get(usize::from(index)).copied().unwrap_or(1);
            let (Subsignature::Content(content), Some(patterns)) = (subsignature, patterns) else {
                add_plug_in(
                    &mut group.plug_ins,
                    logical,
                    index,
                    subsignature,
                    subsignature_count,
                );
                subsignatures.push(PendingSubsignature {
                    pattern: None,
                    pattern_count: 0,
                    ceiling,
                    pass: MatchingPass::Main,
                });
                continue;
            };
            let in_gate = gate.as_ref().is_none_or(|gate| gate.contains(&index));
            let pass = if in_gate || content.placement != Placement::Anywhere {
                MatchingPass::Main
            } else {
                MatchingPass::Second
            };
            let pattern = PatternSignatureId(
                u32::try_from(group.patterns.len()).map_err(|_| BuildError::TooManySignatures)?,
            );
            let pattern_count =
                u8::try_from(patterns.len()).map_err(|_| BuildError::TooManySignatures)?;
            for segments in patterns {
                group.patterns.push(PendingPattern {
                    outcome: PendingOutcome::Subsignature { logical, index },
                    category: signature.category,
                    placement: content.placement,
                    report_rank: 0,
                    pass,
                    segments,
                });
            }
            subsignatures.push(PendingSubsignature {
                pattern: Some(pattern),
                pattern_count,
                ceiling,
                pass,
            });
        }
        group.logical.push(PendingLogical {
            name,
            outcome: signature.outcome,
            category: signature.category,
            steps,
            subsignatures,
            conditions: signature.conditions.clone(),
            holds_with_no_matches: holds_without_matches,
        });
        Ok(())
    }

    pub fn set_engine_features(&mut self, enabled: &[EngineFeature]) {
        self.engine_features = Some(enabled.to_vec());
    }

    pub fn add_certificate_rule(&mut self, rule: CertificateRule) {
        self.certificate_rules.push(rule);
    }

    pub fn set_icon_groups(&mut self, groups: IconGroups) {
        self.icon_groups = Some(groups);
    }

    pub fn add_url_rule(&mut self, rule: UrlRule) {
        self.url_rules.push(rule);
    }

    pub fn add_signature_program(
        &mut self,
        program: SignatureProgram,
    ) -> Result<SignatureProgramId, BuildError> {
        let id = u32::try_from(self.programs.len()).map_err(|_| BuildError::TooManySignatures)?;
        self.programs.push(program);
        Ok(SignatureProgramId(id))
    }

    pub fn add_container_signature(
        &mut self,
        signature: &ContainerSignature<'_>,
    ) -> Result<(), BuildError> {
        let name = self.add_name(signature.name, signature.indicator)?;
        self.containers.push(PendingContainer {
            name,
            signature: PendingContainerSignature {
                name: NameId(0),
                container: signature.container,
                container_size: signature.container_size,
                entry_name: signature.entry_name.clone(),
                compressed_size: signature.compressed_size,
                real_size: signature.real_size,
                encrypted: signature.encrypted,
                position: signature.position,
            },
        });
        Ok(())
    }

    pub fn set_unwanted_category(&mut self, name: &str, category: UnwantedCategory<'_>) {
        self.unwanted_categories.insert(
            name.to_owned(),
            match category {
                UnwantedCategory::Named(text) => Some(text.to_owned()),
                UnwantedCategory::Unnamed => None,
            },
        );
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

    #[must_use]
    pub fn hash_buckets_shared_with_unwanted(&self) -> Vec<(HashBucket, Vec<HashEntryId>)> {
        let mut buckets = Vec::new();
        for (key, unwanted) in &self.partitions {
            if key.category != Category::PotentiallyUnwanted {
                continue;
            }
            let malware_key = PartitionKey {
                category: Category::Malware,
                ..*key
            };
            let Some(malware) = self.partitions.get(&malware_key) else {
                continue;
            };
            let unwanted_keys: BTreeSet<(HashedSize, Digest)> = unwanted
                .iter()
                .map(|hash| (hash.size, hash.digest))
                .collect();
            let mut shared_sizes: Vec<HashedSize> = malware
                .iter()
                .filter(|hash| unwanted_keys.contains(&(hash.size, hash.digest)))
                .map(|hash| hash.size)
                .collect();
            shared_sizes.sort();
            shared_sizes.dedup();
            for size in shared_sizes {
                let mut entries: Vec<(HashEntryId, Digest)> = malware
                    .iter()
                    .chain(unwanted)
                    .filter(|hash| hash.size == size)
                    .map(|hash| (hash.id, hash.digest))
                    .collect();
                entries.sort_by_key(|(id, _)| *id);
                let unwanted_ids = unwanted
                    .iter()
                    .filter(|hash| hash.size == size)
                    .map(|hash| hash.id)
                    .collect();
                buckets.push((
                    HashBucket {
                        key: *key,
                        size,
                        entries_in_load_order: entries,
                    },
                    unwanted_ids,
                ));
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
            unwanted_categories,
            containers,
            engine_features,
            certificate_rules,
            icon_groups,
            url_rules,
            programs,
        } = self;
        let (sorted_names, name_ids) = distinct_sorted_names(&name_text, &name_spans)?;
        let categories_section = categories_section(&unwanted_categories, &sorted_names)?;
        let hash_sections = hash_sections(partitions, &withdrawn_hashes, &name_ids)?;
        let (pattern_sections, logical_sections, anchors) = pattern_sections(groups, &name_ids)?;
        let selections_section = selections_section(&kinds, typing, &anchors)?;
        let containers_section = containers_section(containers, &name_ids)?;
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
        sections.extend(selections_section);
        sections.extend(pattern_sections);
        sections.extend(logical_sections);
        sections.extend(containers_section);
        sections.extend(carried_sections(
            engine_features,
            &certificate_rules,
            icon_groups.as_ref(),
            &url_rules,
            &programs,
        )?);
        sections.extend(categories_section);
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

type SegmentedContents = Vec<Option<Vec<Vec<Segment>>>>;

fn segmented_contents(signature: &LogicalSignature<'_>) -> Result<SegmentedContents, BuildError> {
    let mut segmented = Vec::with_capacity(signature.subsignatures.len());
    for subsignature in signature.subsignatures {
        let Subsignature::Content(content) = subsignature else {
            segmented.push(None);
            continue;
        };
        let mut patterns = Vec::with_capacity(content.patterns.len());
        for pattern in &content.patterns {
            patterns.push(segments_of(pattern).map_err(|reason| BuildError::Pattern {
                name: signature.name.to_owned(),
                reason,
            })?);
        }
        segmented.push(Some(patterns));
    }
    Ok(segmented)
}

fn expected_hits_of_subsignatures(
    subsignatures: &[Subsignature],
    segmented: &SegmentedContents,
) -> Vec<u64> {
    subsignatures
        .iter()
        .zip(segmented)
        .map(|(subsignature, patterns)| match (subsignature, patterns) {
            (Subsignature::Content(content), Some(patterns)) => {
                patterns.iter().fold(0u64, |hits, segments| {
                    hits.saturating_add(expected_hits(content.placement, segments))
                })
            }
            _ => u64::MAX,
        })
        .collect()
}

fn plug_in_aware_ceilings(expression: &Expression, subsignatures: &[Subsignature]) -> Vec<u32> {
    let mut ceilings = count_ceilings(expression, subsignatures.len());
    for subsignature in subsignatures {
        match subsignature {
            Subsignature::RegularExpression(regular) => {
                if let Some(trigger) = &regular.trigger {
                    for (ceiling, wanted) in ceilings
                        .iter_mut()
                        .zip(count_ceilings(trigger, subsignatures.len()))
                    {
                        *ceiling = (*ceiling).max(wanted);
                    }
                }
            }
            Subsignature::ByteComparison(comparison) => {
                if let Some(ceiling) = ceilings.get_mut(usize::from(comparison.subsignature)) {
                    *ceiling = (*ceiling).max(RECORDED_STARTS_OF_A_COMPARED_SUBSIGNATURE);
                }
            }
            Subsignature::Content(_) | Subsignature::ImageFuzzyHash(_) => {}
        }
    }
    ceilings
}

fn add_plug_in(
    plug_ins: &mut PendingPlugIns,
    signature: LogicalSignatureId,
    subsignature: u16,
    model: &Subsignature,
    subsignature_count: usize,
) {
    match model {
        Subsignature::RegularExpression(expression) => {
            plug_ins.expressions.push(PendingExpression {
                signature,
                subsignature,
                expression: expression.clone(),
                subsignature_count,
            });
        }
        Subsignature::ByteComparison(comparison) => plug_ins.comparisons.push(PendingComparison {
            signature,
            subsignature,
            comparison: comparison.clone(),
        }),
        Subsignature::ImageFuzzyHash(hash) => plug_ins.image_hashes.push(PendingImageHash {
            signature,
            subsignature,
            hash: *hash,
        }),
        Subsignature::Content(_) => {}
    }
}

fn carried_section(
    kind: SectionKind,
    item_count: usize,
    bytes: Vec<u8>,
) -> Result<Section, BuildError> {
    Ok(Section {
        kind,
        qualifier: 0,
        item_count: u64::try_from(item_count).map_err(|_| BuildError::CarriedSection(kind))?,
        bytes,
    })
}

fn carried_sections(
    engine_features: Option<Vec<EngineFeature>>,
    certificate_rules: &[CertificateRule],
    icon_groups: Option<&IconGroups>,
    url_rules: &[UrlRule],
    programs: &[SignatureProgram],
) -> Result<Vec<Section>, BuildError> {
    let mut sections = Vec::new();
    if let Some(enabled) = engine_features {
        sections.push(carried_section(
            SectionKind::EngineFeatures,
            enabled.len(),
            engine_features::build(&enabled),
        )?);
    }
    if !certificate_rules.is_empty() {
        let kind = SectionKind::CertificateRules;
        sections.push(carried_section(
            kind,
            certificate_rules.len(),
            certificate_rules::build(certificate_rules)
                .map_err(|_| BuildError::CarriedSection(kind))?,
        )?);
    }
    if let Some(groups) = icon_groups {
        let kind = SectionKind::IconSignatures;
        sections.push(carried_section(
            kind,
            groups.signatures.len(),
            icon_signatures::build(groups).map_err(|_| BuildError::CarriedSection(kind))?,
        )?);
    }
    if !url_rules.is_empty() {
        sections.push(carried_section(
            SectionKind::UrlRules,
            url_rules.len(),
            url_rules::build(url_rules).map_err(BuildError::UrlRules)?,
        )?);
    }
    if !programs.is_empty() {
        let kind = SectionKind::SignaturePrograms;
        sections.push(carried_section(
            kind,
            programs.len(),
            signature_programs::build(programs).map_err(|_| BuildError::CarriedSection(kind))?,
        )?);
    }
    Ok(sections)
}

fn containers_section(
    containers: Vec<PendingContainer>,
    name_ids: &[NameId],
) -> Result<Option<Section>, BuildError> {
    if containers.is_empty() {
        return Ok(None);
    }
    let count = containers.len();
    let mut in_test_order = Vec::with_capacity(count);
    for pending in containers.into_iter().rev() {
        let mut signature = pending.signature;
        signature.name = name_id(name_ids, pending.name)?;
        in_test_order.push(signature);
    }
    Ok(Some(Section {
        kind: SectionKind::ContainerSignatures,
        qualifier: 0,
        item_count: u64::try_from(count).map_err(|_| BuildError::TooManySections)?,
        bytes: container_signatures::build(&in_test_order)
            .map_err(BuildError::ContainerSignatures)?,
    }))
}

fn categories_section(
    categories: &BTreeMap<String, Option<String>>,
    sorted_names: &[(&str, Indicator)],
) -> Result<Option<Section>, BuildError> {
    if categories.is_empty() {
        return Ok(None);
    }
    let mut entries = Vec::with_capacity(categories.len());
    for (name, category) in categories {
        let Ok(position) = sorted_names.binary_search_by(|(sorted, _)| (*sorted).cmp(name)) else {
            continue;
        };
        let id = NameId(u32::try_from(position).map_err(|_| BuildError::UnwantedCategories)?);
        entries.push((id, category.as_deref()));
    }
    entries.sort_by_key(|(id, _)| *id);
    Ok(Some(Section {
        kind: SectionKind::UnwantedCategories,
        qualifier: 0,
        item_count: u64::try_from(entries.len()).map_err(|_| BuildError::UnwantedCategories)?,
        bytes: unwanted_categories::build(&entries).map_err(|_| BuildError::UnwantedCategories)?,
    }))
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
) -> Result<PatternSections, BuildError> {
    let mut sections = Vec::with_capacity(groups.len());
    let mut logical_sections = Vec::new();
    let mut anchors = BTreeMap::new();
    for (group, pending_group) in groups {
        if !pending_group.logical.is_empty() {
            logical_sections.push(logical_section(group, pending_group.logical, name_ids)?);
        }
        if !pending_group.plug_ins.is_empty() {
            logical_sections.push(Section {
                kind: SectionKind::PlugInSubsignatures,
                qualifier: group.0,
                item_count: u64::try_from(
                    pending_group
                        .plug_ins
                        .expressions
                        .len()
                        .saturating_add(pending_group.plug_ins.comparisons.len())
                        .saturating_add(pending_group.plug_ins.image_hashes.len()),
                )
                .map_err(|_| BuildError::TooManySignatures)?,
                bytes: plug_in_subsignatures::build(&pending_group.plug_ins)
                    .map_err(|reason| BuildError::PlugIns { group, reason })?,
            });
        }
        if pending_group.patterns.is_empty() && pending_group.plug_ins.is_empty() {
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
                        PendingOutcome::Subsignature { logical, index } => {
                            RecordedOutcome::Subsignature { logical, index }
                        }
                    },
                    category: pattern.category,
                    placement: pattern.placement,
                    report_rank: pattern.report_rank,
                    pass: pattern.pass,
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
        anchors.insert(group, built.main_anchors);
        sections.push(Section {
            kind: SectionKind::PatternGroup,
            qualifier: group.0,
            item_count: u64::try_from(built.signature_count)
                .map_err(|_| BuildError::TooManySignatures)?,
            bytes: built.bytes,
        });
    }
    Ok((sections, logical_sections, anchors))
}

type PatternSections = (
    Vec<Section>,
    Vec<Section>,
    BTreeMap<SignatureGroup, GroupAnchors>,
);

fn selections_section(
    kinds: &BTreeMap<ObjectKind, KindDescription>,
    typing: Option<TypingRules>,
    anchors: &BTreeMap<SignatureGroup, GroupAnchors>,
) -> Result<Option<Section>, BuildError> {
    let present = |groups: &[SignatureGroup]| -> Vec<SignatureGroup> {
        groups
            .iter()
            .copied()
            .filter(|group| anchors.contains_key(group))
            .collect()
    };
    let recognition = typing.and_then(|typing| typing.recognition_group);
    let mut selections: BTreeSet<Vec<SignatureGroup>> = BTreeSet::new();
    for description in kinds.values() {
        selections.insert(present(&description.groups));
        if let Some(recognition) = recognition {
            let mut with_recognition = description.groups.clone();
            with_recognition.push(recognition);
            selections.insert(present(&with_recognition));
        }
    }
    if let Some(recognition) = recognition {
        selections.insert(present(&[recognition]));
    }
    selections.remove(&Vec::new());
    if selections.is_empty() {
        return Ok(None);
    }
    let selections: Vec<Vec<SignatureGroup>> = selections.into_iter().collect();
    Ok(Some(Section {
        kind: SectionKind::SelectionFilters,
        qualifier: 0,
        item_count: u64::try_from(selections.len()).map_err(|_| BuildError::TooManySections)?,
        bytes: selection_filters::build(&selections, &|group| anchors.get(&group))
            .map_err(|_| BuildError::SelectionFilters)?,
    }))
}

fn logical_section(
    group: SignatureGroup,
    pending: Vec<PendingLogical>,
    name_ids: &[NameId],
) -> Result<Section, BuildError> {
    let signatures = pending
        .into_iter()
        .map(|logical| {
            Ok(PendingLogicalSignature {
                name: name_id(name_ids, logical.name)?,
                outcome: logical.outcome,
                category: logical.category,
                steps: logical.steps,
                subsignatures: logical.subsignatures,
                conditions: logical.conditions,
                holds_with_no_matches: logical.holds_with_no_matches,
            })
        })
        .collect::<Result<Vec<_>, BuildError>>()?;
    let built = logical_group::build(&signatures)
        .map_err(|reason| BuildError::LogicalGroup { group, reason })?;
    Ok(Section {
        kind: SectionKind::LogicalGroup,
        qualifier: group.0,
        item_count: u64::try_from(built.signature_count)
            .map_err(|_| BuildError::TooManySignatures)?,
        bytes: built.bytes,
    })
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
        Provenance::DetachedSignatureVerified => 1,
        Provenance::HeaderSignatureVerified => 2,
        Provenance::IndexSignatureVerified => 3,
        Provenance::UnsignedContainer => 4,
    }
}

fn assemble(sections: &[Section]) -> Result<Vec<u8>, BuildError> {
    let header_length = std::mem::size_of::<Header>();
    let entry_length = std::mem::size_of::<DirectoryEntry>();
    let head_length = sections
        .len()
        .checked_mul(entry_length)
        .and_then(|directory| directory.checked_add(header_length))
        .and_then(|used| used.checked_add(CHECKSUM_LENGTH))
        .ok_or(BuildError::TooManySections)?;
    let mut image = vec![0u8; head_length.next_multiple_of(SECTION_ALIGNMENT)];
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
    let mut head = header.as_bytes().to_vec();
    head.extend_from_slice(directory.as_bytes());
    let checksum: [u8; CHECKSUM_LENGTH] = Sha256::digest(&head).into();
    head.extend_from_slice(&checksum);
    image
        .get_mut(..head.len())
        .ok_or(BuildError::TooManySections)?
        .copy_from_slice(&head);
    Ok(image)
}
