use zerocopy::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::logical_expression::{ExpressionMalformed, ExpressionStep, expression_holds};
use crate::model::{
    Category, CountComparison, CountTest, InclusiveRange, KindCondition, LogicalConditions,
};
use crate::names::NameId;
use crate::object_kind::ObjectKind;
use crate::pattern_group::PatternSignatureId;

const PART_COUNT: usize = 6;
const MOST_INTERMEDIATES: usize = 16;
const MOST_ICON_GROUPS: usize = 2;
const NONE: u32 = u32::MAX;
const ANY_KIND: u16 = u16::MAX;
const CATEGORY_MALWARE: u8 = 1;
const CATEGORY_POTENTIALLY_UNWANTED: u8 = 2;
const STEP_SUBSIGNATURE: u8 = 1;
const STEP_ALL: u8 = 2;
const STEP_ANY: u8 = 3;
const STEP_BLOCK: u8 = 4;
const COMPARISON_NONE: u8 = 0;
const COMPARISON_EXACTLY: u8 = 1;
const COMPARISON_MORE_THAN: u8 = 2;
const COMPARISON_FEWER_THAN: u8 = 3;
const HAS_CONTAINER: u16 = 1;
const HAS_FILE_SIZE: u16 = 2;
const HAS_ENTRY_POINT: u16 = 4;
const HAS_NUMBER_OF_SECTIONS: u16 = 8;
const HAS_HANDLER_TYPE: u16 = 16;
const IN_SECOND_PASS: u8 = 1;
const HAS_NO_PATTERN: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Signatures,
    Subsignatures,
    Steps,
    Conditions,
    HoldingWithNoMatches,
    Text,
}

const PARTS_IN_ORDER: [Part; PART_COUNT] = [
    Part::Signatures,
    Part::Subsignatures,
    Part::Steps,
    Part::Conditions,
    Part::HoldingWithNoMatches,
    Part::Text,
];

impl Part {
    fn index(self) -> usize {
        PARTS_IN_ORDER
            .iter()
            .position(|part| *part == self)
            .unwrap_or(0)
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct PartExtent {
    offset: U32,
    length: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct LogicalHeader {
    signature_count: U32,
    subsignature_count: U32,
    counted_subsignature_count: U32,
    second_pass_subsignature_count: U32,
    parts: [PartExtent; PART_COUNT],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy, Debug)]
#[repr(C)]
struct LogicalEntry {
    name: U32,
    category: u8,
    reserved: u8,
    step_count: U16,
    first_subsignature: U32,
    subsignature_count: U32,
    first_step: U32,
    conditions: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct SubsignatureEntry {
    pattern: U32,
    ceiling: U32,
    flags: u8,
    pattern_count: u8,
    reserved: [u8; 2],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct StepEntry {
    kind: u8,
    comparison: u8,
    subsignature: U16,
    threshold: U32,
    distinct_at_least: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct ConditionsEntry {
    present: U16,
    container: U16,
    handler_type: U16,
    intermediate_count: U16,
    icon_group_count: U16,
    intermediates: [U16; MOST_INTERMEDIATES],
    file_size: [U32; 2],
    entry_point: [U32; 2],
    number_of_sections: [U32; 2],
    icon_group_starts: [U32; MOST_ICON_GROUPS],
    icon_group_lengths: [U32; MOST_ICON_GROUPS],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LogicalSignatureId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchingPass {
    Main,
    Second,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSubsignature {
    pub pattern: Option<PatternSignatureId>,
    pub pattern_count: u8,
    pub ceiling: u32,
    pub pass: MatchingPass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingLogicalSignature {
    pub name: NameId,
    pub category: Category,
    pub steps: Vec<ExpressionStep>,
    pub subsignatures: Vec<PendingSubsignature>,
    pub conditions: LogicalConditions,
    pub holds_with_no_matches: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalGroupNotBuilt {
    BeyondThirtyTwoBits,
    IntermediatesBeyondSixteen,
    IconGroupsBeyondTwo,
}

pub struct BuiltLogicalGroup {
    pub bytes: Vec<u8>,
    pub signature_count: usize,
}

#[derive(Default)]
struct Parts {
    signatures: Vec<LogicalEntry>,
    subsignatures: Vec<SubsignatureEntry>,
    steps: Vec<StepEntry>,
    conditions: Vec<ConditionsEntry>,
    holding_with_no_matches: Vec<U32>,
    text: Vec<u8>,
    counted: u32,
    second_pass: u32,
}

fn too_large<T>(_: T) -> LogicalGroupNotBuilt {
    LogicalGroupNotBuilt::BeyondThirtyTwoBits
}

pub fn build(
    signatures: &[PendingLogicalSignature],
) -> Result<BuiltLogicalGroup, LogicalGroupNotBuilt> {
    let mut parts = Parts::default();
    for (index, signature) in signatures.iter().enumerate() {
        parts.add(u32::try_from(index).map_err(too_large)?, signature)?;
    }
    let header = LogicalHeader {
        signature_count: U32::new(u32::try_from(parts.signatures.len()).map_err(too_large)?),
        subsignature_count: U32::new(u32::try_from(parts.subsignatures.len()).map_err(too_large)?),
        counted_subsignature_count: U32::new(parts.counted),
        second_pass_subsignature_count: U32::new(parts.second_pass),
        parts: [PartExtent {
            offset: U32::new(0),
            length: U32::new(0),
        }; PART_COUNT],
    };
    let bytes: [Vec<u8>; PART_COUNT] = [
        parts.signatures.as_bytes().to_vec(),
        parts.subsignatures.as_bytes().to_vec(),
        parts.steps.as_bytes().to_vec(),
        parts.conditions.as_bytes().to_vec(),
        parts.holding_with_no_matches.as_bytes().to_vec(),
        parts.text,
    ];
    Ok(BuiltLogicalGroup {
        bytes: assemble(header, bytes)?,
        signature_count: signatures.len(),
    })
}

fn assemble(
    mut header: LogicalHeader,
    parts: [Vec<u8>; PART_COUNT],
) -> Result<Vec<u8>, LogicalGroupNotBuilt> {
    let mut offset = std::mem::size_of::<LogicalHeader>();
    for (extent, part) in header.parts.iter_mut().zip(&parts) {
        extent.offset = U32::new(u32::try_from(offset).map_err(too_large)?);
        extent.length = U32::new(u32::try_from(part.len()).map_err(too_large)?);
        offset = offset
            .checked_add(part.len())
            .ok_or(LogicalGroupNotBuilt::BeyondThirtyTwoBits)?;
    }
    let mut bytes = header.as_bytes().to_vec();
    for part in parts {
        bytes.extend(part);
    }
    Ok(bytes)
}

impl Parts {
    fn add(
        &mut self,
        id: u32,
        signature: &PendingLogicalSignature,
    ) -> Result<(), LogicalGroupNotBuilt> {
        let conditions = if signature.conditions == LogicalConditions::default() {
            NONE
        } else {
            let entry = self.conditions_entry(&signature.conditions)?;
            self.conditions.push(entry);
            u32::try_from(self.conditions.len().saturating_sub(1)).map_err(too_large)?
        };
        self.signatures.push(LogicalEntry {
            name: U32::new(signature.name.0),
            category: match signature.category {
                Category::Malware => CATEGORY_MALWARE,
                Category::PotentiallyUnwanted => CATEGORY_POTENTIALLY_UNWANTED,
            },
            reserved: 0,
            step_count: U16::new(u16::try_from(signature.steps.len()).map_err(too_large)?),
            first_subsignature: U32::new(
                u32::try_from(self.subsignatures.len()).map_err(too_large)?,
            ),
            subsignature_count: U32::new(
                u32::try_from(signature.subsignatures.len()).map_err(too_large)?,
            ),
            first_step: U32::new(u32::try_from(self.steps.len()).map_err(too_large)?),
            conditions: U32::new(conditions),
        });
        for subsignature in &signature.subsignatures {
            let mut flags = 0;
            if subsignature.pass == MatchingPass::Second {
                flags |= IN_SECOND_PASS;
                self.second_pass = self.second_pass.saturating_add(1);
            }
            if subsignature.pattern.is_none() {
                flags |= HAS_NO_PATTERN;
            }
            if subsignature.ceiling > 1 {
                self.counted = self.counted.saturating_add(1);
            }
            self.subsignatures.push(SubsignatureEntry {
                pattern: U32::new(subsignature.pattern.map_or(NONE, |pattern| pattern.0)),
                ceiling: U32::new(subsignature.ceiling),
                flags,
                pattern_count: subsignature.pattern_count,
                reserved: [0; 2],
            });
        }
        self.steps.extend(signature.steps.iter().map(step_entry));
        if signature.holds_with_no_matches {
            self.holding_with_no_matches.push(U32::new(id));
        }
        Ok(())
    }

    fn text(&mut self, text: &str) -> Result<(u32, u32), LogicalGroupNotBuilt> {
        let start = u32::try_from(self.text.len()).map_err(too_large)?;
        self.text.extend_from_slice(text.as_bytes());
        Ok((start, u32::try_from(text.len()).map_err(too_large)?))
    }

    fn conditions_entry(
        &mut self,
        conditions: &LogicalConditions,
    ) -> Result<ConditionsEntry, LogicalGroupNotBuilt> {
        if conditions.intermediates.len() > MOST_INTERMEDIATES {
            return Err(LogicalGroupNotBuilt::IntermediatesBeyondSixteen);
        }
        if conditions.icon_groups.len() > MOST_ICON_GROUPS {
            return Err(LogicalGroupNotBuilt::IconGroupsBeyondTwo);
        }
        let mut present = 0;
        let range = |range: Option<InclusiveRange>, flag: u16, present: &mut u16| {
            range.map_or([U32::new(0), U32::new(0)], |range| {
                *present |= flag;
                [U32::new(range.lowest), U32::new(range.highest)]
            })
        };
        let file_size = range(conditions.file_size, HAS_FILE_SIZE, &mut present);
        let entry_point = range(conditions.entry_point, HAS_ENTRY_POINT, &mut present);
        let number_of_sections = range(
            conditions.number_of_sections,
            HAS_NUMBER_OF_SECTIONS,
            &mut present,
        );
        let container = conditions.container.map_or(0, |kind| {
            present |= HAS_CONTAINER;
            kind_code(kind)
        });
        let handler_type = conditions.handler_type.map_or(0, |kind| {
            present |= HAS_HANDLER_TYPE;
            kind.code()
        });
        let mut intermediates = [U16::new(0); MOST_INTERMEDIATES];
        for (slot, kind) in intermediates.iter_mut().zip(&conditions.intermediates) {
            *slot = U16::new(kind_code(*kind));
        }
        let mut icon_group_starts = [U32::new(0); MOST_ICON_GROUPS];
        let mut icon_group_lengths = [U32::new(0); MOST_ICON_GROUPS];
        for (index, name) in conditions.icon_groups.iter().enumerate() {
            let (start, length) = self.text(name)?;
            if let (Some(start_slot), Some(length_slot)) = (
                icon_group_starts.get_mut(index),
                icon_group_lengths.get_mut(index),
            ) {
                *start_slot = U32::new(start);
                *length_slot = U32::new(length);
            }
        }
        Ok(ConditionsEntry {
            present: U16::new(present),
            container: U16::new(container),
            handler_type: U16::new(handler_type),
            intermediate_count: U16::new(
                u16::try_from(conditions.intermediates.len()).map_err(too_large)?,
            ),
            icon_group_count: U16::new(
                u16::try_from(conditions.icon_groups.len()).map_err(too_large)?,
            ),
            intermediates,
            file_size,
            entry_point,
            number_of_sections,
            icon_group_starts,
            icon_group_lengths,
        })
    }
}

fn kind_code(kind: KindCondition) -> u16 {
    match kind {
        KindCondition::AnyKind => ANY_KIND,
        KindCondition::Kind(kind) => kind.code(),
    }
}

fn kind_of_code(code: u16) -> Option<KindCondition> {
    if code == ANY_KIND {
        return Some(KindCondition::AnyKind);
    }
    ObjectKind::from_code(code).map(KindCondition::Kind)
}

fn step_entry(step: &ExpressionStep) -> StepEntry {
    let (kind, subsignature, count) = match *step {
        ExpressionStep::Subsignature { index, count } => (STEP_SUBSIGNATURE, index, count),
        ExpressionStep::All => (STEP_ALL, 0, None),
        ExpressionStep::Any => (STEP_ANY, 0, None),
        ExpressionStep::Block(count) => (STEP_BLOCK, 0, Some(count)),
    };
    let (comparison, threshold) = match count.map(|test| test.comparison) {
        None => (COMPARISON_NONE, 0),
        Some(CountComparison::Exactly(threshold)) => (COMPARISON_EXACTLY, threshold),
        Some(CountComparison::MoreThan(threshold)) => (COMPARISON_MORE_THAN, threshold),
        Some(CountComparison::FewerThan(threshold)) => (COMPARISON_FEWER_THAN, threshold),
    };
    StepEntry {
        kind,
        comparison,
        subsignature: U16::new(subsignature),
        threshold: U32::new(threshold),
        distinct_at_least: U32::new(count.map_or(0, |test| test.distinct_at_least)),
    }
}

fn step_of(entry: &StepEntry) -> Result<ExpressionStep, ExpressionMalformed> {
    let threshold = entry.threshold.get();
    let comparison = match entry.comparison {
        COMPARISON_NONE => None,
        COMPARISON_EXACTLY => Some(CountComparison::Exactly(threshold)),
        COMPARISON_MORE_THAN => Some(CountComparison::MoreThan(threshold)),
        COMPARISON_FEWER_THAN => Some(CountComparison::FewerThan(threshold)),
        _ => return Err(ExpressionMalformed),
    };
    let count = comparison.map(|comparison| CountTest {
        comparison,
        distinct_at_least: entry.distinct_at_least.get(),
    });
    match entry.kind {
        STEP_SUBSIGNATURE => Ok(ExpressionStep::Subsignature {
            index: entry.subsignature.get(),
            count,
        }),
        STEP_ALL => Ok(ExpressionStep::All),
        STEP_ANY => Ok(ExpressionStep::Any),
        STEP_BLOCK => count.map(ExpressionStep::Block).ok_or(ExpressionMalformed),
        _ => Err(ExpressionMalformed),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalGroupMalformed {
    Layout,
    UnknownSignature(LogicalSignatureId),
    Expression(LogicalSignatureId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubsignatureRecord {
    pub pattern: Option<PatternSignatureId>,
    pub pattern_count: u8,
    pub ceiling: u32,
    pub pass: MatchingPass,
}

#[derive(Debug, Clone, Copy)]
pub struct LogicalSignatureRecord<'m> {
    pub name: NameId,
    pub category: Category,
    pub first_subsignature: u32,
    pub subsignature_count: u32,
    entry: &'m LogicalEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionsRecord<'m> {
    pub container: Option<KindCondition>,
    pub intermediates: Vec<KindCondition>,
    pub file_size: Option<InclusiveRange>,
    pub entry_point: Option<InclusiveRange>,
    pub number_of_sections: Option<InclusiveRange>,
    pub handler_type: Option<ObjectKind>,
    pub icon_groups: Vec<&'m str>,
}

fn layout<E>(_: E) -> LogicalGroupMalformed {
    LogicalGroupMalformed::Layout
}

#[derive(Clone, Copy)]
pub struct LogicalGroup<'m> {
    header: &'m LogicalHeader,
    signatures: &'m [LogicalEntry],
    subsignatures: &'m [SubsignatureEntry],
    steps: &'m [StepEntry],
    conditions: &'m [ConditionsEntry],
    holding_with_no_matches: &'m [U32],
    text: &'m [u8],
}

impl<'m> LogicalGroup<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, LogicalGroupMalformed> {
        let (header, _) =
            LogicalHeader::ref_from_prefix(bytes).map_err(|_| LogicalGroupMalformed::Layout)?;
        let part = |part: Part| -> Result<&'m [u8], LogicalGroupMalformed> {
            let extent = header
                .parts
                .get(part.index())
                .ok_or(LogicalGroupMalformed::Layout)?;
            let start =
                usize::try_from(extent.offset.get()).map_err(|_| LogicalGroupMalformed::Layout)?;
            let length =
                usize::try_from(extent.length.get()).map_err(|_| LogicalGroupMalformed::Layout)?;
            bytes
                .get(
                    start
                        ..start
                            .checked_add(length)
                            .ok_or(LogicalGroupMalformed::Layout)?,
                )
                .ok_or(LogicalGroupMalformed::Layout)
        };
        Ok(Self {
            header,
            signatures: <[LogicalEntry]>::ref_from_bytes(part(Part::Signatures)?)
                .map_err(layout)?,
            subsignatures: <[SubsignatureEntry]>::ref_from_bytes(part(Part::Subsignatures)?)
                .map_err(layout)?,
            steps: <[StepEntry]>::ref_from_bytes(part(Part::Steps)?).map_err(layout)?,
            conditions: <[ConditionsEntry]>::ref_from_bytes(part(Part::Conditions)?)
                .map_err(layout)?,
            holding_with_no_matches: <[U32]>::ref_from_bytes(part(Part::HoldingWithNoMatches)?)
                .map_err(layout)?,
            text: part(Part::Text)?,
        })
    }

    #[must_use]
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    #[must_use]
    pub fn subsignature_count(&self) -> usize {
        self.subsignatures.len()
    }

    #[must_use]
    pub fn counted_subsignature_count(&self) -> u32 {
        self.header.counted_subsignature_count.get()
    }

    #[must_use]
    pub fn second_pass_subsignature_count(&self) -> u32 {
        self.header.second_pass_subsignature_count.get()
    }

    pub fn holding_with_no_matches(&self) -> impl Iterator<Item = LogicalSignatureId> + 'm {
        self.holding_with_no_matches
            .iter()
            .map(|id| LogicalSignatureId(id.get()))
    }

    pub fn signature(
        &self,
        id: LogicalSignatureId,
    ) -> Result<LogicalSignatureRecord<'m>, LogicalGroupMalformed> {
        let malformed = LogicalGroupMalformed::UnknownSignature(id);
        let entry = usize::try_from(id.0)
            .ok()
            .and_then(|index| self.signatures.get(index))
            .ok_or(malformed)?;
        let category = match entry.category {
            CATEGORY_MALWARE => Category::Malware,
            CATEGORY_POTENTIALLY_UNWANTED => Category::PotentiallyUnwanted,
            _ => return Err(malformed),
        };
        Ok(LogicalSignatureRecord {
            name: NameId(entry.name.get()),
            category,
            first_subsignature: entry.first_subsignature.get(),
            subsignature_count: entry.subsignature_count.get(),
            entry,
        })
    }

    pub fn subsignature(
        &self,
        signature: &LogicalSignatureRecord<'m>,
        index: u16,
    ) -> Result<SubsignatureRecord, LogicalGroupMalformed> {
        let entry = signature
            .first_subsignature
            .checked_add(u32::from(index))
            .filter(|_| u32::from(index) < signature.subsignature_count)
            .and_then(|global| usize::try_from(global).ok())
            .and_then(|global| self.subsignatures.get(global))
            .ok_or(LogicalGroupMalformed::Layout)?;
        Ok(SubsignatureRecord {
            pattern: (entry.flags & HAS_NO_PATTERN == 0)
                .then(|| PatternSignatureId(entry.pattern.get())),
            pattern_count: entry.pattern_count,
            ceiling: entry.ceiling.get(),
            pass: if entry.flags & IN_SECOND_PASS == 0 {
                MatchingPass::Main
            } else {
                MatchingPass::Second
            },
        })
    }

    pub fn expression_holds(
        &self,
        id: LogicalSignatureId,
        signature: &LogicalSignatureRecord<'m>,
        matches_of: impl Fn(u16) -> u64,
    ) -> Result<bool, LogicalGroupMalformed> {
        let malformed = LogicalGroupMalformed::Expression(id);
        let first = usize::try_from(signature.entry.first_step.get()).map_err(|_| malformed)?;
        let count = usize::from(signature.entry.step_count.get());
        let steps = self
            .steps
            .get(first..first.checked_add(count).ok_or(malformed)?)
            .ok_or(malformed)?;
        expression_holds(steps.iter().map(step_of), matches_of).map_err(|_| malformed)
    }

    pub fn conditions(
        &self,
        signature: &LogicalSignatureRecord<'m>,
    ) -> Result<Option<ConditionsRecord<'m>>, LogicalGroupMalformed> {
        let index = signature.entry.conditions.get();
        if index == NONE {
            return Ok(None);
        }
        let entry = usize::try_from(index)
            .ok()
            .and_then(|index| self.conditions.get(index))
            .ok_or(LogicalGroupMalformed::Layout)?;
        let present = entry.present.get();
        let range = |flag: u16, bounds: [U32; 2]| {
            (present & flag != 0).then(|| InclusiveRange {
                lowest: bounds[0].get(),
                highest: bounds[1].get(),
            })
        };
        let intermediates = entry
            .intermediates
            .get(..usize::from(entry.intermediate_count.get()))
            .ok_or(LogicalGroupMalformed::Layout)?
            .iter()
            .map(|code| kind_of_code(code.get()).ok_or(LogicalGroupMalformed::Layout))
            .collect::<Result<Vec<_>, _>>()?;
        let icon_groups = entry
            .icon_group_starts
            .iter()
            .zip(&entry.icon_group_lengths)
            .take(usize::from(entry.icon_group_count.get()))
            .map(|(start, length)| {
                self.text_at(start.get(), length.get())
                    .ok_or(LogicalGroupMalformed::Layout)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(ConditionsRecord {
            container: if present & HAS_CONTAINER == 0 {
                None
            } else {
                Some(kind_of_code(entry.container.get()).ok_or(LogicalGroupMalformed::Layout)?)
            },
            intermediates,
            file_size: range(HAS_FILE_SIZE, entry.file_size),
            entry_point: range(HAS_ENTRY_POINT, entry.entry_point),
            number_of_sections: range(HAS_NUMBER_OF_SECTIONS, entry.number_of_sections),
            handler_type: if present & HAS_HANDLER_TYPE == 0 {
                None
            } else {
                Some(
                    ObjectKind::from_code(entry.handler_type.get())
                        .ok_or(LogicalGroupMalformed::Layout)?,
                )
            },
            icon_groups,
        }))
    }

    fn text_at(&self, start: u32, length: u32) -> Option<&'m str> {
        let start = usize::try_from(start).ok()?;
        let end = start.checked_add(usize::try_from(length).ok()?)?;
        std::str::from_utf8(self.text.get(start..end)?).ok()
    }
}
