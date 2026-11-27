use std::collections::BTreeMap;

use debar_image::{
    Category, ConditionsRecord, Image, ImageError, Indicator, KindCondition, LogicalGroup,
    LogicalGroupMalformed, LogicalOutcome, LogicalSignatureId, LogicalSignatureRecord,
    MatchingPass, NameId, ObjectKind, SignatureGroup, UnwantedCategory,
};

use crate::executable_layout::LayoutState;
use crate::pattern_scan::{PatternDetection, PatternScanError, PatternSettings};

const BITS_PER_WORD: u32 = u64::BITS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectContext<'r> {
    pub ancestors: &'r [ObjectKind],
    pub retyped: bool,
}

impl ObjectContext<'static> {
    pub const TOP_LEVEL: Self = Self {
        ancestors: &[],
        retyped: false,
    };
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UnwantedCategories<'s> {
    #[default]
    Every,
    Containing(&'s str),
    NotContaining(&'s str),
}

impl UnwantedCategories<'_> {
    pub(crate) fn admit(self, image: &Image<'_>, name: NameId) -> Result<bool, ImageError> {
        if self == Self::Every {
            return Ok(true);
        }
        let Some(UnwantedCategory::Named(category)) = image.unwanted_category(name)? else {
            return Ok(false);
        };
        Ok(match self {
            Self::Every => true,
            Self::Containing(text) => category.contains(text),
            Self::NotContaining(text) => !category.contains(text),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogicalEvent {
    Detection(PatternDetection),
    Rescan(ObjectKind),
    ProgramTrigger(LogicalOutcome),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogicalFindings {
    pub events: Vec<LogicalEvent>,
    pub do_not_cache: bool,
}

impl LogicalFindings {
    pub fn detections(&self) -> impl Iterator<Item = &PatternDetection> {
        self.events.iter().filter_map(|event| match event {
            LogicalEvent::Detection(detection) => Some(detection),
            LogicalEvent::Rescan(_) | LogicalEvent::ProgramTrigger(_) => None,
        })
    }

    pub fn rescans(&self) -> impl Iterator<Item = ObjectKind> {
        self.events.iter().filter_map(|event| match event {
            LogicalEvent::Rescan(kind) => Some(*kind),
            LogicalEvent::Detection(_) | LogicalEvent::ProgramTrigger(_) => None,
        })
    }

    pub fn program_triggers(&self) -> impl Iterator<Item = LogicalOutcome> {
        self.events.iter().filter_map(|event| match event {
            LogicalEvent::ProgramTrigger(outcome) => Some(*outcome),
            LogicalEvent::Detection(_) | LogicalEvent::Rescan(_) => None,
        })
    }

    pub(crate) fn ends_the_scan(&self, every_match: bool) -> bool {
        !every_match
            && self
                .detections()
                .any(|detection| detection.indicator == Indicator::Strong)
    }
}

pub(crate) enum CountedMatches {
    Once,
    EachStart(Vec<u64>),
    Completion,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SubsignatureCount {
    completions: u32,
    starts: Vec<u64>,
}

impl SubsignatureCount {
    fn matches(&self) -> u32 {
        self.completions
            .saturating_add(u32::try_from(self.starts.len()).unwrap_or(u32::MAX))
    }
}

pub(crate) struct Counted {
    pub saturated: bool,
}

pub(crate) struct LogicalState<'m> {
    view: LogicalGroup<'m>,
    group: SignatureGroup,
    matched: Vec<u64>,
    counts: BTreeMap<u32, SubsignatureCount>,
    armed: Vec<u64>,
    armed_in_order: Vec<u32>,
    second_pass_wanted: bool,
}

fn bit_is_set(bits: &[u64], index: u32) -> bool {
    usize::try_from(index / BITS_PER_WORD)
        .ok()
        .and_then(|word| bits.get(word))
        .is_some_and(|word| word & (1u64 << (index % BITS_PER_WORD)) != 0)
}

fn set_bit(bits: &mut Vec<u64>, index: u32, size: usize) -> bool {
    if bits.is_empty() {
        bits.resize(size.div_ceil(64), 0);
    }
    let Some(word) = usize::try_from(index / BITS_PER_WORD)
        .ok()
        .and_then(|word| bits.get_mut(word))
    else {
        return false;
    };
    let mask = 1u64 << (index % BITS_PER_WORD);
    let was_set = *word & mask != 0;
    *word |= mask;
    !was_set
}

impl<'m> LogicalState<'m> {
    pub(crate) fn new(view: LogicalGroup<'m>, group: SignatureGroup) -> Self {
        Self {
            view,
            group,
            matched: Vec::new(),
            counts: BTreeMap::new(),
            armed: Vec::new(),
            armed_in_order: Vec::new(),
            second_pass_wanted: false,
        }
    }

    fn malformed(&self, reason: LogicalGroupMalformed) -> PatternScanError {
        PatternScanError::Image(ImageError::LogicalGroupMalformed {
            group: self.group,
            reason,
        })
    }

    pub(crate) fn is_armed(&self, id: LogicalSignatureId) -> bool {
        bit_is_set(&self.armed, id.0)
    }

    pub(crate) fn view(&self) -> &LogicalGroup<'m> {
        &self.view
    }

    pub(crate) fn armed_signatures(&self) -> &[u32] {
        &self.armed_in_order
    }

    pub(crate) fn needs_second_pass(&self) -> bool {
        self.second_pass_wanted
    }

    pub(crate) fn state_bytes(&self) -> usize {
        let words = self
            .matched
            .capacity()
            .saturating_add(self.armed.capacity());
        words
            .saturating_mul(std::mem::size_of::<u64>())
            .saturating_add(
                self.armed_in_order
                    .capacity()
                    .saturating_mul(std::mem::size_of::<u32>()),
            )
            .saturating_add(self.counts.values().fold(0usize, |bytes, count| {
                bytes
                    .saturating_add(std::mem::size_of::<u32>())
                    .saturating_add(std::mem::size_of::<SubsignatureCount>())
                    .saturating_add(
                        count
                            .starts
                            .capacity()
                            .saturating_mul(std::mem::size_of::<u64>()),
                    )
            }))
    }

    pub(crate) fn counts_each_match(
        &self,
        id: LogicalSignatureId,
        index: u16,
    ) -> Result<bool, PatternScanError> {
        let record = self
            .view
            .signature(id)
            .map_err(|reason| self.malformed(reason))?;
        let subsignature = self
            .view
            .subsignature(&record, index)
            .map_err(|reason| self.malformed(reason))?;
        Ok(subsignature.ceiling > 1)
    }

    pub(crate) fn count(
        &mut self,
        id: LogicalSignatureId,
        index: u16,
        matches: &CountedMatches,
        pass: MatchingPass,
    ) -> Result<Counted, PatternScanError> {
        let record = self
            .view
            .signature(id)
            .map_err(|reason| self.malformed(reason))?;
        let subsignature = self
            .view
            .subsignature(&record, index)
            .map_err(|reason| self.malformed(reason))?;
        let global = record
            .first_subsignature
            .checked_add(u32::from(index))
            .ok_or_else(|| self.malformed(LogicalGroupMalformed::Layout))?;
        set_bit(&mut self.matched, global, self.view.subsignature_count());
        let saturated = if subsignature.ceiling > 1 {
            let count = self.counts.entry(global).or_default();
            match matches {
                CountedMatches::Once | CountedMatches::Completion => {
                    count.completions = count.completions.saturating_add(1);
                }
                CountedMatches::EachStart(starts) => {
                    for start in starts {
                        if count.matches() >= subsignature.ceiling {
                            break;
                        }
                        if let Err(at) = count.starts.binary_search(start) {
                            count.starts.insert(at, *start);
                        }
                    }
                }
            }
            count.matches() >= subsignature.ceiling
        } else {
            true
        };
        let newly_armed = pass == MatchingPass::Main
            && set_bit(&mut self.armed, id.0, self.view.signature_count());
        if newly_armed {
            self.armed_in_order.push(id.0);
            if !self.second_pass_wanted {
                for other in 0..record.subsignature_count {
                    let other = u16::try_from(other).unwrap_or(u16::MAX);
                    let other = self
                        .view
                        .subsignature(&record, other)
                        .map_err(|reason| self.malformed(reason))?;
                    if other.pass == MatchingPass::Second {
                        self.second_pass_wanted = true;
                        break;
                    }
                }
            }
        }
        Ok(Counted { saturated })
    }

    pub(crate) fn current_matches(
        &self,
        id: LogicalSignatureId,
        index: u16,
    ) -> Result<u64, PatternScanError> {
        let record = self
            .view
            .signature(id)
            .map_err(|reason| self.malformed(reason))?;
        Ok(self.matches_of(&record, index))
    }

    pub(crate) fn recorded_starts(
        &self,
        id: LogicalSignatureId,
        index: u16,
    ) -> Result<&[u64], PatternScanError> {
        let record = self
            .view
            .signature(id)
            .map_err(|reason| self.malformed(reason))?;
        if u32::from(index) >= record.subsignature_count {
            return Ok(&[]);
        }
        let Some(global) = record.first_subsignature.checked_add(u32::from(index)) else {
            return Ok(&[]);
        };
        Ok(self
            .counts
            .get(&global)
            .map_or(&[][..], |count| count.starts.as_slice()))
    }

    pub(crate) fn has_pattern(
        &self,
        id: LogicalSignatureId,
        index: u16,
    ) -> Result<bool, PatternScanError> {
        let record = self
            .view
            .signature(id)
            .map_err(|reason| self.malformed(reason))?;
        if u32::from(index) >= record.subsignature_count {
            return Ok(false);
        }
        Ok(self
            .view
            .subsignature(&record, index)
            .map_err(|reason| self.malformed(reason))?
            .pattern
            .is_some())
    }

    fn matches_of(&self, record: &LogicalSignatureRecord<'_>, index: u16) -> u64 {
        let Some(global) = record.first_subsignature.checked_add(u32::from(index)) else {
            return 0;
        };
        if !bit_is_set(&self.matched, global) {
            return 0;
        }
        self.counts
            .get(&global)
            .map_or(1, |count| u64::from(count.matches()))
    }

    pub(crate) fn may_report_here(
        &self,
        id: LogicalSignatureId,
        image: &Image<'_>,
        settings: &PatternSettings<'_>,
        context: &ObjectContext<'_>,
        object_length: u64,
        layout: LayoutState<'_>,
    ) -> Result<bool, PatternScanError> {
        let record = self
            .view
            .signature(id)
            .map_err(|reason| self.malformed(reason))?;
        if !reported_under_the_settings(image, settings, &record)? {
            return Ok(false);
        }
        let conditions = self
            .view
            .conditions(&record)
            .map_err(|reason| self.malformed(reason))?;
        let Some(conditions) = &conditions else {
            return Ok(true);
        };
        Ok(
            match conditions_before_the_outcome(conditions, context, object_length, layout) {
                ConditionsOutcome::Hold => true,
                ConditionsOutcome::FailOnAncestors | ConditionsOutcome::Fail => false,
            },
        )
    }

    pub(crate) fn evaluate(
        &self,
        image: &Image<'_>,
        settings: &PatternSettings<'_>,
        context: &ObjectContext<'_>,
        object_length: u64,
        layout: LayoutState<'_>,
        findings: &mut LogicalFindings,
    ) -> Result<(), PatternScanError> {
        let mut candidates: Vec<u32> = self.armed_in_order.clone();
        candidates.extend(self.view.holding_with_no_matches().map(|id| id.0));
        candidates.sort_unstable();
        candidates.dedup();
        for id in candidates.into_iter().map(LogicalSignatureId) {
            let record = self
                .view
                .signature(id)
                .map_err(|reason| self.malformed(reason))?;
            if !reported_under_the_settings(image, settings, &record)? {
                continue;
            }
            let holds = self
                .view
                .expression_holds(id, &record, |index| self.matches_of(&record, index))
                .map_err(|reason| self.malformed(reason))?;
            if !holds {
                continue;
            }
            let conditions = self
                .view
                .conditions(&record)
                .map_err(|reason| self.malformed(reason))?;
            if let Some(conditions) = &conditions {
                match conditions_before_the_outcome(conditions, context, object_length, layout) {
                    ConditionsOutcome::Hold => {}
                    ConditionsOutcome::FailOnAncestors => {
                        findings.do_not_cache = true;
                        continue;
                    }
                    ConditionsOutcome::Fail => continue,
                }
            }
            if let Some(kind) = conditions
                .as_ref()
                .and_then(|conditions| conditions.handler_type)
                && !context.retyped
            {
                findings.events.push(LogicalEvent::Rescan(kind));
                continue;
            }
            if conditions
                .as_ref()
                .is_some_and(|conditions| !conditions.icon_groups.is_empty())
            {
                continue;
            }
            if record.outcome != LogicalOutcome::Detection {
                findings
                    .events
                    .push(LogicalEvent::ProgramTrigger(record.outcome));
                continue;
            }
            let name = image.signature_name(record.name)?;
            let strong = name.indicator == Indicator::Strong;
            findings
                .events
                .push(LogicalEvent::Detection(PatternDetection {
                    name: name.text,
                    indicator: name.indicator,
                }));
            if strong && !settings.every_match {
                return Ok(());
            }
        }
        Ok(())
    }
}

fn reported_under_the_settings(
    image: &Image<'_>,
    settings: &PatternSettings<'_>,
    record: &LogicalSignatureRecord<'_>,
) -> Result<bool, PatternScanError> {
    Ok(match record.category {
        Category::PotentiallyUnwanted => {
            settings.potentially_unwanted
                && settings.unwanted_categories.admit(image, record.name)?
        }
        Category::Malware => true,
    })
}

enum ConditionsOutcome {
    Hold,
    FailOnAncestors,
    Fail,
}

fn kind_matches(condition: KindCondition, kind: ObjectKind) -> bool {
    match condition {
        KindCondition::AnyKind => true,
        KindCondition::Kind(wanted) => wanted == kind,
    }
}

fn conditions_before_the_outcome(
    conditions: &ConditionsRecord<'_>,
    context: &ObjectContext<'_>,
    object_length: u64,
    layout: LayoutState<'_>,
) -> ConditionsOutcome {
    let parent = context
        .ancestors
        .first()
        .copied()
        .unwrap_or(ObjectKind::Untyped);
    if let Some(container) = conditions.container {
        let holds = match container {
            KindCondition::AnyKind => parent == ObjectKind::Untyped,
            KindCondition::Kind(kind) => kind == parent,
        };
        if !holds {
            return ConditionsOutcome::FailOnAncestors;
        }
    }
    if !conditions.intermediates.is_empty() {
        let holds = conditions.intermediates.len() <= context.ancestors.len()
            && conditions
                .intermediates
                .iter()
                .rev()
                .zip(context.ancestors)
                .all(|(condition, kind)| kind_matches(*condition, *kind));
        if !holds {
            return ConditionsOutcome::FailOnAncestors;
        }
    }
    if conditions
        .file_size
        .is_some_and(|range| !range.holds(object_length))
    {
        return ConditionsOutcome::Fail;
    }
    let executable = match layout {
        LayoutState::Known(layout) => Some(layout),
        LayoutState::Missing | LayoutState::NotExecutable => None,
    };
    if let Some(range) = conditions.entry_point
        && !executable.is_some_and(|layout| range.holds(u64::from(layout.entry_point)))
    {
        return ConditionsOutcome::Fail;
    }
    if let Some(range) = conditions.number_of_sections
        && !executable.is_some_and(|layout| {
            range.holds(u64::try_from(layout.sections.len()).unwrap_or(u64::MAX))
        })
    {
        return ConditionsOutcome::Fail;
    }
    ConditionsOutcome::Hold
}
