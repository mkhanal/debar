use debar_image::{
    AutomatonMalformed, BacktrackingProgram, ComparisonRecord, ExpressionAnchoring,
    ExpressionMatches, ExpressionRecord, Image, ImageError, InPlaceAutomaton, MatchingPass,
    Placement, PlugInSubsignatures, PlugInsMalformed, RecordedForm, ReportWindows, SignatureGroup,
    automaton_in_place, compile_text, compile_text_lazily,
};
use debar_platform::input::InputError;
use regex_automata::dfa::Automaton as _;
use regex_automata::dfa::regex::Regex;
use regex_automata::{Anchored, Input, Match};

use crate::backtracking_search::{
    BacktrackingBounds, BacktrackingSearch, SubjectBytes, search_subject,
};
use zerocopy::IntoBytes;

use crate::byte_values::comparisons_hold;
use crate::executable_layout::{LayoutState, placed_starts};
use crate::logical_state::ObjectContext;
use crate::logical_state::{CountedMatches, LogicalState};
use crate::paged_expression_search::{PagedSearchFailure, search_in_place, search_lazily};
use crate::pattern_scan::{PatternScanError, PatternSettings};
use crate::whole_object::{ObjectPages, PagedSubject, WholeObject};
use crate::work_meter::WorkMeter;

const START_WRAPPED_TO_ANYWHERE: u32 = u32::MAX;
const START_WRAPPED_TO_NOWHERE: u32 = u32::MAX - 1;

pub(crate) struct PlugInRequest<'l, 'm> {
    pub image: &'l Image<'m>,
    pub windows: Option<ReportWindows>,
    pub image_fuzzy_hash: Option<u64>,
    pub settings: PatternSettings<'l>,
    pub context: ObjectContext<'l>,
    pub layout: LayoutState<'l>,
}

fn malformed(group: SignatureGroup, reason: PlugInsMalformed) -> PatternScanError {
    PatternScanError::Image(ImageError::PlugInsMalformed { group, reason })
}

#[inline(never)]
pub(crate) fn match_plug_ins<'m>(
    group: SignatureGroup,
    plug_ins: &PlugInSubsignatures<'m>,
    state: &mut LogicalState<'_>,
    request: &PlugInRequest<'_, 'm>,
    object: &mut WholeObject<'_>,
    work: &mut WorkMeter,
) -> Result<(), PatternScanError> {
    let object_length = object.length();
    let windows = Windows::of(
        request.windows,
        usize::try_from(object_length).unwrap_or(usize::MAX),
    );
    for record in plug_ins.comparisons() {
        let record = record.map_err(|reason| malformed(group, reason))?;
        compare_bytes(&record, state, object, &windows)?;
    }
    if let Some(hash) = request.image_fuzzy_hash {
        for (signature, subsignature) in plug_ins.image_hash_subsignatures(hash) {
            for _ in 0..windows.count() {
                let counted = state.count(
                    signature,
                    subsignature,
                    &CountedMatches::Once,
                    MatchingPass::Main,
                )?;
                if counted.saturated {
                    break;
                }
            }
        }
    }
    if request
        .settings
        .largest_object_for_regular_expressions
        .is_some_and(|largest| object_length > largest)
    {
        return Ok(());
    }
    for (index, trigger) in plug_ins.expression_triggers().enumerate() {
        if work.ran_out() {
            return Ok(());
        }
        if !trigger.runs_unarmed && !state.is_armed(trigger.signature) {
            continue;
        }
        if !state.may_report_here(
            trigger.signature,
            request.image,
            &request.settings,
            &request.context,
            object_length,
            request.layout,
        )? {
            continue;
        }
        let record = plug_ins
            .expression(index)
            .map_err(|reason| malformed(group, reason))?;
        let holds = plug_ins
            .trigger_holds(&record, |index| {
                state.current_matches(record.signature, index).unwrap_or(0)
            })
            .map_err(|reason| malformed(group, reason))?;
        if !holds {
            continue;
        }
        let starts =
            expression_starts(&record, request, object, work).map_err(|failure| match failure {
                ExpressionFailure::Malformed => malformed(group, PlugInsMalformed::Expression),
                ExpressionFailure::Input(error) => PatternScanError::Input(error),
            })?;
        if !starts.is_empty() && !work.ran_out() {
            state.count(
                record.signature,
                record.subsignature,
                &CountedMatches::EachStart(starts),
                MatchingPass::Main,
            )?;
        }
    }
    Ok(())
}

struct Windows {
    length: usize,
    step: usize,
    object_length: usize,
}

impl Windows {
    fn of(windows: Option<ReportWindows>, object_length: usize) -> Self {
        let (length, overlap) = windows.map_or((object_length.max(1), 0), |windows| {
            (
                usize::try_from(windows.length).unwrap_or(usize::MAX).max(1),
                usize::try_from(windows.overlap).unwrap_or(0),
            )
        });
        Self {
            length,
            step: length.saturating_sub(overlap).max(1),
            object_length,
        }
    }

    fn count(&self) -> usize {
        if self.object_length <= self.length {
            return 1;
        }
        self.object_length
            .saturating_sub(self.length)
            .div_ceil(self.step)
            .saturating_add(1)
    }

    fn span(&self, window: usize) -> (usize, usize) {
        let start = window.saturating_mul(self.step);
        let end = start.saturating_add(self.length).min(self.object_length);
        (start, end)
    }
}

fn compare_bytes(
    record: &ComparisonRecord,
    state: &mut LogicalState<'_>,
    object: &mut WholeObject<'_>,
    windows: &Windows,
) -> Result<(), PatternScanError> {
    let comparison = &record.comparison;
    if !state.has_pattern(record.signature, comparison.subsignature)? {
        return Ok(());
    }
    let length = usize::try_from(comparison.length).unwrap_or(usize::MAX);
    for window in 0..windows.count() {
        let (start, end) = windows.span(window);
        let starts = state.recorded_starts(record.signature, comparison.subsignature)?;
        let end_position = u64::try_from(end).unwrap_or(u64::MAX);
        let Some(last) = starts.iter().rev().find(|found| **found < end_position) else {
            continue;
        };
        let Some(position) = i64::try_from(*last)
            .ok()
            .and_then(|last| last.checked_add(comparison.displacement))
            .filter(|position| *position > 0)
            .and_then(|position| usize::try_from(position).ok())
        else {
            continue;
        };
        let window_length = end.saturating_sub(start);
        if position.saturating_add(length) > window_length {
            continue;
        }
        let read_from = start.saturating_add(position);
        let Some(bytes) = object.bytes_at(read_from, length)? else {
            continue;
        };
        if comparisons_hold(
            &bytes,
            comparison.encoding,
            comparison.exact,
            &comparison.comparisons,
        ) {
            let counted = state.count(
                record.signature,
                record.subsignature,
                &CountedMatches::Once,
                MatchingPass::Main,
            )?;
            if counted.saturated {
                break;
            }
        }
    }
    Ok(())
}

struct Subject {
    start: usize,
    end: usize,
    shift: usize,
    anchored: bool,
}

fn subject_of(
    record: &ExpressionRecord<'_>,
    request: &PlugInRequest<'_, '_>,
    object_length: usize,
) -> Option<Subject> {
    let length = u32::try_from(object_length).unwrap_or(u32::MAX);
    let (start, shift, anywhere) = match record.placement {
        Placement::Anywhere => (0, 0, true),
        Placement::FromStart { distance, shift } => (distance, shift, false),
        Placement::BeforeEnd { distance, shift } => match length.wrapping_sub(distance) {
            START_WRAPPED_TO_ANYWHERE => (0, 0, true),
            START_WRAPPED_TO_NOWHERE => return None,
            start => (start, shift, false),
        },
        Placement::InExecutable { .. } => {
            let mut ranges = Vec::new();
            placed_starts(
                record.placement,
                u64::try_from(object_length).unwrap_or(u64::MAX),
                request.layout,
                &mut ranges,
            );
            let (first, last) = ranges.first().copied()?;
            let first = u32::try_from(first).ok()?;
            let shift = u32::try_from(last.saturating_sub(u64::from(first))).ok()?;
            (first, shift, false)
        }
    };
    let start = usize::try_from(start).ok()?;
    let shift = usize::try_from(shift).ok()?;
    if start >= object_length {
        return None;
    }
    let end = if record.bounded_by_shift && shift > 0 {
        start.saturating_add(shift).min(object_length)
    } else {
        object_length
    };
    Some(Subject {
        start,
        end,
        shift,
        anchored: match record.anchoring {
            ExpressionAnchoring::AtTheSubjectStart => true,
            ExpressionAnchoring::NeverAtThePlacement => false,
            ExpressionAnchoring::AtAnUnshiftedPlacement => shift == 0 && !anywhere,
        },
    })
}

pub(crate) fn aligned_copy(bytes: &[u8]) -> Vec<u32> {
    let mut words = vec![0u32; bytes.len().div_ceil(4)];
    if let Some(target) = words.as_mut_bytes().get_mut(..bytes.len()) {
        target.copy_from_slice(bytes);
    }
    words
}

enum ExpressionFailure {
    Malformed,
    Input(InputError),
}

impl From<AutomatonMalformed> for ExpressionFailure {
    fn from(_: AutomatonMalformed) -> Self {
        Self::Malformed
    }
}

impl From<PagedSearchFailure> for ExpressionFailure {
    fn from(failure: PagedSearchFailure) -> Self {
        match failure {
            PagedSearchFailure::Unsearchable => Self::Malformed,
            PagedSearchFailure::Input(error) => Self::Input(error),
        }
    }
}

fn expression_starts<'m>(
    record: &ExpressionRecord<'m>,
    request: &PlugInRequest<'_, 'm>,
    object: &mut WholeObject<'_>,
    work: &mut WorkMeter,
) -> Result<Vec<u64>, ExpressionFailure> {
    let object_length = usize::try_from(object.length()).unwrap_or(usize::MAX);
    let Some(subject) = subject_of(record, request, object_length) else {
        return Ok(Vec::new());
    };
    let anchored = if subject.anchored {
        Anchored::Yes
    } else {
        Anchored::No
    };
    let relative_starts = match object {
        WholeObject::Held(held) => {
            held_starts(request.image, record, &subject, held, anchored, work)?
        }
        WholeObject::Paged(pages) => {
            paged_starts(request.image, record, &subject, pages, anchored, work)?
        }
    };
    let base = u64::try_from(subject.start).unwrap_or(u64::MAX);
    Ok(relative_starts
        .into_iter()
        .map(|start| base.saturating_add(u64::try_from(start).unwrap_or(u64::MAX)))
        .collect())
}

fn in_place<'a, 'm: 'a>(
    image: &Image<'m>,
    bytes: &'m [u8],
    copy: &'a mut Vec<u32>,
) -> Result<InPlaceAutomaton<'a>, AutomatonMalformed> {
    if let Ok(automaton) = image.validated_automaton(bytes) {
        return Ok(automaton);
    }
    *copy = aligned_copy(bytes);
    automaton_in_place(copy.as_bytes())
}

fn held_starts<'m>(
    image: &Image<'m>,
    record: &ExpressionRecord<'m>,
    subject: &Subject,
    held: &[u8],
    anchored: Anchored,
    work: &mut WorkMeter,
) -> Result<Vec<usize>, ExpressionFailure> {
    let haystack = held.get(subject.start..subject.end).unwrap_or_default();
    let automaton_search = |found: Option<Match>| found.map(|found| (found.start(), found.end()));
    Ok(match record.form {
        RecordedForm::Automata {
            forward: forward_bytes,
            reverse: reverse_bytes,
        } => {
            let (mut forward_copy, mut reverse_copy) = (Vec::new(), Vec::new());
            if work.ran_out() {
                return Ok(Vec::new());
            }
            let forward = in_place(image, forward_bytes, &mut forward_copy)?;
            let first_end = forward
                .try_search_fwd(&Input::new(haystack).anchored(anchored))
                .map_err(|_| ExpressionFailure::Malformed)?;
            if first_end.is_none() {
                charge_searched(work, 0, None, haystack.len());
                return Ok(Vec::new());
            }
            let reverse = in_place(image, reverse_bytes, &mut reverse_copy)?;
            let regex = Regex::builder().build_from_dfas(forward, reverse);
            matched_starts(record, subject, haystack.len(), work, |from, work| {
                let input = Input::new(haystack).range(from..).anchored(anchored);
                let found = regex
                    .try_search(&input)
                    .map(automaton_search)
                    .map_err(|_| ExpressionFailure::Malformed)?;
                charge_searched(work, from, found, haystack.len());
                Ok(found)
            })?
        }
        RecordedForm::Text => {
            let regex = compile_text(record.text().map_err(|_| AutomatonMalformed)?)?;
            matched_starts(record, subject, haystack.len(), work, |from, work| {
                let input = Input::new(haystack).range(from..).anchored(anchored);
                let found = automaton_search(regex.search(&input));
                charge_searched(work, from, found, haystack.len());
                Ok(found)
            })?
        }
        RecordedForm::Backtracking(bytes) => {
            let program = BacktrackingProgram::read(bytes).map_err(|_| AutomatonMalformed)?;
            matched_starts(
                record,
                subject,
                haystack.len(),
                work,
                |from, work| match search_subject(
                    &program,
                    &mut &*haystack,
                    from,
                    subject.anchored,
                    BacktrackingBounds::FOR_SIGNATURES,
                    work,
                )
                .map_err(|_| AutomatonMalformed)?
                {
                    BacktrackingSearch::Found { start, end } => Ok(Some((start, end))),
                    BacktrackingSearch::NotFound | BacktrackingSearch::GaveUp => Ok(None),
                },
            )?
        }
    })
}

fn paged_starts<'m>(
    image: &Image<'m>,
    record: &ExpressionRecord<'m>,
    subject: &Subject,
    pages: &mut ObjectPages<'_>,
    anchored: Anchored,
    work: &mut WorkMeter,
) -> Result<Vec<usize>, ExpressionFailure> {
    let mut searched_bytes: PagedSubject<'_, '_> = pages.subject(
        u64::try_from(subject.start).unwrap_or(u64::MAX),
        u64::try_from(subject.end).unwrap_or(u64::MAX),
    );
    let length = searched_bytes.length();
    Ok(match record.form {
        RecordedForm::Automata {
            forward: forward_bytes,
            reverse: reverse_bytes,
        } => {
            let (mut forward_copy, mut reverse_copy) = (Vec::new(), Vec::new());
            let forward = in_place(image, forward_bytes, &mut forward_copy)?;
            let reverse = in_place(image, reverse_bytes, &mut reverse_copy)?;
            matched_starts(record, subject, length, work, |from, work| {
                let found =
                    search_in_place(&forward, &reverse, &mut searched_bytes, from, anchored)?;
                charge_searched(work, from, found, length);
                Ok(found)
            })?
        }
        RecordedForm::Text => {
            let expression = compile_text_lazily(record.text().map_err(|_| AutomatonMalformed)?)?;
            let mut cache = expression.create_cache();
            matched_starts(record, subject, length, work, |from, work| {
                let found =
                    search_lazily(&expression, &mut cache, &mut searched_bytes, from, anchored)?;
                charge_searched(work, from, found, length);
                Ok(found)
            })?
        }
        RecordedForm::Backtracking(bytes) => {
            let program = BacktrackingProgram::read(bytes).map_err(|_| AutomatonMalformed)?;
            matched_starts(record, subject, length, work, |from, work| {
                let searched = search_subject(
                    &program,
                    &mut searched_bytes,
                    from,
                    subject.anchored,
                    BacktrackingBounds::FOR_SIGNATURES,
                    work,
                )
                .map_err(|_| AutomatonMalformed)?;
                searched_bytes
                    .take_failure()
                    .map_err(ExpressionFailure::Input)?;
                match searched {
                    BacktrackingSearch::Found { start, end } => Ok(Some((start, end))),
                    BacktrackingSearch::NotFound | BacktrackingSearch::GaveUp => Ok(None),
                }
            })?
        }
    })
}

fn matched_starts(
    record: &ExpressionRecord<'_>,
    subject: &Subject,
    haystack_length: usize,
    work: &mut WorkMeter,
    mut search: impl FnMut(usize, &mut WorkMeter) -> Result<Option<(usize, usize)>, ExpressionFailure>,
) -> Result<Vec<usize>, ExpressionFailure> {
    let mut starts = Vec::new();
    let mut from = 0usize;
    while !work.ran_out()
        && let Some((start, end)) = search(from, work)?
    {
        if !record.bounded_by_shift && subject.shift > 0 && start > subject.shift {
            break;
        }
        if starts.last() != Some(&start) {
            starts.push(start);
        }
        if record.matches == ExpressionMatches::First || end == from && start == end {
            break;
        }
        from = end;
        if from >= haystack_length {
            break;
        }
    }
    Ok(starts)
}

fn charge_searched(
    work: &mut WorkMeter,
    from: usize,
    found: Option<(usize, usize)>,
    haystack_length: usize,
) {
    let searched_to = found.map_or(haystack_length, |(_, end)| end);
    let searched = searched_to.saturating_sub(from).max(1);
    work.charge(u64::try_from(searched).unwrap_or(u64::MAX));
}
