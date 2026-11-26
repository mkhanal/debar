use debar_image::{
    AutomatonMalformed, ComparisonRecord, ExpressionAnchoring, ExpressionMatches, ExpressionRecord,
    ImageError, InPlaceAutomaton, MatchingPass, Placement, PlugInSubsignatures, PlugInsMalformed,
    ReportWindows, SignatureGroup, automaton_in_place, compile_text,
};
use regex_automata::dfa::regex::Regex;
use regex_automata::{Anchored, Input, Match};
use zerocopy::IntoBytes;

use crate::byte_values::comparisons_hold;
use crate::executable_layout::{LayoutState, placed_starts};
use crate::logical_state::{CountedMatches, LogicalState};
use crate::pattern_scan::PatternScanError;

const START_WRAPPED_TO_ANYWHERE: u32 = u32::MAX;
const START_WRAPPED_TO_NOWHERE: u32 = u32::MAX - 1;

pub(crate) struct PlugInRequest<'o, 'l> {
    pub object: &'o [u8],
    pub windows: Option<ReportWindows>,
    pub image_fuzzy_hash: Option<u64>,
    pub largest_object_for_regular_expressions: Option<u64>,
    pub layout: LayoutState<'l>,
}

fn malformed(group: SignatureGroup, reason: PlugInsMalformed) -> PatternScanError {
    PatternScanError::Image(ImageError::PlugInsMalformed { group, reason })
}

pub(crate) fn match_plug_ins(
    group: SignatureGroup,
    plug_ins: &PlugInSubsignatures<'_>,
    state: &mut LogicalState<'_>,
    request: &PlugInRequest<'_, '_>,
) -> Result<(), PatternScanError> {
    let windows = Windows::of(request.windows, request.object.len());
    for record in plug_ins.comparisons() {
        let record = record.map_err(|reason| malformed(group, reason))?;
        compare_bytes(&record, state, request.object, &windows)?;
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
    let object_length = u64::try_from(request.object.len()).unwrap_or(u64::MAX);
    if request
        .largest_object_for_regular_expressions
        .is_some_and(|largest| object_length > largest)
    {
        return Ok(());
    }
    for record in plug_ins.expressions() {
        let record = record.map_err(|reason| malformed(group, reason))?;
        let may_run = record.unconditional
            || record.trigger_holds_without_matches
            || state.is_armed(record.signature);
        if !may_run {
            continue;
        }
        let holds = plug_ins
            .trigger_holds(&record, |index| {
                state.current_matches(record.signature, index).unwrap_or(0)
            })
            .map_err(|reason| malformed(group, reason))?;
        if !holds {
            continue;
        }
        let starts = expression_starts(&record, request)
            .map_err(|_| malformed(group, PlugInsMalformed::Expression))?;
        if !starts.is_empty() {
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
    object: &[u8],
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
        let Some(bytes) = object.get(read_from..read_from.saturating_add(length)) else {
            continue;
        };
        if comparisons_hold(
            bytes,
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

fn subject_of(record: &ExpressionRecord<'_>, request: &PlugInRequest<'_, '_>) -> Option<Subject> {
    let object_length = request.object.len();
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

fn expression_starts(
    record: &ExpressionRecord<'_>,
    request: &PlugInRequest<'_, '_>,
) -> Result<Vec<u64>, AutomatonMalformed> {
    let Some(subject) = subject_of(record, request) else {
        return Ok(Vec::new());
    };
    let haystack = request
        .object
        .get(subject.start..subject.end)
        .unwrap_or_default();
    let relative_starts = if let Some((forward_bytes, reverse_bytes)) = record.automata {
        let forward_copy;
        let reverse_copy;
        let forward: InPlaceAutomaton<'_> = if let Ok(automaton) = automaton_in_place(forward_bytes)
        {
            automaton
        } else {
            forward_copy = aligned_copy(forward_bytes);
            automaton_in_place(forward_copy.as_bytes())?
        };
        let reverse: InPlaceAutomaton<'_> = if let Ok(automaton) = automaton_in_place(reverse_bytes)
        {
            automaton
        } else {
            reverse_copy = aligned_copy(reverse_bytes);
            automaton_in_place(reverse_copy.as_bytes())?
        };
        let regex = Regex::builder().build_from_dfas(forward, reverse);
        matched_starts(record, &subject, haystack, |input| {
            regex.try_search(input).map_err(|_| AutomatonMalformed)
        })?
    } else {
        let regex = compile_text(record.text().map_err(|_| AutomatonMalformed)?)?;
        matched_starts(record, &subject, haystack, |input| Ok(regex.search(input)))?
    };
    let base = u64::try_from(subject.start).unwrap_or(u64::MAX);
    Ok(relative_starts
        .into_iter()
        .map(|start| base.saturating_add(u64::try_from(start).unwrap_or(u64::MAX)))
        .collect())
}

fn matched_starts(
    record: &ExpressionRecord<'_>,
    subject: &Subject,
    haystack: &[u8],
    mut search: impl FnMut(&Input<'_>) -> Result<Option<Match>, AutomatonMalformed>,
) -> Result<Vec<usize>, AutomatonMalformed> {
    let mut starts = Vec::new();
    let mut from = 0usize;
    loop {
        let input = Input::new(haystack)
            .range(from..)
            .anchored(if subject.anchored {
                Anchored::Yes
            } else {
                Anchored::No
            });
        let Some(found) = search(&input)? else {
            break;
        };
        if !record.bounded_by_shift && subject.shift > 0 && found.start() > subject.shift {
            break;
        }
        if starts.last() != Some(&found.start()) {
            starts.push(found.start());
        }
        if record.matches == ExpressionMatches::First || found.end() == from && found.is_empty() {
            break;
        }
        from = found.end();
        if from >= haystack.len() {
            break;
        }
    }
    Ok(starts)
}
