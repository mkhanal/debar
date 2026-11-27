use std::ops::Range;

use debar_image::{
    AnchorBytes, AnchorCase, ContextView, MaskedRun, ProgramHeader, ProgramMalformed, ProgramView,
    StepView, set_in_sequence_contains,
};

pub struct RetainedBytes<'b> {
    pub bytes: &'b [u8],
    pub first_position: u64,
    pub object_length: u64,
}

impl RetainedBytes<'_> {
    fn slice(&self, position: u64, length: usize) -> Option<&[u8]> {
        let start = usize::try_from(position.checked_sub(self.first_position)?).ok()?;
        self.bytes.get(start..start.checked_add(length)?)
    }

    fn byte(&self, position: u64) -> Option<u8> {
        self.slice(position, 1)
            .and_then(|bytes| bytes.first().copied())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PositionSet {
    first: Option<Range<u64>>,
    later: Vec<Range<u64>>,
}

impl PositionSet {
    #[must_use]
    pub fn between(first: u64, last: u64) -> Self {
        let mut set = Self::default();
        if let Some(end) = last.checked_add(1) {
            set.add(first..end);
        }
        set
    }

    #[must_use]
    pub fn of_ranges(ranges: impl IntoIterator<Item = (u64, u64)>) -> Self {
        Self::of_unordered(
            ranges
                .into_iter()
                .filter(|(first, last)| first <= last)
                .filter_map(|(first, last)| Some(first..last.checked_add(1)?))
                .collect(),
        )
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.first.is_none()
    }

    #[must_use]
    pub fn first(&self) -> Option<u64> {
        self.first.as_ref().map(|range| range.start)
    }

    pub(crate) fn positions(&self) -> impl Iterator<Item = u64> + '_ {
        self.ranges().flat_map(Clone::clone)
    }

    fn ranges(&self) -> impl Iterator<Item = &Range<u64>> {
        self.first.iter().chain(&self.later)
    }

    fn add(&mut self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }
        match self.later.last_mut().or(self.first.as_mut()) {
            Some(last) if last.end >= range.start && last.start <= range.start => {
                last.end = last.end.max(range.end);
            }
            Some(_) => self.later.push(range),
            None => self.first = Some(range),
        }
    }

    fn add_position(&mut self, position: u64) {
        if let Some(end) = position.checked_add(1) {
            self.add(position..end);
        }
    }

    fn of_unordered(mut ranges: Vec<Range<u64>>) -> Self {
        ranges.sort_by_key(|range| range.start);
        let mut merged = Self::default();
        for range in ranges {
            merged.add(range);
        }
        merged
    }
}

pub fn anchor_rules_out(
    program: &ProgramHeader,
    first_start: u64,
    last_start: u64,
    bytes: &RetainedBytes<'_>,
) -> bool {
    let anchor = program.anchor();
    let displacement = anchor.displacement;
    if first_start != last_start
        || displacement.nearest != displacement.farthest
        || first_start < bytes.first_position
    {
        return false;
    }
    let Some(at) = first_start.checked_add(u64::from(displacement.nearest)) else {
        return false;
    };
    let expected: &[u8] = match &anchor.bytes {
        AnchorBytes::Long(expected) => expected,
        AnchorBytes::Short(expected) => expected,
        AnchorBytes::None => return false,
    };
    bytes.slice(at, expected.len()).is_some_and(|found| {
        found.iter().zip(expected).any(|(byte, anchored)| {
            let seen = match anchor.case {
                AnchorCase::Exact => *byte,
                AnchorCase::Folded => byte.to_ascii_lowercase(),
            };
            seen != *anchored
        })
    })
}

pub fn earliest_end(
    program: &ProgramView<'_>,
    bytes: &RetainedBytes<'_>,
    starts: &PositionSet,
) -> Result<Option<u64>, ProgramMalformed> {
    match program.only_run() {
        Some(run) => earliest_run_end(run, bytes, starts),
        None => Ok(match_ends(program, bytes, starts)?.first()),
    }
}

fn earliest_run_end(
    run: MaskedRun<'_>,
    bytes: &RetainedBytes<'_>,
    starts: &PositionSet,
) -> Result<Option<u64>, ProgramMalformed> {
    let length = u64::try_from(run.len()).map_err(|_| ProgramMalformed)?;
    let mut earliest = None;
    for range in starts.ranges() {
        let found = find_run_starts(run, bytes, range, |start| {
            earliest = Some(start);
            Search::Stop
        });
        if found == Search::Stop {
            break;
        }
    }
    Ok(earliest.and_then(|start| start.checked_add(length)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Search {
    Continue,
    Stop,
}

fn find_run_starts(
    run: MaskedRun<'_>,
    bytes: &RetainedBytes<'_>,
    starts: &Range<u64>,
    mut found: impl FnMut(u64) -> Search,
) -> Search {
    let first = starts.start.max(bytes.first_position);
    let Some(retained) = first
        .checked_sub(bytes.first_position)
        .and_then(|offset| usize::try_from(offset).ok())
        .and_then(|offset| bytes.bytes.get(offset..))
    else {
        return Search::Continue;
    };
    let Some(fitting) = retained.len().checked_sub(run.len()) else {
        return Search::Continue;
    };
    let count = usize::try_from(starts.end.saturating_sub(first)).unwrap_or(usize::MAX);
    let fitting = fitting.saturating_add(1).min(count);
    let mut report = |offset: usize| {
        let matched = retained
            .get(offset..offset.saturating_add(run.len()))
            .is_some_and(|window| run.matches(window));
        match u64::try_from(offset)
            .ok()
            .and_then(|offset| first.checked_add(offset))
        {
            Some(start) if matched => found(start),
            _ => Search::Continue,
        }
    };
    let exact_byte = run.masks.iter().position(|mask| *mask == u8::MAX);
    match (exact_byte, run.values.first(), run.masks.first()) {
        (Some(at), _, _) => {
            let (Some(value), Some(searched)) = (
                run.values.get(at),
                retained.get(at..at.saturating_add(fitting)),
            ) else {
                return Search::Continue;
            };
            return each_offset_of(*value, searched, report);
        }
        (None, Some(&value), Some(&mask)) => {
            let searched = retained.get(..fitting).unwrap_or_default();
            for (offset, byte) in searched.iter().enumerate() {
                if byte & mask == value && report(offset) == Search::Stop {
                    return Search::Stop;
                }
            }
        }
        (None, _, _) => {
            for offset in 0..fitting {
                if report(offset) == Search::Stop {
                    return Search::Stop;
                }
            }
        }
    }
    Search::Continue
}

const BYTES_PER_WORD: usize = 8;
const EVERY_BYTE_LOW_BIT: u64 = 0x0101_0101_0101_0101;
const EVERY_BYTE_HIGH_BIT: u64 = 0x8080_8080_8080_8080;

fn each_offset_of(value: u8, haystack: &[u8], mut found: impl FnMut(usize) -> Search) -> Search {
    let repeated = EVERY_BYTE_LOW_BIT.wrapping_mul(u64::from(value));
    let (words, rest) = haystack.as_chunks::<BYTES_PER_WORD>();
    let mut word_start = 0usize;
    for word in words {
        let differences = u64::from_le_bytes(*word) ^ repeated;
        let may_hold =
            differences.wrapping_sub(EVERY_BYTE_LOW_BIT) & !differences & EVERY_BYTE_HIGH_BIT;
        if may_hold != 0 {
            for (index, byte) in word.iter().enumerate() {
                if *byte == value && found(word_start.saturating_add(index)) == Search::Stop {
                    return Search::Stop;
                }
            }
        }
        word_start = word_start.saturating_add(BYTES_PER_WORD);
    }
    for (index, byte) in rest.iter().enumerate() {
        if *byte == value && found(word_start.saturating_add(index)) == Search::Stop {
            return Search::Stop;
        }
    }
    Search::Continue
}

pub fn match_ends(
    program: &ProgramView<'_>,
    bytes: &RetainedBytes<'_>,
    starts: &PositionSet,
) -> Result<PositionSet, ProgramMalformed> {
    if let Some(run) = program.only_run() {
        return run_ends(run, bytes, starts);
    }
    let mut positions = if program.before.is_some() {
        let mut held = PositionSet::default();
        for start in starts.positions() {
            if context_holds(program.before, bytes, start, Side::Before)? {
                held.add_position(start);
            }
        }
        held
    } else {
        starts.clone()
    };
    for step in program.steps() {
        if positions.is_empty() {
            return Ok(positions);
        }
        positions = apply_step(step?, bytes, &positions)?;
    }
    let mut ends = PositionSet::default();
    for end in positions.positions() {
        if context_holds(program.after, bytes, end, Side::After)? {
            ends.add_position(end);
        }
    }
    Ok(ends)
}

fn run_ends(
    run: MaskedRun<'_>,
    bytes: &RetainedBytes<'_>,
    starts: &PositionSet,
) -> Result<PositionSet, ProgramMalformed> {
    let length = u64::try_from(run.len()).map_err(|_| ProgramMalformed)?;
    let mut ends = PositionSet::default();
    for range in starts.ranges() {
        find_run_starts(run, bytes, range, |start| {
            if let Some(end) = start.checked_add(length) {
                ends.add_position(end);
            }
            Search::Continue
        });
    }
    Ok(ends)
}

fn apply_step(
    step: StepView<'_>,
    bytes: &RetainedBytes<'_>,
    positions: &PositionSet,
) -> Result<PositionSet, ProgramMalformed> {
    match step {
        StepView::Bytes(run) => run_ends(run, bytes, positions),
        StepView::OneOf(set) => {
            let mut next = PositionSet::default();
            for position in positions.positions() {
                let accepted = bytes
                    .byte(position)
                    .is_some_and(|byte| set_in_sequence_contains(set, 0, byte));
                if accepted && let Some(after) = position.checked_add(1) {
                    next.add_position(after);
                }
            }
            Ok(next)
        }
        StepView::Gap { minimum, maximum } => {
            let mut next = PositionSet::default();
            if maximum < minimum {
                return Ok(next);
            }
            for range in positions.ranges() {
                let start = range.start.saturating_add(u64::from(minimum));
                let end = range
                    .end
                    .saturating_add(u64::from(maximum))
                    .min(bytes.object_length.saturating_add(1));
                next.add(start..end);
            }
            Ok(next)
        }
        StepView::Choice(alternatives) => {
            let mut next = Vec::new();
            for alternative in alternatives.iter() {
                next.extend(run_ends(alternative?, bytes, positions)?.ranges().cloned());
            }
            Ok(PositionSet::of_unordered(next))
        }
        StepView::NoneOf { width, excluded } => {
            let width_in_bytes = usize::try_from(width).map_err(|_| ProgramMalformed)?;
            let mut next = PositionSet::default();
            for position in positions.positions() {
                let Some(window) = bytes.slice(position, width_in_bytes) else {
                    continue;
                };
                let mut is_excluded = false;
                for alternative in excluded.iter() {
                    if alternative?.matches(window) {
                        is_excluded = true;
                    }
                }
                if !is_excluded && let Some(after) = position.checked_add(u64::from(width)) {
                    next.add_position(after);
                }
            }
            Ok(next)
        }
    }
}

#[derive(Clone, Copy)]
enum Side {
    Before,
    After,
}

fn context_holds(
    test: Option<ContextView<'_>>,
    bytes: &RetainedBytes<'_>,
    position: u64,
    side: Side,
) -> Result<bool, ProgramMalformed> {
    let Some(test) = test else {
        return Ok(true);
    };
    let at_edge = match side {
        Side::Before => position == 0,
        Side::After => position >= bytes.object_length,
    };
    if at_edge {
        return Ok(test.satisfied_at_object_edge);
    }
    let mut seen = false;
    for sets in test.sequences() {
        let sets = sets?;
        let length = sets.len() / 32;
        let first = match side {
            Side::Before => {
                position.checked_sub(u64::try_from(length).map_err(|_| ProgramMalformed)?)
            }
            Side::After => Some(position),
        };
        let Some(window) = first.and_then(|first| bytes.slice(first, length)) else {
            continue;
        };
        if window
            .iter()
            .enumerate()
            .all(|(index, byte)| set_in_sequence_contains(sets, index, *byte))
        {
            seen = true;
        }
    }
    Ok(seen != test.negated)
}
