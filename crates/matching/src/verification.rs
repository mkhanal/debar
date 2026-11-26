use std::ops::Range;

use debar_image::{
    ContextView, MaskedRun, ProgramMalformed, ProgramView, StepView, set_in_sequence_contains,
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
    ranges: Vec<Range<u64>>,
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
        let mut set = Self::default();
        for (first, last) in ranges {
            if first <= last
                && let Some(end) = last.checked_add(1)
            {
                set.ranges.push(first..end);
            }
        }
        set.normalised()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    #[must_use]
    pub fn first(&self) -> Option<u64> {
        self.ranges.first().map(|range| range.start)
    }

    fn positions(&self) -> impl Iterator<Item = u64> + '_ {
        self.ranges.iter().flat_map(Clone::clone)
    }

    fn add(&mut self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }
        match self.ranges.last_mut() {
            Some(last) if last.end >= range.start && last.start <= range.start => {
                last.end = last.end.max(range.end);
            }
            _ => self.ranges.push(range),
        }
    }

    fn add_position(&mut self, position: u64) {
        if let Some(end) = position.checked_add(1) {
            self.add(position..end);
        }
    }

    fn normalised(mut self) -> Self {
        self.ranges.sort_by_key(|range| range.start);
        let mut merged = Self::default();
        for range in self.ranges {
            merged.add(range);
        }
        merged
    }
}

pub fn match_ends(
    program: &ProgramView<'_>,
    bytes: &RetainedBytes<'_>,
    starts: &PositionSet,
) -> Result<PositionSet, ProgramMalformed> {
    if let Some(run) = program.only_run() {
        return run_ends(run, bytes, starts);
    }
    let mut positions = PositionSet::default();
    for start in starts.positions() {
        if context_holds(program.before, bytes, start, Side::Before)? {
            positions.add_position(start);
        }
    }
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
    for start in starts.positions() {
        if bytes
            .slice(start, run.len())
            .is_some_and(|window| run.matches(window))
            && let Some(end) = start.checked_add(length)
        {
            ends.add_position(end);
        }
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
            for range in &positions.ranges {
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
            let mut next = PositionSet::default();
            for alternative in alternatives.iter() {
                for range in run_ends(alternative?, bytes, positions)?.ranges {
                    next.ranges.push(range);
                }
            }
            Ok(next.normalised())
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
