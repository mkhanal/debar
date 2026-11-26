use zerocopy::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::byte_rarity::{rarity_of, spread_penalty};
use crate::model::{ByteSet, ContextTest, MaskedByte, Pattern, PatternElement};

pub const LONG_ANCHOR_LENGTH: usize = 4;
pub const SHORT_ANCHOR_LENGTH: usize = 2;
pub const LONGEST_BOUNDED_SPAN: u32 = 1 << 20;
pub const MOST_SEGMENTS: usize = 1024;
const BYTE_SET_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternNotCompiled {
    NothingToMatch,
    SpanTooLong,
    TooManySegments,
    ElementTooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Bytes(Vec<MaskedByte>),
    OneOf(ByteSet),
    Gap {
        minimum: u32,
        maximum: u32,
    },
    Choice(Vec<Vec<MaskedByte>>),
    NoneOf {
        width: u32,
        excluded: Vec<Vec<MaskedByte>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Displacement {
    pub nearest: u32,
    pub farthest: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    Long {
        bytes: [u8; LONG_ANCHOR_LENGTH],
        displacement: Displacement,
    },
    Short {
        bytes: [u8; SHORT_ANCHOR_LENGTH],
        displacement: Displacement,
    },
    Everywhere,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    steps: Vec<Step>,
    pub gap_before: u32,
    pub gap_most: Option<u32>,
    pub shortest: u32,
    pub longest: u32,
    pub anchor: Anchor,
    before: Option<ContextTest>,
    after: Option<ContextTest>,
}

impl Segment {
    #[must_use]
    pub fn context_reach_before(&self) -> u32 {
        context_reach(self.before.as_ref())
    }
}

fn context_reach(test: Option<&ContextTest>) -> u32 {
    test.map_or(0, |test| {
        test.sequences
            .iter()
            .map(|sequence| u32::try_from(sequence.len()).unwrap_or(u32::MAX))
            .max()
            .unwrap_or(0)
    })
}

pub fn segments_of(pattern: &Pattern) -> Result<Vec<Segment>, PatternNotCompiled> {
    let mut pieces: Vec<Piece> = vec![Piece::default()];
    for element in &pattern.elements {
        match element {
            PatternElement::Gap {
                minimum,
                maximum: None,
            } => {
                let follows_a_gap = pieces.len() > 1;
                match pieces.last_mut() {
                    Some(piece) if piece.steps.is_empty() && follows_a_gap => {
                        piece.gap_before = piece.gap_before.saturating_add(*minimum);
                        piece.gap_most = None;
                    }
                    _ => pieces.push(Piece {
                        gap_before: *minimum,
                        gap_most: None,
                        steps: Vec::new(),
                    }),
                }
            }
            PatternElement::PartBreak { minimum, maximum } => pieces.push(Piece {
                gap_before: *minimum,
                gap_most: *maximum,
                steps: Vec::new(),
            }),
            other => {
                if let Some(piece) = pieces.last_mut() {
                    push_step(&mut piece.steps, other);
                }
            }
        }
    }
    if pieces.len() > MOST_SEGMENTS {
        return Err(PatternNotCompiled::TooManySegments);
    }
    let last = pieces.len().saturating_sub(1);
    let mut segments = Vec::with_capacity(pieces.len());
    for (index, piece) in pieces.into_iter().enumerate() {
        let (shortest, longest) = span_of(&piece.steps)?;
        if longest == 0 {
            return Err(PatternNotCompiled::NothingToMatch);
        }
        segments.push(Segment {
            anchor: anchor_of(&piece.steps),
            steps: piece.steps,
            gap_before: piece.gap_before,
            gap_most: piece.gap_most,
            shortest,
            longest,
            before: if index == 0 {
                pattern.before.clone()
            } else {
                None
            },
            after: if index == last {
                pattern.after.clone()
            } else {
                None
            },
        });
    }
    Ok(segments)
}

#[derive(Default)]
struct Piece {
    gap_before: u32,
    gap_most: Option<u32>,
    steps: Vec<Step>,
}

fn push_step(steps: &mut Vec<Step>, element: &PatternElement) {
    match element {
        PatternElement::Byte(byte) => {
            if let Some(Step::Bytes(run)) = steps.last_mut() {
                run.push(*byte);
            } else {
                steps.push(Step::Bytes(vec![*byte]));
            }
        }
        PatternElement::OneOf(set) => steps.push(Step::OneOf(*set)),
        PatternElement::Gap { minimum, maximum }
        | PatternElement::PartBreak { minimum, maximum } => {
            steps.push(Step::Gap {
                minimum: *minimum,
                maximum: maximum.unwrap_or(*minimum),
            });
        }
        PatternElement::Choice(alternatives) => steps.push(Step::Choice(alternatives.clone())),
        PatternElement::NoneOf { width, excluded } => steps.push(Step::NoneOf {
            width: *width,
            excluded: excluded.clone(),
        }),
    }
}

fn span_of(steps: &[Step]) -> Result<(u32, u32), PatternNotCompiled> {
    let mut shortest: u32 = 0;
    let mut longest: u32 = 0;
    for step in steps {
        let (low, high) = step_span(step)?;
        shortest = shortest.saturating_add(low);
        longest = longest
            .checked_add(high)
            .filter(|longest| *longest <= LONGEST_BOUNDED_SPAN)
            .ok_or(PatternNotCompiled::SpanTooLong)?;
    }
    Ok((shortest, longest))
}

fn step_span(step: &Step) -> Result<(u32, u32), PatternNotCompiled> {
    let length = |run: &Vec<MaskedByte>| {
        u32::try_from(run.len()).map_err(|_| PatternNotCompiled::ElementTooLarge)
    };
    Ok(match step {
        Step::Bytes(run) => {
            let length = length(run)?;
            (length, length)
        }
        Step::OneOf(_) => (1, 1),
        Step::Gap { minimum, maximum } => (*minimum, *maximum),
        Step::Choice(alternatives) => {
            let lengths = alternatives
                .iter()
                .map(length)
                .collect::<Result<Vec<u32>, _>>()?;
            (
                lengths.iter().copied().min().unwrap_or(0),
                lengths.iter().copied().max().unwrap_or(0),
            )
        }
        Step::NoneOf { width, .. } => (*width, *width),
    })
}

struct AnchorCandidate {
    score: u32,
    bytes: Vec<u8>,
    displacement: Displacement,
}

fn anchor_of(steps: &[Step]) -> Anchor {
    if let Some(best) = best_window(steps, LONG_ANCHOR_LENGTH)
        && let Ok(bytes) = <[u8; LONG_ANCHOR_LENGTH]>::try_from(best.bytes.as_slice())
    {
        return Anchor::Long {
            bytes,
            displacement: best.displacement,
        };
    }
    if let Some(best) = best_window(steps, SHORT_ANCHOR_LENGTH)
        && let Ok(bytes) = <[u8; SHORT_ANCHOR_LENGTH]>::try_from(best.bytes.as_slice())
    {
        return Anchor::Short {
            bytes,
            displacement: best.displacement,
        };
    }
    Anchor::Everywhere
}

fn best_window(steps: &[Step], window_length: usize) -> Option<AnchorCandidate> {
    let mut nearest: u32 = 0;
    let mut farthest: u32 = 0;
    let mut best: Option<AnchorCandidate> = None;
    for step in steps {
        if let Step::Bytes(run) = step {
            for (start, window) in run.windows(window_length).enumerate() {
                if !window.iter().all(|byte| byte.is_exact()) {
                    continue;
                }
                let Ok(start) = u32::try_from(start) else {
                    continue;
                };
                let bytes: Vec<u8> = window.iter().map(|byte| byte.value).collect();
                let displacement = Displacement {
                    nearest: nearest.saturating_add(start),
                    farthest: farthest.saturating_add(start),
                };
                let score = rarity_of(&bytes).saturating_sub(spread_penalty(
                    displacement.farthest.saturating_sub(displacement.nearest),
                ));
                if best.as_ref().is_none_or(|best| score > best.score) {
                    best = Some(AnchorCandidate {
                        score,
                        bytes,
                        displacement,
                    });
                }
            }
        }
        let (low, high) = step_span(step).unwrap_or((u32::MAX, u32::MAX));
        nearest = nearest.saturating_add(low);
        farthest = farthest.saturating_add(high);
    }
    best
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct ProgramHeader {
    pub signature: U32,
    pub segment: U32,
    pub segment_count: U32,
    pub gap_before: U32,
    pub gap_most: U32,
    pub shortest: U32,
    pub longest: U32,
    pub step_count: U32,
    pub context_flags: U32,
}

const HAS_BEFORE: u32 = 1;
const HAS_AFTER: u32 = 2;
const HAS_GAP_MOST: u32 = 4;
const TAG_BYTES: u8 = 1;
const TAG_ONE_OF: u8 = 2;
const TAG_GAP: u8 = 3;
const TAG_CHOICE: u8 = 4;
const TAG_NONE_OF: u8 = 5;

pub struct ProgramPlace {
    pub signature: u32,
    pub segment: u32,
    pub segment_count: u32,
}

pub fn encode(segment: &Segment, place: &ProgramPlace) -> Result<Vec<u8>, PatternNotCompiled> {
    let mut context_flags = 0;
    if segment.before.is_some() {
        context_flags |= HAS_BEFORE;
    }
    if segment.after.is_some() {
        context_flags |= HAS_AFTER;
    }
    if segment.gap_most.is_some() {
        context_flags |= HAS_GAP_MOST;
    }
    let header = ProgramHeader {
        signature: U32::new(place.signature),
        segment: U32::new(place.segment),
        segment_count: U32::new(place.segment_count),
        gap_before: U32::new(segment.gap_before),
        gap_most: U32::new(segment.gap_most.unwrap_or(0)),
        shortest: U32::new(segment.shortest),
        longest: U32::new(segment.longest),
        step_count: U32::new(
            u32::try_from(segment.steps.len()).map_err(|_| PatternNotCompiled::ElementTooLarge)?,
        ),
        context_flags: U32::new(context_flags),
    };
    let mut bytes = header.as_bytes().to_vec();
    for test in [&segment.before, &segment.after].into_iter().flatten() {
        encode_context(&mut bytes, test)?;
    }
    for step in &segment.steps {
        encode_step(&mut bytes, step)?;
    }
    Ok(bytes)
}

fn encode_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), PatternNotCompiled> {
    let count = u16::try_from(count).map_err(|_| PatternNotCompiled::ElementTooLarge)?;
    bytes.extend_from_slice(U16::new(count).as_bytes());
    Ok(())
}

fn encode_context(bytes: &mut Vec<u8>, test: &ContextTest) -> Result<(), PatternNotCompiled> {
    bytes.push(u8::from(test.negated));
    bytes.push(u8::from(test.satisfied_at_object_edge));
    encode_count(bytes, test.sequences.len())?;
    for sequence in &test.sequences {
        encode_count(bytes, sequence.len())?;
        for set in sequence {
            bytes.extend_from_slice(&set.0);
        }
    }
    Ok(())
}

fn encode_run(bytes: &mut Vec<u8>, run: &[MaskedByte]) -> Result<(), PatternNotCompiled> {
    encode_count(bytes, run.len())?;
    bytes.extend(run.iter().map(|byte| byte.value & byte.mask));
    bytes.extend(run.iter().map(|byte| byte.mask));
    Ok(())
}

fn encode_runs(bytes: &mut Vec<u8>, runs: &[Vec<MaskedByte>]) -> Result<(), PatternNotCompiled> {
    encode_count(bytes, runs.len())?;
    for run in runs {
        encode_run(bytes, run)?;
    }
    Ok(())
}

fn encode_step(bytes: &mut Vec<u8>, step: &Step) -> Result<(), PatternNotCompiled> {
    match step {
        Step::Bytes(run) => {
            bytes.push(TAG_BYTES);
            let length =
                u32::try_from(run.len()).map_err(|_| PatternNotCompiled::ElementTooLarge)?;
            bytes.extend_from_slice(U32::new(length).as_bytes());
            bytes.extend(run.iter().map(|byte| byte.value & byte.mask));
            bytes.extend(run.iter().map(|byte| byte.mask));
        }
        Step::OneOf(set) => {
            bytes.push(TAG_ONE_OF);
            bytes.extend_from_slice(&set.0);
        }
        Step::Gap { minimum, maximum } => {
            bytes.push(TAG_GAP);
            bytes.extend_from_slice(U32::new(*minimum).as_bytes());
            bytes.extend_from_slice(U32::new(*maximum).as_bytes());
        }
        Step::Choice(alternatives) => {
            bytes.push(TAG_CHOICE);
            encode_runs(bytes, alternatives)?;
        }
        Step::NoneOf { width, excluded } => {
            bytes.push(TAG_NONE_OF);
            bytes.extend_from_slice(U32::new(*width).as_bytes());
            encode_runs(bytes, excluded)?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramMalformed;

#[derive(Debug, Clone, Copy)]
pub struct MaskedRun<'m> {
    pub values: &'m [u8],
    pub masks: &'m [u8],
}

impl MaskedRun<'_> {
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    #[must_use]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        bytes.len() == self.values.len()
            && bytes
                .iter()
                .zip(self.values)
                .zip(self.masks)
                .all(|((byte, value), mask)| byte & mask == *value)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Runs<'m> {
    count: u16,
    bytes: &'m [u8],
}

impl<'m> Runs<'m> {
    pub fn iter(&self) -> impl Iterator<Item = Result<MaskedRun<'m>, ProgramMalformed>> + 'm {
        let mut rest = self.bytes;
        (0..self.count).map(move |_| {
            let run;
            (run, rest) = read_run(rest)?;
            Ok(run)
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ContextView<'m> {
    pub negated: bool,
    pub satisfied_at_object_edge: bool,
    sequence_count: u16,
    bytes: &'m [u8],
}

impl<'m> ContextView<'m> {
    pub fn sequences(&self) -> impl Iterator<Item = Result<&'m [u8], ProgramMalformed>> + 'm {
        let mut rest = self.bytes;
        (0..self.sequence_count).map(move |_| {
            let (length, after) = read_u16(rest)?;
            let set_bytes = usize::from(length)
                .checked_mul(BYTE_SET_LENGTH)
                .ok_or(ProgramMalformed)?;
            let (sets, after) = after.split_at_checked(set_bytes).ok_or(ProgramMalformed)?;
            rest = after;
            Ok(sets)
        })
    }
}

#[must_use]
pub fn set_in_sequence_contains(sets: &[u8], index: usize, byte: u8) -> bool {
    index
        .checked_mul(BYTE_SET_LENGTH)
        .and_then(|start| sets.get(start.checked_add(usize::from(byte >> 3))?))
        .is_some_and(|slot| slot & (1 << (byte & 7)) != 0)
}

#[derive(Debug, Clone, Copy)]
pub enum StepView<'m> {
    Bytes(MaskedRun<'m>),
    OneOf(&'m [u8; BYTE_SET_LENGTH]),
    Gap { minimum: u32, maximum: u32 },
    Choice(Runs<'m>),
    NoneOf { width: u32, excluded: Runs<'m> },
}

#[derive(Clone, Copy)]
pub struct ProgramView<'m> {
    pub header: &'m ProgramHeader,
    pub before: Option<ContextView<'m>>,
    pub after: Option<ContextView<'m>>,
    steps: &'m [u8],
}

impl<'m> ProgramView<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, ProgramMalformed> {
        let (header, mut rest) =
            ProgramHeader::ref_from_prefix(bytes).map_err(|_| ProgramMalformed)?;
        let flags = header.context_flags.get();
        let mut before = None;
        let mut after = None;
        if flags & HAS_BEFORE != 0 {
            let view;
            (view, rest) = read_context(rest)?;
            before = Some(view);
        }
        if flags & HAS_AFTER != 0 {
            let view;
            (view, rest) = read_context(rest)?;
            after = Some(view);
        }
        Ok(Self {
            header,
            before,
            after,
            steps: rest,
        })
    }

    pub fn steps(&self) -> impl Iterator<Item = Result<StepView<'m>, ProgramMalformed>> + 'm {
        let mut rest = self.steps;
        let count = self.header.step_count.get();
        (0..count).map(move |_| {
            let step;
            (step, rest) = read_step(rest)?;
            Ok(step)
        })
    }

    #[must_use]
    pub fn gap_most(&self) -> Option<u32> {
        (self.header.context_flags.get() & HAS_GAP_MOST != 0).then(|| self.header.gap_most.get())
    }

    #[must_use]
    pub fn only_run(&self) -> Option<MaskedRun<'m>> {
        if self.header.step_count.get() != 1 || self.before.is_some() || self.after.is_some() {
            return None;
        }
        match self.steps().next()? {
            Ok(StepView::Bytes(run)) => Some(run),
            _ => None,
        }
    }
}

fn read_u16(bytes: &[u8]) -> Result<(u16, &[u8]), ProgramMalformed> {
    let (value, rest) = U16::read_from_prefix(bytes).map_err(|_| ProgramMalformed)?;
    Ok((value.get(), rest))
}

fn read_u32(bytes: &[u8]) -> Result<(u32, &[u8]), ProgramMalformed> {
    let (value, rest) = U32::read_from_prefix(bytes).map_err(|_| ProgramMalformed)?;
    Ok((value.get(), rest))
}

fn read_context(bytes: &[u8]) -> Result<(ContextView<'_>, &[u8]), ProgramMalformed> {
    let (&[negated, edge], rest) = bytes.split_first_chunk::<2>().ok_or(ProgramMalformed)?;
    let (sequence_count, after_count) = read_u16(rest)?;
    let mut cursor = after_count;
    for _ in 0..sequence_count {
        let (length, after) = read_u16(cursor)?;
        let set_bytes = usize::from(length)
            .checked_mul(BYTE_SET_LENGTH)
            .ok_or(ProgramMalformed)?;
        cursor = after.get(set_bytes..).ok_or(ProgramMalformed)?;
    }
    let consumed = after_count
        .len()
        .checked_sub(cursor.len())
        .ok_or(ProgramMalformed)?;
    Ok((
        ContextView {
            negated: negated != 0,
            satisfied_at_object_edge: edge != 0,
            sequence_count,
            bytes: after_count.get(..consumed).ok_or(ProgramMalformed)?,
        },
        cursor,
    ))
}

fn read_run(bytes: &[u8]) -> Result<(MaskedRun<'_>, &[u8]), ProgramMalformed> {
    let (length, rest) = read_u16(bytes)?;
    let length = usize::from(length);
    let (values, rest) = rest.split_at_checked(length).ok_or(ProgramMalformed)?;
    let (masks, rest) = rest.split_at_checked(length).ok_or(ProgramMalformed)?;
    Ok((MaskedRun { values, masks }, rest))
}

fn read_runs(bytes: &[u8]) -> Result<(Runs<'_>, &[u8]), ProgramMalformed> {
    let (count, after_count) = read_u16(bytes)?;
    let mut cursor = after_count;
    for _ in 0..count {
        (_, cursor) = read_run(cursor)?;
    }
    let consumed = after_count
        .len()
        .checked_sub(cursor.len())
        .ok_or(ProgramMalformed)?;
    Ok((
        Runs {
            count,
            bytes: after_count.get(..consumed).ok_or(ProgramMalformed)?,
        },
        cursor,
    ))
}

fn read_step(bytes: &[u8]) -> Result<(StepView<'_>, &[u8]), ProgramMalformed> {
    let (tag, rest) = bytes.split_first().ok_or(ProgramMalformed)?;
    match *tag {
        TAG_BYTES => {
            let (length, rest) = read_u32(rest)?;
            let length = usize::try_from(length).map_err(|_| ProgramMalformed)?;
            let (values, rest) = rest.split_at_checked(length).ok_or(ProgramMalformed)?;
            let (masks, rest) = rest.split_at_checked(length).ok_or(ProgramMalformed)?;
            Ok((StepView::Bytes(MaskedRun { values, masks }), rest))
        }
        TAG_ONE_OF => {
            let (set, rest) = rest
                .split_first_chunk::<BYTE_SET_LENGTH>()
                .ok_or(ProgramMalformed)?;
            Ok((StepView::OneOf(set), rest))
        }
        TAG_GAP => {
            let (minimum, rest) = read_u32(rest)?;
            let (maximum, rest) = read_u32(rest)?;
            Ok((StepView::Gap { minimum, maximum }, rest))
        }
        TAG_CHOICE => {
            let (runs, rest) = read_runs(rest)?;
            Ok((StepView::Choice(runs), rest))
        }
        TAG_NONE_OF => {
            let (width, rest) = read_u32(rest)?;
            let (excluded, rest) = read_runs(rest)?;
            Ok((StepView::NoneOf { width, excluded }, rest))
        }
        _ => Err(ProgramMalformed),
    }
}
