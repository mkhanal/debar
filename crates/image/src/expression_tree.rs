use regex_syntax::hir::{Class, ClassBytes, ClassBytesRange, Hir, Look, Repetition};

use crate::model::ByteSet;

const NEWLINE: u8 = b'\n';

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpressionTree {
    Empty,
    Byte(ByteSet),
    Concat(Vec<ExpressionTree>),
    Alternation(Vec<ExpressionTree>),
    Repetition(Box<TreeRepetition>),
    Capture {
        group: u32,
        item: Box<ExpressionTree>,
    },
    Backreference {
        group: u32,
        caseless: bool,
    },
    Assertion(Assertion),
    Lookaround {
        direction: LookDirection,
        negated: bool,
        item: Box<ExpressionTree>,
    },
    Atomic(Box<ExpressionTree>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeRepetition {
    pub min: u32,
    pub max: Option<u32>,
    pub greed: Greed,
    pub item: ExpressionTree,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Greed {
    Greedy,
    Lazy,
    Possessive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LookDirection {
    Ahead,
    Behind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Assertion {
    SubjectStart,
    SubjectEnd,
    SubjectEndOrBeforeFinalNewline,
    LineStartNotAtSubjectEnd,
    LineEnd,
    WordBoundary,
    NotWordBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedsBacktracking {
    Backreference,
    Lookaround,
    AtomicGroup,
    PossessiveQuantifier,
    EndBeforeFinalNewlineThenNewline,
}

impl ExpressionTree {
    #[must_use]
    pub fn literal(bytes: &[u8]) -> Self {
        Self::Concat(
            bytes
                .iter()
                .map(|byte| Self::Byte(ByteSet::of([*byte])))
                .collect(),
        )
    }

    pub fn linear_form(&self) -> Result<Hir, NeedsBacktracking> {
        Ok(match self {
            Self::Empty => Hir::empty(),
            Self::Byte(set) => byte_set_hir(set),
            Self::Concat(items) => concat_hir(items)?,
            Self::Alternation(branches) => Hir::alternation(
                branches
                    .iter()
                    .map(Self::linear_form)
                    .collect::<Result<_, _>>()?,
            ),
            Self::Repetition(repetition) => {
                let greedy = match repetition.greed {
                    Greed::Greedy => true,
                    Greed::Lazy => false,
                    Greed::Possessive => return Err(NeedsBacktracking::PossessiveQuantifier),
                };
                Hir::repetition(Repetition {
                    min: repetition.min,
                    max: repetition.max,
                    greedy,
                    sub: Box::new(repetition.item.linear_form()?),
                })
            }
            Self::Capture { item, .. } => item.linear_form()?,
            Self::Backreference { .. } => return Err(NeedsBacktracking::Backreference),
            Self::Assertion(assertion) => assertion_hir(*assertion),
            Self::Lookaround { .. } => return Err(NeedsBacktracking::Lookaround),
            Self::Atomic(_) => return Err(NeedsBacktracking::AtomicGroup),
        })
    }

    #[must_use]
    pub fn shortest_match(&self) -> u32 {
        match self {
            Self::Empty
            | Self::Assertion(_)
            | Self::Lookaround { .. }
            | Self::Backreference { .. } => 0,
            Self::Byte(_) => 1,
            Self::Concat(items) => items.iter().fold(0u32, |total, item| {
                total.saturating_add(item.shortest_match())
            }),
            Self::Alternation(branches) => {
                branches.iter().map(Self::shortest_match).min().unwrap_or(0)
            }
            Self::Repetition(repetition) => repetition
                .item
                .shortest_match()
                .saturating_mul(repetition.min),
            Self::Capture { item, .. } | Self::Atomic(item) => item.shortest_match(),
        }
    }

    #[must_use]
    pub fn longest_match(&self) -> Option<u32> {
        match self {
            Self::Empty | Self::Assertion(_) | Self::Lookaround { .. } => Some(0),
            Self::Byte(_) => Some(1),
            Self::Backreference { .. } => None,
            Self::Concat(items) => items
                .iter()
                .try_fold(0u32, |total, item| total.checked_add(item.longest_match()?)),
            Self::Alternation(branches) => branches
                .iter()
                .map(Self::longest_match)
                .try_fold(0u32, |longest, branch| Some(longest.max(branch?))),
            Self::Repetition(repetition) => {
                let item = repetition.item.longest_match()?;
                if item == 0 {
                    return Some(0);
                }
                item.checked_mul(repetition.max?)
            }
            Self::Capture { item, .. } | Self::Atomic(item) => item.longest_match(),
        }
    }

    #[must_use]
    pub fn can_start_with(&self, byte: u8) -> bool {
        match self {
            Self::Empty | Self::Assertion(_) | Self::Lookaround { .. } => false,
            Self::Byte(set) => set.contains(byte),
            Self::Backreference { .. } => true,
            Self::Repetition(repetition) => repetition.item.can_start_with(byte),
            Self::Capture { item, .. } | Self::Atomic(item) => item.can_start_with(byte),
            Self::Concat(items) => {
                for item in items {
                    if item.can_start_with(byte) {
                        return true;
                    }
                    if item.shortest_match() > 0 {
                        return false;
                    }
                }
                false
            }
            Self::Alternation(branches) => {
                branches.iter().any(|branch| branch.can_start_with(byte))
            }
        }
    }
}

fn concat_hir(items: &[ExpressionTree]) -> Result<Hir, NeedsBacktracking> {
    let mut converted = Vec::with_capacity(items.len());
    let mut after_end_before_final_newline = false;
    for item in items {
        if after_end_before_final_newline && item.shortest_match() != 0 {
            if item.can_start_with(NEWLINE) {
                return Err(NeedsBacktracking::EndBeforeFinalNewlineThenNewline);
            }
            after_end_before_final_newline = false;
        }
        if *item == ExpressionTree::Assertion(Assertion::SubjectEndOrBeforeFinalNewline) {
            after_end_before_final_newline = true;
        }
        converted.push(item.linear_form()?);
    }
    Ok(Hir::concat(converted))
}

fn assertion_hir(assertion: Assertion) -> Hir {
    match assertion {
        Assertion::SubjectStart => Hir::look(Look::Start),
        Assertion::SubjectEnd => Hir::look(Look::End),
        Assertion::SubjectEndOrBeforeFinalNewline => Hir::alternation(vec![
            Hir::look(Look::End),
            Hir::concat(vec![Hir::literal(vec![NEWLINE]), Hir::look(Look::End)]),
        ]),
        Assertion::LineStartNotAtSubjectEnd => Hir::look(Look::StartLF),
        Assertion::LineEnd => Hir::look(Look::EndLF),
        Assertion::WordBoundary => Hir::look(Look::WordAscii),
        Assertion::NotWordBoundary => Hir::look(Look::WordAsciiNegate),
    }
}

#[must_use]
pub fn byte_set_hir(set: &ByteSet) -> Hir {
    let members: Vec<u8> = (0..=u8::MAX).filter(|byte| set.contains(*byte)).collect();
    if let [only] = members.as_slice() {
        return Hir::literal(vec![*only]);
    }
    let mut ranges = Vec::new();
    let mut start: Option<u8> = None;
    for byte in 0..=u8::MAX {
        match (set.contains(byte), start) {
            (true, None) => start = Some(byte),
            (false, Some(low)) => {
                ranges.push(ClassBytesRange::new(low, byte.saturating_sub(1)));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(low) = start {
        ranges.push(ClassBytesRange::new(low, u8::MAX));
    }
    Hir::class(Class::Bytes(ClassBytes::new(ranges)))
}
