use zerocopy::little_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::expression_tree::{Assertion, ExpressionTree, Greed, LookDirection, TreeRepetition};
use crate::model::ByteSet;

pub const LARGEST_BACKTRACKING_PROGRAM: usize = 65_536;
pub const DEEPEST_NESTED_ASSERTION: u32 = 32;
pub const MOST_CAPTURE_GROUPS: u32 = 1_000;
const NO_MAXIMUM: u32 = u32::MAX;
const FILTERS_START_BYTES: u8 = 1;

const OP_MATCH: u8 = 1;
const OP_BYTE: u8 = 2;
const OP_SPLIT: u8 = 3;
const OP_JUMP: u8 = 4;
const OP_SAVE: u8 = 5;
const OP_ASSERT: u8 = 6;
const OP_BACKREFERENCE: u8 = 7;
const OP_REPEAT_BYTE: u8 = 8;
const OP_LOOK: u8 = 9;
const OP_ATOMIC: u8 = 10;
const OP_MARK: u8 = 11;
const OP_CHECK_PROGRESS: u8 = 12;

const LOOK_BEHIND: u8 = 1;
const LOOK_NEGATED: u8 = 2;
const CASELESS: u8 = 1;
const GREED_GREEDY: u8 = 1;
const GREED_LAZY: u8 = 2;
const GREED_POSSESSIVE: u8 = 3;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Header {
    instruction_count: U32,
    set_count: U32,
    range_count: U32,
    capture_groups: U32,
    register_count: U32,
    nesting: U32,
    start_bytes: [u8; 32],
    flags: u8,
    reserved: [u8; 7],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct InstructionEntry {
    op: u8,
    flag: u8,
    reserved: [u8; 2],
    a: U32,
    b: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct RangeEntry {
    min: U32,
    max: U32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BacktrackingNotCompiled {
    TooLarge,
    NestedTooDeep,
    TooManyGroups,
    UnboundedLookbehind,
    BackreferenceToNoGroup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BacktrackingProgramMalformed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepeatedByte {
    pub set: u32,
    pub min: u32,
    pub max: Option<u32>,
    pub greed: Greed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookInstruction {
    pub direction: LookDirection,
    pub negated: bool,
    pub shortest: u32,
    pub longest: u32,
    pub continuation: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instruction {
    Match,
    Byte { set: u32 },
    Split { first: u32, second: u32 },
    Jump { to: u32 },
    Save { slot: u32 },
    Assert(Assertion),
    Backreference { group: u32, caseless: bool },
    RepeatByte(RepeatedByte),
    Look(LookInstruction),
    Atomic { continuation: u32 },
    Mark { register: u32 },
    CheckProgress { register: u32, loop_head: u32 },
}

pub fn compile_backtracking(tree: &ExpressionTree) -> Result<Vec<u8>, BacktrackingNotCompiled> {
    let mut compiler = Compiler::default();
    let groups = highest_group(tree)?;
    compiler.capture_groups = groups.saturating_add(1);
    compiler.tree(tree, 0)?;
    compiler.emit(OP_MATCH, 0, 0, 0)?;
    let filters = tree.shortest_match() > 0;
    let start_bytes = if filters {
        ByteSet::of((0..=u8::MAX).filter(|byte| tree.can_start_with(*byte)))
    } else {
        ByteSet::of(0..=u8::MAX)
    };
    let header = Header {
        instruction_count: U32::new(count(compiler.instructions.len())?),
        set_count: U32::new(count(compiler.sets.len())?),
        range_count: U32::new(count(compiler.ranges.len())?),
        capture_groups: U32::new(compiler.capture_groups),
        register_count: U32::new(compiler.registers),
        nesting: U32::new(compiler.deepest),
        start_bytes: start_bytes.0,
        flags: if filters { FILTERS_START_BYTES } else { 0 },
        reserved: [0; 7],
    };
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(compiler.instructions.as_bytes());
    for set in &compiler.sets {
        bytes.extend_from_slice(&set.0);
    }
    bytes.extend_from_slice(compiler.ranges.as_bytes());
    Ok(bytes)
}

fn count(length: usize) -> Result<u32, BacktrackingNotCompiled> {
    u32::try_from(length).map_err(|_| BacktrackingNotCompiled::TooLarge)
}

fn highest_group(tree: &ExpressionTree) -> Result<u32, BacktrackingNotCompiled> {
    let mut highest = 0u32;
    let mut referenced = 0u32;
    let mut pending: Vec<&ExpressionTree> = vec![tree];
    while let Some(node) = pending.pop() {
        match node {
            ExpressionTree::Empty | ExpressionTree::Byte(_) | ExpressionTree::Assertion(_) => {}
            ExpressionTree::Concat(items) | ExpressionTree::Alternation(items) => {
                pending.extend(items.iter());
            }
            ExpressionTree::Repetition(repetition) => pending.push(&repetition.item),
            ExpressionTree::Capture { group, item } => {
                highest = highest.max(*group);
                pending.push(item);
            }
            ExpressionTree::Backreference { group, .. } => referenced = referenced.max(*group),
            ExpressionTree::Lookaround { item, .. } | ExpressionTree::Atomic(item) => {
                pending.push(item);
            }
        }
    }
    if highest > MOST_CAPTURE_GROUPS {
        return Err(BacktrackingNotCompiled::TooManyGroups);
    }
    if referenced > highest {
        return Err(BacktrackingNotCompiled::BackreferenceToNoGroup);
    }
    Ok(highest)
}

#[derive(Default)]
struct Compiler {
    instructions: Vec<InstructionEntry>,
    sets: Vec<ByteSet>,
    ranges: Vec<RangeEntry>,
    capture_groups: u32,
    registers: u32,
    deepest: u32,
}

impl Compiler {
    fn here(&self) -> Result<u32, BacktrackingNotCompiled> {
        count(self.instructions.len())
    }

    fn emit(&mut self, op: u8, flag: u8, a: u32, b: u32) -> Result<u32, BacktrackingNotCompiled> {
        let at = self.here()?;
        if self.instructions.len() >= LARGEST_BACKTRACKING_PROGRAM {
            return Err(BacktrackingNotCompiled::TooLarge);
        }
        self.instructions.push(InstructionEntry {
            op,
            flag,
            reserved: [0; 2],
            a: U32::new(a),
            b: U32::new(b),
        });
        Ok(at)
    }

    fn patch(&mut self, at: u32, a: Option<u32>, b: Option<u32>) {
        if let Some(entry) = usize::try_from(at)
            .ok()
            .and_then(|at| self.instructions.get_mut(at))
        {
            if let Some(a) = a {
                entry.a = U32::new(a);
            }
            if let Some(b) = b {
                entry.b = U32::new(b);
            }
        }
    }

    fn set(&mut self, set: &ByteSet) -> Result<u32, BacktrackingNotCompiled> {
        if let Some(found) = self.sets.iter().position(|known| known == set) {
            return count(found);
        }
        self.sets.push(*set);
        count(self.sets.len().saturating_sub(1))
    }

    fn range(&mut self, min: u32, max: Option<u32>) -> Result<u32, BacktrackingNotCompiled> {
        self.ranges.push(RangeEntry {
            min: U32::new(min),
            max: U32::new(max.unwrap_or(NO_MAXIMUM)),
        });
        count(self.ranges.len().saturating_sub(1))
    }

    fn register(&mut self) -> u32 {
        let register = self.registers;
        self.registers = self.registers.saturating_add(1);
        register
    }

    fn tree(&mut self, tree: &ExpressionTree, nesting: u32) -> Result<(), BacktrackingNotCompiled> {
        match tree {
            ExpressionTree::Empty => Ok(()),
            ExpressionTree::Byte(set) => {
                let set = self.set(set)?;
                self.emit(OP_BYTE, 0, set, 0).map(drop)
            }
            ExpressionTree::Concat(items) => {
                for item in items {
                    self.tree(item, nesting)?;
                }
                Ok(())
            }
            ExpressionTree::Alternation(branches) => self.alternation(branches, nesting),
            ExpressionTree::Repetition(repetition) => self.repetition(repetition, nesting),
            ExpressionTree::Capture { group, item } => {
                let start = group.saturating_mul(2);
                self.emit(OP_SAVE, 0, start, 0)?;
                self.tree(item, nesting)?;
                self.emit(OP_SAVE, 0, start.saturating_add(1), 0).map(drop)
            }
            ExpressionTree::Backreference { group, caseless } => self
                .emit(
                    OP_BACKREFERENCE,
                    if *caseless { CASELESS } else { 0 },
                    *group,
                    0,
                )
                .map(drop),
            ExpressionTree::Assertion(assertion) => self
                .emit(OP_ASSERT, 0, assertion_code(*assertion), 0)
                .map(drop),
            ExpressionTree::Lookaround {
                direction,
                negated,
                item,
            } => {
                let (shortest, longest) = match direction {
                    LookDirection::Ahead => (0, None),
                    LookDirection::Behind => (
                        item.shortest_match(),
                        Some(
                            item.longest_match()
                                .ok_or(BacktrackingNotCompiled::UnboundedLookbehind)?,
                        ),
                    ),
                };
                let range = self.range(shortest, longest)?;
                let mut flag = 0;
                if *direction == LookDirection::Behind {
                    flag |= LOOK_BEHIND;
                }
                if *negated {
                    flag |= LOOK_NEGATED;
                }
                let look = self.emit(OP_LOOK, flag, 0, range)?;
                self.nested(item, nesting)?;
                let continuation = self.here()?;
                self.patch(look, Some(continuation), None);
                Ok(())
            }
            ExpressionTree::Atomic(item) => self.atomic(item, nesting),
        }
    }

    fn nested(
        &mut self,
        item: &ExpressionTree,
        nesting: u32,
    ) -> Result<(), BacktrackingNotCompiled> {
        let nesting = nesting.saturating_add(1);
        if nesting > DEEPEST_NESTED_ASSERTION {
            return Err(BacktrackingNotCompiled::NestedTooDeep);
        }
        self.deepest = self.deepest.max(nesting);
        self.tree(item, nesting)?;
        self.emit(OP_MATCH, 0, 0, 0).map(drop)
    }

    fn atomic(
        &mut self,
        item: &ExpressionTree,
        nesting: u32,
    ) -> Result<(), BacktrackingNotCompiled> {
        let atomic = self.emit(OP_ATOMIC, 0, 0, 0)?;
        self.nested(item, nesting)?;
        let continuation = self.here()?;
        self.patch(atomic, Some(continuation), None);
        Ok(())
    }

    fn alternation(
        &mut self,
        branches: &[ExpressionTree],
        nesting: u32,
    ) -> Result<(), BacktrackingNotCompiled> {
        let Some((last, rest)) = branches.split_last() else {
            return Ok(());
        };
        let mut jumps_to_end = Vec::new();
        for branch in rest {
            let split = self.emit(OP_SPLIT, 0, 0, 0)?;
            let first = self.here()?;
            self.tree(branch, nesting)?;
            jumps_to_end.push(self.emit(OP_JUMP, 0, 0, 0)?);
            let second = self.here()?;
            self.patch(split, Some(first), Some(second));
        }
        self.tree(last, nesting)?;
        let end = self.here()?;
        for jump in jumps_to_end {
            self.patch(jump, Some(end), None);
        }
        Ok(())
    }

    fn repetition(
        &mut self,
        repetition: &TreeRepetition,
        nesting: u32,
    ) -> Result<(), BacktrackingNotCompiled> {
        if let ExpressionTree::Byte(set) = &repetition.item {
            let set = self.set(set)?;
            let range = self.range(repetition.min, repetition.max)?;
            let greed = match repetition.greed {
                Greed::Greedy => GREED_GREEDY,
                Greed::Lazy => GREED_LAZY,
                Greed::Possessive => GREED_POSSESSIVE,
            };
            return self.emit(OP_REPEAT_BYTE, greed, set, range).map(drop);
        }
        if repetition.greed == Greed::Possessive {
            let greedy = ExpressionTree::Repetition(Box::new(TreeRepetition {
                min: repetition.min,
                max: repetition.max,
                greed: Greed::Greedy,
                item: repetition.item.clone(),
            }));
            return self.atomic(&greedy, nesting);
        }
        let greedy = repetition.greed == Greed::Greedy;
        for _ in 0..repetition.min {
            self.tree(&repetition.item, nesting)?;
        }
        match repetition.max {
            Some(max) => {
                let mut skips = Vec::new();
                for _ in repetition.min..max {
                    skips.push(self.emit(OP_SPLIT, 0, 0, 0)?);
                    let body = self.here()?;
                    if let Some(split) = skips.last() {
                        let split = *split;
                        if greedy {
                            self.patch(split, Some(body), None);
                        } else {
                            self.patch(split, None, Some(body));
                        }
                    }
                    self.tree(&repetition.item, nesting)?;
                }
                let end = self.here()?;
                for split in skips {
                    if greedy {
                        self.patch(split, None, Some(end));
                    } else {
                        self.patch(split, Some(end), None);
                    }
                }
                Ok(())
            }
            None => self.star(&repetition.item, greedy, nesting),
        }
    }

    fn star(
        &mut self,
        item: &ExpressionTree,
        greedy: bool,
        nesting: u32,
    ) -> Result<(), BacktrackingNotCompiled> {
        let head = self.emit(OP_SPLIT, 0, 0, 0)?;
        let body = self.here()?;
        let progress = (item.shortest_match() == 0).then(|| self.register());
        if let Some(register) = progress {
            self.emit(OP_MARK, 0, register, 0)?;
        }
        self.tree(item, nesting)?;
        match progress {
            Some(register) => self.emit(OP_CHECK_PROGRESS, 0, register, head)?,
            None => self.emit(OP_JUMP, 0, head, 0)?,
        };
        let exit = self.here()?;
        if greedy {
            self.patch(head, Some(body), Some(exit));
        } else {
            self.patch(head, Some(exit), Some(body));
        }
        Ok(())
    }
}

const fn assertion_code(assertion: Assertion) -> u32 {
    match assertion {
        Assertion::SubjectStart => 1,
        Assertion::SubjectEnd => 2,
        Assertion::SubjectEndOrBeforeFinalNewline => 3,
        Assertion::LineStartNotAtSubjectEnd => 4,
        Assertion::LineEnd => 5,
        Assertion::WordBoundary => 6,
        Assertion::NotWordBoundary => 7,
    }
}

const fn assertion_of(code: u32) -> Option<Assertion> {
    match code {
        1 => Some(Assertion::SubjectStart),
        2 => Some(Assertion::SubjectEnd),
        3 => Some(Assertion::SubjectEndOrBeforeFinalNewline),
        4 => Some(Assertion::LineStartNotAtSubjectEnd),
        5 => Some(Assertion::LineEnd),
        6 => Some(Assertion::WordBoundary),
        7 => Some(Assertion::NotWordBoundary),
        _ => None,
    }
}

#[derive(Clone, Copy)]
pub struct BacktrackingProgram<'m> {
    header: &'m Header,
    instructions: &'m [InstructionEntry],
    sets: &'m [[u8; 32]],
    ranges: &'m [RangeEntry],
}

fn malformed<E>(_: E) -> BacktrackingProgramMalformed {
    BacktrackingProgramMalformed
}

impl<'m> BacktrackingProgram<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, BacktrackingProgramMalformed> {
        let (header, rest) = Header::ref_from_prefix(bytes).map_err(malformed)?;
        let length = |value: U32| usize::try_from(value.get()).map_err(malformed);
        let (instructions, rest) = <[InstructionEntry]>::ref_from_prefix_with_elems(
            rest,
            length(header.instruction_count)?,
        )
        .map_err(malformed)?;
        let (sets, rest) =
            <[[u8; 32]]>::ref_from_prefix_with_elems(rest, length(header.set_count)?)
                .map_err(malformed)?;
        let ranges = <[RangeEntry]>::ref_from_bytes_with_elems(rest, length(header.range_count)?)
            .map_err(malformed)?;
        if header.capture_groups.get() > MOST_CAPTURE_GROUPS.saturating_add(1)
            || header.nesting.get() > DEEPEST_NESTED_ASSERTION
            || instructions.len() > LARGEST_BACKTRACKING_PROGRAM
            || usize::try_from(header.register_count.get())
                .map_or(true, |registers| registers > instructions.len())
        {
            return Err(BacktrackingProgramMalformed);
        }
        Ok(Self {
            header,
            instructions,
            sets,
            ranges,
        })
    }

    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    #[must_use]
    pub fn capture_groups(&self) -> u32 {
        self.header.capture_groups.get()
    }

    #[must_use]
    pub fn register_count(&self) -> u32 {
        self.header.register_count.get()
    }

    #[must_use]
    pub fn may_start_with(&self, byte: u8) -> bool {
        self.header.flags & FILTERS_START_BYTES == 0
            || ByteSet(self.header.start_bytes).contains(byte)
    }

    #[must_use]
    pub fn filters_start_bytes(&self) -> bool {
        self.header.flags & FILTERS_START_BYTES != 0
    }

    pub fn set_contains(&self, set: u32, byte: u8) -> Result<bool, BacktrackingProgramMalformed> {
        let set = usize::try_from(set)
            .ok()
            .and_then(|set| self.sets.get(set))
            .ok_or(BacktrackingProgramMalformed)?;
        Ok(ByteSet(*set).contains(byte))
    }

    pub fn instruction(&self, pc: u32) -> Result<Instruction, BacktrackingProgramMalformed> {
        let entry = usize::try_from(pc)
            .ok()
            .and_then(|pc| self.instructions.get(pc))
            .ok_or(BacktrackingProgramMalformed)?;
        let range = |index: u32| {
            usize::try_from(index)
                .ok()
                .and_then(|index| self.ranges.get(index))
                .map(|range| {
                    let max = range.max.get();
                    (range.min.get(), (max != NO_MAXIMUM).then_some(max))
                })
                .ok_or(BacktrackingProgramMalformed)
        };
        let (a, b) = (entry.a.get(), entry.b.get());
        Ok(match entry.op {
            OP_MATCH => Instruction::Match,
            OP_BYTE => Instruction::Byte { set: a },
            OP_SPLIT => Instruction::Split {
                first: a,
                second: b,
            },
            OP_JUMP => Instruction::Jump { to: a },
            OP_SAVE => Instruction::Save { slot: a },
            OP_ASSERT => Instruction::Assert(assertion_of(a).ok_or(BacktrackingProgramMalformed)?),
            OP_BACKREFERENCE => Instruction::Backreference {
                group: a,
                caseless: entry.flag & CASELESS != 0,
            },
            OP_REPEAT_BYTE => {
                let (min, max) = range(b)?;
                Instruction::RepeatByte(RepeatedByte {
                    set: a,
                    min,
                    max,
                    greed: match entry.flag {
                        GREED_GREEDY => Greed::Greedy,
                        GREED_LAZY => Greed::Lazy,
                        GREED_POSSESSIVE => Greed::Possessive,
                        _ => return Err(BacktrackingProgramMalformed),
                    },
                })
            }
            OP_LOOK => {
                let (shortest, longest) = range(b)?;
                Instruction::Look(LookInstruction {
                    direction: if entry.flag & LOOK_BEHIND != 0 {
                        LookDirection::Behind
                    } else {
                        LookDirection::Ahead
                    },
                    negated: entry.flag & LOOK_NEGATED != 0,
                    shortest,
                    longest: longest.unwrap_or(0),
                    continuation: a,
                })
            }
            OP_ATOMIC => Instruction::Atomic { continuation: a },
            OP_MARK => Instruction::Mark { register: a },
            OP_CHECK_PROGRESS => Instruction::CheckProgress {
                register: a,
                loop_head: b,
            },
            _ => return Err(BacktrackingProgramMalformed),
        })
    }
}
