use debar_image::{
    Assertion, BacktrackingInstruction, BacktrackingProgram, BacktrackingProgramMalformed, Greed,
    LookDirection, LookInstruction, RepeatedByte,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BacktrackingBounds {
    pub steps_per_start: u32,
    pub live_choices: u32,
}

impl BacktrackingBounds {
    pub const FOR_SIGNATURES: Self = Self {
        steps_per_start: 100_000,
        live_choices: 2_000,
    };
}

const MOST_STACK_ENTRIES: usize = 65_536;
const MOST_INSTRUCTIONS_PER_STEP: u64 = 4_096;
const UNSET: usize = usize::MAX;
const NEWLINE: u8 = b'\n';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BacktrackingSearch {
    Found { start: usize, end: usize },
    NotFound,
    GaveUp,
}

pub fn backtracking_search(
    program: &BacktrackingProgram<'_>,
    subject: &[u8],
    from: usize,
    anchored: bool,
    bounds: BacktrackingBounds,
) -> Result<BacktrackingSearch, BacktrackingProgramMalformed> {
    let slot_count = usize::try_from(program.capture_groups())
        .ok()
        .and_then(|groups| groups.checked_mul(2))
        .and_then(|slots| slots.checked_add(usize::try_from(program.register_count()).ok()?))
        .ok_or(BacktrackingProgramMalformed)?;
    let instruction_count = u64::try_from(program.instruction_count()).unwrap_or(u64::MAX);
    let mut machine = Machine {
        program,
        subject,
        slots: vec![UNSET; slot_count],
        capture_slots: slot_count
            .saturating_sub(usize::try_from(program.register_count()).unwrap_or(0)),
        stack: Vec::new(),
        steps: 0,
        choices: 0,
        fuel: 0,
        most_fuel: u64::from(bounds.steps_per_start)
            .saturating_add(1)
            .saturating_mul(
                instruction_count
                    .saturating_add(1)
                    .min(MOST_INSTRUCTIONS_PER_STEP),
            ),
        bounds,
    };
    let last = if anchored { from } else { subject.len() };
    for start in from..=last {
        if program.filters_start_bytes()
            && !subject
                .get(start)
                .is_some_and(|byte| program.may_start_with(*byte))
        {
            continue;
        }
        machine.restart();
        match machine.run(0, start, None)? {
            Run::Matched(end) => return Ok(BacktrackingSearch::Found { start, end }),
            Run::Failed => {}
            Run::Exhausted => return Ok(BacktrackingSearch::GaveUp),
        }
    }
    Ok(BacktrackingSearch::NotFound)
}

enum Run {
    Matched(usize),
    Failed,
    Exhausted,
}

enum Entry {
    Resume {
        pc: u32,
        at: usize,
    },
    Greedy {
        pc: u32,
        lowest: usize,
        at: usize,
    },
    Lazy {
        pc: u32,
        at: usize,
        remaining: Option<u32>,
        set: u32,
    },
    Restore {
        slot: usize,
        value: usize,
    },
}

struct Machine<'p, 'm, 's> {
    program: &'p BacktrackingProgram<'m>,
    subject: &'s [u8],
    slots: Vec<usize>,
    capture_slots: usize,
    stack: Vec<Entry>,
    steps: u32,
    choices: u32,
    fuel: u64,
    most_fuel: u64,
    bounds: BacktrackingBounds,
}

enum Backtrack {
    Resume(u32, usize),
    Failed,
    Exhausted,
}

enum Flow {
    Next(u32, usize),
    Fail,
    Finished(Run),
}

impl Machine<'_, '_, '_> {
    fn restart(&mut self) {
        self.slots.fill(UNSET);
        self.stack.clear();
        self.steps = 0;
        self.choices = 0;
        self.fuel = 0;
    }

    fn step(&mut self) -> bool {
        self.steps = self.steps.saturating_add(1);
        self.steps <= self.bounds.steps_per_start
    }

    fn push_choice(&mut self, entry: Entry) -> bool {
        self.choices = self.choices.saturating_add(1);
        self.stack.push(entry);
        self.step()
            && self.choices <= self.bounds.live_choices
            && self.stack.len() <= MOST_STACK_ENTRIES
    }

    fn set_slot(
        &mut self,
        slot: usize,
        value: usize,
    ) -> Result<bool, BacktrackingProgramMalformed> {
        let old = self
            .slots
            .get_mut(slot)
            .ok_or(BacktrackingProgramMalformed)?;
        let previous = std::mem::replace(old, value);
        if self.choices > 0 {
            self.stack.push(Entry::Restore {
                slot,
                value: previous,
            });
        }
        Ok(self.stack.len() <= MOST_STACK_ENTRIES)
    }

    fn truncate(&mut self, base: usize) {
        while self.stack.len() > base {
            if let Some(entry) = self.stack.pop()
                && !matches!(entry, Entry::Restore { .. })
            {
                self.choices = self.choices.saturating_sub(1);
            }
        }
    }

    fn run(
        &mut self,
        pc: u32,
        at: usize,
        required_end: Option<usize>,
    ) -> Result<Run, BacktrackingProgramMalformed> {
        let base = self.stack.len();
        let mut pc = pc;
        let mut at = at;
        loop {
            self.fuel = self.fuel.saturating_add(1);
            if self.fuel > self.most_fuel {
                return Ok(Run::Exhausted);
            }
            let flow = match self.program.instruction(pc)? {
                BacktrackingInstruction::Match => {
                    if required_end.is_none_or(|end| end == at) {
                        Flow::Finished(Run::Matched(at))
                    } else {
                        Flow::Fail
                    }
                }
                instruction => self.execute(instruction, pc, at)?,
            };
            match flow {
                Flow::Next(next_pc, next_at) => {
                    pc = next_pc;
                    at = next_at;
                }
                Flow::Finished(Run::Matched(end)) => return Ok(Run::Matched(end)),
                Flow::Finished(run) => {
                    self.truncate(base);
                    return Ok(run);
                }
                Flow::Fail => match self.backtrack(base)? {
                    Backtrack::Resume(next_pc, next_at) => {
                        pc = next_pc;
                        at = next_at;
                    }
                    Backtrack::Failed => return Ok(Run::Failed),
                    Backtrack::Exhausted => {
                        self.truncate(base);
                        return Ok(Run::Exhausted);
                    }
                },
            }
        }
    }

    fn execute(
        &mut self,
        instruction: BacktrackingInstruction,
        pc: u32,
        at: usize,
    ) -> Result<Flow, BacktrackingProgramMalformed> {
        let next = pc.checked_add(1).ok_or(BacktrackingProgramMalformed)?;
        let exhausted = Flow::Finished(Run::Exhausted);
        Ok(match instruction {
            BacktrackingInstruction::Match => Flow::Fail,
            BacktrackingInstruction::Byte { set } => match self.subject.get(at) {
                Some(byte) if self.program.set_contains(set, *byte)? => {
                    Flow::Next(next, at.saturating_add(1))
                }
                _ => Flow::Fail,
            },
            BacktrackingInstruction::Split { first, second } => {
                if self.push_choice(Entry::Resume { pc: second, at }) {
                    Flow::Next(first, at)
                } else {
                    exhausted
                }
            }
            BacktrackingInstruction::Jump { to } => Flow::Next(to, at),
            BacktrackingInstruction::Save { slot } => {
                let slot = usize::try_from(slot).map_err(|_| BacktrackingProgramMalformed)?;
                if slot >= self.capture_slots {
                    return Err(BacktrackingProgramMalformed);
                }
                if self.set_slot(slot, at)? {
                    Flow::Next(next, at)
                } else {
                    exhausted
                }
            }
            BacktrackingInstruction::Assert(assertion) => {
                if self.holds(assertion, at) {
                    Flow::Next(next, at)
                } else {
                    Flow::Fail
                }
            }
            BacktrackingInstruction::Backreference { group, caseless } => {
                match self.backreference_end(group, caseless, at)? {
                    Some(end) => Flow::Next(next, end),
                    None => Flow::Fail,
                }
            }
            BacktrackingInstruction::RepeatByte(repeated) => {
                self.repeat_byte(next, at, repeated)?
            }
            BacktrackingInstruction::Look(look) => self.look(next, at, look)?,
            BacktrackingInstruction::Atomic { continuation } => {
                let before = self.slots.clone();
                let base = self.stack.len();
                match self.run(next, at, None)? {
                    Run::Matched(end) => {
                        if self.keep_captures(&before, base)? {
                            Flow::Next(continuation, end)
                        } else {
                            exhausted
                        }
                    }
                    Run::Failed => Flow::Fail,
                    Run::Exhausted => exhausted,
                }
            }
            BacktrackingInstruction::Mark { register } => {
                let slot = self.register_slot(register)?;
                if self.set_slot(slot, at)? {
                    Flow::Next(next, at)
                } else {
                    exhausted
                }
            }
            BacktrackingInstruction::CheckProgress {
                register,
                loop_head,
            } => {
                let slot = self.register_slot(register)?;
                if self.slots.get(slot).copied() == Some(at) {
                    Flow::Next(next, at)
                } else {
                    Flow::Next(loop_head, at)
                }
            }
        })
    }

    fn register_slot(&self, register: u32) -> Result<usize, BacktrackingProgramMalformed> {
        usize::try_from(register)
            .ok()
            .and_then(|register| self.capture_slots.checked_add(register))
            .filter(|slot| *slot < self.slots.len())
            .ok_or(BacktrackingProgramMalformed)
    }

    fn keep_captures(
        &mut self,
        before: &[usize],
        sub_run_base: usize,
    ) -> Result<bool, BacktrackingProgramMalformed> {
        let after = self.slots.clone();
        self.truncate(sub_run_base);
        self.slots.copy_from_slice(before);
        for (slot, value) in after.iter().enumerate() {
            if before.get(slot) != Some(value) && !self.set_slot(slot, *value)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn look(
        &mut self,
        body: u32,
        at: usize,
        look: LookInstruction,
    ) -> Result<Flow, BacktrackingProgramMalformed> {
        let LookInstruction {
            direction,
            negated,
            shortest,
            longest,
            continuation,
        } = look;
        let before = self.slots.clone();
        let base = self.stack.len();
        let run = match direction {
            LookDirection::Ahead => self.run(body, at, None)?,
            LookDirection::Behind => {
                let mut outcome = Run::Failed;
                for length in shortest..=longest {
                    let Some(start) = usize::try_from(length)
                        .ok()
                        .and_then(|length| at.checked_sub(length))
                    else {
                        break;
                    };
                    outcome = self.run(body, start, Some(at))?;
                    if !matches!(outcome, Run::Failed) {
                        break;
                    }
                }
                outcome
            }
        };
        let matched = match run {
            Run::Exhausted => return Ok(Flow::Finished(Run::Exhausted)),
            Run::Matched(_) => true,
            Run::Failed => false,
        };
        if matched && !negated {
            return Ok(if self.keep_captures(&before, base)? {
                Flow::Next(continuation, at)
            } else {
                Flow::Finished(Run::Exhausted)
            });
        }
        self.truncate(base);
        self.slots.copy_from_slice(&before);
        Ok(if matched == negated {
            Flow::Fail
        } else {
            Flow::Next(continuation, at)
        })
    }

    fn repeat_byte(
        &mut self,
        next: u32,
        at: usize,
        repeated: RepeatedByte,
    ) -> Result<Flow, BacktrackingProgramMalformed> {
        let RepeatedByte {
            set,
            min,
            max,
            greed,
        } = repeated;
        let min = usize::try_from(min).map_err(|_| BacktrackingProgramMalformed)?;
        let wanted = match (greed, max) {
            (Greed::Lazy, _) => min,
            (_, Some(max)) => usize::try_from(max).unwrap_or(usize::MAX),
            (_, None) => usize::MAX,
        };
        let mut taken = 0usize;
        while taken < wanted {
            match self.subject.get(at.saturating_add(taken)) {
                Some(byte) if self.program.set_contains(set, *byte)? => {
                    taken = taken.saturating_add(1);
                }
                _ => break,
            }
        }
        if taken < min {
            return Ok(Flow::Fail);
        }
        let reached = at.saturating_add(taken);
        let alive = match greed {
            Greed::Possessive => true,
            Greed::Greedy => {
                taken == min
                    || self.push_choice(Entry::Greedy {
                        pc: next,
                        lowest: at.saturating_add(min),
                        at: reached,
                    })
            }
            Greed::Lazy => {
                let remaining = max.map(|max| max.saturating_sub(u32::try_from(min).unwrap_or(0)));
                remaining == Some(0)
                    || self.push_choice(Entry::Lazy {
                        pc: next,
                        at: reached,
                        remaining,
                        set,
                    })
            }
        };
        Ok(if alive {
            Flow::Next(next, reached)
        } else {
            Flow::Finished(Run::Exhausted)
        })
    }

    fn backtrack(&mut self, base: usize) -> Result<Backtrack, BacktrackingProgramMalformed> {
        while self.stack.len() > base {
            let Some(entry) = self.stack.pop() else {
                break;
            };
            match entry {
                Entry::Restore { slot, value } => {
                    if let Some(target) = self.slots.get_mut(slot) {
                        *target = value;
                    }
                }
                Entry::Resume { pc, at } => {
                    self.choices = self.choices.saturating_sub(1);
                    return Ok(Backtrack::Resume(pc, at));
                }
                Entry::Greedy { pc, lowest, at } => {
                    if !self.step() {
                        return Ok(Backtrack::Exhausted);
                    }
                    let shorter = at.saturating_sub(1);
                    if shorter > lowest {
                        self.stack.push(Entry::Greedy {
                            pc,
                            lowest,
                            at: shorter,
                        });
                    } else {
                        self.choices = self.choices.saturating_sub(1);
                    }
                    return Ok(Backtrack::Resume(pc, shorter));
                }
                Entry::Lazy {
                    pc,
                    at,
                    remaining,
                    set,
                } => {
                    let extends = remaining != Some(0)
                        && match self.subject.get(at) {
                            Some(byte) => self.program.set_contains(set, *byte)?,
                            None => false,
                        };
                    if !extends {
                        self.choices = self.choices.saturating_sub(1);
                        continue;
                    }
                    if !self.step() {
                        return Ok(Backtrack::Exhausted);
                    }
                    let longer = at.saturating_add(1);
                    let remaining = remaining.map(|remaining| remaining.saturating_sub(1));
                    if remaining == Some(0) {
                        self.choices = self.choices.saturating_sub(1);
                    } else {
                        self.stack.push(Entry::Lazy {
                            pc,
                            at: longer,
                            remaining,
                            set,
                        });
                    }
                    return Ok(Backtrack::Resume(pc, longer));
                }
            }
        }
        Ok(Backtrack::Failed)
    }

    fn holds(&self, assertion: Assertion, at: usize) -> bool {
        let length = self.subject.len();
        let before = at
            .checked_sub(1)
            .and_then(|before| self.subject.get(before));
        let after = self.subject.get(at);
        match assertion {
            Assertion::SubjectStart => at == 0,
            Assertion::SubjectEnd => at == length,
            Assertion::SubjectEndOrBeforeFinalNewline => {
                at == length || (at.saturating_add(1) == length && after == Some(&NEWLINE))
            }
            Assertion::LineStartNotAtSubjectEnd => {
                at == 0 || (before == Some(&NEWLINE) && at < length)
            }
            Assertion::LineEnd => at == length || after == Some(&NEWLINE),
            Assertion::WordBoundary => is_word(before) != is_word(after),
            Assertion::NotWordBoundary => is_word(before) == is_word(after),
        }
    }

    fn backreference_end(
        &self,
        group: u32,
        caseless: bool,
        at: usize,
    ) -> Result<Option<usize>, BacktrackingProgramMalformed> {
        let start_slot = usize::try_from(group)
            .ok()
            .and_then(|group| group.checked_mul(2))
            .ok_or(BacktrackingProgramMalformed)?;
        let start = *self
            .slots
            .get(start_slot)
            .ok_or(BacktrackingProgramMalformed)?;
        let end = *self
            .slots
            .get(start_slot.saturating_add(1))
            .ok_or(BacktrackingProgramMalformed)?;
        if start == UNSET || end == UNSET || end < start {
            return Ok(None);
        }
        let Some(captured) = self.subject.get(start..end) else {
            return Ok(None);
        };
        let Some(candidate) = self.subject.get(at..at.saturating_add(captured.len())) else {
            return Ok(None);
        };
        let same = if caseless {
            captured.eq_ignore_ascii_case(candidate)
        } else {
            captured == candidate
        };
        Ok(same.then(|| at.saturating_add(captured.len())))
    }
}

fn is_word(byte: Option<&u8>) -> bool {
    byte.is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}
