use crate::pdf::filters::{Capacity, Decoder, StageOutcome, step_full};

const MOST_INPUT_KEPT_FOR_A_RETRY: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inflation {
    WantsInput,
    Producing,
    Ended,
    Broken,
}

pub trait Inflater {
    fn restart(&mut self);

    fn inflate(&mut self, input: &[u8], output: &mut Vec<u8>) -> (usize, Inflation);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoneReturn {
    KeptAsDecoded,
    LeftUntouched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attempt {
    First,
    Second,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Start,
    Decoding(Attempt),
    FindingTheNextLine { after_a_line_end: bool },
}

pub struct FirstAttempt<I> {
    inflater: I,
    lone_return: LoneReturn,
    phase: Phase,
    kept: Option<Vec<u8>>,
    replay: Vec<u8>,
    replayed: usize,
    produced: u64,
    capacity: Capacity,
    finished: Option<StageOutcome>,
}

impl<I: Inflater> FirstAttempt<I> {
    pub fn new(inflater: I, lone_return: LoneReturn, limit: Option<u64>) -> Self {
        Self {
            inflater,
            lone_return,
            phase: Phase::Start,
            kept: Some(Vec::new()),
            replay: Vec::new(),
            replayed: 0,
            produced: 0,
            capacity: Capacity::new(limit),
            finished: None,
        }
    }

    fn start(&mut self, input: &[u8], last: bool, output: &mut Vec<u8>) -> Option<usize> {
        let Some(first) = input.first().copied() else {
            if last {
                self.finished = Some(StageOutcome::Failed);
            }
            return Some(0);
        };
        if first != b'\r' {
            self.phase = Phase::Decoding(Attempt::First);
            return None;
        }
        if input.len() == 1 {
            if !last {
                return Some(0);
            }
            self.finished = Some(match self.lone_return {
                LoneReturn::KeptAsDecoded => {
                    output.push(b'\r');
                    StageOutcome::Decoded
                }
                LoneReturn::LeftUntouched => StageOutcome::Untouched,
            });
            return Some(1);
        }
        self.phase = Phase::Decoding(Attempt::First);
        None
    }

    fn keep(&mut self, consumed: &[u8]) {
        if self.produced > 0 {
            self.kept = None;
            return;
        }
        if let Some(kept) = &mut self.kept {
            if kept.len().saturating_add(consumed.len()) > MOST_INPUT_KEPT_FOR_A_RETRY {
                self.kept = None;
            } else {
                kept.extend_from_slice(consumed);
            }
        }
    }

    fn ended(&mut self, attempt: Attempt, broken: bool) {
        if self.produced == 0 && attempt == Attempt::First {
            self.retry();
            return;
        }
        self.finished = Some(if broken && self.produced == 0 {
            StageOutcome::Failed
        } else {
            StageOutcome::Decoded
        });
    }

    fn retry(&mut self) {
        let Some(kept) = self.kept.take() else {
            self.finished = Some(StageOutcome::Failed);
            return;
        };
        self.inflater.restart();
        let mut after_a_line_end = false;
        for (at, byte) in kept.iter().enumerate() {
            if matches!(byte, b'\n' | b'\r') {
                after_a_line_end = true;
            } else if after_a_line_end {
                self.replay = kept.get(at..).unwrap_or_default().to_vec();
                self.replayed = 0;
                self.phase = Phase::Decoding(Attempt::Second);
                return;
            }
        }
        self.phase = Phase::FindingTheNextLine { after_a_line_end };
    }

    fn find_the_next_line(&mut self, input: &[u8], mut after_a_line_end: bool) -> usize {
        for (at, byte) in input.iter().enumerate() {
            if matches!(byte, b'\n' | b'\r') {
                after_a_line_end = true;
            } else if after_a_line_end {
                self.phase = Phase::Decoding(Attempt::Second);
                return at;
            }
        }
        self.phase = Phase::FindingTheNextLine { after_a_line_end };
        input.len()
    }
}

impl<I: Inflater> Decoder for FirstAttempt<I> {
    fn decode(&mut self, input: &[u8], last: bool, output: &mut Vec<u8>) -> usize {
        let mut at = 0usize;
        loop {
            if self.finished.is_some() {
                return input.len();
            }
            match self.phase {
                Phase::Start => {
                    if let Some(consumed) = self.start(input, last, output) {
                        return consumed;
                    }
                    if input.first() == Some(&b'\r') {
                        at = 1;
                    }
                }
                Phase::FindingTheNextLine { after_a_line_end } => {
                    let rest = input.get(at..).unwrap_or_default();
                    at = at.saturating_add(self.find_the_next_line(rest, after_a_line_end));
                    if matches!(self.phase, Phase::FindingTheNextLine { .. }) {
                        if last {
                            self.finished = Some(StageOutcome::Failed);
                        }
                        return at;
                    }
                }
                Phase::Decoding(attempt) => {
                    if step_full(output) {
                        return at;
                    }
                    let replaying = self.replayed < self.replay.len();
                    let before = output.len();
                    let (consumed, inflation) = if replaying {
                        let from = self.replay.get(self.replayed..).unwrap_or_default();
                        self.inflater.inflate(from, output)
                    } else {
                        let from = input.get(at..).unwrap_or_default();
                        self.inflater.inflate(from, output)
                    };
                    if replaying {
                        self.replayed = self.replayed.saturating_add(consumed);
                    } else {
                        if attempt == Attempt::First {
                            let taken = input
                                .get(at..at.saturating_add(consumed))
                                .unwrap_or_default()
                                .to_vec();
                            self.keep(&taken);
                        }
                        at = at.saturating_add(consumed);
                    }
                    let appended = output.len().saturating_sub(before);
                    self.produced = self
                        .produced
                        .saturating_add(u64::try_from(appended).unwrap_or(u64::MAX));
                    if appended > 0 && !self.capacity.holds(self.produced) {
                        self.finished = Some(StageOutcome::Failed);
                        return input.len();
                    }
                    match inflation {
                        Inflation::Ended => self.ended(attempt, false),
                        Inflation::Broken => self.ended(attempt, true),
                        Inflation::Producing => {}
                        Inflation::WantsInput => {
                            if replaying {
                                continue;
                            }
                            if last {
                                self.finished = Some(StageOutcome::Decoded);
                                return input.len();
                            }
                            return at;
                        }
                    }
                }
            }
        }
    }

    fn finished(&self) -> Option<StageOutcome> {
        self.finished
    }

    fn needed_beyond_the_limit(&self) -> Option<u64> {
        self.capacity.needed_beyond_the_limit()
    }
}
