use std::cmp::Ordering;

use crate::pdf::filters::{Capacity, Decoder, StageOutcome, step_full};

const END_OF_DATA: u8 = 128;
const REPEATS_FROM: u16 = 257;

pub struct RunLength {
    produced: u64,
    capacity: Capacity,
    finished: Option<StageOutcome>,
}

impl RunLength {
    pub const fn new(limit: Option<u64>) -> Self {
        Self {
            produced: 0,
            capacity: Capacity::new(limit),
            finished: None,
        }
    }

    fn fail(&mut self, input: &[u8]) -> usize {
        self.finished = Some(StageOutcome::Failed);
        input.len()
    }
}

impl Decoder for RunLength {
    fn decode(&mut self, input: &[u8], last: bool, output: &mut Vec<u8>) -> usize {
        let mut at = 0usize;
        loop {
            if step_full(output) {
                return at;
            }
            let Some(run) = input.get(at).copied() else {
                if last {
                    self.finished = Some(StageOutcome::Decoded);
                }
                return at;
            };
            let body = at.saturating_add(1);
            match run.cmp(&END_OF_DATA) {
                Ordering::Less => {
                    let count = usize::from(run).saturating_add(1);
                    let Some(literal) = input.get(body..body.saturating_add(count)) else {
                        if last {
                            return self.fail(input);
                        }
                        return at;
                    };
                    let after = self
                        .produced
                        .saturating_add(u64::from(run))
                        .saturating_add(1);
                    if !self.capacity.holds(after) {
                        return self.fail(input);
                    }
                    output.extend_from_slice(literal);
                    self.produced = after;
                    at = body.saturating_add(count);
                }
                Ordering::Greater => {
                    let Some(repeated) = input.get(body).copied() else {
                        if last {
                            return self.fail(input);
                        }
                        return at;
                    };
                    let count = REPEATS_FROM.saturating_sub(u16::from(run));
                    let needed = self
                        .produced
                        .saturating_add(u64::from(count))
                        .saturating_add(1);
                    if !self.capacity.holds(needed) {
                        return self.fail(input);
                    }
                    output.resize(output.len().saturating_add(usize::from(count)), repeated);
                    self.produced = self.produced.saturating_add(u64::from(count));
                    at = body.saturating_add(1);
                }
                Ordering::Equal => {
                    self.finished = Some(StageOutcome::Decoded);
                    return input.len();
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
