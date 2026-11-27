mod ascii85;
mod ascii_hex;
mod first_attempt;
mod flate;
mod lzw;
mod run_length;

use std::cell::Cell;
use std::rc::Rc;

use debar_platform::input::InputError;

use crate::pdf::objects::Filter;
use crate::pdf::pulled::Pull;

pub const DECODED_IN_STEPS_OF: u64 = 256 * 1024;
const MOST_OUTPUT_PER_STEP: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageOutcome {
    Decoded,
    Failed,
    Untouched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageReport {
    pub outcome: StageOutcome,
    pub produced: u64,
    pub needed_beyond_the_limit: Option<u64>,
}

impl StageReport {
    const UNFINISHED: Self = Self {
        outcome: StageOutcome::Failed,
        produced: 0,
        needed_beyond_the_limit: None,
    };
}

pub trait Decoder {
    fn decode(&mut self, input: &[u8], last: bool, output: &mut Vec<u8>) -> usize;

    fn finished(&self) -> Option<StageOutcome>;

    fn needed_beyond_the_limit(&self) -> Option<u64> {
        None
    }
}

pub struct Capacity {
    reserved: u64,
    limit: Option<u64>,
    needed_beyond_the_limit: Option<u64>,
}

impl Capacity {
    pub const fn new(limit: Option<u64>) -> Self {
        Self {
            reserved: DECODED_IN_STEPS_OF,
            limit,
            needed_beyond_the_limit: None,
        }
    }

    pub fn holds(&mut self, needed: u64) -> bool {
        while needed > self.reserved {
            let grown = self.reserved.saturating_add(DECODED_IN_STEPS_OF);
            if self.limit.is_some_and(|limit| grown > limit) {
                self.needed_beyond_the_limit = Some(grown);
                return false;
            }
            self.reserved = grown;
        }
        true
    }

    pub const fn needed_beyond_the_limit(&self) -> Option<u64> {
        self.needed_beyond_the_limit
    }
}

pub const fn step_full(output: &[u8]) -> bool {
    output.len() >= MOST_OUTPUT_PER_STEP
}

struct FilterStage<'a> {
    upstream: Box<dyn Pull + 'a>,
    decoder: Box<dyn Decoder>,
    pending: Vec<u8>,
    upstream_finished: bool,
    produced: u64,
    report: Rc<Cell<StageReport>>,
}

impl FilterStage<'_> {
    fn refill(&mut self) -> Result<(), InputError> {
        if !self.upstream_finished && !self.upstream.pull(&mut self.pending)? {
            self.upstream_finished = true;
        }
        Ok(())
    }

    fn finish(&mut self, outcome: StageOutcome) -> Result<(), InputError> {
        self.report.set(StageReport {
            outcome,
            produced: self.produced,
            needed_beyond_the_limit: self.decoder.needed_beyond_the_limit(),
        });
        self.pending.clear();
        while !self.upstream_finished {
            self.pending.clear();
            self.refill()?;
        }
        self.pending.clear();
        Ok(())
    }
}

impl Pull for FilterStage<'_> {
    fn pull(&mut self, into: &mut Vec<u8>) -> Result<bool, InputError> {
        let before = into.len();
        loop {
            if let Some(outcome) = self.decoder.finished() {
                self.finish(outcome)?;
                return Ok(false);
            }
            if self.pending.is_empty() {
                self.refill()?;
            }
            let consumed = self
                .decoder
                .decode(&self.pending, self.upstream_finished, into)
                .min(self.pending.len());
            self.pending.drain(..consumed);
            let appended = into.len().saturating_sub(before);
            if appended > 0 {
                self.produced = self
                    .produced
                    .saturating_add(u64::try_from(appended).unwrap_or(u64::MAX));
                return Ok(true);
            }
            if consumed == 0 && self.decoder.finished().is_none() {
                if self.upstream_finished {
                    self.finish(StageOutcome::Failed)?;
                    return Ok(false);
                }
                self.refill()?;
            }
        }
    }
}

pub struct Pipeline<'a> {
    pub output: Box<dyn Pull + 'a>,
    pub reports: Vec<Rc<Cell<StageReport>>>,
}

pub fn pipeline<'a>(
    source: Box<dyn Pull + 'a>,
    filters: &[Filter],
    limit: Option<u64>,
) -> Pipeline<'a> {
    let mut output = source;
    let mut reports = Vec::with_capacity(filters.len());
    for filter in filters {
        let report = Rc::new(Cell::new(StageReport::UNFINISHED));
        reports.push(Rc::clone(&report));
        output = Box::new(FilterStage {
            upstream: output,
            decoder: decoder(*filter, limit),
            pending: Vec::new(),
            upstream_finished: false,
            produced: 0,
            report,
        });
    }
    Pipeline { output, reports }
}

fn decoder(filter: Filter, limit: Option<u64>) -> Box<dyn Decoder> {
    match filter {
        Filter::AsciiHex => Box::new(ascii_hex::AsciiHex::new()),
        Filter::Ascii85 => Box::new(ascii85::Ascii85::new()),
        Filter::Flate => Box::new(flate::flate(limit)),
        Filter::Lzw => Box::new(lzw::lzw(limit)),
        Filter::RunLength => Box::new(run_length::RunLength::new(limit)),
        Filter::Fax | Filter::Dct | Filter::Jpx => Box::new(Settled(StageOutcome::Untouched)),
        Filter::Crypt => Box::new(Settled(StageOutcome::Failed)),
    }
}

struct Settled(StageOutcome);

impl Decoder for Settled {
    fn decode(&mut self, input: &[u8], _last: bool, _output: &mut Vec<u8>) -> usize {
        input.len()
    }

    fn finished(&self) -> Option<StageOutcome> {
        Some(self.0)
    }
}
