use crate::pdf::filters::first_attempt::{FirstAttempt, Inflater, Inflation, LoneReturn};
use crate::pdf::filters::step_full;

const CLEAR: u16 = 256;
const END_OF_INFORMATION: u16 = 257;
const FIRST_FREE: u16 = 258;
const TABLE_ENTRIES: u16 = 4096;
const SHORTEST_CODE: u32 = 9;
const LONGEST_CODE: u32 = 12;

pub type Lzw = FirstAttempt<LzwInflater>;

pub fn lzw(limit: Option<u64>) -> Lzw {
    FirstAttempt::new(LzwInflater::new(), LoneReturn::LeftUntouched, limit)
}

#[derive(Debug, Clone, Copy, Default)]
struct Entry {
    previous: Option<u16>,
    length: u16,
    value: u8,
    first: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Clearing,
    Codes,
    Stopped,
}

pub struct LzwInflater {
    table: Vec<Entry>,
    free: u16,
    code_bits: u32,
    largest_before_growth: u16,
    old: u16,
    bits: u64,
    bits_held: u32,
    step: Step,
    string: Vec<u8>,
}

impl LzwInflater {
    fn new() -> Self {
        let mut inflater = Self {
            table: vec![Entry::default(); usize::from(TABLE_ENTRIES)],
            free: FIRST_FREE,
            code_bits: SHORTEST_CODE,
            largest_before_growth: code_mask(SHORTEST_CODE).saturating_sub(1),
            old: CLEAR,
            bits: 0,
            bits_held: 0,
            step: Step::Clearing,
            string: Vec::new(),
        };
        inflater.restart();
        inflater
    }

    fn next_code(&mut self, input: &[u8], at: &mut usize) -> Option<u16> {
        let byte = input.get(*at).copied()?;
        *at = at.saturating_add(1);
        self.take(byte);
        if self.bits_held < self.code_bits {
            let byte = input.get(*at).copied()?;
            *at = at.saturating_add(1);
            self.take(byte);
        }
        let shift = self.bits_held.saturating_sub(self.code_bits);
        let code = self.bits.checked_shr(shift).unwrap_or(0) & u64::from(code_mask(self.code_bits));
        self.bits_held = shift;
        u16::try_from(code).ok()
    }

    fn take(&mut self, byte: u8) {
        self.bits = self.bits.wrapping_shl(8) | u64::from(byte);
        self.bits_held = self.bits_held.saturating_add(8);
    }

    fn grow(&mut self) {
        self.code_bits = self.code_bits.saturating_add(1).min(LONGEST_CODE);
        self.largest_before_growth = code_mask(self.code_bits).saturating_sub(1);
    }

    fn clear(&mut self) {
        self.free = FIRST_FREE;
        self.code_bits = SHORTEST_CODE;
        self.largest_before_growth = code_mask(SHORTEST_CODE).saturating_sub(1);
    }

    fn after_clearing(&mut self, code: u16, output: &mut Vec<u8>) -> Option<Inflation> {
        self.old = code;
        self.step = Step::Codes;
        if let Ok(byte) = u8::try_from(code) {
            output.push(byte);
            return None;
        }
        self.step = Step::Stopped;
        Some(if code == END_OF_INFORMATION {
            Inflation::Ended
        } else {
            Inflation::Broken
        })
    }

    fn code(&mut self, code: u16, output: &mut Vec<u8>) -> Option<Inflation> {
        if self.free < TABLE_ENTRIES {
            self.add_entry(code);
        }
        if let Ok(byte) = u8::try_from(code) {
            output.push(byte);
            return None;
        }
        if code >= self.free {
            self.step = Step::Stopped;
            return Some(Inflation::Broken);
        }
        self.write_string(code, output);
        None
    }

    fn add_entry(&mut self, code: u16) {
        let previous = self.entry(self.old);
        let first = previous.first;
        let value = if code < self.free {
            self.entry(code).first
        } else {
            first
        };
        if let Some(slot) = self.table.get_mut(usize::from(self.free)) {
            *slot = Entry {
                previous: Some(self.old),
                length: previous.length.saturating_add(1),
                value,
                first,
            };
        }
        self.free = self.free.saturating_add(1);
        if self.free > self.largest_before_growth {
            self.grow();
        }
        self.old = code;
    }

    fn entry(&self, code: u16) -> Entry {
        self.table
            .get(usize::from(code))
            .copied()
            .unwrap_or_default()
    }

    fn write_string(&mut self, code: u16, output: &mut Vec<u8>) {
        self.string.clear();
        let mut at = Some(code);
        let mut left = self.entry(code).length;
        while let Some(code) = at
            && left > 0
        {
            let entry = self.entry(code);
            self.string.push(entry.value);
            at = entry.previous;
            left = left.saturating_sub(1);
        }
        output.extend(self.string.iter().rev());
    }
}

const fn code_mask(bits: u32) -> u16 {
    match bits {
        9 => 0x1ff,
        10 => 0x3ff,
        11 => 0x7ff,
        _ => 0xfff,
    }
}

impl Inflater for LzwInflater {
    fn restart(&mut self) {
        for (code, entry) in self.table.iter_mut().enumerate() {
            *entry = match u8::try_from(code) {
                Ok(byte) => Entry {
                    previous: None,
                    length: 1,
                    value: byte,
                    first: byte,
                },
                Err(_) => Entry::default(),
            };
        }
        self.clear();
        self.old = CLEAR;
        self.bits = 0;
        self.bits_held = 0;
        self.step = Step::Clearing;
    }

    fn inflate(&mut self, input: &[u8], output: &mut Vec<u8>) -> (usize, Inflation) {
        let mut at = 0usize;
        loop {
            if self.step == Step::Stopped {
                return (at, Inflation::Ended);
            }
            if step_full(output) {
                return (at, Inflation::Producing);
            }
            let Some(code) = self.next_code(input, &mut at) else {
                let inflation = if at > 0 {
                    Inflation::Producing
                } else {
                    Inflation::WantsInput
                };
                return (at, inflation);
            };
            let stopped = match self.step {
                Step::Clearing if code == CLEAR => None,
                Step::Clearing => self.after_clearing(code, output),
                Step::Codes if code == END_OF_INFORMATION => {
                    self.step = Step::Stopped;
                    Some(Inflation::Ended)
                }
                Step::Codes if code == CLEAR => {
                    self.clear();
                    self.step = Step::Clearing;
                    None
                }
                Step::Codes => self.code(code, output),
                Step::Stopped => Some(Inflation::Ended),
            };
            if let Some(inflation) = stopped {
                return (at, inflation);
            }
        }
    }
}
