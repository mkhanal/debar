use crate::pdf::filters::{Decoder, StageOutcome, step_full};
use crate::pdf::tokens::is_c_space;

const FIRST_DIGIT: u8 = b'!';
const LAST_DIGIT: u8 = b'u';
const ZEROS: u8 = b'z';
const BASE: u64 = 85;
const GROUP: u32 = 5;
const LAST_GROUP_PADDING: u64 = 0x00ff_ffff;

pub struct Ascii85 {
    sum: u64,
    digits: u32,
    finished: Option<StageOutcome>,
}

impl Ascii85 {
    pub const fn new() -> Self {
        Self {
            sum: 0,
            digits: 0,
            finished: None,
        }
    }

    fn digit(&mut self, byte: u8, output: &mut Vec<u8>) {
        self.sum = self
            .sum
            .wrapping_mul(BASE)
            .wrapping_add(u64::from(byte.saturating_sub(FIRST_DIGIT)));
        self.digits = self.digits.saturating_add(1);
        if self.digits == GROUP {
            output.extend_from_slice(&low_word(self.sum));
            self.digits = 0;
            self.sum = 0;
        }
    }

    fn end_of_data(&mut self, output: &mut Vec<u8>) {
        if self.digits == 0 {
            self.finished = Some(StageOutcome::Decoded);
            return;
        }
        if self.digits == 1 {
            self.finished = Some(StageOutcome::Failed);
            return;
        }
        for _ in self.digits..GROUP {
            self.sum = self.sum.wrapping_mul(BASE);
        }
        let shift = self.digits.saturating_sub(2).saturating_mul(8);
        self.sum = self
            .sum
            .wrapping_add(LAST_GROUP_PADDING.checked_shr(shift).unwrap_or(0));
        let word = low_word(self.sum);
        let kept = usize::try_from(self.digits.saturating_sub(1)).unwrap_or(0);
        output.extend_from_slice(word.get(..kept).unwrap_or_default());
        self.finished = Some(StageOutcome::Decoded);
    }
}

fn low_word(sum: u64) -> [u8; 4] {
    let [first, second, third, fourth, ..] = sum.to_le_bytes();
    [fourth, third, second, first]
}

impl Decoder for Ascii85 {
    fn decode(&mut self, input: &[u8], last: bool, output: &mut Vec<u8>) -> usize {
        let mut at = 0usize;
        while let Some(byte) = input.get(at).copied() {
            if step_full(output) {
                return at;
            }
            if byte == b'~' {
                match input.get(at.saturating_add(1)) {
                    Some(b'>') => {
                        self.end_of_data(output);
                        return input.len();
                    }
                    None if !last => return at,
                    _ => {}
                }
            }
            at = at.saturating_add(1);
            match byte {
                FIRST_DIGIT..=LAST_DIGIT => self.digit(byte, output),
                ZEROS if self.digits == 0 => output.extend_from_slice(&[0; 4]),
                ZEROS => {
                    self.finished = Some(StageOutcome::Failed);
                    return input.len();
                }
                _ if is_c_space(byte) => {}
                _ => {
                    self.finished = Some(StageOutcome::Failed);
                    return input.len();
                }
            }
        }
        if last {
            self.finished = Some(StageOutcome::Decoded);
        }
        at
    }

    fn finished(&self) -> Option<StageOutcome> {
        self.finished
    }
}
