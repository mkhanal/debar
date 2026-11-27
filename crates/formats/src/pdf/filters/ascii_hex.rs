use crate::pdf::filters::{Decoder, StageOutcome, step_full};
use crate::pdf::tokens::hex_pair;

const TAIL_FORGIVEN: usize = 4;

pub struct AsciiHex {
    finished: Option<StageOutcome>,
}

impl AsciiHex {
    pub const fn new() -> Self {
        Self { finished: None }
    }
}

impl Decoder for AsciiHex {
    fn decode(&mut self, input: &[u8], last: bool, output: &mut Vec<u8>) -> usize {
        let mut at = 0usize;
        loop {
            let left = input.len().saturating_sub(at);
            if !last && left < TAIL_FORGIVEN {
                return at;
            }
            if left < 2 {
                self.finished = Some(StageOutcome::Decoded);
                return input.len();
            }
            if step_full(output) {
                return at;
            }
            let byte = input.get(at).copied().unwrap_or_default();
            if byte == b' ' {
                at = at.saturating_add(1);
                continue;
            }
            if byte == b'>' {
                self.finished = Some(StageOutcome::Decoded);
                return input.len();
            }
            let low = input.get(at.saturating_add(1)).copied().unwrap_or_default();
            if let Some(value) = hex_pair(byte, low) {
                output.push(value);
                at = at.saturating_add(2);
            } else if left < TAIL_FORGIVEN {
                at = at.saturating_add(1);
            } else {
                self.finished = Some(StageOutcome::Failed);
                return input.len();
            }
        }
    }

    fn finished(&self) -> Option<StageOutcome> {
        self.finished
    }
}
