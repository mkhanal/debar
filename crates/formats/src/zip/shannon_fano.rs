use debar_platform::input::InputError;

use crate::zip::prefix_codes::Decoded;

const CODE_BITS: u32 = 16;
const LONGEST_CODE: u8 = 16;

pub struct ShannonFanoCode {
    codes: Vec<Code>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Code {
    length: u8,
    bits: u16,
    symbol: u16,
}

impl ShannonFanoCode {
    pub fn from_lengths(lengths: &[u8]) -> Self {
        let mut by_length: Vec<usize> = (0..lengths.len()).collect();
        by_length.sort_by_key(|symbol| lengths.get(*symbol).copied().unwrap_or(0));
        let mut codes = Vec::with_capacity(lengths.len());
        let mut code = 0u16;
        let mut increment = 0u16;
        let mut last_length = 0u8;
        for symbol in by_length.iter().rev() {
            let length = lengths.get(*symbol).copied().unwrap_or(0);
            code = code.wrapping_add(increment);
            if length != last_length {
                last_length = length;
                increment = 1u16
                    .checked_shl(CODE_BITS.saturating_sub(u32::from(length)))
                    .unwrap_or(0);
            }
            codes.push(Code {
                length,
                bits: code,
                symbol: u16::try_from(*symbol).unwrap_or(u16::MAX),
            });
        }
        codes.sort();
        Self { codes }
    }

    pub fn decode(
        &self,
        mut next_bit: impl FnMut() -> Result<Option<bool>, InputError>,
    ) -> Result<Decoded, InputError> {
        let mut bits = 0u16;
        for length in 1..=LONGEST_CODE {
            let Some(bit) = next_bit()? else {
                return Ok(Decoded::InputEnded);
            };
            bits = bits.wrapping_shl(1) | u16::from(bit);
            let left_aligned = bits
                .checked_shl(CODE_BITS.saturating_sub(u32::from(length)))
                .unwrap_or(0);
            let wanted = (length, left_aligned);
            let first = self
                .codes
                .partition_point(|code| (code.length, code.bits) < wanted);
            if let Some(code) = self
                .codes
                .get(first)
                .filter(|code| (code.length, code.bits) == wanted)
            {
                return Ok(Decoded::Symbol(code.symbol));
            }
        }
        Ok(Decoded::NoSuchCode)
    }
}
