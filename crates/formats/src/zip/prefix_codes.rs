use debar_platform::input::InputError;

pub const LONGEST_CODE: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Complete,
    Incomplete,
    Oversubscribed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoded {
    Symbol(u16),
    NoSuchCode,
    InputEnded,
}

pub struct PrefixCode {
    counts: [u32; LONGEST_CODE + 1],
    symbols: Vec<u16>,
    shape: Shape,
    codes: usize,
    longest: usize,
}

impl PrefixCode {
    pub fn canonical(lengths: &[u8]) -> Self {
        let mut counts = [0u32; LONGEST_CODE + 1];
        for length in lengths {
            if let Some(count) = counts.get_mut(usize::from(*length)) {
                *count = count.saturating_add(1);
            }
        }
        if let Some(unused) = counts.first_mut() {
            *unused = 0;
        }
        let mut left = 1i64;
        let mut shape = Shape::Complete;
        for count in counts.iter().skip(1) {
            left = left.saturating_mul(2).saturating_sub(i64::from(*count));
            if left < 0 {
                shape = Shape::Oversubscribed;
                break;
            }
        }
        if shape == Shape::Complete && left > 0 {
            shape = Shape::Incomplete;
        }
        let mut symbols = Vec::new();
        for wanted in 1..=LONGEST_CODE {
            for (symbol, length) in lengths.iter().enumerate() {
                if usize::from(*length) == wanted {
                    symbols.push(u16::try_from(symbol).unwrap_or(u16::MAX));
                }
            }
        }
        let codes = symbols.len();
        let longest = counts.iter().rposition(|count| *count > 0).unwrap_or(0);
        Self {
            counts,
            symbols,
            shape,
            codes,
            longest,
        }
    }

    pub const fn shape(&self) -> Shape {
        self.shape
    }

    pub const fn codes(&self) -> usize {
        self.codes
    }

    pub const fn longest(&self) -> usize {
        self.longest
    }

    pub fn decode(
        &self,
        mut next_bit: impl FnMut() -> Result<Option<bool>, InputError>,
    ) -> Result<Decoded, InputError> {
        let mut code = 0i64;
        let mut first = 0i64;
        let mut index = 0i64;
        for count in self.counts.iter().skip(1).take(self.longest) {
            let Some(bit) = next_bit()? else {
                return Ok(Decoded::InputEnded);
            };
            code |= i64::from(bit);
            let count = i64::from(*count);
            if code.saturating_sub(count) < first {
                let at = index.saturating_add(code.saturating_sub(first));
                return Ok(usize::try_from(at)
                    .ok()
                    .and_then(|at| self.symbols.get(at))
                    .map_or(Decoded::NoSuchCode, |symbol| Decoded::Symbol(*symbol)));
            }
            index = index.saturating_add(count);
            first = first.saturating_add(count).saturating_mul(2);
            code = code.saturating_mul(2);
        }
        Ok(Decoded::NoSuchCode)
    }
}
