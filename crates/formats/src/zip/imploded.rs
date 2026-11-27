use debar_platform::input::InputError;

use crate::object::Object;
use crate::zip::compressed_bits::LowBitsFirst;
use crate::zip::decoded::{Decoding, Filled};
use crate::zip::prefix_codes::Decoded;
use crate::zip::shannon_fano::ShannonFanoCode;

const LITERAL_SYMBOLS: usize = 256;
const LENGTH_SYMBOLS: usize = 64;
const DISTANCE_SYMBOLS: usize = 64;
const LONGEST_LENGTH_SYMBOL: u16 = 63;
const LARGE_WINDOW_BYTES: usize = 8 * 1024;
const SMALL_WINDOW_BYTES: usize = 4 * 1024;
const LARGE_WINDOW_LOW_DISTANCE_BITS: u32 = 7;
const SMALL_WINDOW_LOW_DISTANCE_BITS: u32 = 6;
const SHORTEST_MATCH_WITH_LITERAL_CODE: u32 = 3;
const SHORTEST_MATCH_WITHOUT_LITERAL_CODE: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImplodedShape {
    pub large_window: bool,
    pub literal_code: bool,
}

pub struct Imploded<'o> {
    bits: LowBitsFirst<'o>,
    shape: ImplodedShape,
    window: Vec<u8>,
    window_at: usize,
    produced: u64,
    state: State,
}

enum State {
    Trees,
    Coded(Box<Codes>),
    Copying {
        codes: Box<Codes>,
        left: u32,
        distance: usize,
    },
    Ended(Decoding),
}

struct Codes {
    literal: Option<ShannonFanoCode>,
    length: ShannonFanoCode,
    distance: ShannonFanoCode,
}

enum Tree<T> {
    Read(T),
    InputEnded,
    Invalid,
}

enum Step {
    Byte(u8),
    Next(State),
}

impl<'o> Imploded<'o> {
    pub fn new(compressed: Object<'o>, shape: ImplodedShape) -> Self {
        let window_bytes = if shape.large_window {
            LARGE_WINDOW_BYTES
        } else {
            SMALL_WINDOW_BYTES
        };
        Self {
            bits: LowBitsFirst::new(compressed),
            shape,
            window: vec![0u8; window_bytes],
            window_at: 0,
            produced: 0,
            state: State::Trees,
        }
    }

    pub fn fill(&mut self, into: &mut [u8]) -> Result<Filled, InputError> {
        let mut written = 0usize;
        while let Some(slot) = into.get_mut(written) {
            let state = std::mem::replace(&mut self.state, State::Ended(Decoding::Failed));
            match self.step(state)? {
                Step::Byte(byte) => {
                    *slot = byte;
                    written = written.saturating_add(1);
                    self.keep(byte);
                }
                Step::Next(next) => {
                    let ended = matches!(next, State::Ended(_));
                    self.state = next;
                    if ended {
                        break;
                    }
                }
            }
        }
        let decoding = match &self.state {
            State::Ended(decoding) => *decoding,
            _ => Decoding::Going,
        };
        Ok(Filled { written, decoding })
    }

    fn keep(&mut self, byte: u8) {
        let window_bytes = self.window.len();
        if let Some(slot) = self.window.get_mut(self.window_at) {
            *slot = byte;
        }
        self.window_at = self
            .window_at
            .saturating_add(1)
            .checked_rem(window_bytes)
            .unwrap_or(0);
        self.produced = self.produced.saturating_add(1);
    }

    fn step(&mut self, state: State) -> Result<Step, InputError> {
        Ok(match state {
            State::Ended(decoding) => Step::Next(State::Ended(decoding)),
            State::Trees => Step::Next(match self.trees()? {
                Tree::Read(codes) => State::Coded(Box::new(codes)),
                Tree::InputEnded => State::Ended(Decoding::Ended),
                Tree::Invalid => State::Ended(Decoding::Failed),
            }),
            State::Copying {
                codes,
                left,
                distance,
            } => {
                let window_bytes = self.window.len();
                let at = self
                    .window_at
                    .wrapping_add(window_bytes)
                    .wrapping_sub(distance.checked_rem(window_bytes).unwrap_or(0))
                    .checked_rem(window_bytes)
                    .unwrap_or(0);
                let byte = if u64::try_from(distance).unwrap_or(u64::MAX) > self.produced {
                    0
                } else {
                    self.window.get(at).copied().unwrap_or(0)
                };
                self.state = if left > 1 {
                    State::Copying {
                        codes,
                        left: left.saturating_sub(1),
                        distance,
                    }
                } else {
                    State::Coded(codes)
                };
                Step::Byte(byte)
            }
            State::Coded(codes) => self.coded(codes)?,
        })
    }

    fn trees(&mut self) -> Result<Tree<Codes>, InputError> {
        let literal = if self.shape.literal_code {
            match self.tree(LITERAL_SYMBOLS)? {
                Tree::Read(code) => Some(code),
                Tree::InputEnded => return Ok(Tree::InputEnded),
                Tree::Invalid => return Ok(Tree::Invalid),
            }
        } else {
            None
        };
        let length = match self.tree(LENGTH_SYMBOLS)? {
            Tree::Read(code) => code,
            Tree::InputEnded => return Ok(Tree::InputEnded),
            Tree::Invalid => return Ok(Tree::Invalid),
        };
        let distance = match self.tree(DISTANCE_SYMBOLS)? {
            Tree::Read(code) => code,
            Tree::InputEnded => return Ok(Tree::InputEnded),
            Tree::Invalid => return Ok(Tree::Invalid),
        };
        Ok(Tree::Read(Codes {
            literal,
            length,
            distance,
        }))
    }

    fn tree(&mut self, symbols: usize) -> Result<Tree<ShannonFanoCode>, InputError> {
        let Some(described_in) = self.bits.whole_byte()? else {
            return Ok(Tree::InputEnded);
        };
        if usize::from(described_in) >= symbols {
            return Ok(Tree::Invalid);
        }
        let mut lengths = Vec::with_capacity(symbols);
        for _ in 0..=described_in {
            let Some(description) = self.bits.whole_byte()? else {
                return Ok(Tree::InputEnded);
            };
            let length = (description & 0x0f).saturating_add(1);
            let count = usize::from(description >> 4).saturating_add(1);
            if lengths.len().saturating_add(count) > symbols {
                return Ok(Tree::Invalid);
            }
            lengths.resize(lengths.len().saturating_add(count), length);
        }
        if lengths.len() != symbols {
            return Ok(Tree::Invalid);
        }
        Ok(Tree::Read(ShannonFanoCode::from_lengths(&lengths)))
    }

    fn symbol(code: &ShannonFanoCode, bits: &mut LowBitsFirst<'_>) -> Result<Decoded, InputError> {
        code.decode(|| bits.bit())
    }

    fn coded(&mut self, codes: Box<Codes>) -> Result<Step, InputError> {
        let Some(literal) = self.bits.bit()? else {
            return Ok(Step::Next(State::Ended(Decoding::Ended)));
        };
        if literal {
            let byte = match &codes.literal {
                Some(code) => match Self::symbol(code, &mut self.bits)? {
                    Decoded::Symbol(symbol) => u8::try_from(symbol).unwrap_or(0),
                    Decoded::InputEnded => return Ok(Step::Next(State::Ended(Decoding::Ended))),
                    Decoded::NoSuchCode => return Ok(Step::Next(State::Ended(Decoding::Failed))),
                },
                None => match self.bits.bits(8)? {
                    Some(byte) => u8::try_from(byte).unwrap_or(0),
                    None => return Ok(Step::Next(State::Ended(Decoding::Ended))),
                },
            };
            self.state = State::Coded(codes);
            return Ok(Step::Byte(byte));
        }
        let low_bits = if self.shape.large_window {
            LARGE_WINDOW_LOW_DISTANCE_BITS
        } else {
            SMALL_WINDOW_LOW_DISTANCE_BITS
        };
        let Some(low) = self.bits.bits(low_bits)? else {
            return Ok(Step::Next(State::Ended(Decoding::Ended)));
        };
        let high = match Self::symbol(&codes.distance, &mut self.bits)? {
            Decoded::Symbol(symbol) => u32::from(symbol),
            Decoded::InputEnded => return Ok(Step::Next(State::Ended(Decoding::Ended))),
            Decoded::NoSuchCode => return Ok(Step::Next(State::Ended(Decoding::Failed))),
        };
        let distance = (high << low_bits | low).saturating_add(1);
        let length = match Self::symbol(&codes.length, &mut self.bits)? {
            Decoded::Symbol(symbol) => symbol,
            Decoded::InputEnded => return Ok(Step::Next(State::Ended(Decoding::Ended))),
            Decoded::NoSuchCode => return Ok(Step::Next(State::Ended(Decoding::Failed))),
        };
        let mut length_value = u32::from(length);
        if length == LONGEST_LENGTH_SYMBOL {
            let Some(more) = self.bits.bits(8)? else {
                return Ok(Step::Next(State::Ended(Decoding::Ended)));
            };
            length_value = length_value.saturating_add(more);
        }
        let shortest = if codes.literal.is_some() {
            SHORTEST_MATCH_WITH_LITERAL_CODE
        } else {
            SHORTEST_MATCH_WITHOUT_LITERAL_CODE
        };
        Ok(Step::Next(State::Copying {
            codes,
            left: length_value.saturating_add(shortest),
            distance: usize::try_from(distance).unwrap_or(usize::MAX),
        }))
    }
}
