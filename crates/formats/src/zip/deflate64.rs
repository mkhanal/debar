use debar_platform::input::InputError;

use crate::object::Object;
use crate::zip::compressed_bits::LowBitsFirst;
use crate::zip::decoded::{Decoding, Filled};
use crate::zip::prefix_codes::{Decoded, PrefixCode, Shape};

const WINDOW_BYTES: usize = 64 * 1024;
const END_OF_BLOCK: u16 = 256;
const FIRST_LENGTH_SYMBOL: u16 = 257;
const LITERAL_LENGTH_SYMBOLS: usize = 288;
const DISTANCE_SYMBOLS: usize = 32;
const MOST_LITERAL_LENGTH_CODES: u32 = 286;
const MOST_DISTANCE_CODES: u32 = 32;
const CODE_LENGTH_SYMBOLS: usize = 19;
const CODE_LENGTH_ORDER: [usize; CODE_LENGTH_SYMBOLS] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];
const LENGTH_BASES: [u32; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 3,
];
const LENGTH_EXTRA_BITS: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16,
];
const DISTANCE_BASES: [u32; DISTANCE_SYMBOLS] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153,
];
const DISTANCE_EXTRA_BITS: [u32; DISTANCE_SYMBOLS] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14,
];
const STORED_BLOCK: u32 = 0;
const FIXED_BLOCK: u32 = 1;
const DYNAMIC_BLOCK: u32 = 2;
const REPEAT_PREVIOUS: u16 = 16;
const REPEAT_ZERO_SHORT: u16 = 17;
const REPEAT_ZERO_LONG: u16 = 18;

pub struct Deflate64<'o> {
    bits: LowBitsFirst<'o>,
    window: Vec<u8>,
    window_at: usize,
    produced: u64,
    last_block: bool,
    state: State,
}

enum State {
    BlockHeader,
    Stored {
        left: u32,
    },
    Coded(Box<Codes>),
    Copying {
        codes: Box<Codes>,
        left: u32,
        distance: usize,
    },
    Ended(Decoding),
}

struct Codes {
    literal_length: PrefixCode,
    distance: PrefixCode,
}

enum Step {
    Byte(u8),
    Next(State),
}

impl<'o> Deflate64<'o> {
    pub fn new(compressed: Object<'o>) -> Self {
        Self {
            bits: LowBitsFirst::new(compressed),
            window: vec![0u8; WINDOW_BYTES],
            window_at: 0,
            produced: 0,
            last_block: false,
            state: State::BlockHeader,
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
        if let Some(slot) = self.window.get_mut(self.window_at) {
            *slot = byte;
        }
        self.window_at = self.window_at.saturating_add(1) % WINDOW_BYTES;
        self.produced = self.produced.saturating_add(1);
    }

    fn step(&mut self, state: State) -> Result<Step, InputError> {
        Ok(match state {
            State::Ended(decoding) => Step::Next(State::Ended(decoding)),
            State::BlockHeader => Step::Next(self.block_header()?),
            State::Stored { left: 0 } => Step::Next(self.after_block()),
            State::Stored { left } => match self.bits.whole_byte()? {
                None => Step::Next(State::Ended(Decoding::Ended)),
                Some(byte) => {
                    self.state = State::Stored {
                        left: left.saturating_sub(1),
                    };
                    Step::Byte(byte)
                }
            },
            State::Copying {
                codes,
                left,
                distance,
            } => {
                let at = self
                    .window_at
                    .wrapping_add(WINDOW_BYTES)
                    .wrapping_sub(distance)
                    % WINDOW_BYTES;
                let byte = self.window.get(at).copied().unwrap_or(0);
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

    fn after_block(&self) -> State {
        if self.last_block {
            State::Ended(Decoding::Ended)
        } else {
            State::BlockHeader
        }
    }

    fn block_header(&mut self) -> Result<State, InputError> {
        let Some(header) = self.bits.bits(3)? else {
            return Ok(State::Ended(Decoding::Ended));
        };
        self.last_block = header & 1 == 1;
        Ok(match header >> 1 {
            STORED_BLOCK => self.stored_header()?,
            FIXED_BLOCK => State::Coded(Box::new(fixed_codes())),
            DYNAMIC_BLOCK => match self.dynamic_codes()? {
                Read::Value(codes) => State::Coded(Box::new(codes)),
                Read::InputEnded => State::Ended(Decoding::Ended),
                Read::Invalid => State::Ended(Decoding::Failed),
            },
            _ => State::Ended(Decoding::Failed),
        })
    }

    fn stored_header(&mut self) -> Result<State, InputError> {
        self.bits.skip_to_byte_boundary();
        let (Some(length), Some(complement)) = (self.bits.bits(16)?, self.bits.bits(16)?) else {
            return Ok(State::Ended(Decoding::Ended));
        };
        if length != !complement & 0xffff {
            return Ok(State::Ended(Decoding::Failed));
        }
        Ok(State::Stored { left: length })
    }

    fn dynamic_codes(&mut self) -> Result<Read<Codes>, InputError> {
        let (Some(literal_lengths), Some(distances), Some(code_lengths)) =
            (self.bits.bits(5)?, self.bits.bits(5)?, self.bits.bits(4)?)
        else {
            return Ok(Read::InputEnded);
        };
        let literal_lengths = literal_lengths.saturating_add(257);
        let distances = distances.saturating_add(1);
        let code_lengths = code_lengths.saturating_add(4);
        if literal_lengths > MOST_LITERAL_LENGTH_CODES || distances > MOST_DISTANCE_CODES {
            return Ok(Read::Invalid);
        }
        let mut lengths_of_code_lengths = [0u8; CODE_LENGTH_SYMBOLS];
        for symbol in CODE_LENGTH_ORDER
            .iter()
            .take(usize::try_from(code_lengths).unwrap_or(0))
        {
            let Some(length) = self.bits.bits(3)? else {
                return Ok(Read::InputEnded);
            };
            if let Some(slot) = lengths_of_code_lengths.get_mut(*symbol) {
                *slot = u8::try_from(length).unwrap_or(0);
            }
        }
        let code_length_code = PrefixCode::canonical(&lengths_of_code_lengths);
        if code_length_code.shape() != Shape::Complete {
            return Ok(Read::Invalid);
        }
        let wanted = usize::try_from(literal_lengths.saturating_add(distances)).unwrap_or(0);
        let mut lengths = Vec::with_capacity(wanted);
        while lengths.len() < wanted {
            let symbol = match code_length_code.decode(|| self.bits.bit())? {
                Decoded::Symbol(symbol) => symbol,
                Decoded::InputEnded => return Ok(Read::InputEnded),
                Decoded::NoSuchCode => return Ok(Read::Invalid),
            };
            let (value, extra_bits, base) = match symbol {
                REPEAT_PREVIOUS => match lengths.last() {
                    Some(previous) => (*previous, 2, 3u32),
                    None => return Ok(Read::Invalid),
                },
                REPEAT_ZERO_SHORT => (0, 3, 3),
                REPEAT_ZERO_LONG => (0, 7, 11),
                length => {
                    lengths.push(u8::try_from(length).unwrap_or(0));
                    continue;
                }
            };
            let Some(extra) = self.bits.bits(extra_bits)? else {
                return Ok(Read::InputEnded);
            };
            let repeat = usize::try_from(base.saturating_add(extra)).unwrap_or(0);
            if lengths.len().saturating_add(repeat) > wanted {
                return Ok(Read::Invalid);
            }
            lengths.resize(lengths.len().saturating_add(repeat), value);
        }
        let split = usize::try_from(literal_lengths).unwrap_or(0);
        let (literal_length_lengths, distance_lengths) = lengths.split_at(split);
        if literal_length_lengths
            .get(usize::from(END_OF_BLOCK))
            .is_none_or(|length| *length == 0)
        {
            return Ok(Read::Invalid);
        }
        let literal_length = PrefixCode::canonical(literal_length_lengths);
        if !acceptable(&literal_length) {
            return Ok(Read::Invalid);
        }
        let distance = PrefixCode::canonical(distance_lengths);
        if !acceptable(&distance) {
            return Ok(Read::Invalid);
        }
        Ok(Read::Value(Codes {
            literal_length,
            distance,
        }))
    }

    fn coded(&mut self, codes: Box<Codes>) -> Result<Step, InputError> {
        let symbol = match codes.literal_length.decode(|| self.bits.bit())? {
            Decoded::Symbol(symbol) => symbol,
            Decoded::InputEnded => return Ok(Step::Next(State::Ended(Decoding::Ended))),
            Decoded::NoSuchCode => return Ok(Step::Next(State::Ended(Decoding::Failed))),
        };
        if symbol < END_OF_BLOCK {
            self.state = State::Coded(codes);
            return Ok(Step::Byte(u8::try_from(symbol).unwrap_or(0)));
        }
        if symbol == END_OF_BLOCK {
            return Ok(Step::Next(self.after_block()));
        }
        let index = usize::from(symbol.saturating_sub(FIRST_LENGTH_SYMBOL));
        let (Some(base), Some(extra_bits)) =
            (LENGTH_BASES.get(index), LENGTH_EXTRA_BITS.get(index))
        else {
            return Ok(Step::Next(State::Ended(Decoding::Failed)));
        };
        let Some(extra) = self.bits.bits(*extra_bits)? else {
            return Ok(Step::Next(State::Ended(Decoding::Ended)));
        };
        let length = base.saturating_add(extra);
        let distance_symbol = match codes.distance.decode(|| self.bits.bit())? {
            Decoded::Symbol(symbol) => usize::from(symbol),
            Decoded::InputEnded => return Ok(Step::Next(State::Ended(Decoding::Ended))),
            Decoded::NoSuchCode => return Ok(Step::Next(State::Ended(Decoding::Failed))),
        };
        let (Some(base), Some(extra_bits)) = (
            DISTANCE_BASES.get(distance_symbol),
            DISTANCE_EXTRA_BITS.get(distance_symbol),
        ) else {
            return Ok(Step::Next(State::Ended(Decoding::Failed)));
        };
        let Some(extra) = self.bits.bits(*extra_bits)? else {
            return Ok(Step::Next(State::Ended(Decoding::Ended)));
        };
        let distance = base.saturating_add(extra);
        if u64::from(distance) > self.produced {
            return Ok(Step::Next(State::Ended(Decoding::Failed)));
        }
        Ok(Step::Next(State::Copying {
            codes,
            left: length,
            distance: usize::try_from(distance).unwrap_or(WINDOW_BYTES),
        }))
    }
}

enum Read<T> {
    Value(T),
    InputEnded,
    Invalid,
}

fn acceptable(code: &PrefixCode) -> bool {
    match code.shape() {
        Shape::Complete => true,
        Shape::Oversubscribed => false,
        Shape::Incomplete => code.codes() == 1 && code.longest() == 1,
    }
}

fn fixed_codes() -> Codes {
    let mut literal_length_lengths = [8u8; LITERAL_LENGTH_SYMBOLS];
    for (symbol, length) in literal_length_lengths.iter_mut().enumerate() {
        *length = match symbol {
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    Codes {
        literal_length: PrefixCode::canonical(&literal_length_lengths),
        distance: PrefixCode::canonical(&[5u8; DISTANCE_SYMBOLS]),
    }
}
