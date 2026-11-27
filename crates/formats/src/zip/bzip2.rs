use std::sync::LazyLock;

use debar_platform::input::InputError;

use crate::object::Object;
use crate::zip::compressed_bits::HighBitsFirst;
use crate::zip::decoded::{Decoding, Filled};
use crate::zip::prefix_codes::{Decoded, PrefixCode};

const STREAM_MAGIC: [u8; 3] = *b"BZh";
const SMALLEST_LEVEL: u8 = b'1';
const LARGEST_LEVEL: u8 = b'9';
const BLOCK_BYTES_PER_LEVEL: u32 = 100_000;
const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const END_OF_STREAM_MAGIC: u64 = 0x1772_4538_5090;
const FEWEST_GROUPS: u32 = 2;
const MOST_GROUPS: u32 = 6;
const MOST_SELECTORS_KEPT: usize = 18_002;
const SYMBOLS_PER_GROUP: u32 = 50;
const SHORTEST_CODE: u32 = 1;
const LONGEST_CODE: u32 = 20;
const RUN_A: u16 = 0;
const RUN_B: u16 = 1;
const LONGEST_RUN_WEIGHT: u32 = 2 * 1024 * 1024;
const BYTES_BEFORE_A_COUNT: u32 = 4;
const CRC_POLYNOMIAL: u32 = 0x04c1_1db7;

pub struct Bzip2<'o> {
    bits: HighBitsFirst<'o>,
    largest_block: u32,
    combined_crc: u32,
    state: State,
}

enum State {
    StreamHeader,
    BlockHeader,
    Emitting(Box<Block>),
    Ended(Decoding),
}

struct Block {
    vector: Vec<u32>,
    at: u32,
    fetched: u32,
    length: u32,
    previous: Option<u8>,
    repeats: u32,
    run_byte: u8,
    run_left: u32,
    crc: u32,
    stored_crc: u32,
}

enum Read<T> {
    Value(T),
    Invalid,
}

impl<'o> Bzip2<'o> {
    pub const fn new(compressed: Object<'o>) -> Self {
        Self {
            bits: HighBitsFirst::new(compressed),
            largest_block: 0,
            combined_crc: 0,
            state: State::StreamHeader,
        }
    }

    pub fn fill(&mut self, into: &mut [u8]) -> Result<Filled, InputError> {
        let mut written = 0usize;
        loop {
            let state = std::mem::replace(&mut self.state, State::Ended(Decoding::Failed));
            self.state = match state {
                State::Ended(decoding) => {
                    self.state = State::Ended(decoding);
                    return Ok(Filled { written, decoding });
                }
                State::StreamHeader => self.stream_header()?,
                State::BlockHeader => self.block_header()?,
                State::Emitting(mut block) => {
                    let rest = into.get_mut(written..).unwrap_or_default();
                    let emitted = block.emit(rest);
                    written = written.saturating_add(emitted);
                    if block.finished() {
                        self.after_block(&block)
                    } else {
                        self.state = State::Emitting(block);
                        return Ok(Filled {
                            written,
                            decoding: Decoding::Going,
                        });
                    }
                }
            };
        }
    }

    fn stream_header(&mut self) -> Result<State, InputError> {
        for wanted in STREAM_MAGIC {
            match self.byte()? {
                None => return Ok(State::Ended(Decoding::Ended)),
                Some(byte) if byte != wanted => return Ok(State::Ended(Decoding::Failed)),
                Some(_) => {}
            }
        }
        let Some(level) = self.byte()? else {
            return Ok(State::Ended(Decoding::Ended));
        };
        if !(SMALLEST_LEVEL..=LARGEST_LEVEL).contains(&level) {
            return Ok(State::Ended(Decoding::Failed));
        }
        self.largest_block =
            u32::from(level.saturating_sub(b'0')).saturating_mul(BLOCK_BYTES_PER_LEVEL);
        Ok(State::BlockHeader)
    }

    fn byte(&mut self) -> Result<Option<u8>, InputError> {
        Ok(self.bits.bits(8)?.and_then(|byte| u8::try_from(byte).ok()))
    }

    fn after_block(&mut self, block: &Block) -> State {
        if !block.crc_holds() {
            return State::Ended(Decoding::Failed);
        }
        self.combined_crc = self.combined_crc.rotate_left(1) ^ block.stored_crc;
        State::BlockHeader
    }

    fn block_header(&mut self) -> Result<State, InputError> {
        let (Some(high), Some(low)) = (self.bits.bits(24)?, self.bits.bits(24)?) else {
            return Ok(State::Ended(Decoding::Ended));
        };
        let magic = (u64::from(high) << 24) | u64::from(low);
        if magic == END_OF_STREAM_MAGIC {
            let ended = match self.bits.bits(32)? {
                None => Decoding::Ended,
                Some(stored) if stored == self.combined_crc => Decoding::Ended,
                Some(_) => Decoding::Failed,
            };
            return Ok(State::Ended(ended));
        }
        if magic != BLOCK_MAGIC {
            return Ok(State::Ended(Decoding::Failed));
        }
        Ok(match self.block()? {
            Some(Read::Value(block)) => State::Emitting(Box::new(block)),
            Some(Read::Invalid) => State::Ended(Decoding::Failed),
            None => State::Ended(Decoding::Ended),
        })
    }

    fn block(&mut self) -> Result<Option<Read<Block>>, InputError> {
        let Some(stored_crc) = self.bits.bits(32)? else {
            return Ok(None);
        };
        let Some(randomised) = self.bits.bit()? else {
            return Ok(None);
        };
        if randomised {
            return Ok(Some(Read::Invalid));
        }
        let Some(origin) = self.bits.bits(24)? else {
            return Ok(None);
        };
        let Some(used) = self.used_bytes()? else {
            return Ok(None);
        };
        if used.is_empty() {
            return Ok(Some(Read::Invalid));
        }
        let alphabet = used.len().saturating_add(2);
        let Some(groups) = self.bits.bits(3)? else {
            return Ok(None);
        };
        if !(FEWEST_GROUPS..=MOST_GROUPS).contains(&groups) {
            return Ok(Some(Read::Invalid));
        }
        let selectors = match self.selectors(groups)? {
            Some(Read::Value(selectors)) => selectors,
            Some(Read::Invalid) => return Ok(Some(Read::Invalid)),
            None => return Ok(None),
        };
        let mut codes = Vec::new();
        for _ in 0..groups {
            match self.code_lengths(alphabet)? {
                Some(Read::Value(lengths)) => codes.push(PrefixCode::canonical(&lengths)),
                Some(Read::Invalid) => return Ok(Some(Read::Invalid)),
                None => return Ok(None),
            }
        }
        let vector = match self.symbols(&used, &selectors, &codes)? {
            Some(Read::Value(vector)) => vector,
            Some(Read::Invalid) => return Ok(Some(Read::Invalid)),
            None => return Ok(None),
        };
        Ok(Some(
            inverted(vector, origin).map_or(Read::Invalid, |vector| {
                Read::Value(Block::new(vector, origin, stored_crc))
            }),
        ))
    }

    fn used_bytes(&mut self) -> Result<Option<Vec<u8>>, InputError> {
        let Some(ranges) = self.bits.bits(16)? else {
            return Ok(None);
        };
        let mut used = Vec::new();
        for range in 0..16u32 {
            if ranges & (0x8000 >> range) == 0 {
                continue;
            }
            let Some(within) = self.bits.bits(16)? else {
                return Ok(None);
            };
            for byte in 0..16u32 {
                if within & (0x8000 >> byte) != 0 {
                    used.push(u8::try_from(range.wrapping_mul(16).wrapping_add(byte)).unwrap_or(0));
                }
            }
        }
        Ok(Some(used))
    }

    fn selectors(&mut self, groups: u32) -> Result<Option<Read<Vec<u8>>>, InputError> {
        let Some(count) = self.bits.bits(15)? else {
            return Ok(None);
        };
        if count < 1 {
            return Ok(Some(Read::Invalid));
        }
        let mut order: Vec<u8> = (0..groups)
            .map(|group| u8::try_from(group).unwrap_or(0))
            .collect();
        let mut selectors = Vec::new();
        for _ in 0..count {
            let mut moved = 0u32;
            loop {
                match self.bits.bit()? {
                    None => return Ok(None),
                    Some(false) => break,
                    Some(true) => {
                        moved = moved.saturating_add(1);
                        if moved >= groups {
                            return Ok(Some(Read::Invalid));
                        }
                    }
                }
            }
            if selectors.len() >= MOST_SELECTORS_KEPT {
                continue;
            }
            let at = usize::try_from(moved).unwrap_or(0);
            if at < order.len() {
                let group = order.remove(at);
                order.insert(0, group);
                selectors.push(group);
            }
        }
        Ok(Some(Read::Value(selectors)))
    }

    fn code_lengths(&mut self, alphabet: usize) -> Result<Option<Read<Vec<u8>>>, InputError> {
        let Some(mut current) = self.bits.bits(5)? else {
            return Ok(None);
        };
        let mut lengths = Vec::with_capacity(alphabet);
        for _ in 0..alphabet {
            loop {
                if !(SHORTEST_CODE..=LONGEST_CODE).contains(&current) {
                    return Ok(Some(Read::Invalid));
                }
                match self.bits.bit()? {
                    None => return Ok(None),
                    Some(false) => break,
                    Some(true) => match self.bits.bit()? {
                        None => return Ok(None),
                        Some(false) => current = current.saturating_add(1),
                        Some(true) => current = current.saturating_sub(1),
                    },
                }
            }
            lengths.push(u8::try_from(current).unwrap_or(0));
        }
        Ok(Some(Read::Value(lengths)))
    }

    fn symbols(
        &mut self,
        used: &[u8],
        selectors: &[u8],
        codes: &[PrefixCode],
    ) -> Result<Option<Read<Vec<u32>>>, InputError> {
        let end_of_block = u16::try_from(used.len().saturating_add(1)).unwrap_or(u16::MAX);
        let largest = usize::try_from(self.largest_block).unwrap_or(0);
        let mut order = used.to_vec();
        let mut vector: Vec<u32> = Vec::new();
        let mut decoded = 0u32;
        let mut run = 0u32;
        let mut run_weight = 1u32;
        loop {
            let group = usize::try_from(decoded / SYMBOLS_PER_GROUP).unwrap_or(usize::MAX);
            let Some(code) = selectors
                .get(group)
                .and_then(|selector| codes.get(usize::from(*selector)))
            else {
                return Ok(Some(Read::Invalid));
            };
            decoded = decoded.saturating_add(1);
            let symbol = match code.decode(|| self.bits.bit())? {
                Decoded::Symbol(symbol) => symbol,
                Decoded::InputEnded => return Ok(None),
                Decoded::NoSuchCode => return Ok(Some(Read::Invalid)),
            };
            if symbol == RUN_A || symbol == RUN_B {
                if run_weight >= LONGEST_RUN_WEIGHT {
                    return Ok(Some(Read::Invalid));
                }
                let weight = if symbol == RUN_A { 1 } else { 2 };
                run = run.saturating_add(run_weight.saturating_mul(weight));
                run_weight = run_weight.saturating_mul(2);
                continue;
            }
            if run > 0 {
                let byte = order.first().copied().unwrap_or(0);
                let run_length = usize::try_from(run).unwrap_or(usize::MAX);
                if vector.len().saturating_add(run_length) > largest {
                    return Ok(Some(Read::Invalid));
                }
                vector.resize(vector.len().saturating_add(run_length), u32::from(byte));
                run = 0;
                run_weight = 1;
            }
            if symbol == end_of_block {
                return Ok(Some(Read::Value(vector)));
            }
            if vector.len() >= largest {
                return Ok(Some(Read::Invalid));
            }
            let at = usize::from(symbol.saturating_sub(1));
            if at >= order.len() {
                return Ok(Some(Read::Invalid));
            }
            let byte = order.remove(at);
            order.insert(0, byte);
            vector.push(u32::from(byte));
        }
    }
}

fn inverted(mut vector: Vec<u32>, origin: u32) -> Option<Vec<u32>> {
    let length = u32::try_from(vector.len()).ok()?;
    if origin >= length {
        return None;
    }
    let mut starts = [0u32; 256];
    for entry in &vector {
        let byte = usize::try_from(*entry & 0xff).unwrap_or(0);
        if let Some(count) = starts.get_mut(byte) {
            *count = count.saturating_add(1);
        }
    }
    let mut total = 0u32;
    for start in &mut starts {
        let count = *start;
        *start = total;
        total = total.saturating_add(count);
    }
    for index in 0..length {
        let at = usize::try_from(index).unwrap_or(0);
        let byte = usize::try_from(vector.get(at).copied().unwrap_or(0) & 0xff).unwrap_or(0);
        let Some(start) = starts.get_mut(byte) else {
            continue;
        };
        let target = usize::try_from(*start).unwrap_or(0);
        *start = start.saturating_add(1);
        if let Some(slot) = vector.get_mut(target) {
            *slot |= index << 8;
        }
    }
    Some(vector)
}

impl Block {
    fn new(vector: Vec<u32>, origin: u32, stored_crc: u32) -> Self {
        let length = u32::try_from(vector.len()).unwrap_or(0);
        let at = vector
            .get(usize::try_from(origin).unwrap_or(0))
            .map_or(0, |entry| entry >> 8);
        Self {
            vector,
            at,
            fetched: 0,
            length,
            previous: None,
            repeats: 0,
            run_byte: 0,
            run_left: 0,
            crc: u32::MAX,
            stored_crc,
        }
    }

    const fn crc_holds(&self) -> bool {
        self.repeats != BYTES_BEFORE_A_COUNT && !self.crc == self.stored_crc
    }

    fn finished(&self) -> bool {
        self.run_left == 0 && self.fetched >= self.length
    }

    fn fetch(&mut self) -> u8 {
        let entry = self
            .vector
            .get(usize::try_from(self.at).unwrap_or(0))
            .copied()
            .unwrap_or(0);
        self.at = entry >> 8;
        self.fetched = self.fetched.saturating_add(1);
        u8::try_from(entry & 0xff).unwrap_or(0)
    }

    fn emit(&mut self, into: &mut [u8]) -> usize {
        let mut written = 0usize;
        while let Some(slot) = into.get_mut(written) {
            if self.run_left > 0 {
                self.run_left = self.run_left.saturating_sub(1);
                *slot = self.run_byte;
                self.crc = crc_step(self.crc, self.run_byte);
                written = written.saturating_add(1);
                continue;
            }
            if self.fetched >= self.length {
                break;
            }
            let byte = self.fetch();
            if self.repeats == BYTES_BEFORE_A_COUNT {
                self.run_byte = self.previous.unwrap_or(0);
                self.run_left = u32::from(byte);
                self.repeats = 0;
                self.previous = None;
                continue;
            }
            if self.previous == Some(byte) {
                self.repeats = self.repeats.saturating_add(1);
            } else {
                self.previous = Some(byte);
                self.repeats = 1;
            }
            *slot = byte;
            self.crc = crc_step(self.crc, byte);
            written = written.saturating_add(1);
        }
        written
    }
}

static CRC_TABLE: LazyLock<[u32; 256]> = LazyLock::new(|| {
    std::array::from_fn(|index| {
        let byte = u32::try_from(index).unwrap_or(0);
        (0..8).fold(byte << 24, |crc, _| {
            if crc & 0x8000_0000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ CRC_POLYNOMIAL
            }
        })
    })
});

fn crc_step(crc: u32, byte: u8) -> u32 {
    let index = usize::from(u8::try_from(crc >> 24).unwrap_or(0) ^ byte);
    (crc << 8) ^ CRC_TABLE.get(index).copied().unwrap_or(0)
}
