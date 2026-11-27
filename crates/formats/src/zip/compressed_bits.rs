use debar_platform::input::{InputError, ObjectBytes};

use crate::object::Object;

const COMPRESSED_READ_BYTES: u64 = 16 * 1024;

pub struct CompressedBytes<'o> {
    compressed: Object<'o>,
    chunk: Vec<u8>,
    chunk_used: usize,
    read_up_to: u64,
}

impl<'o> CompressedBytes<'o> {
    pub const fn new(compressed: Object<'o>) -> Self {
        Self {
            compressed,
            chunk: Vec::new(),
            chunk_used: 0,
            read_up_to: 0,
        }
    }

    pub fn next_byte(&mut self) -> Result<Option<u8>, InputError> {
        if self.chunk_used >= self.chunk.len() && !self.refill()? {
            return Ok(None);
        }
        let byte = self.chunk.get(self.chunk_used).copied();
        self.chunk_used = self.chunk_used.saturating_add(1);
        Ok(byte)
    }

    pub fn unused(&mut self) -> Result<&[u8], InputError> {
        if self.chunk_used >= self.chunk.len() {
            self.refill()?;
        }
        Ok(self.chunk.get(self.chunk_used..).unwrap_or_default())
    }

    pub fn consume(&mut self, count: usize) {
        self.chunk_used = self.chunk_used.saturating_add(count).min(self.chunk.len());
    }

    fn refill(&mut self) -> Result<bool, InputError> {
        let left = self.compressed.length().saturating_sub(self.read_up_to);
        if left == 0 {
            return Ok(false);
        }
        let take = left.min(COMPRESSED_READ_BYTES);
        self.chunk.resize(usize::try_from(take).unwrap_or(0), 0);
        self.compressed.read_at(self.read_up_to, &mut self.chunk)?;
        self.read_up_to = self.read_up_to.saturating_add(take);
        self.chunk_used = 0;
        Ok(true)
    }
}

pub struct LowBitsFirst<'o> {
    bytes: CompressedBytes<'o>,
    held: u64,
    held_count: u32,
}

impl<'o> LowBitsFirst<'o> {
    pub const fn new(compressed: Object<'o>) -> Self {
        Self {
            bytes: CompressedBytes::new(compressed),
            held: 0,
            held_count: 0,
        }
    }

    pub fn bits(&mut self, count: u32) -> Result<Option<u32>, InputError> {
        if !self.hold(count)? {
            return Ok(None);
        }
        let value = self.held & low_mask(count);
        self.drop_bits(count);
        Ok(u32::try_from(value).ok())
    }

    pub fn bit(&mut self) -> Result<Option<bool>, InputError> {
        Ok(self.bits(1)?.map(|bit| bit == 1))
    }

    pub fn skip_to_byte_boundary(&mut self) {
        let partial = self.held_count % 8;
        self.drop_bits(partial);
    }

    pub fn whole_byte(&mut self) -> Result<Option<u8>, InputError> {
        if self.held_count >= 8 {
            return Ok(self.bits(8)?.and_then(|byte| u8::try_from(byte).ok()));
        }
        self.bytes.next_byte()
    }

    fn hold(&mut self, count: u32) -> Result<bool, InputError> {
        while self.held_count < count {
            let Some(byte) = self.bytes.next_byte()? else {
                return Ok(false);
            };
            self.held |= u64::from(byte) << self.held_count;
            self.held_count = self.held_count.saturating_add(8);
        }
        Ok(true)
    }

    fn drop_bits(&mut self, count: u32) {
        self.held = self.held.checked_shr(count).unwrap_or(0);
        self.held_count = self.held_count.saturating_sub(count);
    }
}

pub struct HighBitsFirst<'o> {
    bytes: CompressedBytes<'o>,
    held: u64,
    held_count: u32,
}

impl<'o> HighBitsFirst<'o> {
    pub const fn new(compressed: Object<'o>) -> Self {
        Self {
            bytes: CompressedBytes::new(compressed),
            held: 0,
            held_count: 0,
        }
    }

    pub fn bits(&mut self, count: u32) -> Result<Option<u32>, InputError> {
        while self.held_count < count {
            let Some(byte) = self.bytes.next_byte()? else {
                return Ok(None);
            };
            self.held = (self.held << 8) | u64::from(byte);
            self.held_count = self.held_count.saturating_add(8);
        }
        let shift = self.held_count.saturating_sub(count);
        let value = self.held.checked_shr(shift).unwrap_or(0) & low_mask(count);
        self.held_count = shift;
        self.held &= low_mask(shift);
        Ok(u32::try_from(value).ok())
    }

    pub fn bit(&mut self) -> Result<Option<bool>, InputError> {
        Ok(self.bits(1)?.map(|bit| bit == 1))
    }
}

fn low_mask(count: u32) -> u64 {
    1u64.checked_shl(count)
        .map_or(u64::MAX, |bit| bit.saturating_sub(1))
}
