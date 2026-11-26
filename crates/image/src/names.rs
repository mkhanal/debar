use zerocopy::little_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::model::{Indicator, SignatureName};

const NAMES_PER_BLOCK: usize = 16;
const VARINT_PAYLOAD_BITS: u32 = 7;
const VARINT_CONTINUES: u8 = 0x80;
const VARINT_PAYLOAD: u8 = 0x7f;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NameId(pub u32);

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct NamesHeader {
    name_count: U32,
    block_count: U32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct NamesNotBuilt;

pub fn build(sorted_distinct_names: &[(&str, Indicator)]) -> Result<Vec<u8>, NamesNotBuilt> {
    let mut blocks = Vec::new();
    let mut block_starts = Vec::new();
    for block in sorted_distinct_names.chunks(NAMES_PER_BLOCK) {
        block_starts.push(U32::new(
            u32::try_from(blocks.len()).map_err(|_| NamesNotBuilt)?,
        ));
        let mut previous: &[u8] = &[];
        for (name, _) in block {
            let name = name.as_bytes();
            let shared = previous
                .iter()
                .zip(name)
                .take_while(|(earlier, later)| earlier == later)
                .count();
            let suffix = name.get(shared..).ok_or(NamesNotBuilt)?;
            write_varint(&mut blocks, shared)?;
            write_varint(&mut blocks, suffix.len())?;
            blocks.extend_from_slice(suffix);
            previous = name;
        }
    }
    let header = NamesHeader {
        name_count: U32::new(
            u32::try_from(sorted_distinct_names.len()).map_err(|_| NamesNotBuilt)?,
        ),
        block_count: U32::new(u32::try_from(block_starts.len()).map_err(|_| NamesNotBuilt)?),
    };
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend(
        sorted_distinct_names
            .iter()
            .map(|(_, indicator)| indicator_code(*indicator)),
    );
    bytes.extend_from_slice(block_starts.as_bytes());
    bytes.extend_from_slice(&blocks);
    Ok(bytes)
}

const fn indicator_code(indicator: Indicator) -> u8 {
    match indicator {
        Indicator::Strong => 1,
        Indicator::PotentiallyUnwanted => 2,
        Indicator::Weak => 3,
    }
}

fn indicator_from_code(code: u8) -> Option<Indicator> {
    [
        Indicator::Strong,
        Indicator::PotentiallyUnwanted,
        Indicator::Weak,
    ]
    .into_iter()
    .find(|indicator| indicator_code(*indicator) == code)
}

#[derive(Debug, PartialEq, Eq)]
pub enum NamesMalformed {
    Layout,
    UnknownName(NameId),
    Encoding,
}

pub struct NamesView<'m> {
    name_count: u32,
    indicators: &'m [u8],
    block_starts: &'m [U32],
    blocks: &'m [u8],
}

impl<'m> NamesView<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, NamesMalformed> {
        let (header, rest) =
            NamesHeader::ref_from_prefix(bytes).map_err(|_| NamesMalformed::Layout)?;
        let block_count =
            usize::try_from(header.block_count.get()).map_err(|_| NamesMalformed::Layout)?;
        let name_count =
            usize::try_from(header.name_count.get()).map_err(|_| NamesMalformed::Layout)?;
        let (indicators, rest) = rest
            .split_at_checked(name_count)
            .ok_or(NamesMalformed::Layout)?;
        let (block_starts, blocks) = <[U32]>::ref_from_prefix_with_elems(rest, block_count)
            .map_err(|_| NamesMalformed::Layout)?;
        Ok(Self {
            name_count: header.name_count.get(),
            indicators,
            block_starts,
            blocks,
        })
    }

    pub fn signature_name(&self, id: NameId) -> Result<SignatureName, NamesMalformed> {
        let index = usize::try_from(id.0).map_err(|_| NamesMalformed::Layout)?;
        let indicator = self
            .indicators
            .get(index)
            .copied()
            .and_then(indicator_from_code)
            .ok_or(NamesMalformed::Encoding)?;
        Ok(SignatureName {
            text: self.text(id)?,
            indicator,
        })
    }

    fn text(&self, id: NameId) -> Result<String, NamesMalformed> {
        if id.0 >= self.name_count {
            return Err(NamesMalformed::UnknownName(id));
        }
        let index = usize::try_from(id.0).map_err(|_| NamesMalformed::Layout)?;
        let block = index / NAMES_PER_BLOCK;
        let within = index % NAMES_PER_BLOCK;
        let start = self
            .block_starts
            .get(block)
            .ok_or(NamesMalformed::UnknownName(id))?
            .get();
        let mut rest = self
            .blocks
            .get(usize::try_from(start).map_err(|_| NamesMalformed::Layout)?..)
            .ok_or(NamesMalformed::Encoding)?;
        let mut name: Vec<u8> = Vec::new();
        for _ in 0..=within {
            let shared;
            let suffix_length;
            (shared, rest) = read_varint(rest)?;
            (suffix_length, rest) = read_varint(rest)?;
            let (suffix, after) = rest
                .split_at_checked(suffix_length)
                .ok_or(NamesMalformed::Encoding)?;
            if shared > name.len() {
                return Err(NamesMalformed::Encoding);
            }
            name.truncate(shared);
            name.extend_from_slice(suffix);
            rest = after;
        }
        String::from_utf8(name).map_err(|_| NamesMalformed::Encoding)
    }
}

fn write_varint(bytes: &mut Vec<u8>, value: usize) -> Result<(), NamesNotBuilt> {
    let mut remaining = u32::try_from(value).map_err(|_| NamesNotBuilt)?;
    loop {
        let [low, ..] = remaining.to_le_bytes();
        let payload = low & VARINT_PAYLOAD;
        remaining >>= VARINT_PAYLOAD_BITS;
        if remaining == 0 {
            bytes.push(payload);
            return Ok(());
        }
        bytes.push(payload | VARINT_CONTINUES);
    }
}

fn read_varint(bytes: &[u8]) -> Result<(usize, &[u8]), NamesMalformed> {
    let mut value: u32 = 0;
    let mut shift: u32 = 0;
    let mut rest = bytes;
    loop {
        let (byte, after) = rest.split_first().ok_or(NamesMalformed::Encoding)?;
        rest = after;
        let payload = u32::from(byte & VARINT_PAYLOAD)
            .checked_shl(shift)
            .ok_or(NamesMalformed::Encoding)?;
        value |= payload;
        if byte & VARINT_CONTINUES == 0 {
            return Ok((
                usize::try_from(value).map_err(|_| NamesMalformed::Encoding)?,
                rest,
            ));
        }
        shift = shift
            .checked_add(VARINT_PAYLOAD_BITS)
            .filter(|next| *next < u32::BITS)
            .ok_or(NamesMalformed::Encoding)?;
    }
}
