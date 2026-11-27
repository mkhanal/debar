use debar_platform::input::InputError;

use crate::little_endian::Fields;
use crate::ole2::sectors::{Sector, Sectors};
use crate::ole2::stream_bytes::StreamChain;

const ENTRY_BYTES: u64 = 128;
const ENTRIES_PER_DIRECTORY_SECTOR: i32 = 4;
const DIRECTORY_SECTOR_BYTES: u64 = 512;
const NAME_BYTES: u16 = 64;
const NAME_SIZE_AT: usize = 64;
const TYPE_AT: usize = 66;
const LEFT_AT: usize = 68;
const RIGHT_AT: usize = 72;
const CHILD_AT: usize = 76;
const START_AT: usize = 116;
const SIZE_AT: usize = 120;
const LONGEST_DECODED_NAME_SOURCE: u16 = 128;
const NO_ENTRY: i32 = -1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryIndex(pub i32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    Storage,
    Stream,
    Root,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub index: EntryIndex,
    pub entry_type: EntryType,
    pub name: Option<String>,
    pub left: Option<EntryIndex>,
    pub right: Option<EntryIndex>,
    pub child: Option<EntryIndex>,
    pub chain: StreamChain,
}

pub fn entry_at(
    sectors: &Sectors<'_>,
    index: EntryIndex,
) -> Result<Option<DirectoryEntry>, InputError> {
    if index.0 < 0 || sectors.is_beyond_the_highest_unit(index.0) {
        return Ok(None);
    }
    let steps = u64::try_from(
        index
            .0
            .checked_div(ENTRIES_PER_DIRECTORY_SECTOR)
            .unwrap_or(0),
    )
    .unwrap_or(0);
    let slot = u64::try_from(
        index
            .0
            .checked_rem(ENTRIES_PER_DIRECTORY_SECTOR)
            .unwrap_or(0),
    )
    .unwrap_or(0);
    let sector = sectors.chain_from(sectors.geometry().first_directory_sector, steps)?;
    let Some(span) = sectors.span(sector, DIRECTORY_SECTOR_BYTES) else {
        return Ok(None);
    };
    let bytes = sectors.read(span)?;
    let start = usize::try_from(slot.saturating_mul(ENTRY_BYTES)).unwrap_or(0);
    let end = start.saturating_add(usize::try_from(ENTRY_BYTES).unwrap_or(0));
    let Some(raw) = bytes.get(start..end) else {
        return Ok(None);
    };
    Ok(entry_from(raw, index))
}

fn entry_from(raw: &[u8], index: EntryIndex) -> Option<DirectoryEntry> {
    let fields = Fields::of(raw);
    let type_code = raw.get(TYPE_AT).copied().unwrap_or(0);
    if type_code == 0 {
        return None;
    }
    let name_size = fields.u16_at(NAME_SIZE_AT);
    if name_size > NAME_BYTES || name_size % 2 == 1 {
        return None;
    }
    let entry_type = match type_code {
        1 => EntryType::Storage,
        2 => EntryType::Stream,
        5 => EntryType::Root,
        _ => EntryType::Unknown,
    };
    Some(DirectoryEntry {
        index,
        entry_type,
        name: decoded_name(raw, name_size),
        left: linked(fields.u32_at(LEFT_AT)),
        right: linked(fields.u32_at(RIGHT_AT)),
        child: linked(fields.u32_at(CHILD_AT)),
        chain: StreamChain {
            start: i32::from_ne_bytes(fields.u32_at(START_AT).to_ne_bytes()),
            declared_size: fields.u32_at(SIZE_AT),
        },
    })
}

fn linked(field: u32) -> Option<EntryIndex> {
    let index = i32::from_ne_bytes(field.to_ne_bytes());
    (index != NO_ENTRY).then_some(EntryIndex(index))
}

pub fn decoded_name(raw: &[u8], name_size: u16) -> Option<String> {
    if raw.get(..2) == Some([0, 0].as_slice())
        || name_size == 0
        || name_size > LONGEST_DECODED_NAME_SOURCE
    {
        return None;
    }
    let units = usize::from(name_size.saturating_sub(2)) / 2;
    let mut name = String::new();
    let (pairs, _) = raw.as_chunks::<2>();
    for [low, high] in pairs.iter().take(units) {
        decode_unit(*low, *high, &mut name);
    }
    (!name.is_empty()).then_some(name)
}

fn decode_unit(low: u8, high: u8, name: &mut String) {
    if high == 0 && (0x20..0x7f).contains(&low) {
        name.push(char::from(low.to_ascii_lowercase()));
        return;
    }
    if high == 0 && low <= 9 {
        name.push('_');
        name.push(char::from(b'0'.saturating_add(low)));
        name.push('_');
        return;
    }
    let mixed = (u16::from(low) << 8) | u16::from(high);
    name.push('_');
    for shift in [0u16, 4, 8] {
        let nibble = u8::try_from((mixed >> shift) & 0xf).unwrap_or(0);
        name.push(char::from(b'a'.saturating_add(nibble)));
    }
    name.push('_');
}

impl DirectoryEntry {
    pub const fn start_sector(&self) -> Sector {
        Sector(self.chain.start)
    }
}
