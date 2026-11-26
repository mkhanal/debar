use zerocopy::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::object_kind::ObjectKind;

const FILE_TABLE: u8 = 1;
const PARTITION_TABLE: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MagicTable {
    Files,
    Partitions,
}

impl MagicTable {
    const fn code(self) -> u8 {
        match self {
            Self::Files => FILE_TABLE,
            Self::Partitions => PARTITION_TABLE,
        }
    }
}

pub struct PendingMagic {
    pub table: MagicTable,
    pub offset: u32,
    pub bytes: Vec<u8>,
    pub found: ObjectKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MagicNotBuilt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MagicMalformed {
    Layout,
    UnknownKind,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct MagicEntry {
    table: u8,
    reserved: u8,
    found: U16,
    offset: U32,
    bytes_start: U32,
    bytes_length: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct MagicHeader {
    entry_count: U32,
    byte_count: U32,
}

pub fn build(entries: &[PendingMagic]) -> Result<Vec<u8>, MagicNotBuilt> {
    let count = |value: usize| u32::try_from(value).map_err(|_| MagicNotBuilt);
    let mut records = Vec::with_capacity(entries.len());
    let mut bytes = Vec::new();
    for entry in entries {
        records.push(MagicEntry {
            table: entry.table.code(),
            reserved: 0,
            found: U16::new(entry.found.code()),
            offset: U32::new(entry.offset),
            bytes_start: U32::new(count(bytes.len())?),
            bytes_length: U32::new(count(entry.bytes.len())?),
        });
        bytes.extend_from_slice(&entry.bytes);
    }
    let header = MagicHeader {
        entry_count: U32::new(count(records.len())?),
        byte_count: U32::new(count(bytes.len())?),
    };
    let mut section = header.as_bytes().to_vec();
    section.extend_from_slice(records.as_bytes());
    section.extend_from_slice(&bytes);
    Ok(section)
}

#[derive(Clone, Copy)]
pub struct TypeMagic<'m> {
    entries: &'m [MagicEntry],
    bytes: &'m [u8],
}

impl<'m> TypeMagic<'m> {
    pub fn read(section: &'m [u8]) -> Result<Self, MagicMalformed> {
        let (header, rest) =
            MagicHeader::ref_from_prefix(section).map_err(|_| MagicMalformed::Layout)?;
        let entry_count =
            usize::try_from(header.entry_count.get()).map_err(|_| MagicMalformed::Layout)?;
        let (entries, bytes) = <[MagicEntry]>::ref_from_prefix_with_elems(rest, entry_count)
            .map_err(|_| MagicMalformed::Layout)?;
        if usize::try_from(header.byte_count.get()).ok() != Some(bytes.len()) {
            return Err(MagicMalformed::Layout);
        }
        Ok(Self { entries, bytes })
    }

    pub fn first_match(
        &self,
        table: MagicTable,
        prefix: &[u8],
    ) -> Result<Option<ObjectKind>, MagicMalformed> {
        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.table == table.code())
        {
            let start =
                usize::try_from(entry.bytes_start.get()).map_err(|_| MagicMalformed::Layout)?;
            let length =
                usize::try_from(entry.bytes_length.get()).map_err(|_| MagicMalformed::Layout)?;
            let magic = start
                .checked_add(length)
                .and_then(|end| self.bytes.get(start..end))
                .ok_or(MagicMalformed::Layout)?;
            let held = usize::try_from(entry.offset.get())
                .ok()
                .and_then(|offset| prefix.get(offset..offset.checked_add(length)?));
            if held == Some(magic) {
                return ObjectKind::from_code(entry.found.get())
                    .map(Some)
                    .ok_or(MagicMalformed::UnknownKind);
            }
        }
        Ok(None)
    }
}
