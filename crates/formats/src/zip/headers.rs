use debar_platform::input::{InputError, ObjectBytes};

use crate::module::ContainerEntry;
use crate::zip::little_endian::{Fields, read_within};

pub const LOCAL_HEADER_MAGIC: [u8; 4] = *b"PK\x03\x04";
const CENTRAL_HEADER_MAGIC: [u8; 4] = *b"PK\x01\x02";
const DATA_DESCRIPTOR_MAGIC_LENGTH: u64 = 4;
pub const LOCAL_HEADER_LENGTH: u64 = 30;
const CENTRAL_HEADER_LENGTH: u64 = 46;
const LONGEST_NAME_TESTED: u64 = 255;
const ENCRYPTED: u16 = 0x0001;
const SIZES_IN_A_DATA_DESCRIPTOR: u16 = 0x0008;
const MASKED_HEADER: u16 = 0x2000;
const DATA_DESCRIPTOR_LENGTH: u64 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub offset: u64,
    pub header_length: u64,
    pub compressed_size: u64,
    pub real_size: u64,
    pub method: u16,
    pub flags: u16,
    pub encrypted: bool,
}

impl Record {
    pub const UNREAD: Self = Self {
        offset: 0,
        header_length: 0,
        compressed_size: 0,
        real_size: 0,
        method: 0,
        flags: 0,
        encrypted: false,
    };

    pub const fn data_offset(&self) -> u64 {
        self.offset.saturating_add(self.header_length)
    }

    pub const fn end(&self) -> u64 {
        self.data_offset().saturating_add(self.compressed_size)
    }

    pub const fn same_member_as(&self, other: &Self) -> bool {
        self.offset == other.offset
            && self.header_length == other.header_length
            && self.compressed_size == other.compressed_size
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclaredSizes {
    pub compressed: u64,
    pub real: u64,
}

pub enum LocalParse {
    Unreadable,
    Rejected {
        entry: ContainerEntry,
    },
    Accepted {
        entry: ContainerEntry,
        record: Record,
    },
}

pub fn local_record_at(
    object: &dyn ObjectBytes,
    offset: u64,
    central_sizes: Option<DeclaredSizes>,
    position: u64,
) -> Result<LocalParse, InputError> {
    let Some(fixed) = read_within(object, offset, LOCAL_HEADER_LENGTH)? else {
        return Ok(LocalParse::Unreadable);
    };
    let fields = Fields::of(&fixed);
    if fixed.get(..4) != Some(LOCAL_HEADER_MAGIC.as_slice()) {
        return Ok(LocalParse::Unreadable);
    }
    let name_length = u64::from(fields.u16_at(26));
    let extra_length = u64::from(fields.u16_at(28));
    let name_at = offset.saturating_add(LOCAL_HEADER_LENGTH);
    let mut remaining = object.length().saturating_sub(name_at);
    if remaining <= name_length {
        return Ok(LocalParse::Unreadable);
    }
    let flags = fields.u16_at(6);
    let local_sizes = DeclaredSizes {
        compressed: u64::from(fields.u32_at(18)),
        real: u64::from(fields.u32_at(22)),
    };
    let entry = ContainerEntry {
        name: Some(tested_name(object, name_at, name_length)?),
        compressed_size: local_sizes.compressed,
        real_size: local_sizes.real,
        encrypted: flags & ENCRYPTED != 0,
        position,
    };
    let rejected = |entry| Ok(LocalParse::Rejected { entry });
    if flags & MASKED_HEADER != 0 {
        return rejected(entry);
    }
    let sizes = if flags & SIZES_IN_A_DATA_DESCRIPTOR == 0 {
        local_sizes
    } else {
        match central_sizes {
            Some(sizes) => sizes,
            None => return rejected(entry),
        }
    };
    remaining = remaining.saturating_sub(name_length);
    if remaining <= extra_length {
        return rejected(entry);
    }
    remaining = remaining.saturating_sub(extra_length);
    if remaining < sizes.compressed {
        return rejected(entry);
    }
    let record = Record {
        offset,
        header_length: LOCAL_HEADER_LENGTH
            .saturating_add(name_length)
            .saturating_add(extra_length),
        compressed_size: sizes.compressed,
        real_size: sizes.real,
        method: fields.u16_at(8),
        flags,
        encrypted: flags & ENCRYPTED != 0,
    };
    if flags & SIZES_IN_A_DATA_DESCRIPTOR != 0
        && (remaining.saturating_sub(sizes.compressed) < DATA_DESCRIPTOR_LENGTH
            || read_within(object, record.end(), DATA_DESCRIPTOR_MAGIC_LENGTH)?.is_none())
    {
        return rejected(entry);
    }
    Ok(LocalParse::Accepted { entry, record })
}

pub enum CentralParse {
    EndOfDirectory,
    EndAfter(ContainerEntry),
    Record {
        entry: ContainerEntry,
        local_header_offset: u64,
        sizes: DeclaredSizes,
        length: u64,
    },
}

pub fn central_record_at(
    object: &dyn ObjectBytes,
    at: u64,
    position: u64,
) -> Result<CentralParse, InputError> {
    let Some(fixed) = read_within(object, at, CENTRAL_HEADER_LENGTH)? else {
        return Ok(CentralParse::EndOfDirectory);
    };
    if fixed.get(..4) != Some(CENTRAL_HEADER_MAGIC.as_slice()) {
        return Ok(CentralParse::EndOfDirectory);
    }
    let fields = Fields::of(&fixed);
    let name_length = u64::from(fields.u16_at(28));
    let extra_length = u64::from(fields.u16_at(30));
    let comment_length = u64::from(fields.u16_at(32));
    let length = object.length();
    let name_at = at.saturating_add(CENTRAL_HEADER_LENGTH);
    if length <= name_at.saturating_add(name_length) {
        return Ok(CentralParse::EndOfDirectory);
    }
    let sizes = DeclaredSizes {
        compressed: u64::from(fields.u32_at(20)),
        real: u64::from(fields.u32_at(24)),
    };
    let entry = ContainerEntry {
        name: Some(tested_name(object, name_at, name_length)?),
        compressed_size: sizes.compressed,
        real_size: sizes.real,
        encrypted: fields.u16_at(8) & ENCRYPTED != 0,
        position,
    };
    let after_name = name_at.saturating_add(name_length);
    if length <= after_name.saturating_add(extra_length) {
        return Ok(CentralParse::EndAfter(entry));
    }
    let after_extra = after_name.saturating_add(extra_length);
    if length < after_extra.saturating_add(comment_length) {
        return Ok(CentralParse::EndAfter(entry));
    }
    Ok(CentralParse::Record {
        entry,
        local_header_offset: u64::from(fields.u32_at(42)),
        sizes,
        length: CENTRAL_HEADER_LENGTH
            .saturating_add(name_length)
            .saturating_add(extra_length)
            .saturating_add(comment_length),
    })
}

fn tested_name(
    object: &dyn ObjectBytes,
    name_at: u64,
    name_length: u64,
) -> Result<Vec<u8>, InputError> {
    let tested_length = name_length.min(LONGEST_NAME_TESTED);
    let mut name = read_within(object, name_at, tested_length)?.unwrap_or_default();
    if let Some(end) = name.iter().position(|byte| *byte == 0) {
        name.truncate(end);
    }
    Ok(name)
}
