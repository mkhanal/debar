use debar_platform::input::{InputError, ObjectBytes};

use crate::little_endian::{Fields, read_within};
use crate::object::Object;
use crate::ole2::sectors::Sector;

pub const HEADER_BYTES: u64 = 512;
pub const HEADER_FAT_SECTORS: usize = 109;
const SIGNATURE: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const SECTOR_SHIFT_AT: usize = 0x1e;
const MINI_SECTOR_SHIFT_AT: usize = 0x20;
const FAT_SECTOR_COUNT_AT: usize = 0x2c;
const FIRST_DIRECTORY_SECTOR_AT: usize = 0x30;
const MINI_STREAM_CUTOFF_AT: usize = 0x38;
const FIRST_MINI_FAT_SECTOR_AT: usize = 0x3c;
const FIRST_DIFAT_SECTOR_AT: usize = 0x44;
const HEADER_FAT_LIST_AT: usize = 0x4c;
const SMALLEST_SECTOR_SHIFT: u16 = 6;
const LARGEST_SECTOR_SHIFT: u16 = 28;
const LARGEST_DOCUMENT: u64 = 0x7fff_ffff;

#[derive(Debug, Clone)]
pub struct Geometry {
    pub sector_shift: u32,
    pub mini_sector_shift: u32,
    pub mini_stream_cutoff: u32,
    pub fat_sector_count: u32,
    pub first_directory_sector: Sector,
    pub first_mini_fat_sector: Sector,
    pub first_difat_sector: Sector,
    pub header_fat_sectors: [Sector; HEADER_FAT_SECTORS],
    pub document_length: u64,
    pub highest_unit_number: i64,
}

pub enum Header {
    Holds(Box<Geometry>),
    TooShort,
    Rejected { at: u64 },
}

pub fn header_of(document: &Object<'_>) -> Result<Header, InputError> {
    let Some(bytes) = read_within(document, 0, HEADER_BYTES)? else {
        return Ok(Header::TooShort);
    };
    if bytes.get(..SIGNATURE.len()) != Some(SIGNATURE.as_slice()) {
        return Ok(Header::Rejected { at: 0 });
    }
    let fields = Fields::of(&bytes);
    let sector_shift = fields.u16_at(SECTOR_SHIFT_AT);
    if !(SMALLEST_SECTOR_SHIFT..=LARGEST_SECTOR_SHIFT).contains(&sector_shift) {
        return Ok(Header::Rejected {
            at: offset(SECTOR_SHIFT_AT),
        });
    }
    let sector_shift = u32::from(sector_shift);
    let mini_sector_shift = fields.u32_at(MINI_SECTOR_SHIFT_AT);
    if mini_sector_shift == 0 || mini_sector_shift > sector_shift {
        return Ok(Header::Rejected {
            at: offset(MINI_SECTOR_SHIFT_AT),
        });
    }
    let document_length = document.length();
    if document_length > LARGEST_DOCUMENT {
        return Ok(Header::Rejected { at: 0 });
    }
    let mut header_fat_sectors = [Sector(0); HEADER_FAT_SECTORS];
    for (slot, sector) in header_fat_sectors.iter_mut().enumerate() {
        let at = slot
            .checked_mul(4)
            .and_then(|step| step.checked_add(HEADER_FAT_LIST_AT))
            .unwrap_or(usize::MAX);
        *sector = Sector::from_field(fields.u32_at(at));
    }
    let data_start = data_start(sector_shift);
    let highest_unit_number = i64::try_from(document_length)
        .unwrap_or(i64::MAX)
        .saturating_sub(i64::try_from(data_start).unwrap_or(i64::MAX))
        .checked_shr(mini_sector_shift)
        .unwrap_or(0);
    Ok(Header::Holds(Box::new(Geometry {
        sector_shift,
        mini_sector_shift,
        mini_stream_cutoff: fields.u32_at(MINI_STREAM_CUTOFF_AT),
        fat_sector_count: fields.u32_at(FAT_SECTOR_COUNT_AT),
        first_directory_sector: Sector::from_field(fields.u32_at(FIRST_DIRECTORY_SECTOR_AT)),
        first_mini_fat_sector: Sector::from_field(fields.u32_at(FIRST_MINI_FAT_SECTOR_AT)),
        first_difat_sector: Sector::from_field(fields.u32_at(FIRST_DIFAT_SECTOR_AT)),
        header_fat_sectors,
        document_length,
        highest_unit_number,
    })))
}

impl Geometry {
    pub const fn sector_bytes(&self) -> u64 {
        1u64 << self.sector_shift
    }

    pub const fn mini_sector_bytes(&self) -> u64 {
        1u64 << self.mini_sector_shift
    }

    pub const fn data_start(&self) -> u64 {
        data_start(self.sector_shift)
    }
}

const fn data_start(sector_shift: u32) -> u64 {
    let sector = 1u64 << sector_shift;
    if sector > HEADER_BYTES {
        sector
    } else {
        HEADER_BYTES
    }
}

fn offset(at: usize) -> u64 {
    u64::try_from(at).unwrap_or(u64::MAX)
}
