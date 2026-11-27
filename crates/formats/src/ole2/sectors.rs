use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use debar_platform::input::{InputError, ObjectBytes};

use crate::little_endian::Fields;
use crate::object::Object;
use crate::ole2::header::{Geometry, HEADER_FAT_SECTORS};

const TABLE_SECTOR_BYTES: u64 = 512;
const ENTRIES_PER_TABLE_SECTOR: i32 = 128;
const ENTRIES_PER_DIFAT_SECTOR: i32 = 127;
const NEXT_DIFAT_SECTOR_SLOT: i32 = 127;
const PAST_THE_FAT: Sector = Sector(-10);
const UNREADABLE: Sector = Sector(-1);
const LARGEST_OFFSET: u64 = 0x7fff_ffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sector(pub i32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MiniSector(pub i32);

impl Sector {
    pub fn from_field(field: u32) -> Self {
        Self(i32::from_ne_bytes(field.to_ne_bytes()))
    }

    pub const fn is_end(self) -> bool {
        self.0 < 0
    }
}

impl MiniSector {
    pub fn from_field(field: u32) -> Self {
        Self(i32::from_ne_bytes(field.to_ne_bytes()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub offset: u64,
    pub present: u64,
    pub length: u64,
}

pub struct Sectors<'o> {
    document: Object<'o>,
    geometry: Box<Geometry>,
    fat: RefCell<HashMap<i32, Option<Rc<[u8]>>>>,
    tables: RefCell<HashMap<Sector, Option<Rc<[u8]>>>>,
    chains: RefCell<HashMap<Sector, Vec<Sector>>>,
    difat: RefCell<Vec<Option<Sector>>>,
    mini_stream_start: Cell<Option<Sector>>,
}

impl<'o> Sectors<'o> {
    pub fn new(document: Object<'o>, geometry: Box<Geometry>) -> Self {
        Self {
            document,
            geometry,
            fat: RefCell::new(HashMap::new()),
            tables: RefCell::new(HashMap::new()),
            chains: RefCell::new(HashMap::new()),
            difat: RefCell::new(Vec::new()),
            mini_stream_start: Cell::new(None),
        }
    }

    pub const fn geometry(&self) -> &Geometry {
        &self.geometry
    }

    pub const fn document(&self) -> &Object<'o> {
        &self.document
    }

    pub fn set_mini_stream_start(&self, start: Sector) {
        self.mini_stream_start.set(Some(start));
    }

    pub fn is_beyond_the_highest_unit(&self, number: i32) -> bool {
        i64::from(number) > self.geometry.highest_unit_number
    }

    pub fn span(&self, sector: Sector, length: u64) -> Option<Span> {
        let number = u64::try_from(sector.0).ok()?;
        let shifted = number.checked_shl(self.geometry.sector_shift)?;
        let data_start = self.geometry.data_start();
        let offset = if shifted >= LARGEST_OFFSET.saturating_sub(data_start) {
            LARGEST_OFFSET.saturating_sub(length)
        } else {
            shifted.saturating_add(data_start)
        };
        let document_length = self.geometry.document_length;
        if offset >= document_length {
            return None;
        }
        Some(Span {
            offset,
            present: length.min(document_length.saturating_sub(offset)),
            length,
        })
    }

    pub fn mini_span(&self, mini: MiniSector) -> Result<Option<Span>, InputError> {
        let Some(start) = self.mini_stream_start.get() else {
            return Ok(None);
        };
        let Ok(number) = u64::try_from(mini.0) else {
            return Ok(None);
        };
        let per_sector = self
            .geometry
            .sector_bytes()
            .checked_div(self.geometry.mini_sector_bytes())
            .unwrap_or(1)
            .max(1);
        let steps = number.checked_div(per_sector).unwrap_or(0);
        let within = number
            .checked_rem(per_sector)
            .unwrap_or(0)
            .saturating_mul(self.geometry.mini_sector_bytes());
        let sector = self.chain_from(start, steps)?;
        let Some(holding) = self.span(sector, self.geometry.sector_bytes()) else {
            return Ok(None);
        };
        let offset = holding.offset.saturating_add(within);
        let length = self.geometry.mini_sector_bytes();
        let present = length.min(self.geometry.document_length.saturating_sub(offset));
        Ok(Some(Span {
            offset,
            present,
            length,
        }))
    }

    pub fn read(&self, span: Span) -> Result<Vec<u8>, InputError> {
        let mut bytes = vec![0u8; usize::try_from(span.length).unwrap_or(0)];
        let present = usize::try_from(span.present).unwrap_or(0);
        if let Some(into) = bytes.get_mut(..present) {
            self.document.read_at(span.offset, into)?;
        }
        Ok(bytes)
    }

    pub fn next_sector(&self, sector: Sector) -> Result<Sector, InputError> {
        if sector.is_end() {
            return Ok(sector);
        }
        let table_index = sector.0.checked_div(ENTRIES_PER_TABLE_SECTOR).unwrap_or(0);
        let slot = sector.0.checked_rem(ENTRIES_PER_TABLE_SECTOR).unwrap_or(0);
        if i64::from(table_index) > i64::from(self.geometry.fat_sector_count) {
            return Ok(PAST_THE_FAT);
        }
        let Some(table) = self.fat_table(table_index)? else {
            return Ok(UNREADABLE);
        };
        Ok(Sector::from_field(entry_at(&table, slot)))
    }

    pub fn next_mini_sector(&self, mini: MiniSector) -> Result<MiniSector, InputError> {
        let Ok(number) = u64::try_from(mini.0) else {
            return Ok(mini);
        };
        let per_table = u64::try_from(ENTRIES_PER_TABLE_SECTOR).unwrap_or(1);
        let steps = number.checked_div(per_table).unwrap_or(0);
        let slot = mini.0.checked_rem(ENTRIES_PER_TABLE_SECTOR).unwrap_or(0);
        let sector = self.chain_from(self.geometry.first_mini_fat_sector, steps)?;
        let Some(table) = self.table(sector)? else {
            return Ok(MiniSector(UNREADABLE.0));
        };
        Ok(MiniSector::from_field(entry_at(&table, slot)))
    }

    pub fn chain_from(&self, start: Sector, steps: u64) -> Result<Sector, InputError> {
        let mut chains = self.chains.borrow_mut();
        let chain = chains.entry(start).or_insert_with(|| vec![start]);
        let wanted = usize::try_from(steps).unwrap_or(usize::MAX);
        while chain.len() <= wanted {
            let Some(last) = chain.last().copied() else {
                break;
            };
            let next = if last.is_end() {
                last
            } else {
                self.next_sector(last)?
            };
            chain.push(next);
        }
        Ok(chain.get(wanted).copied().unwrap_or(UNREADABLE))
    }

    pub fn table(&self, sector: Sector) -> Result<Option<Rc<[u8]>>, InputError> {
        if let Some(cached) = self.tables.borrow().get(&sector) {
            return Ok(cached.clone());
        }
        let read = match self.span(sector, TABLE_SECTOR_BYTES) {
            Some(span) => Some(Rc::from(self.read(span)?)),
            None => None,
        };
        self.tables.borrow_mut().insert(sector, read.clone());
        Ok(read)
    }

    fn fat_table(&self, table_index: i32) -> Result<Option<Rc<[u8]>>, InputError> {
        if let Some(cached) = self.fat.borrow().get(&table_index) {
            return Ok(cached.clone());
        }
        let holding = self.fat_sector_holding(table_index)?;
        let table = match holding {
            Some(sector) => self.table(sector)?,
            None => None,
        };
        self.fat.borrow_mut().insert(table_index, table.clone());
        Ok(table)
    }

    fn fat_sector_holding(&self, table_index: i32) -> Result<Option<Sector>, InputError> {
        let in_header = usize::try_from(table_index).ok();
        if let Some(sector) = in_header.and_then(|slot| self.geometry.header_fat_sectors.get(slot))
        {
            return Ok(Some(*sector));
        }
        let header_count = i32::try_from(HEADER_FAT_SECTORS).unwrap_or(i32::MAX);
        let beyond = table_index.saturating_sub(header_count);
        let difat_steps = beyond.checked_div(ENTRIES_PER_DIFAT_SECTOR).unwrap_or(0);
        let slot = beyond.checked_rem(ENTRIES_PER_DIFAT_SECTOR).unwrap_or(0);
        let Some(difat) = self.difat_sector(usize::try_from(difat_steps).unwrap_or(0))? else {
            return Ok(None);
        };
        let Some(table) = self.table(difat)? else {
            return Ok(None);
        };
        Ok(Some(Sector::from_field(entry_at(&table, slot))))
    }
}

impl Sectors<'_> {
    fn difat_sector(&self, position: usize) -> Result<Option<Sector>, InputError> {
        let mut difat = self.difat.borrow_mut();
        if difat.is_empty() {
            difat.push(Some(self.geometry.first_difat_sector));
        }
        while difat.len() <= position {
            let Some(Some(last)) = difat.last().copied() else {
                return Ok(None);
            };
            let next = self
                .table(last)?
                .map(|table| Sector::from_field(entry_at(&table, NEXT_DIFAT_SECTOR_SLOT)));
            difat.push(next);
        }
        Ok(difat.get(position).copied().flatten())
    }
}

fn entry_at(table: &[u8], slot: i32) -> u32 {
    let at = usize::try_from(slot).unwrap_or(0).saturating_mul(4);
    Fields::of(table).u32_at(at)
}
