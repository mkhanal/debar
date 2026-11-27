use std::collections::BTreeMap;

use crate::pdf::searchable::Searchable;
use crate::pdf::tokens::{
    byte_at_signed, is_digit, is_structure_space, read_long, structure_space_back,
};

pub const MOST_OBJECTS: usize = 64 * 1024;
pub const MOST_FILTERS: usize = 64;
const OBJECT_KEYWORD: &[u8] = b"obj";
const END_OBJECT_KEYWORD: &[u8] = b"endobj";
const END_OF_FILE_MARK: &[u8] = b"%%EOF";
const KEYWORD_WITH_SPACE: u64 = 4;
const END_OF_FILE_MARK_BEFORE_ID: i64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Stream,
    Dictionary,
    EmbeddedFile,
    AsciiHex,
    Ascii85,
    Flate,
    Lzw,
    RunLength,
    Fax,
    Dct,
    Jpx,
    Crypt,
    JavaScript,
    OpenAction,
    HasFilters,
    Signed,
    Image,
    Standard,
    LaunchAction,
    Page,
    Contents,
    Uri,
}

impl Mark {
    const fn bit(self) -> u32 {
        match self {
            Self::Stream => 0x1,
            Self::Dictionary => 0x2,
            Self::EmbeddedFile => 0x4,
            Self::AsciiHex => 0x8,
            Self::Ascii85 => 0x10,
            Self::Flate => 0x20,
            Self::Lzw => 0x40,
            Self::RunLength => 0x80,
            Self::Fax => 0x100,
            Self::Dct => 0x200,
            Self::Jpx => 0x400,
            Self::Crypt => 0x800,
            Self::JavaScript => 0x1000,
            Self::OpenAction => 0x2000,
            Self::HasFilters => 0x4000,
            Self::Signed => 0x8000,
            Self::Image => 0x1_0000,
            Self::Standard => 0x2_0000,
            Self::LaunchAction => 0x4_0000,
            Self::Page => 0x8_0000,
            Self::Contents => 0x10_0000,
            Self::Uri => 0x20_0000,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Marks(u32);

impl Marks {
    pub const fn has(self, mark: Mark) -> bool {
        self.0 & mark.bit() != 0
    }

    pub fn set(&mut self, mark: Mark) {
        self.0 |= mark.bit();
    }

    pub fn clear(&mut self, mark: Mark) {
        self.0 &= !mark.bit();
    }

    pub fn any_of(self, marks: &[Mark]) -> bool {
        marks.iter().any(|mark| self.has(*mark))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    AsciiHex,
    Ascii85,
    Flate,
    Lzw,
    RunLength,
    Fax,
    Dct,
    Jpx,
    Crypt,
}

impl Filter {
    pub const fn recorded_for(mark: Mark) -> Option<Self> {
        match mark {
            Mark::AsciiHex => Some(Self::AsciiHex),
            Mark::Ascii85 => Some(Self::Ascii85),
            Mark::Flate => Some(Self::Flate),
            Mark::Lzw => Some(Self::Lzw),
            Mark::RunLength => Some(Self::RunLength),
            Mark::Fax => Some(Self::Fax),
            Mark::Dct => Some(Self::Dct),
            Mark::Jpx => Some(Self::Jpx),
            Mark::Crypt => Some(Self::Crypt),
            Mark::Stream
            | Mark::Dictionary
            | Mark::EmbeddedFile
            | Mark::JavaScript
            | Mark::OpenAction
            | Mark::HasFilters
            | Mark::Signed
            | Mark::Image
            | Mark::Standard
            | Mark::LaunchAction
            | Mark::Page
            | Mark::Contents
            | Mark::Uri => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Home {
    Document,
    ObjectStream(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamBounds {
    pub start: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfObject {
    pub id: u32,
    pub start: u64,
    pub size: u64,
    pub home: Home,
    pub marks: Marks,
    pub stream: Option<StreamBounds>,
    pub filters: Vec<Filter>,
}

impl PdfObject {
    fn new(id: u32, start: u64, size: u64, home: Home) -> Self {
        Self {
            id,
            start,
            size,
            home,
            marks: Marks::default(),
            stream: None,
            filters: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct ObjectTable {
    objects: Vec<PdfObject>,
    by_id: BTreeMap<u32, Vec<usize>>,
}

impl ObjectTable {
    pub fn is_full(&self) -> bool {
        self.objects.len() >= MOST_OBJECTS
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn get(&self, index: usize) -> Option<&PdfObject> {
        self.objects.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut PdfObject> {
        self.objects.get_mut(index)
    }

    pub fn objects(&self) -> &[PdfObject] {
        &self.objects
    }

    pub fn push(&mut self, id: u32, start: u64, size: u64, home: Home) -> Option<usize> {
        if self.is_full() {
            return None;
        }
        let index = self.objects.len();
        self.objects.push(PdfObject::new(id, start, size, home));
        self.by_id.entry(id).or_default().push(index);
        Some(index)
    }

    pub fn find_from(&self, current: usize, id: u32) -> Option<usize> {
        let indices = self.by_id.get(&id)?;
        let at_or_after = indices.partition_point(|index| *index < current);
        indices
            .get(at_or_after)
            .or_else(|| indices.first())
            .copied()
    }
}

pub fn object_id(number: u64, generation: u64) -> u32 {
    let [first, second, third, fourth, ..] = number
        .wrapping_shl(8)
        .wrapping_add(generation & 0xff)
        .to_le_bytes();
    u32::from_le_bytes([first, second, third, fourth])
}

enum Search {
    Found {
        start: u64,
        size: u64,
        id: u32,
        next: u64,
    },
    NotAnObject {
        next: u64,
    },
    NoMore,
}

pub fn find_objects<T: Searchable + ?Sized>(document: &T, table: &mut ObjectTable) {
    let mut offset = 0u64;
    while !table.is_full() {
        match next_object_at(document, offset) {
            Search::Found {
                start,
                size,
                id,
                next,
            } => {
                let _ = table.push(id, start, size, Home::Document);
                offset = next;
            }
            Search::NotAnObject { next } => offset = next,
            Search::NoMore => return,
        }
    }
}

fn next_object_at<T: Searchable + ?Sized>(document: &T, offset: u64) -> Search {
    let size = document.length();
    let Some(keyword_space) = keyword_space(document, offset, size) else {
        return Search::NoMore;
    };
    let object_end = keyword_space.saturating_add(KEYWORD_WITH_SPACE);
    let not_an_object = Search::NotAnObject { next: object_end };
    let Some(id) = object_number_before(document, offset, keyword_space) else {
        return not_an_object;
    };
    match document.find(END_OBJECT_KEYWORD, object_end, size) {
        Some(end_keyword) => Search::Found {
            start: object_end,
            size: end_keyword.saturating_sub(object_end),
            id,
            next: end_keyword.saturating_add(6),
        },
        None => Search::Found {
            start: object_end,
            size: size.saturating_sub(object_end),
            id,
            next: size,
        },
    }
}

fn keyword_space<T: Searchable + ?Sized>(document: &T, offset: u64, size: u64) -> Option<u64> {
    let mut left = size.checked_sub(offset)?;
    let mut at = offset.checked_add(1)?;
    while left > KEYWORD_WITH_SPACE {
        let found = document.find(
            OBJECT_KEYWORD,
            at,
            at.saturating_add(left.saturating_sub(1)),
        )?;
        let before = found.checked_sub(1)?;
        left = size
            .checked_sub(offset)?
            .checked_sub(before.checked_sub(offset)?)?;
        if is_structure_space(document.byte_or_nul(before)) {
            return Some(before);
        }
        at = before.checked_add(KEYWORD_WITH_SPACE)?;
        left = left.checked_sub(KEYWORD_WITH_SPACE)?;
    }
    None
}

fn object_number_before<T: Searchable + ?Sized>(
    document: &T,
    offset: u64,
    keyword_space: u64,
) -> Option<u32> {
    let start = i64::try_from(offset).ok()?;
    let keyword_space = i64::try_from(keyword_space).ok()?;
    let generation_at = digits_back(document, keyword_space.checked_sub(1)?, start);
    let generation = read_signed(
        document,
        generation_at,
        keyword_space.checked_sub(generation_at)?,
    )?;
    let mut number_at = digits_back(document, generation_at.checked_sub(1)?, start);
    let read = read_signed_long(document, number_at, generation_at.checked_sub(number_at)?);
    let number = if let Some(number) = read {
        u64::try_from(number).ok()?
    } else {
        let mark_at = number_at.checked_sub(END_OF_FILE_MARK_BEFORE_ID)?;
        if mark_at <= start || !holds_at(document, mark_at, END_OF_FILE_MARK) {
            return None;
        }
        number_at = number_at.checked_add(1)?;
        read_signed(
            document,
            number_at,
            generation_at.checked_sub(1)?.checked_sub(number_at)?,
        )?
    };
    Some(object_id(number, generation))
}

fn digits_back<T: Searchable + ?Sized>(document: &T, from: i64, start: i64) -> i64 {
    let mut at = structure_space_back(document, from, start);
    while at > start && is_digit(byte_at_signed(document, at)) {
        at = at.saturating_sub(1);
    }
    at
}

fn read_signed<T: Searchable + ?Sized>(document: &T, at: i64, length: i64) -> Option<u64> {
    u64::try_from(read_signed_long(document, at, length)?).ok()
}

fn read_signed_long<T: Searchable + ?Sized>(document: &T, at: i64, length: i64) -> Option<i64> {
    let at = u64::try_from(at).ok()?;
    let length = u64::try_from(length).unwrap_or(u64::MAX);
    read_long(document, at, length)
}

fn holds_at<T: Searchable + ?Sized>(document: &T, at: i64, wanted: &[u8]) -> bool {
    let Ok(at) = u64::try_from(at) else {
        return false;
    };
    wanted
        .iter()
        .zip(0u64..)
        .all(|(byte, offset)| document.byte(at.saturating_add(offset)) == Some(*byte))
}
