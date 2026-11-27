use crate::pdf::names::DocumentSigns;
use crate::pdf::object_dictionary::read_object;
use crate::pdf::objects::{Home, ObjectTable, object_id};
use crate::pdf::searchable::Searchable;
use crate::pdf::stream_length::ObjectStreamText;
use crate::pdf::tokens::{
    dictionary_int, dictionary_value, is_digit, read_count, structure_space_forward,
};

pub const MOST_OBJECT_STREAM_BYTES_HELD: u64 = 8 * 1024 * 1024;
const OBJECT_STREAM_TYPE: &[u8] = b"/Type/ObjStm";
const FIRST_KEY: &[u8] = b"/First";
const LENGTH_KEY: &[u8] = b"/Length";
const COUNT_KEY: &[u8] = b"/N";
const UNREADABLE: i32 = -1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectStreamLayout {
    first: u64,
    count: u64,
}

pub fn object_stream_layout<T: Searchable + ?Sized>(
    document: &T,
    dictionary_start: u64,
    dictionary_length: u64,
) -> Option<ObjectStreamLayout> {
    let length = i64::try_from(dictionary_length).ok()?;
    dictionary_value(document, dictionary_start, length, OBJECT_STREAM_TYPE)?;
    let first = dictionary_int(document, dictionary_start, length, FIRST_KEY);
    if first == UNREADABLE {
        return None;
    }
    if dictionary_int(document, dictionary_start, length, LENGTH_KEY) == UNREADABLE {
        return None;
    }
    let count = dictionary_int(document, dictionary_start, length, COUNT_KEY);
    if count == UNREADABLE {
        return None;
    }
    Some(ObjectStreamLayout {
        first: widened(first),
        count: widened(count),
    })
}

fn widened(value: i32) -> u64 {
    u64::from_le_bytes(i64::from(value).to_le_bytes())
}

#[derive(Debug, Default)]
pub struct ObjectStreams {
    held: Vec<Vec<u8>>,
    held_bytes: u64,
}

impl ObjectStreamText for ObjectStreams {
    fn object_stream(&self, stream: usize) -> Option<&[u8]> {
        self.held.get(stream).map(Vec::as_slice)
    }
}

impl ObjectStreams {
    pub fn room_left(&self) -> u64 {
        MOST_OBJECT_STREAM_BYTES_HELD.saturating_sub(self.held_bytes)
    }

    pub fn add(
        &mut self,
        content: Vec<u8>,
        layout: ObjectStreamLayout,
        table: &mut ObjectTable,
        signs: &mut DocumentSigns,
    ) {
        let stream = self.held.len();
        self.held_bytes = self
            .held_bytes
            .saturating_add(u64::try_from(content.len()).unwrap_or(u64::MAX));
        objects_within(&content, layout, stream, table, signs);
        self.held.push(content);
    }
}

fn objects_within(
    content: &[u8],
    layout: ObjectStreamLayout,
    stream: usize,
    table: &mut ObjectTable,
    signs: &mut DocumentSigns,
) {
    let length = content.length();
    if layout.first == 0 || length == 0 || layout.count == 0 || layout.first >= length {
        return;
    }
    let mut pair = 0u64;
    let mut found = 0u64;
    for _ in 0..layout.count {
        if table.is_full() {
            return;
        }
        let Some(object) = next_in_stream(content, layout, &mut pair, &mut found) else {
            return;
        };
        let Some(index) = table.push(
            object.id,
            object.start,
            object.size,
            Home::ObjectStream(stream),
        ) else {
            return;
        };
        read_object(content, table, index, signs);
    }
}

struct InStream {
    id: u32,
    start: u64,
    size: u64,
}

fn next_in_stream(
    content: &[u8],
    layout: ObjectStreamLayout,
    pair: &mut u64,
    found: &mut u64,
) -> Option<InStream> {
    let length = content.length();
    let mut at = *pair;
    let number = read_count(content, at, length.saturating_sub(at))?;
    at = digits_end(content, at);
    at = structure_space_forward(content, at, layout.first);
    let offset = read_count(content, at, length.saturating_sub(at))?;
    if layout.first.checked_add(offset)? > length {
        return None;
    }
    let start = layout.first.checked_add(offset)?;
    *found = found.saturating_add(1);
    at = digits_end(content, at);
    *pair = structure_space_forward(content, at, layout.first);
    let size = if *found < layout.count && at < length {
        let mut next = *pair;
        next = digits_end(content, next);
        next = structure_space_forward(content, next, layout.first);
        let next_offset = read_count(content, next, length.saturating_sub(next))?;
        if next_offset <= offset || layout.first.checked_add(next_offset)? > length {
            return None;
        }
        next_offset.checked_sub(offset)?
    } else {
        length.checked_sub(start)?
    };
    Some(InStream {
        id: object_id(number, 0),
        start,
        size,
    })
}

fn digits_end(content: &[u8], from: u64) -> u64 {
    let length = content.length();
    let mut at = from;
    while at < length && is_digit(content.byte_or_nul(at)) {
        at = at.saturating_add(1);
    }
    at
}
