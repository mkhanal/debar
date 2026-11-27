use crate::pdf::objects::{Home, ObjectTable, object_id};
use crate::pdf::searchable::Searchable;
use crate::pdf::tokens::{is_digit, next_object, read_count};

const LENGTH_KEY: &[u8] = b"/Length";
const SHORTEST_DICTIONARY_WITH_LENGTH: u64 = 8;
const KEPT_BEFORE_THE_END: u64 = 5;

pub trait ObjectStreamText {
    fn object_stream(&self, stream: usize) -> Option<&[u8]>;
}

pub fn declared_length<T: Searchable + ?Sized>(
    document: &T,
    object_streams: &dyn ObjectStreamText,
    table: &ObjectTable,
    index: usize,
    dictionary_start: u64,
    dictionary_length: u64,
) -> u64 {
    let Some((value_at, length)) = read_length(
        document,
        object_streams,
        table,
        index,
        dictionary_start,
        dictionary_length,
    ) else {
        return 0;
    };
    let size = document.length();
    if value_at
        .wrapping_add(length)
        .wrapping_add(KEPT_BEFORE_THE_END)
        > size
    {
        return size
            .wrapping_sub(value_at)
            .wrapping_sub(KEPT_BEFORE_THE_END);
    }
    length
}

fn read_length<T: Searchable + ?Sized>(
    document: &T,
    object_streams: &dyn ObjectStreamText,
    table: &ObjectTable,
    index: usize,
    dictionary_start: u64,
    dictionary_length: u64,
) -> Option<(u64, u64)> {
    if dictionary_length < SHORTEST_DICTIONARY_WITH_LENGTH {
        return None;
    }
    let key = document.find(
        LENGTH_KEY,
        dictionary_start,
        dictionary_start.saturating_add(dictionary_length),
    )?;
    let mut left = dictionary_length.checked_sub(key.checked_sub(dictionary_start)?)?;
    if left < 1 {
        return None;
    }
    let mut at = key.checked_add(1)?;
    left = left.checked_sub(1)?;
    let value_at = next_object(document, at, left)?;
    left = left.checked_sub(value_at.checked_sub(at)?)?;
    at = value_at;
    let mut length = read_count(document, at, left)?;
    while left > 0 && is_digit(document.byte_or_nul(at)) {
        at = at.checked_add(1)?;
        left = left.checked_sub(1)?;
    }
    if left == 0 || document.byte(at) != Some(b' ') {
        return Some((value_at, length));
    }
    at = at.checked_add(1)?;
    left = left.checked_sub(1)?;
    let generation = read_count(document, at, left)?;
    while left > 0 && is_digit(document.byte_or_nul(at)) {
        at = at.checked_add(1)?;
        left = left.checked_sub(1)?;
    }
    if left < 2 {
        return None;
    }
    if document.byte(at) == Some(b' ') && document.byte(at.checked_add(1)?) == Some(b'R') {
        let target = table.find_from(index, object_id(length, generation))?;
        let object = table.get(target)?;
        length = match object.home {
            Home::Document => length_object_value(document, object.start, object.size)?,
            Home::ObjectStream(stream) => {
                let text = object_streams.object_stream(stream)?;
                length_object_value(text, object.start, object.size)?
            }
        };
    }
    Some((value_at, length))
}

fn length_object_value<T: Searchable + ?Sized>(text: &T, start: u64, size: u64) -> Option<u64> {
    let whole = text.length();
    if !contained(whole, start, size) {
        return None;
    }
    let left = whole.checked_sub(start)?;
    let value = next_object(text, start, left)?;
    let left = left.checked_sub(value.checked_sub(start)?)?;
    read_count(text, value, left)
}

fn contained(whole: u64, start: u64, size: u64) -> bool {
    whole > 0
        && size > 0
        && size <= whole
        && start
            .checked_add(size)
            .is_some_and(|end| end <= whole && end > 0)
        && start < whole
}
