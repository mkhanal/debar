use crate::pdf::names::{DocumentSigns, NameState, mark_for_reference, name_read};
use crate::pdf::objects::{Home, Mark, ObjectTable, StreamBounds, object_id};
use crate::pdf::searchable::Searchable;
use crate::pdf::tokens::{hex_pair, is_digit, next_object, read_count};

const STREAM_KEYWORD: &[u8] = b"stream";
const END_STREAM_KEYWORD: &[u8] = b"endstream";
const LONGEST_NAME: usize = 63;

pub fn read_object<T: Searchable + ?Sized>(
    text: &T,
    table: &mut ObjectTable,
    index: usize,
    signs: &mut DocumentSigns,
) {
    let Some(object) = table.get(index) else {
        return;
    };
    let (start, size, home) = (object.start, object.size, object.home);
    if start > text.length() || size == 0 {
        return;
    }
    if home == Home::Document
        && let Some(bounds) = stream_bounds(text, start, size)
        && let Some(object) = table.get_mut(index)
    {
        object.marks.set(Mark::Stream);
        object.stream = Some(bounds);
    }
    let Some(dictionary) = dictionary_bounds(text, start, size) else {
        return;
    };
    if let Some(object) = table.get_mut(index) {
        object.marks.set(Mark::Dictionary);
    }
    read_names(text, table, index, dictionary, signs);
}

fn stream_bounds<T: Searchable + ?Sized>(text: &T, start: u64, size: u64) -> Option<StreamBounds> {
    let keyword = text.find(STREAM_KEYWORD, start, start.saturating_add(size))?;
    let mut at = keyword.checked_add(6)?;
    if at.checked_sub(start)? >= size {
        return None;
    }
    let mut left = size.checked_sub(at.checked_sub(start)?)?;
    if left >= 2 && text.byte(at) == Some(b'\r') && text.byte(at.checked_add(1)?) == Some(b'\n') {
        at = at.checked_add(2)?;
        left = left.checked_sub(2)?;
        if left > 2 && text.byte(at) == Some(b'\n') {
            at = at.checked_add(1)?;
            left = left.checked_sub(1)?;
        }
    } else if left > 0 && text.byte(at) == Some(b'\n') {
        at = at.checked_add(1)?;
        left = left.checked_sub(1)?;
    }
    let end = text
        .find(END_STREAM_KEYWORD, at, at.saturating_add(left))
        .unwrap_or_else(|| start.saturating_add(size));
    Some(StreamBounds {
        start: at,
        size: end.saturating_sub(at),
    })
}

#[derive(Debug, Clone, Copy)]
struct DictionaryBounds {
    start: u64,
    length: i64,
}

fn dictionary_bounds<T: Searchable + ?Sized>(
    text: &T,
    start: u64,
    size: u64,
) -> Option<DictionaryBounds> {
    let open = dictionary_open(text, start, size)?;
    let dictionary = open.checked_add(2)?;
    let left = i64::try_from(size)
        .ok()?
        .checked_sub(i64::try_from(dictionary.checked_sub(start)?).ok()?)?;
    if left < 0 {
        return None;
    }
    let last = i64::try_from(dictionary)
        .ok()?
        .checked_add(left)?
        .checked_sub(1)?;
    let close = dictionary_close(text, dictionary, last)?;
    Some(DictionaryBounds {
        start: dictionary,
        length: i64::try_from(close.checked_sub(dictionary)?).ok()?,
    })
}

fn dictionary_open<T: Searchable + ?Sized>(text: &T, start: u64, size: u64) -> Option<u64> {
    let mut at = start;
    let mut left = i64::try_from(size.min(text.length().saturating_sub(start))).ok()?;
    loop {
        if left < 0 {
            return None;
        }
        let next = next_object(text, at, u64::try_from(left).ok()?)?;
        left = left.checked_sub(i64::try_from(next.checked_sub(at)?).ok()?)?;
        if left < 0 {
            return None;
        }
        let from = if at == 0 { at } else { at.checked_sub(1)? };
        let open = text.find_byte(b'<', from, next);
        at = next.checked_add(1)?;
        left = left.checked_sub(1)?;
        if let Some(open) = open
            && text.byte(open.checked_add(1)?) == Some(b'<')
        {
            return Some(open);
        }
    }
}

fn dictionary_close<T: Searchable + ?Sized>(text: &T, dictionary: u64, last: i64) -> Option<u64> {
    let mut at = dictionary;
    let mut opened = 1u64;
    let mut close = None;
    while i64::try_from(at).ok()? < last.checked_sub(1)? && opened > 0 {
        let last_at = u64::try_from(last).ok()?;
        let Some(found) = text.find_byte(b'>', at, last_at) else {
            break;
        };
        close = Some(found);
        if text.byte(found.checked_add(1)?) == Some(b'>') {
            while let Some(open) = text.find_byte(b'<', at.checked_sub(1)?, found) {
                if text.byte(open.checked_add(1)?) == Some(b'<') {
                    opened = opened.checked_add(1)?;
                }
                at = open.checked_add(2)?;
            }
            opened = opened.checked_sub(1)?;
        }
        at = found.checked_add(2)?;
    }
    if opened > 0 {
        return None;
    }
    close
}

fn read_names<T: Searchable + ?Sized>(
    text: &T,
    table: &mut ObjectTable,
    index: usize,
    dictionary: DictionaryBounds,
    signs: &mut DocumentSigns,
) {
    let mut state = NameState::None;
    let mut at = dictionary.start;
    let mut left = dictionary.length;
    while left > 0 {
        let Some(slash) = text.find_byte(b'/', at, at.saturating_add(left.unsigned_abs())) else {
            return;
        };
        left = left.saturating_sub(i64::try_from(slash.saturating_sub(at)).unwrap_or(i64::MAX));
        at = slash;
        let mut name = [0u8; LONGEST_NAME];
        let mut name_length = 0usize;
        let mut escaped = false;
        while left > 0 && name_length < LONGEST_NAME {
            at = at.saturating_add(1);
            left = left.saturating_sub(1);
            let byte = text.byte_or_nul(at);
            if byte == b'#' {
                let Some(value) = hex_pair(
                    text.byte_or_nul(at.saturating_add(1)),
                    text.byte_or_nul(at.saturating_add(2)),
                ) else {
                    break;
                };
                if let Some(slot) = name.get_mut(name_length) {
                    *slot = value;
                }
                at = at.saturating_add(2);
                left = left.saturating_sub(2);
                escaped = true;
                name_length = name_length.saturating_add(1);
                continue;
            }
            if matches!(
                byte,
                b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'>' | b'[' | b']' | b'<' | b'('
            ) {
                break;
            }
            if let Some(slot) = name.get_mut(name_length) {
                *slot = byte;
            }
            name_length = name_length.saturating_add(1);
        }
        let Some(object) = table.get_mut(index) else {
            return;
        };
        name_read(
            name.get(..name_length).unwrap_or_default(),
            escaped,
            &mut state,
            object,
            signs,
        );
        match state {
            NameState::Linearized => state = NameState::None,
            NameState::LaunchAction => signs.launches_a_program = true,
            _ => {}
        }
        if left > 0
            && let Some(mark) = mark_for_reference(state)
        {
            if mark == Mark::OpenAction {
                signs.opens_with_an_action = true;
            }
            if follow_reference(text, table, index, at, left, mark) == Reference::Unreadable {
                return;
            }
            state = NameState::None;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reference {
    Followed,
    Unreadable,
}

fn follow_reference<T: Searchable + ?Sized>(
    text: &T,
    table: &mut ObjectTable,
    index: usize,
    at: u64,
    left: i64,
    mark: Mark,
) -> Reference {
    let mut remaining = left;
    let Some(number_at) = next_object(text, at, left.unsigned_abs()) else {
        return Reference::Followed;
    };
    if !is_digit(text.byte_or_nul(number_at)) {
        return Reference::Followed;
    }
    remaining = remaining.saturating_sub(signed_distance(at, number_at));
    let Some(number) = read_count(text, number_at, remaining.unsigned_abs()) else {
        return Reference::Unreadable;
    };
    let mut after_number = number_at;
    while remaining > 0 && is_digit(text.byte_or_nul(after_number)) {
        after_number = after_number.saturating_add(1);
        remaining = remaining.saturating_sub(1);
    }
    let Some(generation_at) = next_object(text, after_number, remaining.unsigned_abs()) else {
        return Reference::Followed;
    };
    if !is_digit(text.byte_or_nul(generation_at)) {
        return Reference::Followed;
    }
    remaining = remaining.saturating_sub(signed_distance(after_number, generation_at));
    let Some(generation) = read_count(text, generation_at, remaining.unsigned_abs()) else {
        return Reference::Unreadable;
    };
    let Some(keyword_at) = next_object(text, generation_at, remaining.unsigned_abs()) else {
        return Reference::Followed;
    };
    if text.byte(keyword_at) != Some(b'R') {
        return Reference::Followed;
    }
    if let Some(target) = table.find_from(index, object_id(number, generation)) {
        if let Some(object) = table.get_mut(index) {
            object.marks.clear(mark);
        }
        if let Some(object) = table.get_mut(target) {
            object.marks.set(mark);
        }
    }
    Reference::Followed
}

fn signed_distance(from: u64, to: u64) -> i64 {
    i64::try_from(to.saturating_sub(from)).unwrap_or(i64::MAX)
}
