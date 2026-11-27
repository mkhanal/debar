use crate::pdf::searchable::Searchable;
use crate::pdf::tokens::{dictionary_value, hex_pair, next_object};

const JAVASCRIPT_NAME: &[u8] = b"/JavaScript";
const SCRIPT_KEY: &[u8] = b"/JS";
const SHORTEST_HEX_STRING: i64 = 3;

pub fn scripts_of<T: Searchable + ?Sized>(
    text: &T,
    start: u64,
    size: u64,
    admitted: &mut dyn FnMut(u64) -> bool,
) -> Vec<u8> {
    let mut written = Vec::new();
    let mut at = start;
    let mut left = i64::try_from(size).unwrap_or(i64::MAX);
    while let Some(name) = text.find(JAVASCRIPT_NAME, at, at.saturating_add(left.unsigned_abs())) {
        left = left.saturating_sub(distance(at, name).saturating_add(11));
        at = name.saturating_add(11);
        let (script, ended_at) = script_string(text, at, left);
        left = left.saturating_sub(distance(at, ended_at));
        at = ended_at;
        if let Some(script) = script {
            let script = script.split(|byte| *byte == 0).next().unwrap_or_default();
            write(&mut written, script, admitted);
            if left > 0 {
                trailing(text, at, left, &mut written, admitted);
            }
        }
        if left <= 0 {
            break;
        }
    }
    written
}

fn trailing<T: Searchable + ?Sized>(
    text: &T,
    at: u64,
    left: i64,
    written: &mut Vec<u8>,
    admitted: &mut dyn FnMut(u64) -> bool,
) {
    let span = left.unsigned_abs();
    let mut end =
        next_object(text, at, span).unwrap_or_else(|| at.saturating_add(span).saturating_sub(1));
    if let Some(close) = text.find_byte(b')', at, at.saturating_add(span))
        && close < end
    {
        end = close;
    }
    while end > at && text.byte(end.saturating_sub(1)) == Some(b' ') {
        end = end.saturating_sub(1);
    }
    if end > at {
        let from = at.saturating_sub(1);
        let mut bytes = Vec::new();
        text.copy(from, end.saturating_sub(from), &mut bytes);
        write(written, &bytes, admitted);
    }
}

fn write(written: &mut Vec<u8>, bytes: &[u8], admitted: &mut dyn FnMut(u64) -> bool) {
    let so_far = u64::try_from(written.len()).unwrap_or(u64::MAX);
    if admitted(so_far) {
        written.extend_from_slice(bytes);
    }
}

fn distance(from: u64, to: u64) -> i64 {
    i64::try_from(to.saturating_sub(from)).unwrap_or(i64::MAX)
}

fn script_string<T: Searchable + ?Sized>(
    text: &T,
    from: u64,
    length: i64,
) -> (Option<Vec<u8>>, u64) {
    let Some(value) = dictionary_value(text, from, length, SCRIPT_KEY) else {
        return (None, from);
    };
    if value.left <= 0 {
        return (None, from);
    }
    match text.byte(value.at) {
        Some(b'(') => literal_string(text, value.at, value.left)
            .map_or((None, from), |(bytes, end)| (Some(bytes), end)),
        Some(b'<') if value.left >= SHORTEST_HEX_STRING => {
            match hex_string_close(text, value.at, value.left) {
                Some((start, close)) => (hex_bytes(text, start, close), close),
                None => (None, from),
            }
        }
        _ => (None, from),
    }
}

fn literal_string<T: Searchable + ?Sized>(
    text: &T,
    open: u64,
    length: i64,
) -> Option<(Vec<u8>, u64)> {
    let start = open.checked_add(1)?;
    let mut at = start;
    let mut left = length.checked_sub(1)?;
    let mut depth = 1u64;
    while depth > 0 && left > 0 {
        match text.byte_or_nul(at) {
            b'(' => depth = depth.saturating_add(1),
            b')' => depth = depth.saturating_sub(1),
            b'\\' => {
                at = at.saturating_add(1);
                left = left.saturating_sub(1);
            }
            _ => {}
        }
        at = at.saturating_add(1);
        left = left.saturating_sub(1);
    }
    if left <= 0 {
        return None;
    }
    let end = at;
    let content_end = at.checked_sub(1)?;
    let mut bytes = Vec::new();
    text.copy(start, content_end.saturating_sub(start), &mut bytes);
    Some((bytes, end))
}

fn hex_string_close<T: Searchable + ?Sized>(
    text: &T,
    open: u64,
    length: i64,
) -> Option<(u64, u64)> {
    let mut start = open.checked_add(1)?;
    let mut left = length.checked_sub(1)?;
    while left > 0 && text.byte(start) == Some(b'\n') {
        start = start.checked_add(1)?;
        left = left.checked_sub(1)?;
    }
    if left <= 0 {
        return None;
    }
    let search_from = start.checked_add(1)?;
    let search_length = u64::try_from(left.checked_sub(1)?).ok()?;
    let close = text.find_byte(b'>', search_from, search_from.saturating_add(search_length))?;
    Some((start, close))
}

fn hex_bytes<T: Searchable + ?Sized>(text: &T, start: u64, close: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut at = start;
    while at < close {
        let value = hex_pair(text.byte_or_nul(at), text.byte_or_nul(at.saturating_add(1)))?;
        bytes.push(value);
        at = at.saturating_add(2);
    }
    Some(bytes)
}
