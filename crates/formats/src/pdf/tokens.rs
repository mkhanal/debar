use crate::pdf::searchable::Searchable;

const LARGEST_LONG: u64 = 0x7fff_ffff_ffff_ffff;
const LARGEST_NEGATED_LONG: u64 = 0x8000_0000_0000_0000;
const LOWER_HEX_LETTER_BASE: u8 = 87;
const UPPER_HEX_LETTER_BASE: u8 = 55;

pub const fn is_digit(byte: u8) -> bool {
    byte.is_ascii_digit()
}

pub const fn is_c_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

pub const fn is_structure_space(byte: u8) -> bool {
    matches!(byte, 0 | b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

pub const fn is_line_end(byte: u8) -> bool {
    matches!(byte, b'\r' | b'\n' | 0)
}

pub fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => byte.checked_sub(b'0'),
        b'a'..=b'f' => byte.checked_sub(LOWER_HEX_LETTER_BASE),
        b'A'..=b'F' => byte.checked_sub(UPPER_HEX_LETTER_BASE),
        _ => None,
    }
}

pub fn hex_pair(high: u8, low: u8) -> Option<u8> {
    let high = hex_value(high)?;
    let low = hex_value(low)?;
    high.checked_mul(16)?.checked_add(low)
}

pub fn read_long<T: Searchable + ?Sized>(text: &T, at: u64, length: u64) -> Option<i64> {
    if length == 0 {
        return None;
    }
    let end = at.saturating_add(length);
    let mut position = at;
    while is_c_space(text.byte_or_nul(position)) {
        position = position.checked_add(1)?;
        if position >= end {
            return None;
        }
    }
    let negative = match text.byte_or_nul(position) {
        b'-' => true,
        b'+' => false,
        _ => {
            return digits_from(text, position, end, false);
        }
    };
    position = position.checked_add(1)?;
    if position >= end {
        return None;
    }
    digits_from(text, position, end, negative)
}

fn digits_from<T: Searchable + ?Sized>(
    text: &T,
    from: u64,
    end: u64,
    negative: bool,
) -> Option<i64> {
    let most = if negative {
        LARGEST_NEGATED_LONG
    } else {
        LARGEST_LONG
    };
    let mut value: u64 = 0;
    let mut any = false;
    let mut overflowed = false;
    let mut position = from;
    while position < end {
        let byte = text.byte_or_nul(position);
        if !is_digit(byte) {
            break;
        }
        any = true;
        let digit = u64::from(byte.saturating_sub(b'0'));
        match value
            .checked_mul(10)
            .and_then(|tens| tens.checked_add(digit))
            .filter(|next| *next <= most)
        {
            Some(next) if !overflowed => value = next,
            _ => overflowed = true,
        }
        position = position.checked_add(1)?;
    }
    if !any || overflowed {
        return None;
    }
    if negative {
        0i64.checked_sub_unsigned(value)
    } else {
        i64::try_from(value).ok()
    }
}

pub fn read_count<T: Searchable + ?Sized>(text: &T, at: u64, length: u64) -> Option<u64> {
    u64::try_from(read_long(text, at, length)?).ok()
}

pub fn next_line_start<T: Searchable + ?Sized>(text: &T, at: u64, length: u64) -> Option<u64> {
    let mut left = length;
    if left == 0 {
        return None;
    }
    let mut position = at;
    while !is_line_end(text.byte_or_nul(position)) {
        left = left.checked_sub(1).filter(|left| *left > 0)?;
        position = position.checked_add(1)?;
    }
    while is_line_end(text.byte_or_nul(position)) {
        left = left.checked_sub(1).filter(|left| *left > 0)?;
        position = position.checked_add(1)?;
    }
    Some(position)
}

pub fn next_object<T: Searchable + ?Sized>(text: &T, at: u64, length: u64) -> Option<u64> {
    let mut left = length;
    let mut position = at;
    let mut in_object = true;
    while left > 0 {
        match text.byte_or_nul(position) {
            b'\n' | b'\r' | b'%' => {
                let line = next_line_start(text, position, left)?;
                left = left.checked_sub(line.checked_sub(position)?)?;
                position = line;
                in_object = false;
            }
            b' ' | b'\t' | b'[' | 0x0b | 0x0c | b'<' => {
                in_object = false;
                position = position.checked_add(1)?;
                left = left.checked_sub(1)?;
            }
            b'/' | b'(' => return Some(position),
            _ => {
                if !in_object {
                    return Some(position);
                }
                position = position.checked_add(1)?;
                left = left.checked_sub(1)?;
            }
        }
    }
    None
}

pub struct DictionaryValue {
    pub at: u64,
    pub left: i64,
}

pub fn dictionary_value<T: Searchable + ?Sized>(
    text: &T,
    from: u64,
    length: i64,
    key: &[u8],
) -> Option<DictionaryValue> {
    if length <= 0 {
        return None;
    }
    let key_at = text.find(key, from, from.saturating_add(u64::try_from(length).ok()?))?;
    let left = length.checked_sub(i64::try_from(key_at.checked_sub(from)?).ok()?)?;
    let after_slash = key_at.checked_add(1)?;
    let mut value = next_object(text, after_slash, u64::try_from(left.checked_sub(1)?).ok()?)?;
    while value > key_at {
        let before = text.byte_or_nul(value.checked_sub(1)?);
        if before != b'<' && before != b'\n' {
            break;
        }
        value = value.checked_sub(1)?;
    }
    let left = left.checked_sub(i64::try_from(value.checked_sub(key_at)?).ok()?)?;
    Some(DictionaryValue { at: value, left })
}

pub fn dictionary_int<T: Searchable + ?Sized>(text: &T, from: u64, length: i64, key: &[u8]) -> i32 {
    dictionary_value(text, from, length, key)
        .and_then(|value| {
            let left = u64::try_from(value.left).unwrap_or(u64::MAX);
            read_long(text, value.at, left)
        })
        .map_or(-1, truncated_to_int)
}

fn truncated_to_int(value: i64) -> i32 {
    let [first, second, third, fourth, ..] = value.to_le_bytes();
    i32::from_le_bytes([first, second, third, fourth])
}

pub fn structure_space_back<T: Searchable + ?Sized>(text: &T, from: i64, start: i64) -> i64 {
    let mut position = from;
    while position > start && is_structure_space(byte_at_signed(text, position)) {
        position = position.saturating_sub(1);
    }
    position
}

pub fn structure_space_forward<T: Searchable + ?Sized>(text: &T, from: u64, end: u64) -> u64 {
    let mut position = from;
    while position < end && is_structure_space(text.byte_or_nul(position)) {
        position = position.saturating_add(1);
    }
    position
}

pub fn byte_at_signed<T: Searchable + ?Sized>(text: &T, at: i64) -> u8 {
    u64::try_from(at).map_or(0, |at| text.byte_or_nul(at))
}
