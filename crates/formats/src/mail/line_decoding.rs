const NOT_IN_THE_ALPHABET: u8 = 255;
const VALUE_OF_A_BAD_HEX_DIGIT: u8 = b'=';
const YENC_SHIFT: u8 = 42;
const YENC_ESCAPED_SHIFT: u8 = 64;
const YENC_END: &[u8] = b"=yend ";
const LONGEST_UUENCODED_LINE: usize = 62;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Base64Carry {
    held: [u8; 3],
    count: usize,
}

pub const fn hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte.wrapping_sub(b'0'),
        b'A'..=b'F' => byte.wrapping_sub(b'A').wrapping_add(10),
        b'a'..=b'f' => byte.wrapping_sub(b'a').wrapping_add(10),
        _ => VALUE_OF_A_BAD_HEX_DIGIT,
    }
}

pub fn as_written(line: Option<&[u8]>, out: &mut Vec<u8>) {
    if let Some(text) = line {
        out.extend_from_slice(text);
    }
    out.push(b'\n');
}

pub fn quoted_printable(line: Option<&[u8]>, out: &mut Vec<u8>) {
    let Some(text) = line else {
        out.push(b'\n');
        return;
    };
    let mut at = 0usize;
    let mut soft_break = false;
    while let Some(&byte) = text.get(at) {
        if byte != b'=' {
            out.push(byte);
            at = at.saturating_add(1);
            continue;
        }
        let Some(&first) = text.get(at.saturating_add(1)) else {
            soft_break = true;
            break;
        };
        let high = hex_digit(first);
        let Some(&second) = text.get(at.saturating_add(2)) else {
            out.push(high);
            break;
        };
        if high == VALUE_OF_A_BAD_HEX_DIGIT {
            out.push(b'=');
            at = at.saturating_add(1);
        } else {
            out.push(high.wrapping_shl(4) | hex_digit(second));
            at = at.saturating_add(3);
        }
    }
    if !soft_break {
        out.push(b'\n');
    }
}

pub fn base64(line: Option<&[u8]>, carry: &mut Base64Carry, out: &mut Vec<u8>) {
    let Some(text) = line else {
        return;
    };
    let before_padding = text
        .iter()
        .position(|byte| *byte == b'=')
        .map_or(text, |padding| text.get(..padding).unwrap_or_default());
    let values: Vec<u8> = before_padding
        .iter()
        .map(|byte| base64_value(*byte))
        .filter(|value| *value != NOT_IN_THE_ALPHABET)
        .collect();
    let in_whole_groups =
        before_padding.len() == text.len() && values.len().is_multiple_of(4) && carry.count == 0;
    if in_whole_groups {
        for &[first, second, third, fourth] in values.as_chunks::<4>().0 {
            write_group(first, second, third, fourth, out);
        }
        return;
    }
    let mut fresh = values.iter().copied();
    let mut remaining = values.len();
    while remaining > 0 {
        let mut group = [0u8; 4];
        let mut filled = 0usize;
        let mut taken_from_carry = 0usize;
        while filled < 4 {
            let from_carry = carry.count > 0 && filled < 3;
            if from_carry {
                if let (Some(slot), Some(value)) =
                    (group.get_mut(filled), carry.held.get(taken_from_carry))
                {
                    *slot = *value;
                }
                taken_from_carry = taken_from_carry.saturating_add(1);
                carry.count = carry.count.saturating_sub(1);
            } else if let Some(value) = fresh.next() {
                if let Some(slot) = group.get_mut(filled) {
                    *slot = value;
                }
                remaining = remaining.saturating_sub(1);
            }
            filled = filled.saturating_add(1);
            if filled < 4 && remaining == 0 {
                break;
            }
        }
        if filled == 4 {
            let [first, second, third, fourth] = group;
            write_group(first, second, third, fourth, out);
            continue;
        }
        let [first, second, third, _] = group;
        carry.held = [first, second, third];
        carry.count = filled;
        break;
    }
}

pub fn base64_flush(carry: &mut Base64Carry, out: &mut Vec<u8>) {
    let [first, second, third] = carry.held;
    match carry.count {
        0 => return,
        1 => out.push(first.wrapping_shl(2)),
        2 if second == 0 => out.push(first.wrapping_shl(2)),
        2 => {
            out.push(first.wrapping_shl(2) | ((second >> 4) & 0x3));
            if second.wrapping_shl(4) != 0 {
                out.push(second.wrapping_shl(4));
            }
        }
        _ => {
            out.push(first.wrapping_shl(2) | ((second >> 4) & 0x3));
            out.push(second.wrapping_shl(4) | ((third >> 2) & 0xf));
            if third & 0x3 != 0 {
                out.push(third.wrapping_shl(6));
            }
        }
    }
    carry.count = 0;
}

pub fn yenc(line: Option<&[u8]>, out: &mut Vec<u8>) {
    let Some(text) = line.filter(|text| !text.is_empty()) else {
        return;
    };
    if text.starts_with(YENC_END) {
        return;
    }
    let mut bytes = text.iter();
    while let Some(&byte) = bytes.next() {
        if byte == b'=' {
            let Some(&escaped) = bytes.next() else {
                break;
            };
            out.push(escaped.wrapping_sub(YENC_ESCAPED_SHIFT));
        } else {
            out.push(byte.wrapping_sub(YENC_SHIFT));
        }
    }
}

pub fn is_yenc_end(line: Option<&[u8]>) -> bool {
    line.is_some_and(|text| text.starts_with(YENC_END))
}

pub fn uudecoded_line(line: &[u8], out: &mut Vec<u8>) -> bool {
    let Some((&count, rest)) = line.split_first() else {
        return false;
    };
    if count & 0x3f == b' ' {
        return false;
    }
    let length = usize::from(count.wrapping_sub(b' '));
    if length == 0 || length > LONGEST_UUENCODED_LINE || length > rest.len() {
        return false;
    }
    let start = out.len();
    for &[first, second, third, fourth] in rest.as_chunks::<4>().0 {
        write_group(
            first.wrapping_sub(b' '),
            second.wrapping_sub(b' '),
            third.wrapping_sub(b' '),
            fourth.wrapping_sub(b' '),
            out,
        );
    }
    out.resize(start.saturating_add(length), 0);
    true
}

fn write_group(first: u8, second: u8, third: u8, fourth: u8, out: &mut Vec<u8>) {
    out.push(first.wrapping_shl(2) | ((second >> 4) & 0x3));
    out.push(second.wrapping_shl(4) | ((third >> 2) & 0xf));
    out.push(third.wrapping_shl(6) | (fourth & 0x3f));
}

const fn base64_value(byte: u8) -> u8 {
    match byte {
        b'A'..=b'Z' => byte.wrapping_sub(b'A'),
        b'a'..=b'z' => byte.wrapping_sub(b'a').wrapping_add(26),
        b'0'..=b'9' => byte.wrapping_sub(b'0').wrapping_add(52),
        b'+' => 62,
        b'/' => 63,
        b'=' => 0,
        _ => NOT_IN_THE_ALPHABET,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base64_lines(lines: &[&[u8]]) -> Vec<u8> {
        let mut carry = Base64Carry::default();
        let mut out = Vec::new();
        for line in lines {
            base64(Some(line), &mut carry, &mut out);
        }
        base64_flush(&mut carry, &mut out);
        out
    }

    #[test]
    fn base64_carries_a_short_line_into_the_next() {
        assert_eq!(
            base64_lines(&[
                b"QUJD",
                b"REVG!!R0hJ",
                b"SktM TU5P",
                b"UF",
                b"FSUw==",
                b"VFVW"
            ]),
            b"ABCDEFGHIJKLMNOPQRS\x05EU`".to_vec()
        );
    }

    #[test]
    fn base64_of_whole_lines_is_the_usual_decoding() {
        assert_eq!(
            base64_lines(&[b"SGVsbG8gYXR0YWNobWVudCB3b3JsZCEhIQo="]),
            b"Hello attachment world!!!\n".to_vec()
        );
    }

    #[test]
    fn quoted_printable_keeps_what_it_cannot_decode() {
        let mut out = Vec::new();
        quoted_printable(Some(b"ab=3Dcd="), &mut out);
        quoted_printable(Some(b"ef  "), &mut out);
        quoted_printable(Some(b"low=3d=zz end"), &mut out);
        assert_eq!(out, b"ab=cdef  \nlow==zz end\n".to_vec());
    }
}
