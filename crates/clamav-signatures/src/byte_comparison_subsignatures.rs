use std::fmt;

use debar_image::{ByteComparison, ByteEncoding, ByteOrder, ValueComparison};

const OPENING: u8 = b'(';
const CLOSING: u8 = b')';
const FIELD_SEPARATOR: u8 = b'#';
const COMPARISON_SEPARATOR: u8 = b',';
const HIGHEST_REFERENCE: i64 = 64;
const LONGEST_HEXADECIMAL: u32 = 18;
const BINARY_LENGTHS: [u32; 4] = [1, 2, 4, 8];
const MOST_COMPARISONS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedByteComparison {
    Reference,
    ReferenceBeyondSixtyFour,
    NotClosed,
    FieldCount,
    Offset,
    Options,
    Length,
    Comparisons,
}

impl fmt::Display for MalformedByteComparison {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Reference => "a byte comparison's subsignature reference is malformed",
            Self::ReferenceBeyondSixtyFour => {
                "a byte comparison refers to a subsignature beyond 64"
            }
            Self::NotClosed => "a byte comparison's parentheses are not closed",
            Self::FieldCount => "a byte comparison does not have three fields",
            Self::Offset => "a byte comparison's offset is malformed",
            Self::Options => "a byte comparison's options are malformed",
            Self::Length => "a byte comparison's length is malformed",
            Self::Comparisons => "a byte comparison's comparisons are malformed",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    Hexadecimal,
    Decimal,
    Binary,
    Automatic,
}

pub fn read_byte_comparison(field: &[u8]) -> Result<ByteComparison, MalformedByteComparison> {
    let opening = field
        .iter()
        .position(|byte| *byte == OPENING)
        .ok_or(MalformedByteComparison::Reference)?;
    let reference = c_integer(field.get(..opening).unwrap_or_default(), 10)
        .ok_or(MalformedByteComparison::Reference)?;
    if reference > HIGHEST_REFERENCE {
        return Err(MalformedByteComparison::ReferenceBeyondSixtyFour);
    }
    let inside = field.get(opening.saturating_add(1)..).unwrap_or_default();
    let closing = inside
        .iter()
        .position(|byte| *byte == CLOSING)
        .ok_or(MalformedByteComparison::NotClosed)?;
    let inside = inside.get(..closing).unwrap_or_default();
    let fields: Vec<&[u8]> = inside.split(|byte| *byte == FIELD_SEPARATOR).collect();
    let [offset, options, comparisons] = fields.as_slice() else {
        return Err(MalformedByteComparison::FieldCount);
    };
    let displacement = read_displacement(offset)?;
    let (encoding, length, exact) = read_options(options)?;
    let comparisons = read_comparisons(comparisons)?;
    Ok(ByteComparison {
        subsignature: u16::try_from(reference).unwrap_or(u16::MAX),
        displacement,
        encoding,
        length,
        exact,
        comparisons,
    })
}

fn read_displacement(field: &[u8]) -> Result<i64, MalformedByteComparison> {
    if field.is_empty() || field.first() == Some(&b'0') {
        return Ok(0);
    }
    let (negative, amount) = if let Some(amount) = field.strip_prefix(b">>") {
        (false, amount)
    } else if let Some(amount) = field.strip_prefix(b"<<") {
        (true, amount)
    } else {
        return Err(MalformedByteComparison::Offset);
    };
    let amount = c_integer(amount, 0).ok_or(MalformedByteComparison::Offset)?;
    Ok(if negative {
        amount.saturating_neg()
    } else {
        amount
    })
}

fn read_options(field: &[u8]) -> Result<(ByteEncoding, u32, bool), MalformedByteComparison> {
    let letters = field
        .iter()
        .take_while(|byte| !byte.is_ascii_digit())
        .count();
    if letters == field.len() {
        return Err(MalformedByteComparison::Options);
    }
    let mut base: Option<Base> = None;
    let mut order: Option<ByteOrder> = None;
    let mut exact = false;
    for letter in field.get(..letters).unwrap_or_default() {
        let chosen = match letter {
            b'h' => Base::Hexadecimal,
            b'd' => Base::Decimal,
            b'i' => Base::Binary,
            b'a' => Base::Automatic,
            b'l' | b'b' => {
                let wanted = if *letter == b'l' {
                    ByteOrder::Little
                } else {
                    ByteOrder::Big
                };
                if order.is_some_and(|order| order != wanted)
                    || (wanted == ByteOrder::Little && base == Some(Base::Decimal))
                {
                    return Err(MalformedByteComparison::Options);
                }
                order = Some(wanted);
                continue;
            }
            b'e' => {
                exact = true;
                continue;
            }
            _ => return Err(MalformedByteComparison::Options),
        };
        if base.is_some_and(|base| base != chosen) {
            return Err(MalformedByteComparison::Options);
        }
        if chosen == Base::Decimal {
            if order == Some(ByteOrder::Little) {
                return Err(MalformedByteComparison::Options);
            }
            order = Some(ByteOrder::Big);
        }
        base = Some(chosen);
    }
    let length = c_integer(field.get(letters..).unwrap_or_default(), 0)
        .and_then(|length| u32::try_from(length).ok())
        .filter(|length| *length > 0)
        .ok_or(MalformedByteComparison::Length)?;
    match base {
        Some(Base::Binary) if !BINARY_LENGTHS.contains(&length) => {
            return Err(MalformedByteComparison::Length);
        }
        Some(Base::Hexadecimal) if length > LONGEST_HEXADECIMAL => {
            return Err(MalformedByteComparison::Length);
        }
        _ => {}
    }
    let encoding = match (base, order) {
        (Some(Base::Decimal), _) => ByteEncoding::DecimalText,
        (Some(Base::Hexadecimal), Some(order)) => ByteEncoding::HexadecimalText(order),
        (Some(Base::Binary), Some(order)) => ByteEncoding::Binary(order),
        (Some(Base::Automatic), Some(order)) => ByteEncoding::HexadecimalOrDecimalText(order),
        _ => ByteEncoding::NeverMatches,
    };
    Ok((encoding, length, exact))
}

fn read_comparisons(field: &[u8]) -> Result<Vec<ValueComparison>, MalformedByteComparison> {
    let parts: Vec<&[u8]> = field.split(|byte| *byte == COMPARISON_SEPARATOR).collect();
    if parts.len() > MOST_COMPARISONS {
        return Err(MalformedByteComparison::Comparisons);
    }
    parts
        .into_iter()
        .map(|part| {
            let (symbol, value) = part
                .split_first()
                .ok_or(MalformedByteComparison::Comparisons)?;
            let value = c_integer(value, 0).ok_or(MalformedByteComparison::Comparisons)?;
            match symbol {
                b'=' => Ok(ValueComparison::Equal(value)),
                b'>' => Ok(ValueComparison::Greater(value)),
                b'<' => Ok(ValueComparison::Less(value)),
                _ => Err(MalformedByteComparison::Comparisons),
            }
        })
        .collect()
}

fn c_integer(text: &[u8], base: u32) -> Option<i64> {
    let spaces = text
        .iter()
        .take_while(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r'))
        .count();
    let text = text.get(spaces..).unwrap_or_default();
    let (negative, text) = match text.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, text),
    };
    let (radix, digits) = match base {
        0 => {
            if let Some(rest) = text
                .strip_prefix(b"0x")
                .or_else(|| text.strip_prefix(b"0X"))
                .filter(|rest| rest.first().is_some_and(u8::is_ascii_hexdigit))
            {
                (16, rest)
            } else if text.first() == Some(&b'0') {
                (8, text)
            } else {
                (10, text)
            }
        }
        other => (other, text),
    };
    let magnitude = digits.iter().try_fold(0i64, |value, digit| {
        let digit = char::from(*digit).to_digit(radix)?;
        Some(
            value
                .saturating_mul(i64::from(radix))
                .saturating_add(i64::from(digit)),
        )
    })?;
    Some(if negative {
        magnitude.saturating_neg()
    } else {
        magnitude
    })
}
