use debar_image::{ByteEncoding, ByteOrder, ValueComparison};

const SHORTEST_AUTOMATIC_TEXT: usize = 3;
const HEXADECIMAL_PREFIXES: [&[u8]; 2] = [b"0x", b"0X"];
const HEXADECIMAL_MARK: u8 = b'x';
const ZERO_DIGIT: u8 = b'0';

pub(crate) fn comparisons_hold(
    bytes: &[u8],
    encoding: ByteEncoding,
    exact: bool,
    comparisons: &[ValueComparison],
) -> bool {
    let Some(value) = value_of(bytes, encoding, exact) else {
        return false;
    };
    comparisons.iter().all(|comparison| match comparison {
        ValueComparison::Equal(expected) => value == *expected,
        ValueComparison::Greater(bound) => value > *bound,
        ValueComparison::Less(bound) => value < *bound,
    })
}

fn value_of(bytes: &[u8], encoding: ByteEncoding, exact: bool) -> Option<i64> {
    match encoding {
        ByteEncoding::NeverMatches => None,
        ByteEncoding::Binary(order) => Some(binary(bytes, order)),
        ByteEncoding::DecimalText => {
            let text = without_leading_space(bytes, exact)?;
            text_number(text, 10, exact)
        }
        ByteEncoding::HexadecimalText(order) => {
            let text = without_leading_space(bytes, exact)?;
            hexadecimal_text(text, order, exact)
        }
        ByteEncoding::HexadecimalOrDecimalText(order) => {
            let text = without_leading_space(bytes, exact)?;
            if text.len() < SHORTEST_AUTOMATIC_TEXT {
                return None;
            }
            if HEXADECIMAL_PREFIXES
                .iter()
                .any(|prefix| text.starts_with(prefix))
            {
                hexadecimal_text(text, order, exact)
            } else if order == ByteOrder::Big {
                text_number(text, 10, exact)
            } else {
                None
            }
        }
    }
}

fn binary(bytes: &[u8], order: ByteOrder) -> i64 {
    let fold = |value: u64, byte: &u8| value.checked_shl(8).unwrap_or(0) | u64::from(*byte);
    let unsigned = match order {
        ByteOrder::Big => bytes.iter().fold(0u64, fold),
        ByteOrder::Little => bytes.iter().rev().fold(0u64, fold),
    };
    i64::from_le_bytes(unsigned.to_le_bytes())
}

fn is_c_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

fn without_leading_space(bytes: &[u8], exact: bool) -> Option<&[u8]> {
    let spaces = bytes.iter().take_while(|byte| is_c_space(**byte)).count();
    if exact && spaces > 0 {
        return None;
    }
    bytes.get(spaces..)
}

fn hexadecimal_text(text: &[u8], order: ByteOrder, exact: bool) -> Option<i64> {
    match order {
        ByteOrder::Big => text_number(text, 16, exact),
        ByteOrder::Little => text_number(&little_endian_digits(text), 16, exact),
    }
}

fn little_endian_digits(text: &[u8]) -> Vec<u8> {
    if text.len() <= 1 {
        return text.to_vec();
    }
    let prefixed = HEXADECIMAL_PREFIXES
        .iter()
        .any(|prefix| text.starts_with(prefix));
    let odd = text.len() % 2 == 1;
    let mut digits: Vec<u8> = Vec::with_capacity(text.len().saturating_add(1));
    match (odd, prefixed) {
        (true, true) => {
            digits.extend_from_slice(&[HEXADECIMAL_MARK, ZERO_DIGIT, ZERO_DIGIT]);
            digits.extend_from_slice(text.get(2..).unwrap_or_default());
        }
        (true, false) => {
            digits.push(ZERO_DIGIT);
            digits.extend_from_slice(text);
        }
        (false, true) => {
            digits.push(HEXADECIMAL_MARK);
            digits.extend_from_slice(text.get(1..).unwrap_or_default());
        }
        (false, false) => digits.extend_from_slice(text),
    }
    let length = digits.len();
    let mut reordered = vec![ZERO_DIGIT; length];
    let mut at = 0;
    while at < length {
        let pair = length.saturating_sub(at).saturating_sub(2);
        for offset in 0..2 {
            let digit = digits
                .get(pair.saturating_add(offset))
                .copied()
                .unwrap_or(ZERO_DIGIT);
            if !digit.is_ascii_hexdigit() && !matches!(digit, b'x' | b'X') {
                reordered.fill(ZERO_DIGIT);
                break;
            }
            if let Some(slot) = reordered.get_mut(at.saturating_add(offset)) {
                *slot = digit;
            }
        }
        at = at.saturating_add(2);
    }
    reordered
}

fn text_number(text: &[u8], radix: u32, exact: bool) -> Option<i64> {
    let spaces = text.iter().take_while(|byte| is_c_space(**byte)).count();
    let mut rest = text.get(spaces..).unwrap_or_default();
    let negative = match rest.first() {
        Some(b'-') => {
            rest = rest.get(1..).unwrap_or_default();
            true
        }
        Some(b'+') => {
            rest = rest.get(1..).unwrap_or_default();
            false
        }
        _ => false,
    };
    if radix == 16
        && HEXADECIMAL_PREFIXES
            .iter()
            .any(|prefix| rest.starts_with(prefix))
        && rest.len() > 2
    {
        rest = rest.get(2..).unwrap_or_default();
    }
    let digits = rest
        .iter()
        .take_while(|byte| char::from(**byte).is_digit(radix))
        .count();
    if exact && digits != rest.len() {
        return None;
    }
    let magnitude =
        rest.get(..digits)
            .unwrap_or_default()
            .iter()
            .try_fold(0i64, |value, digit| {
                value
                    .checked_mul(i64::from(radix))?
                    .checked_add(i64::from(char::from(*digit).to_digit(radix)?))
            })?;
    if negative {
        magnitude.checked_neg()
    } else {
        Some(magnitude)
    }
}
