const DECIMAL_BASE: i64 = 10;

#[must_use]
pub fn leading_integer(text: &[u8]) -> i64 {
    let text = skip_c_space(text);
    let (negative, digits) = match text.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, text),
    };
    let magnitude =
        digits
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .fold(0i64, |value, digit| {
                value
                    .saturating_mul(DECIMAL_BASE)
                    .saturating_add(i64::from(digit.saturating_sub(b'0')))
            });
    if negative {
        magnitude.saturating_neg()
    } else {
        magnitude
    }
}

#[must_use]
pub fn whole_unsigned_decimal(text: &[u8]) -> Option<u64> {
    let text = skip_c_space(text);
    let digits = text.strip_prefix(b"+").unwrap_or(text);
    if digits.is_empty() {
        return Some(0);
    }
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    digits.iter().try_fold(0u64, |value, digit| {
        value
            .checked_mul(10)?
            .checked_add(u64::from(digit.checked_sub(b'0')?))
    })
}

fn skip_c_space(text: &[u8]) -> &[u8] {
    let spaces = text
        .iter()
        .take_while(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r'))
        .count();
    text.get(spaces..).unwrap_or_default()
}
