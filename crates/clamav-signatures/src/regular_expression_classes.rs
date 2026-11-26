use regex_syntax::hir::{Class, ClassBytes, ClassBytesRange, Hir};

use crate::regular_expression_syntax::MalformedRegularExpression;

const CASE_BIT: u8 = 0x20;
const OCTAL_DIGITS: usize = 3;
const HEX_DIGITS: usize = 2;
const LARGEST_BYTE: u32 = 0xff;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ByteClass([u64; 4]);

impl ByteClass {
    fn word_and_bit(byte: u8) -> (usize, u64) {
        (usize::from(byte >> 6), 1u64 << (byte & 63))
    }

    pub fn insert(&mut self, byte: u8) {
        let (word, bit) = Self::word_and_bit(byte);
        if let Some(slot) = self.0.get_mut(word) {
            *slot |= bit;
        }
    }

    #[must_use]
    pub fn contains(&self, byte: u8) -> bool {
        let (word, bit) = Self::word_and_bit(byte);
        self.0.get(word).is_some_and(|slot| slot & bit != 0)
    }

    pub fn insert_range(&mut self, low: u8, high: u8) {
        for byte in low..=high {
            self.insert(byte);
        }
    }

    pub fn insert_all(&mut self, other: &Self) {
        for (slot, other) in self.0.iter_mut().zip(other.0) {
            *slot |= other;
        }
    }

    #[must_use]
    pub fn complement(&self) -> Self {
        Self(self.0.map(|word| !word))
    }

    fn of(bytes: impl IntoIterator<Item = u8>) -> Self {
        let mut class = Self::default();
        for byte in bytes {
            class.insert(byte);
        }
        class
    }

    fn of_ranges(ranges: &[(u8, u8)]) -> Self {
        let mut class = Self::default();
        for (low, high) in ranges {
            class.insert_range(*low, *high);
        }
        class
    }

    #[must_use]
    pub fn case_folded(&self) -> Self {
        let mut folded = *self;
        for byte in 0..=u8::MAX {
            if self.contains(byte) && byte.is_ascii_alphabetic() {
                folded.insert(byte ^ CASE_BIT);
            }
        }
        folded
    }
}

const DIGITS: [(u8, u8); 1] = [(b'0', b'9')];
const WORD: [(u8, u8); 4] = [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')];
const SPACE: [(u8, u8); 2] = [(b'\t', b'\r'), (b' ', b' ')];
const HORIZONTAL_SPACE: [(u8, u8); 3] = [(b'\t', b'\t'), (b' ', b' '), (0xa0, 0xa0)];
const VERTICAL_SPACE: [(u8, u8); 2] = [(b'\n', b'\r'), (0x85, 0x85)];

type ByteRanges = &'static [(u8, u8)];

const POSIX_CLASSES: [(&[u8], ByteRanges); 14] = [
    (b"alnum", &[(b'0', b'9'), (b'A', b'Z'), (b'a', b'z')]),
    (b"alpha", &[(b'A', b'Z'), (b'a', b'z')]),
    (b"ascii", &[(0, 0x7f)]),
    (b"blank", &[(b'\t', b'\t'), (b' ', b' ')]),
    (b"cntrl", &[(0, 0x1f), (0x7f, 0x7f)]),
    (b"digit", &DIGITS),
    (b"graph", &[(0x21, 0x7e)]),
    (b"lower", &[(b'a', b'z')]),
    (b"print", &[(0x20, 0x7e)]),
    (
        b"punct",
        &[(0x21, 0x2f), (0x3a, 0x40), (0x5b, 0x60), (0x7b, 0x7e)],
    ),
    (b"space", &SPACE),
    (b"upper", &[(b'A', b'Z')]),
    (b"word", &WORD),
    (b"xdigit", &[(b'0', b'9'), (b'A', b'F'), (b'a', b'f')]),
];

#[must_use]
pub fn posix_class_named(name: &[u8]) -> Option<ByteClass> {
    POSIX_CLASSES
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, ranges)| ByteClass::of_ranges(ranges))
}

pub enum ClassEscape {
    Byte(u8),
    Set(ByteClass),
    UnicodeProperty,
}

pub struct ReadClass {
    pub bytes: ByteClass,
    pub needs_backtracking: bool,
}

#[must_use]
pub fn class_hir(class: &ByteClass) -> Hir {
    let mut ranges = Vec::new();
    let mut start: Option<u8> = None;
    for byte in 0..=u8::MAX {
        match (class.contains(byte), start) {
            (true, None) => start = Some(byte),
            (false, Some(low)) => {
                ranges.push(ClassBytesRange::new(low, byte.saturating_sub(1)));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(low) = start {
        ranges.push(ClassBytesRange::new(low, u8::MAX));
    }
    Hir::class(Class::Bytes(ClassBytes::new(ranges)))
}

#[must_use]
pub fn any_byte() -> Hir {
    class_hir(&ByteClass::default().complement())
}

#[must_use]
pub fn folded_literal(byte: u8, caseless: bool) -> Hir {
    if caseless && byte.is_ascii_alphabetic() {
        class_hir(&ByteClass::of([byte, byte ^ CASE_BIT]))
    } else {
        Hir::literal(vec![byte])
    }
}

fn set(ranges: &[(u8, u8)], negated: bool) -> ClassEscape {
    let class = ByteClass::of_ranges(ranges);
    ClassEscape::Set(if negated { class.complement() } else { class })
}

pub fn class_escape(
    text: &[u8],
    in_class: bool,
) -> Result<(ClassEscape, &[u8]), MalformedRegularExpression> {
    let Some((letter, rest)) = text.split_first() else {
        return Err(MalformedRegularExpression::MalformedEscape);
    };
    let byte = |value: u8| Ok((ClassEscape::Byte(value), rest));
    match letter {
        b'd' | b'D' => Ok((set(&DIGITS, *letter == b'D'), rest)),
        b'w' | b'W' => Ok((set(&WORD, *letter == b'W'), rest)),
        b's' | b'S' => Ok((set(&SPACE, *letter == b'S'), rest)),
        b'h' | b'H' => Ok((set(&HORIZONTAL_SPACE, *letter == b'H'), rest)),
        b'v' | b'V' => Ok((set(&VERTICAL_SPACE, *letter == b'V'), rest)),
        b'n' => byte(b'\n'),
        b'r' => byte(b'\r'),
        b't' => byte(b'\t'),
        b'f' => byte(0x0c),
        b'e' => byte(0x1b),
        b'a' => byte(0x07),
        b'b' if in_class => byte(0x08),
        b'x' => hexadecimal(rest),
        b'o' => braced_octal(rest),
        b'0'..=b'7' => Ok(octal(text)),
        b'c' => {
            let (control, rest) = rest
                .split_first()
                .filter(|(control, _)| (0x20..=0x7e).contains(*control))
                .ok_or(MalformedRegularExpression::MalformedEscape)?;
            Ok((ClassEscape::Byte(control.to_ascii_uppercase() ^ 0x40), rest))
        }
        b'p' | b'P' => {
            let rest = match rest.split_first() {
                Some((b'{', inner)) => inner
                    .iter()
                    .position(|byte| *byte == b'}')
                    .and_then(|close| inner.get(close.saturating_add(1)..))
                    .ok_or(MalformedRegularExpression::MalformedEscape)?,
                Some((_, inner)) => inner,
                None => return Err(MalformedRegularExpression::MalformedEscape),
            };
            Ok((ClassEscape::UnicodeProperty, rest))
        }
        other if other.is_ascii_alphanumeric() => {
            Err(MalformedRegularExpression::UnknownEscape(*other))
        }
        other => byte(*other),
    }
}

fn hex_value(digit: u8) -> Option<u32> {
    char::from(digit).to_digit(16)
}

fn hexadecimal(text: &[u8]) -> Result<(ClassEscape, &[u8]), MalformedRegularExpression> {
    if let Some(inner) = text.strip_prefix(b"{") {
        let close = inner
            .iter()
            .position(|byte| *byte == b'}')
            .ok_or(MalformedRegularExpression::MalformedEscape)?;
        let digits = inner.get(..close).unwrap_or_default();
        if digits.is_empty() {
            return Err(MalformedRegularExpression::MalformedEscape);
        }
        let value = digits
            .iter()
            .try_fold(0u32, |value, digit| {
                value.checked_mul(16)?.checked_add(hex_value(*digit)?)
            })
            .and_then(|value| u8::try_from(value).ok())
            .ok_or(MalformedRegularExpression::MalformedEscape)?;
        return Ok((
            ClassEscape::Byte(value),
            inner.get(close.saturating_add(1)..).unwrap_or_default(),
        ));
    }
    let digits = text
        .iter()
        .take(HEX_DIGITS)
        .take_while(|byte| byte.is_ascii_hexdigit())
        .count();
    let value = text
        .get(..digits)
        .unwrap_or_default()
        .iter()
        .fold(0u32, |value, digit| {
            value
                .saturating_mul(16)
                .saturating_add(hex_value(*digit).unwrap_or(0))
        });
    Ok((
        ClassEscape::Byte(u8::try_from(value).unwrap_or(u8::MAX)),
        text.get(digits..).unwrap_or_default(),
    ))
}

fn braced_octal(text: &[u8]) -> Result<(ClassEscape, &[u8]), MalformedRegularExpression> {
    let inner = text
        .strip_prefix(b"{")
        .ok_or(MalformedRegularExpression::MalformedEscape)?;
    let close = inner
        .iter()
        .position(|byte| *byte == b'}')
        .ok_or(MalformedRegularExpression::MalformedEscape)?;
    let digits = inner.get(..close).unwrap_or_default();
    if digits.is_empty() {
        return Err(MalformedRegularExpression::MalformedEscape);
    }
    let value = digits
        .iter()
        .try_fold(0u32, |value, digit| {
            value
                .checked_mul(8)?
                .checked_add(char::from(*digit).to_digit(8)?)
        })
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(MalformedRegularExpression::MalformedEscape)?;
    Ok((
        ClassEscape::Byte(value),
        inner.get(close.saturating_add(1)..).unwrap_or_default(),
    ))
}

fn octal(text: &[u8]) -> (ClassEscape, &[u8]) {
    let digits = text
        .iter()
        .take(OCTAL_DIGITS)
        .take_while(|byte| (b'0'..=b'7').contains(*byte))
        .count();
    let value = text
        .get(..digits)
        .unwrap_or_default()
        .iter()
        .fold(0u32, |value, digit| {
            value
                .saturating_mul(8)
                .saturating_add(u32::from(digit.saturating_sub(b'0')))
        });
    (
        ClassEscape::Byte(u8::try_from(value & LARGEST_BYTE).unwrap_or(u8::MAX)),
        text.get(digits..).unwrap_or_default(),
    )
}

enum ClassItem {
    Byte(u8),
    Set(ByteClass),
}

pub fn read_class(
    text: &[u8],
    caseless: bool,
) -> Result<(ReadClass, &[u8]), MalformedRegularExpression> {
    let (negated, mut rest) = match text.split_first() {
        Some((b'^', rest)) => (true, rest),
        _ => (false, text),
    };
    let mut class = ByteClass::default();
    let mut needs_backtracking = false;
    let mut first = true;
    loop {
        let Some((byte, after)) = rest.split_first() else {
            return Err(MalformedRegularExpression::UnterminatedClass);
        };
        if *byte == b']' && !first {
            rest = after;
            break;
        }
        first = false;
        let (item, after) = class_item(rest, &mut needs_backtracking)?;
        rest = after;
        match item {
            ClassItem::Set(set) => {
                if range_follows(rest) {
                    return Err(MalformedRegularExpression::InvalidRange);
                }
                class.insert_all(&set);
            }
            ClassItem::Byte(low) => {
                if range_follows(rest) {
                    let after_dash = rest.get(1..).unwrap_or_default();
                    let (high, after) = class_item(after_dash, &mut needs_backtracking)?;
                    let ClassItem::Byte(high) = high else {
                        return Err(MalformedRegularExpression::InvalidRange);
                    };
                    if high < low {
                        return Err(MalformedRegularExpression::RangeOutOfOrder);
                    }
                    class.insert_range(low, high);
                    rest = after;
                } else {
                    class.insert(low);
                }
            }
        }
    }
    if caseless {
        class = class.case_folded();
    }
    if negated {
        class = class.complement();
    }
    Ok((
        ReadClass {
            bytes: class,
            needs_backtracking,
        },
        rest,
    ))
}

fn range_follows(rest: &[u8]) -> bool {
    rest.first() == Some(&b'-') && rest.get(1).is_some_and(|byte| *byte != b']')
}

fn class_item<'t>(
    text: &'t [u8],
    needs_backtracking: &mut bool,
) -> Result<(ClassItem, &'t [u8]), MalformedRegularExpression> {
    let Some((byte, rest)) = text.split_first() else {
        return Err(MalformedRegularExpression::UnterminatedClass);
    };
    match byte {
        b'\\' => {
            let (escape, rest) = class_escape(rest, true)?;
            Ok(match escape {
                ClassEscape::Byte(byte) => (ClassItem::Byte(byte), rest),
                ClassEscape::Set(set) => (ClassItem::Set(set), rest),
                ClassEscape::UnicodeProperty => {
                    *needs_backtracking = true;
                    (ClassItem::Set(ByteClass::default()), rest)
                }
            })
        }
        b'[' if matches!(rest.first(), Some(b':' | b'.' | b'=')) => match posix_class(rest)? {
            Some((set, rest)) => Ok((ClassItem::Set(set), rest)),
            None => Ok((ClassItem::Byte(b'['), rest)),
        },
        other => Ok((ClassItem::Byte(*other), rest)),
    }
}

fn posix_class(text: &[u8]) -> Result<Option<(ByteClass, &[u8])>, MalformedRegularExpression> {
    let Some((delimiter, inner)) = text.split_first() else {
        return Ok(None);
    };
    let Some(end) = inner
        .windows(2)
        .position(|pair| pair.first() == Some(delimiter) && pair.get(1) == Some(&b']'))
    else {
        return Ok(None);
    };
    let name = inner.get(..end).unwrap_or_default();
    if name.contains(&b']') {
        return Ok(None);
    }
    if *delimiter != b':' {
        return Err(MalformedRegularExpression::UnknownPosixClass);
    }
    let (negated, name) = match name.split_first() {
        Some((b'^', name)) => (true, name),
        _ => (false, name),
    };
    let class = posix_class_named(name).ok_or(MalformedRegularExpression::UnknownPosixClass)?;
    Ok(Some((
        if negated { class.complement() } else { class },
        inner.get(end.saturating_add(2)..).unwrap_or_default(),
    )))
}
