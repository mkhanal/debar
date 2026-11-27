#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Codepage(pub u16);

pub const LATIN_1: Codepage = Codepage(28591);
pub const UTF_16_LITTLE_ENDIAN: Codepage = Codepage(1200);
const US_ASCII: Codepage = Codepage(20127);
const UTF_8: Codepage = Codepage(65001);
const WINDOWS_1252: Codepage = Codepage(1252);
const CONTINUATION_MASK: u8 = 0b1100_0000;
const CONTINUATION: u8 = 0b1000_0000;

const WINDOWS_1252_FROM_0X80: [Option<char>; 32] = [
    Some('\u{20ac}'),
    None,
    Some('\u{201a}'),
    Some('\u{0192}'),
    Some('\u{201e}'),
    Some('\u{2026}'),
    Some('\u{2020}'),
    Some('\u{2021}'),
    Some('\u{02c6}'),
    Some('\u{2030}'),
    Some('\u{0160}'),
    Some('\u{2039}'),
    Some('\u{0152}'),
    None,
    Some('\u{017d}'),
    None,
    None,
    Some('\u{2018}'),
    Some('\u{2019}'),
    Some('\u{201c}'),
    Some('\u{201d}'),
    Some('\u{2022}'),
    Some('\u{2013}'),
    Some('\u{2014}'),
    Some('\u{02dc}'),
    Some('\u{2122}'),
    Some('\u{0161}'),
    Some('\u{203a}'),
    Some('\u{0153}'),
    None,
    Some('\u{017e}'),
    Some('\u{0178}'),
];

pub fn to_utf8(bytes: &[u8], codepage: Codepage) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return None;
    }
    match codepage {
        US_ASCII => Some(bytes.to_vec()),
        UTF_8 => Some(utf8_with_its_last_character_checked(bytes)),
        LATIN_1 => Some(single_byte(bytes, |byte| Some(char::from(byte)))),
        WINDOWS_1252 => {
            let mut converted = String::new();
            for byte in bytes {
                converted.push(windows_1252(*byte)?);
            }
            Some(converted.into_bytes())
        }
        UTF_16_LITTLE_ENDIAN => utf16_little_endian(bytes),
        _ => None,
    }
}

fn single_byte(bytes: &[u8], each: impl Fn(u8) -> Option<char>) -> Vec<u8> {
    bytes
        .iter()
        .filter_map(|byte| each(*byte))
        .collect::<String>()
        .into_bytes()
}

fn windows_1252(byte: u8) -> Option<char> {
    match byte {
        0x80..=0x9f => WINDOWS_1252_FROM_0X80
            .get(usize::from(byte.saturating_sub(0x80)))
            .copied()
            .flatten(),
        _ => Some(char::from(byte)),
    }
}

fn utf16_little_endian(bytes: &[u8]) -> Option<Vec<u8>> {
    let (units, rest) = bytes.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let units = units.iter().map(|unit| u16::from_le_bytes(*unit));
    let mut converted = String::new();
    for decoded in char::decode_utf16(units) {
        converted.push(decoded.ok()?);
    }
    Some(converted.into_bytes())
}

fn utf8_with_its_last_character_checked(bytes: &[u8]) -> Vec<u8> {
    let mut copied = bytes.to_vec();
    if copied.last().is_some_and(|last| last & CONTINUATION == 0) {
        return copied;
    }
    let start = copied
        .iter()
        .rposition(|byte| byte & CONTINUATION_MASK != CONTINUATION)
        .unwrap_or(0);
    let character_bytes = copied.len().saturating_sub(start);
    let lead_ones = copied
        .get(start)
        .map_or(0, |lead| usize::try_from(lead.leading_ones()).unwrap_or(0));
    if lead_ones != character_bytes
        && let Some(character) = copied.get_mut(start..)
    {
        character.fill(0);
    }
    copied
}
