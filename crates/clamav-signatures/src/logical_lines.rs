use crate::FUNCTIONALITY_LEVEL;
use crate::body_pattern::{ByteWidth, longest_part_of_body};
use crate::ignore_list::IgnoreList;

const FIELD_SEPARATOR: u8 = b';';
const DESCRIPTION_SEPARATOR: u8 = b',';
const KEY_SEPARATOR: u8 = b':';
const RANGE_SEPARATOR: u8 = b'-';
const MODIFIER_MARK: &[u8] = b"::";
const WIDE_MODIFIER: u8 = b'w';
const COMMENT_MARK: u8 = b'#';
const TARGET_KEY: &[u8] = b"Target";
const LEVEL_KEY: &[u8] = b"Engine";
const FIRST_SUBSIGNATURE_FIELD: usize = 3;
const TARGET_COUNT: u32 = 15;
const REGULAR_EXPRESSION_MARK: u8 = b'/';
const NON_CONTENT_MARKS: [u8; 2] = *b"#$";

pub struct LoadedContent {
    pub target: u32,
    pub longest_part: u32,
}

pub fn loaded_content(line: &[u8], ignored: &IgnoreList) -> Option<LoadedContent> {
    if line.first() == Some(&COMMENT_MARK) {
        return None;
    }
    let fields: Vec<&[u8]> = line.split(|byte| *byte == FIELD_SEPARATOR).collect();
    let name = fields.first()?;
    if ignored.ignores(name, line) {
        return None;
    }
    let mut target = 0;
    for entry in fields.get(1)?.split(|byte| *byte == DESCRIPTION_SEPARATOR) {
        let (key, value) = split_once(entry, KEY_SEPARATOR)?;
        if key == TARGET_KEY {
            target = decimal(value)?;
        } else if key == LEVEL_KEY && !level_range_holds_ours(value)? {
            return None;
        }
    }
    if target >= TARGET_COUNT {
        return None;
    }
    let longest_part = fields
        .get(FIRST_SUBSIGNATURE_FIELD..)?
        .iter()
        .filter_map(|subsignature| longest_content_part(subsignature))
        .max()
        .unwrap_or(0);
    Some(LoadedContent {
        target,
        longest_part,
    })
}

fn longest_content_part(subsignature: &[u8]) -> Option<u32> {
    let (content, modifiers) = match subsignature
        .windows(MODIFIER_MARK.len())
        .position(|window| window == MODIFIER_MARK)
    {
        Some(at) => (
            subsignature.get(..at)?,
            subsignature.get(at.checked_add(MODIFIER_MARK.len())?..)?,
        ),
        None => (subsignature, &b""[..]),
    };
    if content.contains(&REGULAR_EXPRESSION_MARK)
        || content.iter().any(|byte| NON_CONTENT_MARKS.contains(byte))
    {
        return None;
    }
    let body = split_once(content, KEY_SEPARATOR).map_or(content, |(_, body)| body);
    let width = if modifiers.contains(&WIDE_MODIFIER) {
        ByteWidth::Wide
    } else {
        ByteWidth::Narrow
    };
    longest_part_of_body(body, width).ok()
}

fn level_range_holds_ours(range: &[u8]) -> Option<bool> {
    let ours = u32::try_from(FUNCTIONALITY_LEVEL).ok()?;
    let (lowest, highest) = split_once(range, RANGE_SEPARATOR).unwrap_or((range, b""));
    let lowest = if lowest.is_empty() {
        0
    } else {
        decimal(lowest)?
    };
    let holds_highest = highest.is_empty() || decimal(highest)? >= ours;
    Some(lowest <= ours && holds_highest)
}

fn split_once(text: &[u8], separator: u8) -> Option<(&[u8], &[u8])> {
    let at = text.iter().position(|byte| *byte == separator)?;
    Some((text.get(..at)?, text.get(at.checked_add(1)?..)?))
}

fn decimal(text: &[u8]) -> Option<u32> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    text.iter().try_fold(0u32, |value, digit| {
        value
            .checked_mul(10)?
            .checked_add(u32::from(digit.checked_sub(b'0')?))
    })
}
