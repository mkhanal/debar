use std::collections::BTreeMap;

use md5::{Digest as _, Md5};

use crate::line_text::{lines, without_line_ending};

const UNOFFICIAL_SUFFIX: &[u8] = b".UNOFFICIAL";
const OPEN_BRACE_SUFFIX: &[u8] = b".{";
const MD5_HEX_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
enum IgnoredWhen {
    AnyLine,
    LineDigestIs([u8; 16]),
}

#[derive(Debug, Default)]
pub struct IgnoreList {
    entries: BTreeMap<Vec<u8>, Vec<IgnoredWhen>>,
}

impl IgnoreList {
    pub fn add_entries_from(&mut self, contents: &[u8]) -> usize {
        let mut entry_lines = 0usize;
        for line in lines(contents) {
            entry_lines = entry_lines.saturating_add(1);
            let fields: Vec<&[u8]> = without_line_ending(line)
                .split(|byte| *byte == b':')
                .collect();
            let (name, when) = match fields.as_slice() {
                [name, digest] => (
                    *name,
                    md5_from_hex(digest).map_or(IgnoredWhen::AnyLine, IgnoredWhen::LineDigestIs),
                ),
                [name] | [_, _, name, ..] => (*name, IgnoredWhen::AnyLine),
                [] => continue,
            };
            self.entries
                .entry(normalised(name).to_vec())
                .or_default()
                .push(when);
        }
        entry_lines
    }

    #[must_use]
    pub fn ignores(&self, name: &[u8], line_without_ending: &[u8]) -> bool {
        let Some(conditions) = self.entries.get(normalised(name)) else {
            return false;
        };
        let mut line_digest = None;
        conditions.iter().any(|condition| match condition {
            IgnoredWhen::AnyLine => true,
            IgnoredWhen::LineDigestIs(expected) => {
                let digest: [u8; 16] =
                    *line_digest.get_or_insert_with(|| Md5::digest(line_without_ending).into());
                digest == *expected
            }
        })
    }
}

fn normalised(name: &[u8]) -> &[u8] {
    if let Some(stripped) = name.strip_suffix(UNOFFICIAL_SUFFIX) {
        return stripped;
    }
    if name.ends_with(b"}")
        && let Some(position) = name
            .windows(OPEN_BRACE_SUFFIX.len())
            .rposition(|window| window == OPEN_BRACE_SUFFIX)
    {
        return name.get(..position).unwrap_or(name);
    }
    name
}

fn md5_from_hex(text: &[u8]) -> Option<[u8; 16]> {
    if text.len() != MD5_HEX_LENGTH {
        return None;
    }
    let mut digest = [0u8; 16];
    for (byte, [high, low]) in digest.iter_mut().zip(text.as_chunks::<2>().0) {
        *byte = hex_value(*high)?
            .checked_mul(16)?
            .checked_add(hex_value(*low)?)?;
    }
    Some(digest)
}

pub fn hex_value(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}
