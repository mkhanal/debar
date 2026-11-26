use std::fmt;

use debar_image::{UrlList, UrlPattern, UrlRule, UrlVerdict};

use crate::FUNCTIONALITY_LEVEL;
use crate::ignore_list::hex_value;
use crate::posix_expression_syntax::{MalformedPosixExpression, translate_posix};

const COMMENT_MARK: u8 = b'#';
const FIELD_SEPARATOR: u8 = b':';
const LEVEL_SEPARATOR: u8 = b'-';
const PATTERN_END: u8 = b'/';
const LONGEST_LINE: usize = 8_188;
const OPTIONAL_PATH_TAIL: &[u8] = b"([/?].*)?/";
const PATH_TAIL: &[u8] = b"([/?].*)/";
const SHORTEST_SUFFIX: usize = 2;
const LARGEST_EXPANDED_CLASS: usize = 16;
const ALLOWED_DIGEST_TYPE: u8 = b'W';
const FULL_DIGEST_TYPE: u8 = b'F';
const DIGEST_PREFIX_TYPE: u8 = b'P';

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UrlFile {
    Monitored,
    Allowed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalformedUrlLine {
    NoSeparator,
    TooLong,
    KindNotAccepted(u8),
    Expression(MalformedPosixExpression),
    PatternTooShort,
    DigestType(u8),
    DigestNotHexadecimal,
}

impl fmt::Display for MalformedUrlLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSeparator => formatter.write_str("the line has no ':'"),
            Self::TooLong => write!(formatter, "the line is longer than {LONGEST_LINE} bytes"),
            Self::KindNotAccepted(kind) => write!(
                formatter,
                "the line kind {:?} is not accepted in this file",
                char::from(*kind)
            ),
            Self::Expression(reason) => write!(formatter, "the regular expression: {reason}"),
            Self::PatternTooShort => formatter
                .write_str("the pattern leaves less than two bytes of fixed text at its end"),
            Self::DigestType(kind) => {
                write!(
                    formatter,
                    "the digest type {:?} is unknown",
                    char::from(*kind)
                )
            }
            Self::DigestNotHexadecimal => {
                formatter.write_str("the digest is empty, of odd length or not hexadecimal")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadUrlLine {
    Comment,
    OutsideFunctionalityLevel,
    Rule(UrlRule),
}

pub fn read_line(
    file: UrlFile,
    line_without_ending: &[u8],
) -> Result<ReadUrlLine, MalformedUrlLine> {
    if line_without_ending.is_empty() || line_without_ending.first() == Some(&COMMENT_MARK) {
        return Ok(ReadUrlLine::Comment);
    }
    let Some(line) = within_functionality_level(line_without_ending) else {
        return Ok(ReadUrlLine::OutsideFunctionalityLevel);
    };
    let separator = line
        .iter()
        .position(|byte| *byte == FIELD_SEPARATOR)
        .ok_or(MalformedUrlLine::NoSeparator)?;
    if line.len() > LONGEST_LINE {
        return Err(MalformedUrlLine::TooLong);
    }
    let kind = line.first().copied().unwrap_or_default();
    let field = line.get(separator.saturating_add(1)..).unwrap_or_default();
    let mut pattern = field.to_vec();
    pattern.push(PATTERN_END);
    let list = match file {
        UrlFile::Monitored => UrlList::Monitored,
        UrlFile::Allowed => UrlList::Allowed,
    };
    let rule = match (file, kind) {
        (UrlFile::Monitored, b'R') | (UrlFile::Allowed, b'X' | b'Y') => {
            expression_rule(list, pattern)?
        }
        (UrlFile::Monitored, b'H') | (UrlFile::Allowed, b'M') => {
            if pattern.len() < SHORTEST_SUFFIX {
                return Err(MalformedUrlLine::PatternTooShort);
            }
            UrlRule {
                list,
                pattern: UrlPattern::Host(pattern),
                never_matches: false,
            }
        }
        (_, b'S') => {
            let verdict_byte = line.get(1).copied().unwrap_or(FIELD_SEPARATOR);
            digest_rule(file, list, verdict_byte, field)?
        }
        (_, other) => return Err(MalformedUrlLine::KindNotAccepted(other)),
    };
    Ok(ReadUrlLine::Rule(rule))
}

fn within_functionality_level(line: &[u8]) -> Option<&[u8]> {
    let Some(last) = line.iter().rposition(|byte| *byte == FIELD_SEPARATOR) else {
        return Some(line);
    };
    let level = line.get(last.saturating_add(1)..).unwrap_or_default();
    let Some(dash) = level.iter().position(|byte| *byte == LEVEL_SEPARATOR) else {
        return Some(line);
    };
    let lowest = level.get(..dash).unwrap_or_default();
    let highest = level.get(dash.saturating_add(1)..).unwrap_or_default();
    if !lowest.iter().all(u8::is_ascii_digit) || !highest.iter().all(u8::is_ascii_digit) {
        return Some(line);
    }
    let engine = i64::from(u32::try_from(FUNCTIONALITY_LEVEL).unwrap_or(u32::MAX));
    let lowest = decimal(lowest);
    let highest = if highest.is_empty() {
        i64::MAX
    } else {
        decimal(highest)
    };
    if lowest > engine || highest < engine {
        return None;
    }
    line.get(..last)
}

fn decimal(text: &[u8]) -> i64 {
    text.iter().fold(0i64, |value, digit| {
        value
            .saturating_mul(10)
            .saturating_add(i64::from(digit.saturating_sub(b'0')))
    })
}

fn expression_rule(list: UrlList, mut pattern: Vec<u8>) -> Result<UrlRule, MalformedUrlLine> {
    for tail in [OPTIONAL_PATH_TAIL, PATH_TAIL] {
        if pattern.len() > tail.len() && pattern.ends_with(tail) {
            pattern.truncate(pattern.len().saturating_sub(tail.len()));
            pattern.push(PATTERN_END);
        }
    }
    let expression = translate_posix(&pattern).map_err(MalformedUrlLine::Expression)?;
    let never_matches = match fixed_tails(&pattern) {
        FixedTails::EndsTheParse => true,
        FixedTails::Tails(tails) => {
            if tails.iter().any(|tail| tail.len() < SHORTEST_SUFFIX) {
                return Err(MalformedUrlLine::PatternTooShort);
            }
            tails
                .iter()
                .all(|tail| tail.iter().any(|byte| matches!(byte, b'{' | b'}')))
        }
    };
    Ok(UrlRule {
        list,
        pattern: UrlPattern::Expression {
            text: pattern,
            expression,
        },
        never_matches,
    })
}

enum FixedTails {
    EndsTheParse,
    Tails(Vec<Vec<u8>>),
}

enum Token {
    Fixed(u8),
    Class(Vec<u8>),
    Group(Vec<Vec<Token>>),
    Stop,
}

const DEEPEST_GROUP: usize = 32;

fn fixed_tails(pattern: &[u8]) -> FixedTails {
    let body = pattern.strip_prefix(b"(?i)").unwrap_or(pattern);
    if contains_unescaped(body, b'$') {
        return FixedTails::EndsTheParse;
    }
    let mut position = 0;
    let branches = branches_of(body, &mut position, 0);
    let mut tails = Vec::new();
    for branch in &branches {
        tails.extend(branch_tails(branch, Vec::new(), 0));
    }
    FixedTails::Tails(tails)
}

fn branch_tails(tokens: &[Token], after: Vec<u8>, depth: usize) -> Vec<Vec<u8>> {
    let mut collected: Vec<Vec<u8>> = vec![after];
    for token in tokens.iter().rev() {
        match token {
            Token::Fixed(byte) => {
                for tail in &mut collected {
                    tail.push(*byte);
                }
            }
            Token::Class(members) if members.len() <= LARGEST_EXPANDED_CLASS => {
                collected = collected
                    .iter()
                    .flat_map(|tail| {
                        members.iter().map(move |member| {
                            let mut extended = tail.clone();
                            extended.push(*member);
                            extended
                        })
                    })
                    .collect();
            }
            Token::Group(branches) if depth < DEEPEST_GROUP => {
                return collected
                    .iter()
                    .flat_map(|tail| {
                        branches
                            .iter()
                            .flat_map(|branch| {
                                branch_tails(branch, tail.clone(), depth.saturating_add(1))
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect();
            }
            Token::Class(_) | Token::Group(_) | Token::Stop => break,
        }
    }
    collected
}

fn contains_unescaped(text: &[u8], wanted: u8) -> bool {
    let mut escaped = false;
    for byte in text {
        if escaped {
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == wanted {
            return true;
        }
    }
    false
}

fn branches_of(text: &[u8], position: &mut usize, depth: usize) -> Vec<Vec<Token>> {
    let mut branches = vec![Vec::new()];
    while let Some(byte) = text.get(*position) {
        *position = position.saturating_add(1);
        let tokens = branches.last_mut();
        let Some(tokens) = tokens else {
            break;
        };
        match byte {
            b'\\' => {
                if let Some(escaped) = text.get(*position) {
                    tokens.push(Token::Fixed(*escaped));
                    *position = position.saturating_add(1);
                }
            }
            b'|' => branches.push(Vec::new()),
            b')' if depth > 0 => return branches,
            b'(' => {
                let inner = branches_of(text, position, depth.saturating_add(1));
                tokens.push(if depth < DEEPEST_GROUP {
                    Token::Group(inner)
                } else {
                    Token::Stop
                });
            }
            b'*' | b'?' | b'+' => {
                tokens.pop();
                tokens.push(Token::Stop);
            }
            b'.' | b')' => tokens.push(Token::Stop),
            b'[' => {
                let (members, length) = bracket_members(text.get(*position..).unwrap_or_default());
                *position = position.saturating_add(length);
                tokens.push(members.map_or(Token::Stop, Token::Class));
            }
            other => tokens.push(Token::Fixed(*other)),
        }
    }
    branches
}

fn bracket_members(text: &[u8]) -> (Option<Vec<u8>>, usize) {
    let negated = text.first() == Some(&b'^');
    let mut position = usize::from(negated);
    let mut members = Vec::new();
    let mut first = true;
    let mut named_class = false;
    while let Some(byte) = text.get(position) {
        if *byte == b']' && !first {
            position = position.saturating_add(1);
            break;
        }
        first = false;
        if *byte == b'['
            && matches!(
                text.get(position.saturating_add(1)),
                Some(b':' | b'.' | b'=')
            )
        {
            named_class = true;
        }
        if text.get(position.saturating_add(1)) == Some(&b'-')
            && text
                .get(position.saturating_add(2))
                .is_some_and(|end| *end != b']')
        {
            let low = *byte;
            let high = text.get(position.saturating_add(2)).copied().unwrap_or(low);
            members.extend(low..=high);
            position = position.saturating_add(3);
            continue;
        }
        members.push(*byte);
        position = position.saturating_add(1);
    }
    if negated || named_class {
        return (None, position);
    }
    members.sort_unstable();
    members.dedup();
    (Some(members), position)
}

fn digest_rule(
    file: UrlFile,
    list: UrlList,
    verdict_byte: u8,
    field: &[u8],
) -> Result<UrlRule, MalformedUrlLine> {
    let digest_type = field.first().copied().unwrap_or_default();
    let accepted = match file {
        UrlFile::Monitored => matches!(
            digest_type,
            ALLOWED_DIGEST_TYPE | FULL_DIGEST_TYPE | DIGEST_PREFIX_TYPE
        ),
        UrlFile::Allowed => digest_type == ALLOWED_DIGEST_TYPE,
    };
    if file == UrlFile::Allowed && !accepted {
        return Err(MalformedUrlLine::KindNotAccepted(b'S'));
    }
    if !accepted || field.get(1) != Some(&FIELD_SEPARATOR) {
        return Err(MalformedUrlLine::DigestType(digest_type));
    }
    let hex = field.get(2..).unwrap_or_default();
    if hex.is_empty() || hex.len() % 2 == 1 {
        return Err(MalformedUrlLine::DigestNotHexadecimal);
    }
    let (pairs, _) = hex.as_chunks::<2>();
    let digest = pairs
        .iter()
        .map(|[high, low]| {
            hex_value(*high)
                .zip(hex_value(*low))
                .map(|(high, low)| high.wrapping_shl(4) | low)
        })
        .collect::<Option<Vec<u8>>>()
        .ok_or(MalformedUrlLine::DigestNotHexadecimal)?;
    let verdict = if digest_type == ALLOWED_DIGEST_TYPE {
        UrlVerdict::Allowed
    } else {
        match verdict_byte {
            b'1' => UrlVerdict::Blocked,
            b'2' => UrlVerdict::SuspectedPhishing,
            _ => UrlVerdict::SuspectedMalware,
        }
    };
    let pattern = if digest_type == DIGEST_PREFIX_TYPE {
        UrlPattern::DigestPrefix {
            prefix: digest,
            verdict,
        }
    } else {
        UrlPattern::Digest { digest, verdict }
    };
    Ok(UrlRule {
        list,
        never_matches: digest_type == DIGEST_PREFIX_TYPE || file == UrlFile::Allowed,
        pattern,
    })
}

#[must_use]
pub fn shadowed_by_an_allowed_digest(stored: &[UrlRule], rule: &UrlRule) -> bool {
    let UrlPattern::Digest { digest, verdict } = &rule.pattern else {
        return false;
    };
    *verdict != UrlVerdict::Allowed
        && stored.iter().any(|existing| {
            existing.list == rule.list
                && matches!(
                    &existing.pattern,
                    UrlPattern::Digest { digest: known, verdict: UrlVerdict::Allowed } if known == digest
                )
        })
}
