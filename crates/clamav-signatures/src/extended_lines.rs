use std::fmt;

use debar_image::{Category, Indicator, Pattern, Placement};

use crate::FUNCTIONALITY_LEVEL;
use crate::body_pattern::{MalformedBody, ReadBody, UnsupportedBody, read_body};
use crate::hash_lines::indicator_named;
use crate::ignore_list::IgnoreList;

const FIELD_SEPARATOR: u8 = b':';
const FEWEST_FIELDS: usize = 4;
const MOST_FIELDS: usize = 6;
const COMMENT_MARK: u8 = b'#';
const NAME_TRAILER: &[u8] = b" (Clam)";
const ANY_TARGET: &[u8] = b"*";
const TARGET_COUNT: u32 = 15;
const GENERIC_TARGET: u32 = 0;
const TARGETS_WITH_EXECUTABLE_OFFSETS: [u32; 3] = [1, 6, 9];
const ANYWHERE: &[u8] = b"*";
const BEFORE_END: &[u8] = b"EOF-";
const LONGEST_OFFSET: usize = 64;
const MACRO_MARK: u8 = b'$';
const MACRO_GROUPS: u32 = 32;
const EXECUTABLE_OFFSET_PREFIXES: [&[u8]; 4] = [b"EP+", b"EP-", b"SL+", b"SE"];
const VERSION_INFO: &[u8] = b"VI";
const LONGEST_LINE: usize = 8190;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalformedExtendedLine {
    TooLong,
    TooFewFields,
    TooManyFields,
    EmptyName,
    NameNotText,
    LevelNotDigits,
    TargetNotANumber,
    OffsetTooLong,
    OffsetMalformed,
    ExecutableOffsetOnTarget { target: u32 },
    Body(MalformedBody),
}

impl fmt::Display for MalformedExtendedLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(formatter, "longer than {LONGEST_LINE} characters"),
            Self::TooFewFields => write!(formatter, "fewer than four fields"),
            Self::TooManyFields => write!(formatter, "more than six fields"),
            Self::EmptyName => write!(formatter, "the signature name is empty"),
            Self::NameNotText => write!(formatter, "the signature name is not UTF-8 text"),
            Self::LevelNotDigits => {
                write!(formatter, "a functionality level is not a decimal number")
            }
            Self::TargetNotANumber => write!(formatter, "the target is not * or a decimal number"),
            Self::OffsetTooLong => write!(formatter, "the offset is longer than 64 characters"),
            Self::OffsetMalformed => write!(formatter, "the offset is malformed"),
            Self::ExecutableOffsetOnTarget { target } => write!(
                formatter,
                "an offset in an executable is not allowed for target {target}"
            ),
            Self::Body(reason) => write!(formatter, "{reason}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadExtendedLine<'a> {
    Comment,
    Ignored,
    OutsideFunctionalityLevel,
    TargetNotLoaded,
    NeverReports,
    NeedsExecutableFacts,
    TargetNotYetCompiled,
    BodyNotYetCompiled(UnsupportedBody),
    Signature(ExtendedSignature<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedSignature<'a> {
    pub name: &'a str,
    pub indicator: Indicator,
    pub category: Category,
    pub placement: Placement,
    pub pattern: Pattern,
    pub plain_bytes: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Offset {
    Placed(Placement),
    MacroGroup,
    InAnExecutable,
}

pub fn read_line<'a>(
    category: Category,
    line_without_ending: &'a [u8],
    ignored: &IgnoreList,
) -> Result<ReadExtendedLine<'a>, MalformedExtendedLine> {
    if line_without_ending.len() > LONGEST_LINE {
        return Err(MalformedExtendedLine::TooLong);
    }
    if line_without_ending.first() == Some(&COMMENT_MARK) {
        return Ok(ReadExtendedLine::Comment);
    }
    let fields: Vec<&[u8]> = line_without_ending
        .split(|byte| *byte == FIELD_SEPARATOR)
        .collect();
    if fields.len() < FEWEST_FIELDS {
        return Err(MalformedExtendedLine::TooFewFields);
    }
    if fields.len() > MOST_FIELDS {
        return Err(MalformedExtendedLine::TooManyFields);
    }
    let [
        name_field,
        target_field,
        offset_field,
        body_field,
        levels @ ..,
    ] = fields.as_slice()
    else {
        return Err(MalformedExtendedLine::TooFewFields);
    };
    if ignored.ignores(name_field, line_without_ending) {
        return Ok(ReadExtendedLine::Ignored);
    }
    if outside_functionality_level(levels)? {
        return Ok(ReadExtendedLine::OutsideFunctionalityLevel);
    }
    let target = read_target(target_field)?;
    if target >= TARGET_COUNT {
        return Ok(ReadExtendedLine::TargetNotLoaded);
    }
    if name_field.is_empty() {
        return Err(MalformedExtendedLine::EmptyName);
    }
    let name = std::str::from_utf8(without_trailer(name_field))
        .map_err(|_| MalformedExtendedLine::NameNotText)?;
    let offset = read_offset(offset_field, target)?;
    let body = read_body(body_field).map_err(MalformedExtendedLine::Body)?;
    let (pattern, plain_bytes) = match body {
        ReadBody::Pattern {
            pattern,
            plain_bytes,
        } => (pattern, plain_bytes),
        ReadBody::Unsupported(reason) => return Ok(ReadExtendedLine::BodyNotYetCompiled(reason)),
    };
    let placement = match offset {
        Offset::MacroGroup => return Ok(ReadExtendedLine::NeverReports),
        Offset::InAnExecutable => return Ok(ReadExtendedLine::NeedsExecutableFacts),
        Offset::Placed(placement) => placement,
    };
    if target != GENERIC_TARGET {
        return Ok(ReadExtendedLine::TargetNotYetCompiled);
    }
    Ok(ReadExtendedLine::Signature(ExtendedSignature {
        name,
        indicator: indicator_named(name),
        category,
        placement,
        pattern,
        plain_bytes,
    }))
}

fn outside_functionality_level(levels: &[&[u8]]) -> Result<bool, MalformedExtendedLine> {
    let loaded = u64::try_from(FUNCTIONALITY_LEVEL).unwrap_or(0);
    if let Some(lowest) = levels.first()
        && level(lowest)? > loaded
    {
        return Ok(true);
    }
    if let Some(highest) = levels.get(1)
        && level(highest)? < loaded
    {
        return Ok(true);
    }
    Ok(false)
}

fn level(field: &[u8]) -> Result<u64, MalformedExtendedLine> {
    decimal_or_zero(field).ok_or(MalformedExtendedLine::LevelNotDigits)
}

fn decimal_or_zero(field: &[u8]) -> Option<u64> {
    if !field.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(field.iter().fold(0u64, |value, digit| {
        value
            .saturating_mul(10)
            .saturating_add(u64::from(digit.saturating_sub(b'0')))
    }))
}

fn read_target(field: &[u8]) -> Result<u32, MalformedExtendedLine> {
    if field == ANY_TARGET {
        return Ok(GENERIC_TARGET);
    }
    decimal_or_zero(field)
        .map(|target| u32::try_from(target).unwrap_or(u32::MAX))
        .ok_or(MalformedExtendedLine::TargetNotANumber)
}

fn read_offset(field: &[u8], target: u32) -> Result<Offset, MalformedExtendedLine> {
    if field.len() > LONGEST_OFFSET {
        return Err(MalformedExtendedLine::OffsetTooLong);
    }
    if field == ANYWHERE {
        return Ok(Offset::Placed(Placement::Anywhere));
    }
    if is_executable_offset(field) {
        return if TARGETS_WITH_EXECUTABLE_OFFSETS.contains(&target) {
            Ok(Offset::InAnExecutable)
        } else {
            Err(MalformedExtendedLine::ExecutableOffsetOnTarget { target })
        };
    }
    if let Some(group) = field
        .strip_prefix(&[MACRO_MARK])
        .and_then(|rest| rest.strip_suffix(&[MACRO_MARK]))
        .filter(|group| !group.is_empty())
    {
        return match decimal_or_zero(group) {
            Some(group) if group < u64::from(MACRO_GROUPS) => Ok(Offset::MacroGroup),
            _ => Err(MalformedExtendedLine::OffsetMalformed),
        };
    }
    let (position, shift) = match field.iter().position(|byte| *byte == b',') {
        Some(comma) => (
            field.get(..comma).unwrap_or_default(),
            field.get(comma.saturating_add(1)..).unwrap_or_default(),
        ),
        None => (field, &b""[..]),
    };
    let number = |digits: &[u8]| {
        decimal_or_zero(digits)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(MalformedExtendedLine::OffsetMalformed)
    };
    let shift = number(shift)?;
    if let Some(distance) = position.strip_prefix(BEFORE_END) {
        return Ok(Offset::Placed(Placement::BeforeEnd {
            distance: number(distance)?,
            shift,
        }));
    }
    Ok(Offset::Placed(Placement::FromStart {
        distance: number(position)?,
        shift,
    }))
}

fn is_executable_offset(field: &[u8]) -> bool {
    field == VERSION_INFO
        || EXECUTABLE_OFFSET_PREFIXES
            .iter()
            .any(|prefix| field.starts_with(prefix))
        || field
            .strip_prefix(b"S")
            .is_some_and(|rest| rest.first().is_some_and(u8::is_ascii_digit))
}

fn without_trailer(name: &[u8]) -> &[u8] {
    name.windows(NAME_TRAILER.len())
        .position(|window| window == NAME_TRAILER)
        .and_then(|position| name.get(..position))
        .unwrap_or(name)
}
