use std::fmt;

use debar_image::{Indicator, KindCondition, SizeCondition};
use regex_syntax::hir::Hir;

use crate::FUNCTIONALITY_LEVEL;
use crate::hash_lines::indicator_named;
use crate::ignore_list::IgnoreList;
use crate::posix_expression_syntax::{MalformedPosixExpression, translate_posix};
use crate::type_names::{NamedType, type_named};

const COMMENT_MARK: u8 = b'#';
const FIELD_SEPARATOR: u8 = b':';
const FEWEST_FIELDS: usize = 10;
const MOST_FIELDS: usize = 12;
const ANY: &[u8] = b"*";
const RANGE_SEPARATOR: u8 = b'-';

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalformedContainerLine {
    FieldCount { found: usize },
    LevelNotDigits,
    EmptyName,
    NameNotText,
    UnknownContainerType,
    EntryName(MalformedPosixExpression),
    Size,
    Encrypted,
}

impl fmt::Display for MalformedContainerLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FieldCount { found } => write!(
                formatter,
                "{found} fields where a container signature has 10 to 12"
            ),
            Self::LevelNotDigits => {
                formatter.write_str("a functionality level is not a decimal number")
            }
            Self::EmptyName => formatter.write_str("the signature name is empty"),
            Self::NameNotText => formatter.write_str("the signature name is not UTF-8 text"),
            Self::UnknownContainerType => formatter.write_str("the container type is unknown"),
            Self::EntryName(reason) => write!(formatter, "the entry name expression: {reason}"),
            Self::Size => formatter.write_str("a size or position is malformed"),
            Self::Encrypted => formatter.write_str("the encrypted field is not *, 0 or 1"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerLine<'a> {
    pub name: &'a str,
    pub indicator: Indicator,
    pub container: KindCondition,
    pub container_size: SizeCondition,
    pub entry_name: Option<Hir>,
    pub compressed_size: SizeCondition,
    pub real_size: SizeCondition,
    pub encrypted: Option<bool>,
    pub position: SizeCondition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadContainerLine<'a> {
    Comment,
    OutsideFunctionalityLevel,
    Ignored,
    Signature(ContainerLine<'a>),
}

pub fn read_line<'a>(
    line: &'a [u8],
    ignored: &IgnoreList,
) -> Result<ReadContainerLine<'a>, MalformedContainerLine> {
    if line.first() == Some(&COMMENT_MARK) {
        return Ok(ReadContainerLine::Comment);
    }
    let fields: Vec<&[u8]> = line.split(|byte| *byte == FIELD_SEPARATOR).collect();
    if !(FEWEST_FIELDS..=MOST_FIELDS).contains(&fields.len()) {
        return Err(MalformedContainerLine::FieldCount {
            found: fields.len(),
        });
    }
    let level = u64::try_from(FUNCTIONALITY_LEVEL).unwrap_or(0);
    if let Some(lowest) = fields.get(10)
        && digits(lowest)? > level
    {
        return Ok(ReadContainerLine::OutsideFunctionalityLevel);
    }
    if let Some(highest) = fields.get(11)
        && digits(highest)? < level
    {
        return Ok(ReadContainerLine::OutsideFunctionalityLevel);
    }
    let field = |index: usize| fields.get(index).copied().unwrap_or_default();
    if ignored.ignores(field(0), line) {
        return Ok(ReadContainerLine::Ignored);
    }
    if field(0).is_empty() {
        return Err(MalformedContainerLine::EmptyName);
    }
    let name = std::str::from_utf8(field(0)).map_err(|_| MalformedContainerLine::NameNotText)?;
    let container = if field(1) == ANY {
        KindCondition::AnyKind
    } else {
        let type_name = std::str::from_utf8(field(1))
            .map_err(|_| MalformedContainerLine::UnknownContainerType)?;
        match type_named(type_name).ok_or(MalformedContainerLine::UnknownContainerType)? {
            NamedType::AnyType => KindCondition::AnyKind,
            NamedType::Kind(kind) => KindCondition::Kind(kind),
        }
    };
    let entry_name = if field(3) == ANY {
        None
    } else {
        Some(translate_posix(field(3)).map_err(MalformedContainerLine::EntryName)?)
    };
    let encrypted = match field(6) {
        ANY => None,
        b"0" => Some(false),
        b"1" => Some(true),
        _ => return Err(MalformedContainerLine::Encrypted),
    };
    Ok(ReadContainerLine::Signature(ContainerLine {
        name,
        indicator: indicator_named(name),
        container,
        container_size: size_condition(field(2))?,
        entry_name,
        compressed_size: size_condition(field(4))?,
        real_size: size_condition(field(5))?,
        encrypted,
        position: size_condition(field(7))?,
    }))
}

fn digits(text: &[u8]) -> Result<u64, MalformedContainerLine> {
    if !text.iter().all(u8::is_ascii_digit) {
        return Err(MalformedContainerLine::LevelNotDigits);
    }
    Ok(text.iter().fold(0u64, |value, digit| {
        value
            .saturating_mul(10)
            .saturating_add(u64::from(digit.saturating_sub(b'0')))
    }))
}

fn unsigned(text: &[u8]) -> Option<u32> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let value = text.iter().fold(0u64, |value, digit| {
        value
            .saturating_mul(10)
            .saturating_add(u64::from(digit.saturating_sub(b'0')))
    });
    Some(u32::try_from(value & u64::from(u32::MAX)).unwrap_or(u32::MAX))
}

fn size_condition(text: &[u8]) -> Result<SizeCondition, MalformedContainerLine> {
    if text == ANY {
        return Ok(SizeCondition::Any);
    }
    let Some(separator) = text.iter().position(|byte| *byte == RANGE_SEPARATOR) else {
        if text.is_empty() {
            return Ok(SizeCondition::Exactly(0));
        }
        return unsigned(text)
            .map(SizeCondition::Exactly)
            .ok_or(MalformedContainerLine::Size);
    };
    let low =
        unsigned(text.get(..separator).unwrap_or_default()).ok_or(MalformedContainerLine::Size)?;
    let rest = text.get(separator.saturating_add(1)..).unwrap_or_default();
    let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
    let high =
        unsigned(rest.get(..digits).unwrap_or_default()).ok_or(MalformedContainerLine::Size)?;
    let bound = |value: u32| (value != 0).then_some(value);
    Ok(SizeCondition::Between {
        lowest: bound(low),
        highest: bound(high),
    })
}
