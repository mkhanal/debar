use std::fmt;

use debar_image::{ObjectKind, Pattern, Placement};

use crate::FUNCTIONALITY_LEVEL;
use crate::body_pattern::{MalformedBody, ReadBody, UnsupportedBody, read_type_recognition_body};
use crate::extended_lines::{MalformedExtendedLine, Offset, read_offset};
use crate::type_names::{NamedType, type_named};

const FIELD_SEPARATOR: u8 = b':';
const FEWEST_FIELDS: usize = 6;
const MOST_FIELDS: usize = 8;
const COMMENT_MARK: u8 = b'#';
const GENERIC_TARGET: u32 = 0;
const MAGIC_AT_THE_START_OF_A_FILE: &[u8] = b"0";
const PATTERN_IN_THE_GENERIC_SIGNATURES: &[u8] = b"1";
const MAGIC_AT_THE_START_OF_A_PARTITION: &[u8] = b"4";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalformedFileTypeLine {
    TooFewFields,
    TooManyFields,
    LevelNotDigits,
    OffsetMalformed,
    MagicNotHex,
    EmptyMagic,
    UnknownTypeName { name: String },
    Body(MalformedBody),
    Offset(MalformedExtendedLine),
}

impl fmt::Display for MalformedFileTypeLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewFields => write!(formatter, "fewer than six fields"),
            Self::TooManyFields => write!(formatter, "more than eight fields"),
            Self::LevelNotDigits => {
                write!(formatter, "a functionality level is not a decimal number")
            }
            Self::OffsetMalformed => {
                write!(formatter, "the magic's offset is not a decimal number")
            }
            Self::MagicNotHex => write!(formatter, "the magic is not hexadecimal bytes"),
            Self::EmptyMagic => write!(formatter, "the magic is empty"),
            Self::UnknownTypeName { name } => write!(formatter, "{name:?} names no file type"),
            Self::Body(reason) => write!(formatter, "{reason}"),
            Self::Offset(reason) => write!(formatter, "{reason}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadFileTypeLine {
    Comment,
    OutsideFunctionalityLevel,
    OtherMode,
    BodyNotYetCompiled {
        reason: UnsupportedBody,
        longest_part: u32,
    },
    NeverReports {
        longest_part: u32,
    },
    Magic(MagicLine),
    Recognition(RecognitionLine),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MagicTarget {
    File,
    Partition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicLine {
    pub target: MagicTarget,
    pub offset: u32,
    pub magic: Vec<u8>,
    pub found: ObjectKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecognitionLine {
    pub placement: Placement,
    pub pattern: Pattern,
    pub plain_bytes: bool,
    pub longest_part: u32,
    pub required: Option<ObjectKind>,
    pub found: ObjectKind,
}

pub fn read_line(line_without_ending: &[u8]) -> Result<ReadFileTypeLine, MalformedFileTypeLine> {
    if line_without_ending.first() == Some(&COMMENT_MARK) {
        return Ok(ReadFileTypeLine::Comment);
    }
    let fields: Vec<&[u8]> = line_without_ending
        .split(|byte| *byte == FIELD_SEPARATOR)
        .collect();
    if fields.len() < FEWEST_FIELDS {
        return Err(MalformedFileTypeLine::TooFewFields);
    }
    if fields.len() > MOST_FIELDS {
        return Err(MalformedFileTypeLine::TooManyFields);
    }
    let [mode, offset, body, _name, required, found, levels @ ..] = fields.as_slice() else {
        return Err(MalformedFileTypeLine::TooFewFields);
    };
    if outside_functionality_level(levels)? {
        return Ok(ReadFileTypeLine::OutsideFunctionalityLevel);
    }
    let required = match named(required)? {
        NamedType::AnyType => None,
        NamedType::Kind(kind) => Some(kind),
    };
    let found = match named(found)? {
        NamedType::AnyType => ObjectKind::Untyped,
        NamedType::Kind(kind) => kind,
    };
    let magic_target = match *mode {
        MAGIC_AT_THE_START_OF_A_FILE => Some(MagicTarget::File),
        MAGIC_AT_THE_START_OF_A_PARTITION => Some(MagicTarget::Partition),
        _ => None,
    };
    if let Some(target) = magic_target {
        return Ok(ReadFileTypeLine::Magic(MagicLine {
            target,
            offset: decimal(offset)
                .and_then(|offset| u32::try_from(offset).ok())
                .ok_or(MalformedFileTypeLine::OffsetMalformed)?,
            magic: hex_bytes(body)?,
            found,
        }));
    }
    if *mode != PATTERN_IN_THE_GENERIC_SIGNATURES {
        return Ok(ReadFileTypeLine::OtherMode);
    }
    let offset = read_offset(offset, GENERIC_TARGET).map_err(MalformedFileTypeLine::Offset)?;
    match read_type_recognition_body(body).map_err(MalformedFileTypeLine::Body)? {
        ReadBody::Pattern {
            pattern,
            plain_bytes,
            longest_part,
        } => Ok(match offset {
            Offset::Placed(placement) => ReadFileTypeLine::Recognition(RecognitionLine {
                placement,
                pattern,
                plain_bytes,
                longest_part,
                required,
                found,
            }),
            Offset::MacroGroup => ReadFileTypeLine::NeverReports { longest_part },
        }),
        ReadBody::Unsupported {
            reason,
            longest_part,
        } => Ok(ReadFileTypeLine::BodyNotYetCompiled {
            reason,
            longest_part,
        }),
    }
}

fn named(field: &[u8]) -> Result<NamedType, MalformedFileTypeLine> {
    std::str::from_utf8(field)
        .ok()
        .and_then(type_named)
        .ok_or_else(|| MalformedFileTypeLine::UnknownTypeName {
            name: String::from_utf8_lossy(field).into_owned(),
        })
}

fn outside_functionality_level(levels: &[&[u8]]) -> Result<bool, MalformedFileTypeLine> {
    let loaded = u64::try_from(FUNCTIONALITY_LEVEL).unwrap_or(0);
    if let Some(lowest) = levels.first()
        && decimal(lowest).ok_or(MalformedFileTypeLine::LevelNotDigits)? > loaded
    {
        return Ok(true);
    }
    if let Some(highest) = levels.get(1)
        && decimal(highest).ok_or(MalformedFileTypeLine::LevelNotDigits)? < loaded
    {
        return Ok(true);
    }
    Ok(false)
}

fn decimal(field: &[u8]) -> Option<u64> {
    if !field.iter().all(u8::is_ascii_digit) {
        return None;
    }
    field.iter().try_fold(0u64, |value, digit| {
        value
            .checked_mul(10)?
            .checked_add(u64::from(digit.checked_sub(b'0')?))
    })
}

fn hex_bytes(field: &[u8]) -> Result<Vec<u8>, MalformedFileTypeLine> {
    if field.is_empty() {
        return Err(MalformedFileTypeLine::EmptyMagic);
    }
    if !field.len().is_multiple_of(2) {
        return Err(MalformedFileTypeLine::MagicNotHex);
    }
    field
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or(MalformedFileTypeLine::MagicNotHex)
        })
        .collect()
}
