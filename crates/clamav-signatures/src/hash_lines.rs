use std::fmt;

use debar_image::{Category, Digest, HashPurpose, HashedSize, Indicator};

use crate::FUNCTIONALITY_LEVEL;
use crate::ignore_list::{IgnoreList, hex_value};
use crate::numbers::{leading_integer, whole_unsigned_decimal};

const FIELD_SEPARATOR: u8 = b':';
const MOST_FIELDS: usize = 5;
const ANY_SIZE: &[u8] = b"*";
const LOWEST_LEVEL_FOR_ANY_SIZE: i64 = 73;
const LARGEST_SIZE_EXCLUSIVE: u64 = 4_294_967_295;
const NAME_TRAILER: &[u8] = b" (Clam)";
const COMMENT_MARK: u8 = b'#';
const POTENTIALLY_UNWANTED_PREFIXES: [&str; 3] = ["PUA.", "Heuristics.", "BC.Heuristics."];
const WEAK_PREFIX: &str = "Weak.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldOrder {
    HashSizeName,
    SizeHashName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashFile {
    pub purpose: HashPurpose,
    pub category: Category,
    pub field_order: FieldOrder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalformedLine {
    TooFewFields,
    TooManyFields,
    SizeNotANumberInRange,
    AnySizeWithoutLevelSeventyThree,
    HashNotHex,
    HashOfUnknownLength,
    EmptyName,
    NameNotText,
}

impl fmt::Display for MalformedLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooFewFields => "fewer than three fields",
            Self::TooManyFields => "more than five fields",
            Self::SizeNotANumberInRange => "the size is not a decimal number from 1 to 4294967294",
            Self::AnySizeWithoutLevelSeventyThree => {
                "a size of * needs a minimum functionality level of at least 73"
            }
            Self::HashNotHex => "the hash is not hexadecimal",
            Self::HashOfUnknownLength => "the hash is not 32, 40 or 64 hexadecimal digits",
            Self::EmptyName => "the signature name is empty",
            Self::NameNotText => "the signature name is not UTF-8 text",
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadLine<'a> {
    Comment,
    OutsideFunctionalityLevel,
    Ignored,
    Signature(LineSignature<'a>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct LineSignature<'a> {
    pub purpose: HashPurpose,
    pub category: Category,
    pub size: HashedSize,
    pub digest: Digest,
    pub name: &'a str,
    pub indicator: Indicator,
}

pub fn read_line<'a>(
    file: HashFile,
    line_without_ending: &'a [u8],
    ignored: &IgnoreList,
) -> Result<ReadLine<'a>, MalformedLine> {
    if line_without_ending.first() == Some(&COMMENT_MARK) {
        return Ok(ReadLine::Comment);
    }
    let fields: Vec<&[u8]> = line_without_ending
        .split(|byte| *byte == FIELD_SEPARATOR)
        .collect();
    if fields.len() < 3 {
        return Err(MalformedLine::TooFewFields);
    }
    if fields.len() > MOST_FIELDS {
        return Err(MalformedLine::TooManyFields);
    }
    let lowest_level = fields.get(3).map(|field| leading_integer(field));
    let highest_level = fields.get(4).map(|field| leading_integer(field));
    if lowest_level.is_some_and(|lowest| FUNCTIONALITY_LEVEL < lowest)
        || highest_level.is_some_and(|highest| FUNCTIONALITY_LEVEL > highest)
    {
        return Ok(ReadLine::OutsideFunctionalityLevel);
    }
    let (hash_field, size_field) = match file.field_order {
        FieldOrder::HashSizeName => (fields.first(), fields.get(1)),
        FieldOrder::SizeHashName => (fields.get(1), fields.first()),
    };
    let (Some(hash_field), Some(size_field), Some(name_field)) =
        (hash_field, size_field, fields.get(2))
    else {
        return Err(MalformedLine::TooFewFields);
    };
    let size = read_size(size_field, lowest_level)?;
    if ignored.ignores(name_field, line_without_ending) {
        return Ok(ReadLine::Ignored);
    }
    let digest = read_digest(hash_field)?;
    if name_field.is_empty() {
        return Err(MalformedLine::EmptyName);
    }
    let name =
        std::str::from_utf8(without_trailer(name_field)).map_err(|_| MalformedLine::NameNotText)?;
    Ok(ReadLine::Signature(LineSignature {
        purpose: file.purpose,
        category: file.category,
        size,
        digest,
        name,
        indicator: indicator_named(name),
    }))
}

fn read_size(field: &[u8], lowest_level: Option<i64>) -> Result<HashedSize, MalformedLine> {
    if field == ANY_SIZE {
        return if lowest_level.is_some_and(|lowest| lowest >= LOWEST_LEVEL_FOR_ANY_SIZE) {
            Ok(HashedSize::Any)
        } else {
            Err(MalformedLine::AnySizeWithoutLevelSeventyThree)
        };
    }
    whole_unsigned_decimal(field)
        .filter(|size| (1..LARGEST_SIZE_EXCLUSIVE).contains(size))
        .and_then(|size| u32::try_from(size).ok())
        .map(HashedSize::Exactly)
        .ok_or(MalformedLine::SizeNotANumberInRange)
}

fn read_digest(field: &[u8]) -> Result<Digest, MalformedLine> {
    let bytes = field
        .chunks(2)
        .map(|pair| match pair {
            [high, low] => hex_value(*high)?
                .checked_mul(16)?
                .checked_add(hex_value(*low)?),
            _ => None,
        })
        .collect::<Option<Vec<u8>>>();
    let Some(bytes) = bytes else {
        return if field.iter().all(u8::is_ascii_hexdigit) {
            Err(MalformedLine::HashOfUnknownLength)
        } else {
            Err(MalformedLine::HashNotHex)
        };
    };
    if let Ok(md5) = <[u8; 16]>::try_from(bytes.as_slice()) {
        return Ok(Digest::Md5(md5));
    }
    if let Ok(sha1) = <[u8; 20]>::try_from(bytes.as_slice()) {
        return Ok(Digest::Sha1(sha1));
    }
    <[u8; 32]>::try_from(bytes.as_slice())
        .map(Digest::Sha256)
        .map_err(|_| MalformedLine::HashOfUnknownLength)
}

fn without_trailer(name: &[u8]) -> &[u8] {
    name.windows(NAME_TRAILER.len())
        .position(|window| window == NAME_TRAILER)
        .and_then(|position| name.get(..position))
        .unwrap_or(name)
}

#[must_use]
pub fn indicator_named(name: &str) -> Indicator {
    if POTENTIALLY_UNWANTED_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        Indicator::PotentiallyUnwanted
    } else if name.starts_with(WEAK_PREFIX) {
        Indicator::Weak
    } else {
        Indicator::Strong
    }
}
