use std::fmt;

use debar_image::{
    ByteSet, ContentSubsignature, ContextTest, Expression, InclusiveRange, Indicator,
    KindCondition, LogicalConditions, MaskedByte, ObjectKind, Pattern, PatternElement, Placement,
    Subsignature,
};

use crate::FUNCTIONALITY_LEVEL;
use crate::body_pattern::{
    ByteWidth, MalformedBody, ReadBody, longest_part_of_body, read_subsignature_body,
};
use crate::byte_comparison_subsignatures::{MalformedByteComparison, read_byte_comparison};
use crate::extended_lines::{MalformedExtendedLine, Offset, read_offset, without_trailer};
use crate::hash_lines::indicator_named;
use crate::ignore_list::IgnoreList;
use crate::logical_expression::{MalformedExpression, parse_expression};
use crate::regular_expression_subsignatures::{
    MalformedRegularExpressionSubsignature, ReadRegularExpression, read_regular_expression,
};
use crate::regular_expression_syntax::UnsupportedConstruct;
use crate::type_names::{NamedType, type_named};

const FIELD_SEPARATOR: u8 = b';';
const MOST_FIELDS: usize = 68;
const FEWEST_FIELDS: usize = 4;
const FIRST_FIELD_AWARE_OF_EXPRESSIONS: usize = 2;
const LONGEST_LINE: usize = 32_767;
const COMMENT_MARK: u8 = b'#';
const MOST_SUBSIGNATURES: usize = 64;
const DESCRIPTION_SEPARATOR: u8 = b',';
const MOST_ATTRIBUTES: usize = 10;
const KEY_SEPARATOR: u8 = b':';
const RANGE_SEPARATOR: u8 = b'-';
const INTERMEDIATES_SEPARATOR: u8 = b'>';
const MOST_INTERMEDIATES: usize = 16;
const LOWEST_ENGINE_FOR_CONDITIONS: u32 = 51;
const TARGET_COUNT: u32 = 15;
const EXECUTABLE_TARGETS: [u32; 3] = [1, 6, 9];
const PORTABLE_EXECUTABLE_TARGET: u32 = 1;
const REGULAR_EXPRESSION_MARK: u8 = b'/';
const ESCAPE: u8 = b'\\';
const MACRO_MARK: u8 = b'$';
const BYTE_COMPARISON_MARKS: (u8, u8) = (b'(', b'#');
const IMAGE_FUZZY_HASH_PREFIX: &[u8] = b"fuzzy_img#";
const IMAGE_FUZZY_HASH_SEPARATOR: u8 = b'#';
const IMAGE_FUZZY_HASH_DIGITS: usize = 16;
const SUBSIGNATURE_FIELD_SEPARATOR: u8 = b':';
const MOST_SUBSIGNATURE_FIELDS: usize = 5;
const WORD_BOUNDARY: &[u8] = b"(W)";
const WIDE_PADDING: &[u8] = b"00";
const CASE_BIT: u8 = 0x20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalformedLogicalLine {
    TooLong,
    TooFewFields,
    Expression(MalformedExpression),
    SubsignatureCountDisagrees {
        named: usize,
        given: usize,
    },
    TooManySubsignatures,
    AttributeWithoutValue,
    EngineNotFirst,
    AttributeNeedsEngine,
    MalformedAttribute,
    NoTarget,
    IconGroupOnTarget {
        target: u32,
    },
    ExecutableAttributeOnTarget {
        target: u32,
    },
    EmptyName,
    NameNotText,
    Subsignature {
        index: usize,
        reason: MalformedSubsignature,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalformedSubsignature {
    Offset(MalformedExtendedLine),
    Body(MalformedBody),
    UnknownModifier(u8),
    RegularExpression(MalformedRegularExpressionSubsignature),
    ByteComparison(MalformedByteComparison),
    ImageFuzzyHash,
}

impl fmt::Display for MalformedLogicalLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(formatter, "longer than {LONGEST_LINE} characters"),
            Self::TooFewFields => write!(formatter, "fewer than four fields"),
            Self::Expression(reason) => write!(formatter, "{reason}"),
            Self::SubsignatureCountDisagrees { named, given } => write!(
                formatter,
                "the logical expression names {named} subsignatures but the line gives {given}"
            ),
            Self::TooManySubsignatures => {
                write!(formatter, "more than {MOST_SUBSIGNATURES} subsignatures")
            }
            Self::AttributeWithoutValue => {
                write!(
                    formatter,
                    "an attribute of the target description has no value"
                )
            }
            Self::EngineNotFirst => write!(
                formatter,
                "Engine is not the first attribute of the target description"
            ),
            Self::AttributeNeedsEngine => write!(
                formatter,
                "an attribute other than Target needs an Engine range from {LOWEST_ENGINE_FOR_CONDITIONS}"
            ),
            Self::MalformedAttribute => {
                write!(
                    formatter,
                    "an attribute of the target description is malformed"
                )
            }
            Self::NoTarget => write!(formatter, "the target description has no Target"),
            Self::IconGroupOnTarget { target } => {
                write!(
                    formatter,
                    "an icon group is not allowed for target {target}"
                )
            }
            Self::ExecutableAttributeOnTarget { target } => write!(
                formatter,
                "an entry point or section count is not allowed for target {target}"
            ),
            Self::EmptyName => write!(formatter, "the signature name is empty"),
            Self::NameNotText => write!(formatter, "the signature name is not UTF-8 text"),
            Self::Subsignature { index, reason } => {
                write!(formatter, "subsignature {index}: ")?;
                match reason {
                    MalformedSubsignature::Offset(reason) => write!(formatter, "{reason}"),
                    MalformedSubsignature::Body(reason) => write!(formatter, "{reason}"),
                    MalformedSubsignature::UnknownModifier(letter) => write!(
                        formatter,
                        "the modifier {:?} is not one of i, f, w, a",
                        char::from(*letter)
                    ),
                    MalformedSubsignature::RegularExpression(reason) => {
                        write!(formatter, "{reason}")
                    }
                    MalformedSubsignature::ByteComparison(reason) => write!(formatter, "{reason}"),
                    MalformedSubsignature::ImageFuzzyHash => formatter.write_str(
                        "an image fuzzy hash is not 16 hexadecimal digits with distance 0",
                    ),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubsignatureNotYetCompiled {
    Macro,
    ClassAtAnInnerPartEdge,
    RegularExpression(UnsupportedConstruct),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadedContent {
    pub target: u32,
    pub longest_part: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalLine<'a> {
    pub target: u32,
    pub name: &'a str,
    pub indicator: Indicator,
    pub expression: Expression,
    pub subsignatures: Vec<Subsignature>,
    pub conditions: LogicalConditions,
    pub longest_part: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadLogicalLine<'a> {
    Comment,
    Ignored,
    OutsideFunctionalityLevel,
    TargetNotLoaded,
    NotLoaded,
    NotYetCompiled {
        reason: SubsignatureNotYetCompiled,
        loaded: LoadedContent,
    },
    Signature(LogicalLine<'a>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SubsignatureCount {
    AsTheExpressionNames,
    AtLeastTheExpressionNames,
}

pub fn read_line<'a>(
    line_without_ending: &'a [u8],
    ignored: &IgnoreList,
) -> Result<ReadLogicalLine<'a>, MalformedLogicalLine> {
    read_logical_line(
        line_without_ending,
        ignored,
        SubsignatureCount::AsTheExpressionNames,
    )
}

pub fn read_program_trigger<'a>(
    line_without_ending: &'a [u8],
    ignored: &IgnoreList,
) -> Result<ReadLogicalLine<'a>, MalformedLogicalLine> {
    read_logical_line(
        line_without_ending,
        ignored,
        SubsignatureCount::AtLeastTheExpressionNames,
    )
}

fn read_logical_line<'a>(
    line_without_ending: &'a [u8],
    ignored: &IgnoreList,
    counting: SubsignatureCount,
) -> Result<ReadLogicalLine<'a>, MalformedLogicalLine> {
    if line_without_ending.len() > LONGEST_LINE {
        return Err(MalformedLogicalLine::TooLong);
    }
    if line_without_ending.first() == Some(&COMMENT_MARK) {
        return Ok(ReadLogicalLine::Comment);
    }
    let fields = fields_of(line_without_ending);
    let [
        name_field,
        description_field,
        expression_field,
        subsignature_fields @ ..,
    ] = fields.as_slice()
    else {
        return Err(MalformedLogicalLine::TooFewFields);
    };
    if fields.len() < FEWEST_FIELDS {
        return Err(MalformedLogicalLine::TooFewFields);
    }
    if ignored.ignores(name_field, line_without_ending) {
        return Ok(ReadLogicalLine::Ignored);
    }
    let parsed = parse_expression(expression_field).map_err(MalformedLogicalLine::Expression)?;
    let named = usize::try_from(parsed.highest_index)
        .unwrap_or(usize::MAX)
        .saturating_add(1);
    let disagrees = match counting {
        SubsignatureCount::AsTheExpressionNames => named != subsignature_fields.len(),
        SubsignatureCount::AtLeastTheExpressionNames => named > subsignature_fields.len(),
    };
    if disagrees {
        return Err(MalformedLogicalLine::SubsignatureCountDisagrees {
            named,
            given: subsignature_fields.len(),
        });
    }
    if subsignature_fields.len() > MOST_SUBSIGNATURES {
        return Err(MalformedLogicalLine::TooManySubsignatures);
    }
    let Some(description) = read_description(description_field)? else {
        return Ok(ReadLogicalLine::NotLoaded);
    };
    if let Some(engine) = description.engine
        && !engine.holds(u64::try_from(FUNCTIONALITY_LEVEL).unwrap_or(0))
    {
        return Ok(ReadLogicalLine::OutsideFunctionalityLevel);
    }
    let target = description.target.ok_or(MalformedLogicalLine::NoTarget)?;
    if target >= TARGET_COUNT {
        return Ok(ReadLogicalLine::TargetNotLoaded);
    }
    if !description.conditions.icon_groups.is_empty() && target != PORTABLE_EXECUTABLE_TARGET {
        return Err(MalformedLogicalLine::IconGroupOnTarget { target });
    }
    if (description.conditions.entry_point.is_some()
        || description.conditions.number_of_sections.is_some())
        && !EXECUTABLE_TARGETS.contains(&target)
    {
        return Err(MalformedLogicalLine::ExecutableAttributeOnTarget { target });
    }
    let name = without_trailer(name_field);
    if name.is_empty() {
        return Err(MalformedLogicalLine::EmptyName);
    }
    let name = std::str::from_utf8(name).map_err(|_| MalformedLogicalLine::NameNotText)?;
    let read = read_subsignatures(subsignature_fields, target)?;
    let loaded = LoadedContent {
        target,
        longest_part: read.longest_part,
    };
    if let Some(reason) = read.not_yet_compiled {
        return Ok(ReadLogicalLine::NotYetCompiled { reason, loaded });
    }
    let (subsignatures, longest_part) = (read.subsignatures, read.longest_part);
    Ok(ReadLogicalLine::Signature(LogicalLine {
        target,
        name,
        indicator: indicator_named(name),
        expression: parsed.expression,
        subsignatures,
        conditions: description.conditions,
        longest_part,
    }))
}

#[derive(Default)]
struct ReadSubsignatures {
    subsignatures: Vec<Subsignature>,
    not_yet_compiled: Option<SubsignatureNotYetCompiled>,
    longest_part: u32,
}

fn read_subsignatures(
    fields: &[&[u8]],
    target: u32,
) -> Result<ReadSubsignatures, MalformedLogicalLine> {
    let mut read = ReadSubsignatures::default();
    for (index, field) in fields.iter().enumerate() {
        match read_subsignature(field, index, target)
            .map_err(|reason| MalformedLogicalLine::Subsignature { index, reason })?
        {
            ReadSubsignature::Compiled {
                subsignature,
                longest_part,
            } => {
                read.longest_part = read.longest_part.max(longest_part);
                read.subsignatures.push(subsignature);
            }
            ReadSubsignature::NotYetCompiled {
                reason,
                longest_part,
            } => {
                read.longest_part = read.longest_part.max(longest_part);
                read.not_yet_compiled = read.not_yet_compiled.or(Some(reason));
            }
        }
    }
    Ok(read)
}

fn fields_of(line: &[u8]) -> Vec<&[u8]> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut in_expression = false;
    for (position, byte) in line.iter().enumerate() {
        if fields.len() >= FIRST_FIELD_AWARE_OF_EXPRESSIONS
            && *byte == REGULAR_EXPRESSION_MARK
            && position
                .checked_sub(1)
                .and_then(|before| line.get(before))
                .is_none_or(|before| *before != ESCAPE)
        {
            in_expression = !in_expression;
        }
        if *byte == FIELD_SEPARATOR && !in_expression {
            fields.push(line.get(start..position).unwrap_or_default());
            start = position.saturating_add(1);
            if fields.len() == MOST_FIELDS {
                return fields;
            }
        }
    }
    fields.push(line.get(start..).unwrap_or_default());
    fields
}

struct Description {
    target: Option<u32>,
    engine: Option<InclusiveRange>,
    conditions: LogicalConditions,
}

enum Attribute {
    Target,
    Engine,
    FileSize,
    EntryPoint,
    NumberOfSections,
    Container,
    HandlerType,
    Intermediates,
    IconGroup1,
    IconGroup2,
}

const ATTRIBUTES: [(&[u8], Attribute); 10] = [
    (b"Target", Attribute::Target),
    (b"Engine", Attribute::Engine),
    (b"FileSize", Attribute::FileSize),
    (b"EntryPoint", Attribute::EntryPoint),
    (b"NumberOfSections", Attribute::NumberOfSections),
    (b"Container", Attribute::Container),
    (b"HandlerType", Attribute::HandlerType),
    (b"Intermediates", Attribute::Intermediates),
    (b"IconGroup1", Attribute::IconGroup1),
    (b"IconGroup2", Attribute::IconGroup2),
];

fn read_description(field: &[u8]) -> Result<Option<Description>, MalformedLogicalLine> {
    let mut description = Description {
        target: None,
        engine: None,
        conditions: LogicalConditions::default(),
    };
    let mut icon_groups: [Option<String>; 2] = [None, None];
    for (position, attribute) in field
        .split(|byte| *byte == DESCRIPTION_SEPARATOR)
        .take(MOST_ATTRIBUTES)
        .enumerate()
    {
        let at = attribute
            .iter()
            .position(|byte| *byte == KEY_SEPARATOR)
            .ok_or(MalformedLogicalLine::AttributeWithoutValue)?;
        let key = attribute.get(..at).unwrap_or_default();
        let value = attribute.get(at.saturating_add(1)..).unwrap_or_default();
        let Some((_, kind)) = ATTRIBUTES.iter().find(|(known, _)| *known == key) else {
            return Ok(None);
        };
        match kind {
            Attribute::Engine if position != 0 => return Err(MalformedLogicalLine::EngineNotFirst),
            Attribute::Target | Attribute::Engine => {}
            _ => {
                if description
                    .engine
                    .is_none_or(|engine| engine.lowest < LOWEST_ENGINE_FOR_CONDITIONS)
                {
                    return Err(MalformedLogicalLine::AttributeNeedsEngine);
                }
            }
        }
        let conditions = &mut description.conditions;
        match kind {
            Attribute::Target => description.target = Some(read_number(value)?),
            Attribute::Engine => description.engine = Some(read_range(value)?),
            Attribute::FileSize => conditions.file_size = Some(read_range(value)?),
            Attribute::EntryPoint => conditions.entry_point = Some(read_range(value)?),
            Attribute::NumberOfSections => conditions.number_of_sections = Some(read_range(value)?),
            Attribute::Container => {
                let Some(kind) = kind_condition(value) else {
                    return Ok(None);
                };
                conditions.container = Some(kind);
            }
            Attribute::HandlerType => {
                let Some(kind) = kind_condition(value) else {
                    return Ok(None);
                };
                conditions.handler_type = Some(match kind {
                    KindCondition::AnyKind => ObjectKind::Untyped,
                    KindCondition::Kind(kind) => kind,
                });
            }
            Attribute::Intermediates => {
                let mut kinds = Vec::new();
                for name in value
                    .split(|byte| *byte == INTERMEDIATES_SEPARATOR)
                    .take(MOST_INTERMEDIATES)
                {
                    let Some(kind) = kind_condition(name) else {
                        return Ok(None);
                    };
                    kinds.push(kind);
                }
                conditions.intermediates = kinds;
            }
            Attribute::IconGroup1 | Attribute::IconGroup2 => {
                let slot = usize::from(matches!(kind, Attribute::IconGroup2));
                let text = String::from_utf8_lossy(value).into_owned();
                if let Some(group) = icon_groups.get_mut(slot) {
                    *group = Some(text);
                }
            }
        }
    }
    description.conditions.icon_groups = icon_groups.into_iter().flatten().collect();
    Ok(Some(description))
}

fn kind_condition(name: &[u8]) -> Option<KindCondition> {
    match type_named(std::str::from_utf8(name).ok()?)? {
        NamedType::AnyType => Some(KindCondition::AnyKind),
        NamedType::Kind(kind) => Some(KindCondition::Kind(kind)),
    }
}

fn atoi_as_unsigned(digits: &[u8]) -> u32 {
    let value = digits.iter().fold(0u64, |value, digit| {
        value
            .saturating_mul(10)
            .saturating_add(u64::from(digit.saturating_sub(b'0')))
            .min(u64::try_from(i64::MAX).unwrap_or(u64::MAX))
    });
    u32::try_from(value & u64::from(u32::MAX)).unwrap_or(u32::MAX)
}

fn read_number(value: &[u8]) -> Result<u32, MalformedLogicalLine> {
    if !value.iter().all(u8::is_ascii_digit) {
        return Err(MalformedLogicalLine::MalformedAttribute);
    }
    Ok(atoi_as_unsigned(value))
}

fn read_range(value: &[u8]) -> Result<InclusiveRange, MalformedLogicalLine> {
    let at = value
        .iter()
        .position(|byte| *byte == RANGE_SEPARATOR)
        .ok_or(MalformedLogicalLine::MalformedAttribute)?;
    Ok(InclusiveRange {
        lowest: read_number(value.get(..at).unwrap_or_default())?,
        highest: read_number(value.get(at.saturating_add(1)..).unwrap_or_default())?,
    })
}

enum ReadSubsignature {
    Compiled {
        subsignature: Subsignature,
        longest_part: u32,
    },
    NotYetCompiled {
        reason: SubsignatureNotYetCompiled,
        longest_part: u32,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Widths {
    #[default]
    Narrow,
    Wide,
    WideAndNarrow,
}

#[derive(Debug, Clone, Copy, Default)]
struct Modifiers {
    case_insensitive: bool,
    whole_word: bool,
    widths: Widths,
}

enum SubsignatureKind {
    Macro,
    RegularExpression,
    ByteComparison,
    ImageFuzzyHash,
    Content,
}

fn kind_of_subsignature(field: &[u8]) -> SubsignatureKind {
    if field.first() == Some(&MACRO_MARK) {
        return SubsignatureKind::Macro;
    }
    if field.contains(&REGULAR_EXPRESSION_MARK) {
        return SubsignatureKind::RegularExpression;
    }
    let (opening, hash) = BYTE_COMPARISON_MARKS;
    let first_hash = field.iter().position(|byte| *byte == hash);
    let last_hash = field.iter().rposition(|byte| *byte == hash);
    if field.contains(&opening) && first_hash.is_some() && first_hash != last_hash {
        return SubsignatureKind::ByteComparison;
    }
    if field.starts_with(IMAGE_FUZZY_HASH_PREFIX) {
        return SubsignatureKind::ImageFuzzyHash;
    }
    SubsignatureKind::Content
}

fn compiled(subsignature: Subsignature) -> ReadSubsignature {
    ReadSubsignature::Compiled {
        subsignature,
        longest_part: 0,
    }
}

fn read_subsignature(
    field: &[u8],
    index: usize,
    target: u32,
) -> Result<ReadSubsignature, MalformedSubsignature> {
    match kind_of_subsignature(field) {
        SubsignatureKind::Macro => {
            return Ok(ReadSubsignature::NotYetCompiled {
                reason: SubsignatureNotYetCompiled::Macro,
                longest_part: 0,
            });
        }
        SubsignatureKind::RegularExpression => {
            return match read_regular_expression(field, index, target)
                .map_err(MalformedSubsignature::RegularExpression)?
            {
                ReadRegularExpression::Compiled(expression) => {
                    Ok(compiled(Subsignature::RegularExpression(expression)))
                }
                ReadRegularExpression::Unsupported(construct) => {
                    Ok(ReadSubsignature::NotYetCompiled {
                        reason: SubsignatureNotYetCompiled::RegularExpression(construct),
                        longest_part: 0,
                    })
                }
            };
        }
        SubsignatureKind::ByteComparison => {
            return read_byte_comparison(field)
                .map(|comparison| compiled(Subsignature::ByteComparison(comparison)))
                .map_err(MalformedSubsignature::ByteComparison);
        }
        SubsignatureKind::ImageFuzzyHash => {
            return read_image_fuzzy_hash(field)
                .map(|hash| compiled(Subsignature::ImageFuzzyHash(hash)));
        }
        SubsignatureKind::Content => {}
    }
    read_content_subsignature(field, target)
}

fn read_image_fuzzy_hash(field: &[u8]) -> Result<u64, MalformedSubsignature> {
    let mut fields = field
        .split(|byte| *byte == IMAGE_FUZZY_HASH_SEPARATOR)
        .skip(1);
    let digits = fields
        .next()
        .filter(|digits| digits.len() == IMAGE_FUZZY_HASH_DIGITS)
        .ok_or(MalformedSubsignature::ImageFuzzyHash)?;
    let hash = digits
        .iter()
        .try_fold(0u64, |hash, digit| {
            Some(hash.checked_shl(4)? | u64::from(char::from(*digit).to_digit(16)?))
        })
        .ok_or(MalformedSubsignature::ImageFuzzyHash)?;
    if let Some(distance) = fields.next() {
        let distance = std::str::from_utf8(distance)
            .ok()
            .and_then(|text| text.parse::<u32>().ok())
            .ok_or(MalformedSubsignature::ImageFuzzyHash)?;
        if distance != 0 {
            return Err(MalformedSubsignature::ImageFuzzyHash);
        }
    }
    Ok(hash)
}

fn read_content_subsignature(
    field: &[u8],
    target: u32,
) -> Result<ReadSubsignature, MalformedSubsignature> {
    let mut parts: Vec<&[u8]> = Vec::new();
    let mut rest = field;
    while parts.len().saturating_add(1) < MOST_SUBSIGNATURE_FIELDS {
        match rest
            .iter()
            .position(|byte| *byte == SUBSIGNATURE_FIELD_SEPARATOR)
        {
            Some(at) => {
                parts.push(rest.get(..at).unwrap_or_default());
                rest = rest.get(at.saturating_add(1)..).unwrap_or_default();
            }
            None => break,
        }
    }
    let last = rest
        .iter()
        .position(|byte| *byte == SUBSIGNATURE_FIELD_SEPARATOR)
        .map_or(rest, |at| rest.get(..at).unwrap_or_default());
    parts.push(last);
    let (offset, body, modifier_letters): (Option<&[u8]>, &[u8], &[u8]) = match parts.as_slice() {
        [offset, body] => (Some(offset), body, b""),
        [body, _, modifiers] => (None, body, modifiers),
        [offset, body, _, modifiers] => (Some(offset), body, modifiers),
        [body, ..] => (None, body, b""),
        [] => (None, b"", b""),
    };
    let modifiers = read_modifiers(modifier_letters)?;
    let placement = match offset {
        None => Placement::Anywhere,
        Some(offset) => match read_offset(offset, target).map_err(MalformedSubsignature::Offset)? {
            Offset::Placed(placement) => placement,
            Offset::MacroGroup => {
                return Ok(ReadSubsignature::NotYetCompiled {
                    reason: SubsignatureNotYetCompiled::Macro,
                    longest_part: 0,
                });
            }
        },
    };
    let text = if modifiers.whole_word {
        whole_word(body)
    } else {
        body.to_vec()
    };
    let mut forms: Vec<(Vec<u8>, ByteWidth)> = Vec::new();
    if modifiers.widths != Widths::Narrow {
        forms.push((widened(&text), ByteWidth::Wide));
    }
    if modifiers.widths != Widths::Wide {
        forms.push((text.clone(), ByteWidth::Narrow));
    }
    let mut longest_part: u32 = 0;
    let mut patterns = Vec::with_capacity(forms.len());
    let mut unsupported = None;
    for (form, width) in &forms {
        let counted = match width {
            ByteWidth::Narrow => text.clone(),
            ByteWidth::Wide => brackets_as_gaps(&text),
        };
        longest_part = longest_part
            .max(longest_part_of_body(&counted, *width).map_err(MalformedSubsignature::Body)?);
        match read_subsignature_body(form, target).map_err(MalformedSubsignature::Body)? {
            ReadBody::Pattern { pattern, .. } => {
                let pattern = if modifiers.case_insensitive {
                    case_folded(pattern)
                } else {
                    pattern
                };
                let pattern = if modifiers.whole_word && *width == ByteWidth::Wide {
                    with_wide_word_edges(pattern)
                } else {
                    pattern
                };
                patterns.push(pattern);
            }
            ReadBody::Unsupported { .. } => {
                unsupported = Some(SubsignatureNotYetCompiled::ClassAtAnInnerPartEdge);
            }
        }
    }
    if let Some(reason) = unsupported {
        return Ok(ReadSubsignature::NotYetCompiled {
            reason,
            longest_part,
        });
    }
    Ok(ReadSubsignature::Compiled {
        subsignature: Subsignature::Content(ContentSubsignature {
            placement,
            patterns,
        }),
        longest_part,
    })
}

fn read_modifiers(letters: &[u8]) -> Result<Modifiers, MalformedSubsignature> {
    let mut modifiers = Modifiers::default();
    let mut wide = false;
    let mut also_narrow = false;
    for letter in letters {
        match letter {
            b'i' => modifiers.case_insensitive = true,
            b'f' => modifiers.whole_word = true,
            b'w' => wide = true,
            b'a' => also_narrow = true,
            other => return Err(MalformedSubsignature::UnknownModifier(*other)),
        }
    }
    modifiers.widths = match (wide, also_narrow) {
        (false, _) => Widths::Narrow,
        (true, false) => Widths::Wide,
        (true, true) => Widths::WideAndNarrow,
    };
    Ok(modifiers)
}

fn brackets_as_gaps(body: &[u8]) -> Vec<u8> {
    body.iter()
        .map(|byte| match byte {
            b'[' => b'{',
            b']' => b'}',
            other => *other,
        })
        .collect()
}

fn whole_word(body: &[u8]) -> Vec<u8> {
    let mut text = WORD_BOUNDARY.to_vec();
    text.extend(brackets_as_gaps(body));
    text.extend_from_slice(WORD_BOUNDARY);
    text
}

fn widened(text: &[u8]) -> Vec<u8> {
    let mut wide = Vec::with_capacity(text.len().saturating_mul(2));
    let mut at = 0usize;
    while let Some(byte) = text.get(at) {
        let next = at.saturating_add(1);
        match byte {
            b'(' if matches!(
                text.get(next..next.saturating_add(2)),
                Some(b"B)" | b"L)" | b"W)")
            ) =>
            {
                wide.extend_from_slice(text.get(at..at.saturating_add(3)).unwrap_or_default());
                at = at.saturating_add(3);
            }
            b'{' | b'[' => {
                let closing = if *byte == b'{' { b'}' } else { b']' };
                let end = text
                    .get(at..)
                    .and_then(|rest| rest.iter().position(|byte| *byte == closing))
                    .map_or(text.len(), |close| {
                        at.saturating_add(close).saturating_add(1)
                    });
                wide.extend(brackets_as_gaps(text.get(at..end).unwrap_or_default()));
                at = end;
            }
            b'*' | b'|' | b'(' | b')' | b'!' => {
                wide.push(*byte);
                at = next;
            }
            _ => {
                let pair = text.get(at..at.saturating_add(2)).unwrap_or_default();
                wide.extend_from_slice(pair);
                if pair.len() == 2 {
                    wide.extend_from_slice(WIDE_PADDING);
                }
                at = at.saturating_add(2);
            }
        }
    }
    wide
}

fn folded_byte(byte: MaskedByte) -> MaskedByte {
    if byte.is_exact() && byte.value.is_ascii_alphabetic() {
        MaskedByte {
            value: byte.value & !CASE_BIT,
            mask: !CASE_BIT,
        }
    } else {
        byte
    }
}

fn folded_strings(strings: Vec<Vec<MaskedByte>>) -> Vec<Vec<MaskedByte>> {
    strings
        .into_iter()
        .map(|string| string.into_iter().map(folded_byte).collect())
        .collect()
}

fn case_folded(pattern: Pattern) -> Pattern {
    let elements = pattern
        .elements
        .into_iter()
        .map(|element| match element {
            PatternElement::Byte(byte) => PatternElement::Byte(folded_byte(byte)),
            PatternElement::OneOf(set) => {
                PatternElement::OneOf(ByteSet::of((0..=u8::MAX).filter(|byte| {
                    set.contains(*byte)
                        || (byte.is_ascii_alphabetic() && set.contains(*byte ^ CASE_BIT))
                })))
            }
            PatternElement::Choice(strings) => PatternElement::Choice(folded_strings(strings)),
            PatternElement::NoneOf { width, excluded } => PatternElement::NoneOf {
                width,
                excluded: folded_strings(excluded),
            },
            other => other,
        })
        .collect();
    Pattern {
        before: pattern.before,
        elements,
        after: pattern.after,
    }
}

fn wide_word_edge() -> ContextTest {
    ContextTest {
        sequences: vec![vec![
            ByteSet::of((0..=u8::MAX).filter(u8::is_ascii_alphanumeric)),
            ByteSet::of([0]),
        ]],
        negated: true,
        satisfied_at_object_edge: true,
    }
}

fn with_wide_word_edges(pattern: Pattern) -> Pattern {
    Pattern {
        before: Some(wide_word_edge()),
        elements: pattern.elements,
        after: Some(wide_word_edge()),
    }
}
