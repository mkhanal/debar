use std::fmt;

use debar_image::{
    ExpressionAnchoring, ExpressionMatches, Placement, RegularExpressionSubsignature,
};

use crate::extended_lines::{MalformedExtendedLine, Offset, read_offset};
use crate::logical_expression::{MalformedExpression, parse_expression};
use crate::regular_expression_syntax::{
    ExpressionFlags, MalformedRegularExpression, Translation, UnsupportedConstruct, translate,
};

const DELIMITER: u8 = b'/';
const ESCAPE: u8 = b'\\';
const OFFSET_SEPARATOR: u8 = b':';
const MOST_TOKENS: usize = 5;
const UNCONDITIONAL_TRIGGER: &[u8] = b"7374756c747a676574737265676578";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalformedRegularExpressionSubsignature {
    StartsWithDelimiter,
    MismatchedDelimiter,
    EmptyTrigger,
    EmptyExpression,
    Trigger(MalformedExpression),
    TriggerNamesALaterSubsignature,
    TriggerNamesItself,
    Offset(MalformedExtendedLine),
    UnknownFlag(u8),
    Expression(MalformedRegularExpression),
}

impl fmt::Display for MalformedRegularExpressionSubsignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartsWithDelimiter => {
                formatter.write_str("a regular expression subsignature has no trigger")
            }
            Self::MismatchedDelimiter => {
                formatter.write_str("a regular expression lacks its closing '/'")
            }
            Self::EmptyTrigger => formatter.write_str("a regular expression's trigger is empty"),
            Self::EmptyExpression => formatter.write_str("a regular expression is empty"),
            Self::Trigger(reason) => write!(formatter, "the trigger: {reason}"),
            Self::TriggerNamesALaterSubsignature => {
                formatter.write_str("the trigger names a later subsignature")
            }
            Self::TriggerNamesItself => {
                formatter.write_str("the trigger names its own subsignature")
            }
            Self::Offset(reason) => write!(formatter, "{reason}"),
            Self::UnknownFlag(flag) => write!(
                formatter,
                "the regular expression flag {:?} is unknown",
                char::from(*flag)
            ),
            Self::Expression(reason) => write!(formatter, "the regular expression: {reason}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadRegularExpression {
    Compiled(RegularExpressionSubsignature),
    Unsupported(UnsupportedConstruct),
}

#[expect(clippy::struct_excessive_bools)]
#[derive(Default)]
struct Flags {
    expression: ExpressionFlags,
    anchored: bool,
    every_match: bool,
    rolling: bool,
    encompassed: bool,
}

pub fn read_regular_expression(
    field: &[u8],
    own_index: usize,
    target: u32,
) -> Result<ReadRegularExpression, MalformedRegularExpressionSubsignature> {
    if field.first() == Some(&DELIMITER) {
        return Err(MalformedRegularExpressionSubsignature::StartsWithDelimiter);
    }
    let (offset, body) = offset_and_body(field);
    let first = body.iter().position(|byte| *byte == DELIMITER);
    let last = body.iter().rposition(|byte| *byte == DELIMITER);
    let (Some(first), Some(last)) = (first, last) else {
        return Err(MalformedRegularExpressionSubsignature::MismatchedDelimiter);
    };
    if first == last {
        return Err(MalformedRegularExpressionSubsignature::MismatchedDelimiter);
    }
    let trigger_text = body.get(..first).unwrap_or_default();
    let pattern = body.get(first.saturating_add(1)..last).unwrap_or_default();
    let flag_text = body.get(last.saturating_add(1)..).unwrap_or_default();
    if trigger_text.is_empty() {
        return Err(MalformedRegularExpressionSubsignature::EmptyTrigger);
    }
    if pattern.is_empty() {
        return Err(MalformedRegularExpressionSubsignature::EmptyExpression);
    }
    let trigger = if trigger_text == UNCONDITIONAL_TRIGGER {
        None
    } else {
        let parsed = parse_expression(trigger_text)
            .map_err(MalformedRegularExpressionSubsignature::Trigger)?;
        let highest = usize::try_from(parsed.highest_index).unwrap_or(usize::MAX);
        if highest > own_index {
            return Err(MalformedRegularExpressionSubsignature::TriggerNamesALaterSubsignature);
        }
        if highest == own_index {
            return Err(MalformedRegularExpressionSubsignature::TriggerNamesItself);
        }
        Some(parsed.expression)
    };
    let placement = match offset {
        None => Placement::Anywhere,
        Some(offset) => match read_offset(offset, target)
            .map_err(MalformedRegularExpressionSubsignature::Offset)?
        {
            Offset::Placed(placement) => placement,
            Offset::MacroGroup => {
                return Err(MalformedRegularExpressionSubsignature::Offset(
                    MalformedExtendedLine::OffsetMalformed,
                ));
            }
        },
    };
    let flags = read_flags(flag_text)?;
    let expression = match translate(pattern, flags.expression)
        .map_err(MalformedRegularExpressionSubsignature::Expression)?
    {
        Translation::Compiled(expression) => expression,
        Translation::Unsupported(construct) => {
            return Ok(ReadRegularExpression::Unsupported(construct));
        }
    };
    Ok(ReadRegularExpression::Compiled(
        RegularExpressionSubsignature {
            trigger,
            placement,
            expression,
            anchoring: if flags.anchored {
                ExpressionAnchoring::AtTheSubjectStart
            } else if flags.rolling {
                ExpressionAnchoring::NeverAtThePlacement
            } else {
                ExpressionAnchoring::AtAnUnshiftedPlacement
            },
            matches: if flags.every_match {
                ExpressionMatches::EveryOneNotOverlapping
            } else {
                ExpressionMatches::First
            },
            bounded_by_shift: flags.encompassed,
        },
    ))
}

fn offset_and_body(field: &[u8]) -> (Option<&[u8]>, &[u8]) {
    let mut separators = Vec::new();
    let mut within = false;
    for (position, byte) in field.iter().enumerate() {
        if !within && *byte == OFFSET_SEPARATOR {
            separators.push(position);
            if separators.len() == MOST_TOKENS {
                break;
            }
            continue;
        }
        if *byte == DELIMITER
            && position
                .checked_sub(1)
                .and_then(|before| field.get(before))
                .is_some_and(|before| *before != ESCAPE)
        {
            within = !within;
        }
    }
    match separators.as_slice() {
        [only] => (
            Some(field.get(..*only).unwrap_or_default()),
            field.get(only.saturating_add(1)..).unwrap_or_default(),
        ),
        [] => (None, field),
        [first, ..] => (None, field.get(..*first).unwrap_or_default()),
    }
}

fn read_flags(text: &[u8]) -> Result<Flags, MalformedRegularExpressionSubsignature> {
    let mut flags = Flags::default();
    for flag in text {
        match flag {
            b'i' => flags.expression.caseless = true,
            b's' => flags.expression.dot_all = true,
            b'm' => flags.expression.multiline = true,
            b'x' => flags.expression.extended = true,
            b'U' => flags.expression.ungreedy = true,
            b'E' => flags.expression.dollar_end_only = true,
            b'A' => flags.anchored = true,
            b'g' => flags.every_match = true,
            b'r' => flags.rolling = true,
            b'e' => flags.encompassed = true,
            other => return Err(MalformedRegularExpressionSubsignature::UnknownFlag(*other)),
        }
    }
    Ok(flags)
}
