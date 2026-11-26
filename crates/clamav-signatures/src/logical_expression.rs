use std::fmt;

use debar_image::{CountComparison, CountTest, Expression};

const DEEPEST_NESTING: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalformedExpression {
    Empty,
    UnbalancedParentheses,
    MissingOperand,
    NotASubsignatureIndex,
    ModifierWithoutNumber,
    ModifierOnAGroupWithoutOperator,
    TooDeep,
}

impl fmt::Display for MalformedExpression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::Empty => "the logical expression is empty",
            Self::UnbalancedParentheses => "the logical expression's parentheses do not balance",
            Self::MissingOperand => "an operator in the logical expression lacks an operand",
            Self::NotASubsignatureIndex => {
                "the logical expression names something that is not a subsignature index"
            }
            Self::ModifierWithoutNumber => {
                "a count modifier in the logical expression has no number"
            }
            Self::ModifierOnAGroupWithoutOperator => {
                "a count modifier follows parentheses that hold no operator"
            }
            Self::TooDeep => "the logical expression nests more than 256 deep",
        };
        formatter.write_str(reason)
    }
}

pub struct ParsedExpression {
    pub expression: Expression,
    pub highest_index: u32,
}

pub fn parse_expression(text: &[u8]) -> Result<ParsedExpression, MalformedExpression> {
    let compact: Vec<u8> = text
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if compact.is_empty() {
        return Err(MalformedExpression::Empty);
    }
    let mut highest_index = 0;
    let expression = expression(&compact, 0, &mut highest_index)?;
    Ok(ParsedExpression {
        expression,
        highest_index,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OperatorChoice {
    First,
    Last,
}

fn expression(
    text: &[u8],
    depth: usize,
    highest_index: &mut u32,
) -> Result<Expression, MalformedExpression> {
    if depth > DEEPEST_NESTING {
        return Err(MalformedExpression::TooDeep);
    }
    let deeper = depth.saturating_add(1);
    if let Some(at) = top_level_operator(text, OperatorChoice::First) {
        return joined(text, at, deeper, highest_index);
    }
    if text.first() == Some(&b'(') {
        let closing = matching_parenthesis(text)?;
        let inner = text
            .get(1..closing)
            .ok_or(MalformedExpression::UnbalancedParentheses)?;
        let rest = text.get(closing.saturating_add(1)..).unwrap_or_default();
        if rest.is_empty() {
            return group(inner, deeper, highest_index);
        }
        if top_level_operator(inner, OperatorChoice::Last).is_none() {
            return Err(MalformedExpression::ModifierOnAGroupWithoutOperator);
        }
        let inner = group(inner, deeper, highest_index)?;
        return Ok(Expression::Block {
            inner: Box::new(inner),
            count: count_test(rest)?,
        });
    }
    leaf(text, highest_index)
}

fn group(
    inner: &[u8],
    depth: usize,
    highest_index: &mut u32,
) -> Result<Expression, MalformedExpression> {
    match top_level_operator(inner, OperatorChoice::Last) {
        Some(at) => joined(inner, at, depth, highest_index),
        None => expression(inner, depth, highest_index),
    }
}

fn joined(
    text: &[u8],
    at: usize,
    depth: usize,
    highest_index: &mut u32,
) -> Result<Expression, MalformedExpression> {
    let left_text = text.get(..at).unwrap_or_default();
    let right_text = text.get(at.saturating_add(1)..).unwrap_or_default();
    if left_text.is_empty() || right_text.is_empty() {
        return Err(MalformedExpression::MissingOperand);
    }
    let left = Box::new(expression(left_text, depth, highest_index)?);
    let right = Box::new(expression(right_text, depth, highest_index)?);
    Ok(match text.get(at) {
        Some(b'&') => Expression::All(left, right),
        _ => Expression::Any(left, right),
    })
}

fn leading_number(text: &[u8]) -> Option<u32> {
    let unsigned = text.strip_prefix(b"+").unwrap_or(text);
    let digits = unsigned
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    (digits > 0).then(|| decimal(unsigned.get(..digits).unwrap_or_default()))
}

fn leaf(text: &[u8], highest_index: &mut u32) -> Result<Expression, MalformedExpression> {
    let index = leading_number(text).ok_or(MalformedExpression::NotASubsignatureIndex)?;
    let count = match text
        .iter()
        .rposition(|byte| matches!(byte, b'<' | b'>' | b'='))
    {
        None => None,
        Some(at) => {
            let threshold = leading_number(text.get(at.saturating_add(1)..).unwrap_or_default())
                .ok_or(MalformedExpression::ModifierWithoutNumber)?;
            let comparison = match text.get(at) {
                Some(b'=') => CountComparison::Exactly(threshold),
                Some(b'>') => CountComparison::MoreThan(threshold),
                _ => CountComparison::FewerThan(threshold),
            };
            Some(CountTest {
                comparison,
                distinct_at_least: 0,
            })
        }
    };
    *highest_index = (*highest_index).max(index);
    Ok(Expression::Subsignature {
        index: u16::try_from(index).unwrap_or(u16::MAX),
        count,
    })
}

fn count_test(text: &[u8]) -> Result<CountTest, MalformedExpression> {
    let (symbol, numbers) = text
        .split_first()
        .ok_or(MalformedExpression::ModifierWithoutNumber)?;
    let (count, distinct) = match numbers.iter().position(|byte| *byte == b',') {
        Some(comma) => (
            numbers.get(..comma).unwrap_or_default(),
            Some(numbers.get(comma.saturating_add(1)..).unwrap_or_default()),
        ),
        None => (numbers, None),
    };
    let number = |digits: &[u8]| {
        let digits = digits.strip_prefix(b"+").unwrap_or(digits);
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return Err(MalformedExpression::ModifierWithoutNumber);
        }
        Ok(decimal(digits))
    };
    let threshold = number(count)?;
    let distinct_at_least = distinct.map(number).transpose()?.unwrap_or(0);
    let comparison = match symbol {
        b'=' => CountComparison::Exactly(threshold),
        b'>' => CountComparison::MoreThan(threshold),
        b'<' => CountComparison::FewerThan(threshold),
        _ => return Err(MalformedExpression::NotASubsignatureIndex),
    };
    Ok(CountTest {
        comparison,
        distinct_at_least,
    })
}

fn decimal(digits: &[u8]) -> u32 {
    digits.iter().fold(0u32, |value, digit| {
        value
            .saturating_mul(10)
            .saturating_add(u32::from(digit.saturating_sub(b'0')))
    })
}

fn top_level_operator(text: &[u8], choice: OperatorChoice) -> Option<usize> {
    let mut depth: usize = 0;
    let mut found = None;
    for (position, byte) in text.iter().enumerate() {
        match byte {
            b'(' => depth = depth.saturating_add(1),
            b')' => depth = depth.saturating_sub(1),
            b'&' | b'|' if depth == 0 => {
                found = Some(position);
                if choice == OperatorChoice::First {
                    return found;
                }
            }
            _ => {}
        }
    }
    found
}

fn matching_parenthesis(text: &[u8]) -> Result<usize, MalformedExpression> {
    let mut depth: usize = 0;
    for (position, byte) in text.iter().enumerate() {
        match byte {
            b'(' => depth = depth.saturating_add(1),
            b')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(MalformedExpression::UnbalancedParentheses)?;
                if depth == 0 {
                    return Ok(position);
                }
            }
            _ => {}
        }
    }
    Err(MalformedExpression::UnbalancedParentheses)
}
