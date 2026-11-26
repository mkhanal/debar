use std::fmt;

use regex_syntax::hir::{Hir, Look, Repetition};

use crate::regular_expression_classes::{
    ByteClass, any_byte, class_hir, folded_literal, posix_class_named,
};

const CASELESS_PREFIX: &[u8] = b"(?i)";
const LARGEST_BOUND: u32 = 255;
const DEEPEST_NESTING: usize = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedPosixExpression {
    UnmatchedParenthesis,
    EmptySubexpression,
    NothingToRepeat,
    MalformedBound,
    UnterminatedBracket,
    RangeOutOfOrder,
    UnknownClass,
    TrailingBackslash,
    TooDeep,
}

impl fmt::Display for MalformedPosixExpression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnmatchedParenthesis => "a parenthesis does not match",
            Self::EmptySubexpression => "a subexpression is empty",
            Self::NothingToRepeat => "a repetition follows nothing",
            Self::MalformedBound => "a repetition bound is malformed",
            Self::UnterminatedBracket => "a bracket expression is not closed",
            Self::RangeOutOfOrder => "a bracket range is out of order",
            Self::UnknownClass => "a character class name is unknown",
            Self::TrailingBackslash => "the expression ends in a backslash",
            Self::TooDeep => "parentheses nest too deep",
        })
    }
}

pub fn translate_posix(text: &[u8]) -> Result<Hir, MalformedPosixExpression> {
    let (caseless, text) = match text.strip_prefix(CASELESS_PREFIX) {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let mut parser = Parser {
        text,
        at: 0,
        caseless,
    };
    let hir = parser.alternation(0)?;
    if parser.at < text.len() {
        return Err(MalformedPosixExpression::UnmatchedParenthesis);
    }
    Ok(hir)
}

struct Parser<'t> {
    text: &'t [u8],
    at: usize,
    caseless: bool,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.at = self.at.saturating_add(1);
        Some(byte)
    }

    fn alternation(&mut self, depth: usize) -> Result<Hir, MalformedPosixExpression> {
        let mut branches = vec![self.concatenation(depth)?];
        while self.peek() == Some(b'|') {
            self.at = self.at.saturating_add(1);
            branches.push(self.concatenation(depth)?);
        }
        Ok(Hir::alternation(branches))
    }

    fn concatenation(&mut self, depth: usize) -> Result<Hir, MalformedPosixExpression> {
        let mut items = Vec::new();
        while let Some(byte) = self.peek() {
            if matches!(byte, b'|' | b')') {
                break;
            }
            let atom = self.atom(depth)?;
            items.push(self.repetitions(atom)?);
        }
        if items.is_empty() {
            return Err(MalformedPosixExpression::EmptySubexpression);
        }
        Ok(Hir::concat(items))
    }

    fn atom(&mut self, depth: usize) -> Result<Hir, MalformedPosixExpression> {
        let Some(byte) = self.next() else {
            return Err(MalformedPosixExpression::EmptySubexpression);
        };
        match byte {
            b'(' => {
                let depth = depth.saturating_add(1);
                if depth > DEEPEST_NESTING {
                    return Err(MalformedPosixExpression::TooDeep);
                }
                let inner = self.alternation(depth)?;
                if self.next() != Some(b')') {
                    return Err(MalformedPosixExpression::UnmatchedParenthesis);
                }
                Ok(inner)
            }
            b'[' => self.bracket(),
            b'.' => Ok(any_byte()),
            b'^' => Ok(Hir::look(Look::Start)),
            b'$' => Ok(Hir::look(Look::End)),
            b'*' | b'+' | b'?' => Err(MalformedPosixExpression::NothingToRepeat),
            b'{' if self.peek().is_some_and(|byte| byte.is_ascii_digit()) => {
                Err(MalformedPosixExpression::NothingToRepeat)
            }
            b'\\' => {
                let escaped = self
                    .next()
                    .ok_or(MalformedPosixExpression::TrailingBackslash)?;
                Ok(folded_literal(escaped, self.caseless))
            }
            literal => Ok(folded_literal(literal, self.caseless)),
        }
    }

    fn repetitions(&mut self, mut item: Hir) -> Result<Hir, MalformedPosixExpression> {
        loop {
            let (min, max) = match self.peek() {
                Some(b'*') => (0, None),
                Some(b'+') => (1, None),
                Some(b'?') => (0, Some(1)),
                Some(b'{')
                    if self
                        .text
                        .get(self.at.saturating_add(1))
                        .is_some_and(u8::is_ascii_digit) =>
                {
                    self.at = self.at.saturating_add(1);
                    let bounds = self.bound()?;
                    item = repeated(item, bounds.0, bounds.1);
                    continue;
                }
                _ => return Ok(item),
            };
            self.at = self.at.saturating_add(1);
            item = repeated(item, min, max);
        }
    }

    fn number(&mut self) -> Result<u32, MalformedPosixExpression> {
        let mut value: u32 = 0;
        let mut digits = 0usize;
        while let Some(digit) = self.peek().filter(u8::is_ascii_digit) {
            value = value
                .saturating_mul(10)
                .saturating_add(u32::from(digit.saturating_sub(b'0')));
            digits = digits.saturating_add(1);
            self.at = self.at.saturating_add(1);
        }
        if digits == 0 || value > LARGEST_BOUND {
            return Err(MalformedPosixExpression::MalformedBound);
        }
        Ok(value)
    }

    fn bound(&mut self) -> Result<(u32, Option<u32>), MalformedPosixExpression> {
        let min = self.number()?;
        let max = if self.peek() == Some(b',') {
            self.at = self.at.saturating_add(1);
            if self.peek() == Some(b'}') {
                None
            } else {
                Some(self.number()?)
            }
        } else {
            Some(min)
        };
        if self.next() != Some(b'}') || max.is_some_and(|max| max < min) {
            return Err(MalformedPosixExpression::MalformedBound);
        }
        Ok((min, max))
    }

    fn bracket(&mut self) -> Result<Hir, MalformedPosixExpression> {
        let negated = self.peek() == Some(b'^');
        if negated {
            self.at = self.at.saturating_add(1);
        }
        let mut class = ByteClass::default();
        let mut first = true;
        loop {
            let byte = self
                .next()
                .ok_or(MalformedPosixExpression::UnterminatedBracket)?;
            if byte == b']' && !first {
                break;
            }
            first = false;
            let low = if byte == b'[' && matches!(self.peek(), Some(b':' | b'=' | b'.')) {
                match self.bracket_term()? {
                    BracketTerm::Class(set) => {
                        class.insert_all(&set);
                        continue;
                    }
                    BracketTerm::Byte(byte) => byte,
                }
            } else {
                byte
            };
            let range_ahead = self.peek() == Some(b'-')
                && self
                    .text
                    .get(self.at.saturating_add(1))
                    .is_some_and(|after| *after != b']');
            if range_ahead {
                self.at = self.at.saturating_add(1);
                let high = self
                    .next()
                    .ok_or(MalformedPosixExpression::UnterminatedBracket)?;
                let high = if high == b'[' && matches!(self.peek(), Some(b'=' | b'.')) {
                    match self.bracket_term()? {
                        BracketTerm::Byte(byte) => byte,
                        BracketTerm::Class(_) => {
                            return Err(MalformedPosixExpression::RangeOutOfOrder);
                        }
                    }
                } else {
                    high
                };
                if high < low {
                    return Err(MalformedPosixExpression::RangeOutOfOrder);
                }
                class.insert_range(low, high);
            } else {
                class.insert(low);
            }
        }
        if self.caseless {
            class = class.case_folded();
        }
        if negated {
            class = class.complement();
        }
        Ok(class_hir(&class))
    }

    fn bracket_term(&mut self) -> Result<BracketTerm, MalformedPosixExpression> {
        let delimiter = self
            .next()
            .ok_or(MalformedPosixExpression::UnterminatedBracket)?;
        let start = self.at;
        loop {
            match self.next() {
                None => return Err(MalformedPosixExpression::UnterminatedBracket),
                Some(byte) if byte == delimiter && self.peek() == Some(b']') => break,
                Some(_) => {}
            }
        }
        let name = self
            .text
            .get(start..self.at.saturating_sub(1))
            .unwrap_or_default();
        self.at = self.at.saturating_add(1);
        if delimiter == b':' {
            return posix_class_named(name)
                .map(BracketTerm::Class)
                .ok_or(MalformedPosixExpression::UnknownClass);
        }
        match name {
            [only] => Ok(BracketTerm::Byte(*only)),
            _ => Err(MalformedPosixExpression::UnknownClass),
        }
    }
}

enum BracketTerm {
    Class(ByteClass),
    Byte(u8),
}

fn repeated(item: Hir, min: u32, max: Option<u32>) -> Hir {
    Hir::repetition(Repetition {
        min,
        max,
        greedy: true,
        sub: Box::new(item),
    })
}
