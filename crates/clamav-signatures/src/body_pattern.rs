use std::fmt;

use debar_image::{ByteSet, ContextTest, MaskedByte, Pattern, PatternElement};

const BEFORE_A_WORD: &[u8] = b" -./_<@";
const AFTER_A_WORD: &[u8] = b"\n\r \"'-/=>_";
const LINE_FEED: u8 = b'\n';
const CARRIAGE_RETURN: u8 = b'\r';
const LARGEST_EXPANDED_GAP: u32 = 127;
const LARGEST_LONE_BYTE_DISTANCE: u32 = 32;
const MOST_LONE_BYTE_DISTANCES: usize = 2;
const DEEPEST_ALTERNATIVES: usize = 16;
const MOST_EXPANDED_ALTERNATIVES: usize = 4096;
const SHORTEST_PLAIN_EXTENDED_BODY: usize = 3;
const SHORTEST_PLAIN_TYPE_RECOGNITION_BODY: usize = 2;
const SHORTEST_PART: usize = 2;
const SHORTEST_FIXED_RUN: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalformedBody {
    Empty,
    UnexpectedCharacter { at: usize },
    UnfinishedByte { at: usize },
    UnclosedGroup { at: usize },
    MalformedRange { at: usize },
    EmptyPart,
    PartTooShort,
    NoFixedPairInPart,
    PlainBodyTooShort,
    MisplacedLoneByteDistance { at: usize },
    NestedTooDeep { at: usize },
    NegatedGenericAlternatives { at: usize },
    UnsupportedInsideAlternatives { at: usize },
    TooManyAlternatives { at: usize },
}

impl fmt::Display for MalformedBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(formatter, "the body is empty"),
            Self::UnexpectedCharacter { at } => {
                write!(formatter, "the body has an unexpected character at {at}")
            }
            Self::UnfinishedByte { at } => write!(formatter, "the body ends inside a byte at {at}"),
            Self::UnclosedGroup { at } => {
                write!(formatter, "the group opened at {at} is not closed")
            }
            Self::MalformedRange { at } => write!(formatter, "the range at {at} is malformed"),
            Self::EmptyPart => write!(formatter, "a part of the body is empty"),
            Self::PartTooShort => {
                write!(formatter, "a part of the body is shorter than two elements")
            }
            Self::NoFixedPairInPart => {
                write!(
                    formatter,
                    "a part of the body has no two fixed bytes in a row"
                )
            }
            Self::PlainBodyTooShort => {
                write!(formatter, "a body of plain bytes is shorter than three")
            }
            Self::MisplacedLoneByteDistance { at } => write!(
                formatter,
                "the distance at {at} is not beside a lone byte at the edge of its part, or exceeds 32"
            ),
            Self::NestedTooDeep { at } => {
                write!(
                    formatter,
                    "the alternatives at {at} are nested more than 16 deep"
                )
            }
            Self::NegatedGenericAlternatives { at } => write!(
                formatter,
                "the negated alternatives at {at} are not single bytes or strings of one length"
            ),
            Self::UnsupportedInsideAlternatives { at } => write!(
                formatter,
                "the alternatives at {at} hold a range, a long gap, a star or a class"
            ),
            Self::TooManyAlternatives { at } => write!(
                formatter,
                "the alternatives at {at} expand to more than {MOST_EXPANDED_ALTERNATIVES} strings"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedBody {
    ClassAtAnInnerPartEdge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadBody {
    Pattern {
        pattern: Pattern,
        plain_bytes: bool,
        longest_part: u32,
    },
    Unsupported {
        reason: UnsupportedBody,
        longest_part: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassName {
    Boundary,
    LineBreak,
    NonAlphanumeric,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Byte(MaskedByte),
    Star,
    Gap {
        minimum: u32,
        maximum: Option<u32>,
        exact_small: bool,
    },
    LoneByteDistance {
        minimum: u32,
        maximum: u32,
        at: usize,
    },
    Choice(Vec<Vec<MaskedByte>>),
    NoneOf {
        width: u32,
        excluded: Vec<Vec<MaskedByte>>,
    },
    Class {
        name: ClassName,
        negated: bool,
    },
}

pub fn read_body(text: &[u8]) -> Result<ReadBody, MalformedBody> {
    read_body_at_least(text, SHORTEST_PLAIN_EXTENDED_BODY)
}

pub fn read_type_recognition_body(text: &[u8]) -> Result<ReadBody, MalformedBody> {
    read_body_at_least(text, SHORTEST_PLAIN_TYPE_RECOGNITION_BODY)
}

fn read_body_at_least(text: &[u8], shortest_plain_body: usize) -> Result<ReadBody, MalformedBody> {
    let mut reader = Reader { text, at: 0 };
    let mut tokens = Vec::new();
    while reader.peek().is_some() {
        tokens.push(reader.token()?);
    }
    if tokens.is_empty() {
        return Err(MalformedBody::Empty);
    }
    let plain_bytes = text.iter().all(u8::is_ascii_hexdigit);
    if plain_bytes && tokens.len() < shortest_plain_body {
        return Err(MalformedBody::PlainBodyTooShort);
    }
    let longest_part = longest_part_as_the_reference_counts(&tokens, ByteWidth::Narrow);
    expand_leading_small_gaps(&mut tokens);
    let before = match tokens.first() {
        Some(Token::Class {
            name,
            negated: false,
        }) => Some(edge_test(*name, false, Edge::Before)),
        _ => None,
    };
    if before.is_some() {
        tokens.remove(0);
    }
    let after = match tokens.last() {
        Some(Token::Class { name, negated }) => Some(edge_test(*name, *negated, Edge::After)),
        _ => None,
    };
    if after.is_some() {
        tokens.pop();
    }
    let parts = split_into_parts(tokens)?;
    for part in &parts {
        validate_part(&part.tokens)?;
    }
    let inner_edge_class = parts.iter().any(|part| {
        matches!(part.tokens.first(), Some(Token::Class { .. }))
            || matches!(part.tokens.last(), Some(Token::Class { .. }))
    }) && parts.len() > 1;
    if inner_edge_class {
        return Ok(ReadBody::Unsupported {
            reason: UnsupportedBody::ClassAtAnInnerPartEdge,
            longest_part,
        });
    }
    let mut elements = Vec::new();
    for part in parts {
        if let Some(gap) = part.gap_before {
            elements.push(gap);
        }
        elements.extend(part_elements(part.tokens)?);
    }
    Ok(ReadBody::Pattern {
        pattern: Pattern {
            before,
            elements,
            after,
        },
        plain_bytes,
        longest_part,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteWidth {
    Narrow,
    Wide,
}

pub fn longest_part_of_body(text: &[u8], width: ByteWidth) -> Result<u32, MalformedBody> {
    let mut reader = Reader { text, at: 0 };
    let mut tokens = Vec::new();
    while reader.peek().is_some() {
        tokens.push(reader.token()?);
    }
    Ok(longest_part_as_the_reference_counts(&tokens, width))
}

fn longest_part_as_the_reference_counts(tokens: &[Token], width: ByteWidth) -> u32 {
    let byte_length: u32 = match width {
        ByteWidth::Narrow => 1,
        ByteWidth::Wide => 2,
    };
    let widened = |length: u32| length.saturating_mul(byte_length);
    let first_other_gap = tokens
        .iter()
        .position(|token| {
            matches!(
                token,
                Token::Gap {
                    exact_small: false,
                    ..
                }
            )
        })
        .unwrap_or(tokens.len());
    let mut longest: u32 = 0;
    let mut current: u32 = 0;
    let mut part_tokens: u32 = 0;
    let mut skip_next_byte = false;
    for (index, token) in tokens.iter().enumerate() {
        let length = match token {
            Token::Gap {
                minimum,
                exact_small: true,
                ..
            } if index < first_other_gap => Some(*minimum),
            Token::Star | Token::Gap { .. } => None,
            Token::Byte(_) if skip_next_byte => {
                skip_next_byte = false;
                Some(0)
            }
            Token::Byte(_) => Some(byte_length),
            Token::Choice(alternatives) => Some(widened(
                alternatives
                    .iter()
                    .map(|alternative| u32::try_from(alternative.len()).unwrap_or(u32::MAX))
                    .max()
                    .unwrap_or(0),
            )),
            Token::NoneOf { width, .. } => Some(widened(*width)),
            Token::Class { .. } => Some(0),
            Token::LoneByteDistance { .. } => {
                if part_tokens == 1 {
                    current = current.saturating_sub(byte_length);
                } else {
                    skip_next_byte = true;
                }
                Some(0)
            }
        };
        if let Some(length) = length {
            current = current.saturating_add(length);
            part_tokens = part_tokens.saturating_add(1);
            longest = longest.max(current);
        } else {
            current = 0;
            part_tokens = 0;
            skip_next_byte = false;
        }
    }
    longest
}

fn expand_leading_small_gaps(tokens: &mut Vec<Token>) {
    let first_other_gap = tokens
        .iter()
        .position(|token| {
            matches!(
                token,
                Token::Gap {
                    exact_small: false,
                    ..
                }
            )
        })
        .unwrap_or(tokens.len());
    let mut expanded = Vec::with_capacity(tokens.len());
    for (index, token) in tokens.drain(..).enumerate() {
        match token {
            Token::Gap {
                minimum,
                exact_small: true,
                ..
            } if index < first_other_gap => {
                expanded.extend((0..minimum).map(|_| Token::Byte(MaskedByte::ANY)));
            }
            Token::Gap {
                minimum,
                maximum,
                exact_small: true,
            } => expanded.push(Token::Gap {
                minimum,
                maximum,
                exact_small: false,
            }),
            other => expanded.push(other),
        }
    }
    *tokens = expanded;
}

struct Part {
    gap_before: Option<PatternElement>,
    tokens: Vec<Token>,
}

fn split_into_parts(tokens: Vec<Token>) -> Result<Vec<Part>, MalformedBody> {
    let mut parts = vec![Part {
        gap_before: None,
        tokens: Vec::new(),
    }];
    for token in tokens {
        let gap = match token {
            Token::Star => Some((0, None)),
            Token::Gap {
                minimum, maximum, ..
            } => Some((minimum, maximum.filter(|maximum| *maximum != 0))),
            _ => None,
        };
        match (gap, token) {
            (Some((minimum, maximum)), _) => {
                parts.push(Part {
                    gap_before: Some(PatternElement::PartBreak { minimum, maximum }),
                    tokens: Vec::new(),
                });
            }
            (None, other) => {
                if let Some(part) = parts.last_mut() {
                    part.tokens.push(other);
                }
            }
        }
    }
    if parts.iter().any(|part| part.tokens.is_empty()) {
        return Err(MalformedBody::EmptyPart);
    }
    Ok(parts)
}

fn validate_part(tokens: &[Token]) -> Result<(), MalformedBody> {
    let counted = tokens
        .iter()
        .filter(|token| !matches!(token, Token::LoneByteDistance { .. }))
        .count();
    if counted < SHORTEST_PART {
        return Err(MalformedBody::PartTooShort);
    }
    let mut run = 0usize;
    let mut longest_run = 0usize;
    for token in tokens {
        run = match token {
            Token::Byte(byte) if byte.is_exact() => run.saturating_add(1),
            _ => 0,
        };
        longest_run = longest_run.max(run);
    }
    if longest_run < SHORTEST_FIXED_RUN {
        return Err(MalformedBody::NoFixedPairInPart);
    }
    let distances: Vec<(usize, usize)> = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| match token {
            Token::LoneByteDistance { at, .. } => Some((index, *at)),
            _ => None,
        })
        .collect();
    if distances.len() > MOST_LONE_BYTE_DISTANCES {
        let at = distances.last().map_or(0, |(_, at)| *at);
        return Err(MalformedBody::MisplacedLoneByteDistance { at });
    }
    let last = tokens.len().saturating_sub(1);
    let mut sides = Vec::new();
    for (index, at) in distances {
        let side = if index == 1 {
            Edge::Before
        } else if Some(index) == last.checked_sub(1) {
            Edge::After
        } else {
            return Err(MalformedBody::MisplacedLoneByteDistance { at });
        };
        if sides.contains(&side) {
            return Err(MalformedBody::MisplacedLoneByteDistance { at });
        }
        sides.push(side);
    }
    Ok(())
}

fn part_elements(tokens: Vec<Token>) -> Result<Vec<PatternElement>, MalformedBody> {
    let mut elements = Vec::with_capacity(tokens.len());
    let mut previous_was_any_byte = false;
    for token in tokens {
        let element = match token {
            Token::Byte(byte) => {
                previous_was_any_byte = byte.mask == 0;
                elements.push(PatternElement::Byte(byte));
                continue;
            }
            Token::LoneByteDistance { .. } if previous_was_any_byte => continue,
            Token::LoneByteDistance {
                minimum, maximum, ..
            } => PatternElement::Gap {
                minimum,
                maximum: Some(maximum),
            },
            Token::Choice(alternatives) => PatternElement::Choice(alternatives),
            Token::NoneOf { width, excluded } => PatternElement::NoneOf { width, excluded },
            Token::Class { name, negated } => middle_class(name, negated),
            Token::Gap { .. } | Token::Star => return Err(MalformedBody::EmptyPart),
        };
        previous_was_any_byte = false;
        elements.push(element);
    }
    Ok(elements)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edge {
    Before,
    After,
}

fn edge_test(name: ClassName, negated: bool, edge: Edge) -> ContextTest {
    let sequences = match (name, edge) {
        (ClassName::Boundary, Edge::Before) => {
            vec![vec![ByteSet::of(BEFORE_A_WORD.iter().copied())]]
        }
        (ClassName::Boundary, Edge::After) => vec![vec![ByteSet::of(AFTER_A_WORD.iter().copied())]],
        (ClassName::LineBreak, Edge::Before) => vec![vec![ByteSet::of([LINE_FEED])]],
        (ClassName::LineBreak, Edge::After) => vec![
            vec![ByteSet::of([LINE_FEED])],
            vec![ByteSet::of([CARRIAGE_RETURN]), ByteSet::of([LINE_FEED])],
        ],
        (ClassName::NonAlphanumeric, _) => vec![vec![non_alphanumeric()]],
    };
    ContextTest {
        sequences,
        negated,
        satisfied_at_object_edge: !negated,
    }
}

fn non_alphanumeric() -> ByteSet {
    ByteSet::of((0..=u8::MAX).filter(|byte| !byte.is_ascii_alphanumeric()))
}

fn middle_class(name: ClassName, negated: bool) -> PatternElement {
    let set = match name {
        ClassName::Boundary => ByteSet::of(BEFORE_A_WORD.iter().chain(AFTER_A_WORD).copied()),
        ClassName::LineBreak if !negated => {
            return PatternElement::Choice(vec![
                vec![MaskedByte::exactly(LINE_FEED)],
                vec![
                    MaskedByte::exactly(CARRIAGE_RETURN),
                    MaskedByte::exactly(LINE_FEED),
                ],
            ]);
        }
        ClassName::LineBreak => ByteSet::of([LINE_FEED]),
        ClassName::NonAlphanumeric => non_alphanumeric(),
    };
    PatternElement::OneOf(if negated {
        ByteSet::of((0..=u8::MAX).filter(|byte| !set.contains(*byte)))
    } else {
        set
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Branch {
    Byte(MaskedByte),
    Group(Vec<Vec<Branch>>),
}

struct Reader<'t> {
    text: &'t [u8],
    at: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn advance(&mut self) {
        self.at = self.at.saturating_add(1);
    }

    fn unexpected(&self) -> MalformedBody {
        if self.peek().is_some() {
            MalformedBody::UnexpectedCharacter { at: self.at }
        } else {
            MalformedBody::UnfinishedByte { at: self.at }
        }
    }

    fn token(&mut self) -> Result<Token, MalformedBody> {
        let started = self.at;
        match self.peek() {
            Some(b'*') => {
                self.advance();
                Ok(Token::Star)
            }
            Some(b'{') => {
                let (minimum, maximum) = self.range(b'}')?;
                let exact_small =
                    maximum == Some(minimum) && (1..=LARGEST_EXPANDED_GAP).contains(&minimum);
                Ok(Token::Gap {
                    minimum,
                    maximum,
                    exact_small,
                })
            }
            Some(b'[') => {
                let (minimum, maximum) = self.range(b']')?;
                match maximum {
                    Some(maximum)
                        if minimum <= maximum && maximum <= LARGEST_LONE_BYTE_DISTANCE =>
                    {
                        Ok(Token::LoneByteDistance {
                            minimum,
                            maximum,
                            at: started,
                        })
                    }
                    _ => Err(MalformedBody::MisplacedLoneByteDistance { at: started }),
                }
            }
            Some(b'!') => {
                self.advance();
                if self.peek() != Some(b'(') {
                    return Err(self.unexpected());
                }
                self.group(true, started)
            }
            Some(b'(') => self.group(false, started),
            Some(_) => self.masked_byte().map(Token::Byte),
            None => Err(self.unexpected()),
        }
    }

    fn group(&mut self, negated: bool, started: usize) -> Result<Token, MalformedBody> {
        self.advance();
        if let Some(name) = self.class_name() {
            return Ok(Token::Class { name, negated });
        }
        let branches = self.branches(started, 1)?;
        let has_nested = branches
            .iter()
            .flatten()
            .any(|branch| matches!(branch, Branch::Group(_)));
        let strings = expand(&branches, started)?;
        let strings: Vec<Vec<MaskedByte>> = strings
            .into_iter()
            .filter(|string| !string.is_empty())
            .collect();
        if strings.is_empty() {
            return Err(MalformedBody::Empty);
        }
        if !negated {
            return Ok(Token::Choice(strings));
        }
        let width = strings.first().map_or(0, Vec::len);
        let generic = has_nested
            || strings.iter().any(|string| string.len() != width)
            || strings.iter().flatten().any(|byte| !byte.is_exact());
        if generic {
            return Err(MalformedBody::NegatedGenericAlternatives { at: started });
        }
        Ok(Token::NoneOf {
            width: u32::try_from(width)
                .map_err(|_| MalformedBody::MalformedRange { at: started })?,
            excluded: strings,
        })
    }

    fn branches(
        &mut self,
        started: usize,
        depth: usize,
    ) -> Result<Vec<Vec<Branch>>, MalformedBody> {
        if depth > DEEPEST_ALTERNATIVES {
            return Err(MalformedBody::NestedTooDeep { at: started });
        }
        let mut branches: Vec<Vec<Branch>> = vec![Vec::new()];
        loop {
            match self.peek() {
                Some(b'|') => {
                    self.advance();
                    branches.push(Vec::new());
                }
                Some(b')') => {
                    self.advance();
                    return Ok(branches);
                }
                Some(b'(') => {
                    let nested_at = self.at;
                    self.advance();
                    if self.class_name().is_some() {
                        return Err(MalformedBody::UnsupportedInsideAlternatives { at: nested_at });
                    }
                    let nested = self.branches(nested_at, depth.saturating_add(1))?;
                    if let Some(current) = branches.last_mut() {
                        current.push(Branch::Group(nested));
                    }
                }
                Some(b'{') => {
                    let gap_at = self.at;
                    let (minimum, maximum) = self.range(b'}')?;
                    let small =
                        maximum == Some(minimum) && (1..=LARGEST_EXPANDED_GAP).contains(&minimum);
                    if !small {
                        return Err(MalformedBody::UnsupportedInsideAlternatives { at: gap_at });
                    }
                    if let Some(current) = branches.last_mut() {
                        current.extend((0..minimum).map(|_| Branch::Byte(MaskedByte::ANY)));
                    }
                }
                Some(b'*' | b'[' | b'!') => {
                    return Err(MalformedBody::UnsupportedInsideAlternatives { at: self.at });
                }
                Some(_) => {
                    let byte = self.masked_byte()?;
                    if let Some(current) = branches.last_mut() {
                        current.push(Branch::Byte(byte));
                    }
                }
                None => return Err(MalformedBody::UnclosedGroup { at: started }),
            }
        }
    }

    fn class_name(&mut self) -> Option<ClassName> {
        let name = match self.text.get(self.at..self.at.checked_add(2)?)? {
            b"B)" => ClassName::Boundary,
            b"L)" => ClassName::LineBreak,
            b"W)" => ClassName::NonAlphanumeric,
            _ => return None,
        };
        self.advance();
        self.advance();
        Some(name)
    }

    fn range(&mut self, closing: u8) -> Result<(u32, Option<u32>), MalformedBody> {
        let started = self.at;
        self.advance();
        let from = self.at;
        while let Some(character) = self.peek() {
            if character == closing {
                let text = self.text.get(from..self.at).unwrap_or_default();
                self.advance();
                return range_from(text).ok_or(MalformedBody::MalformedRange { at: started });
            }
            self.advance();
        }
        Err(MalformedBody::UnclosedGroup { at: started })
    }

    fn masked_byte(&mut self) -> Result<MaskedByte, MalformedBody> {
        let at = self.at;
        let high = self.peek().ok_or(MalformedBody::UnfinishedByte { at })?;
        self.advance();
        let low = self.peek().ok_or(MalformedBody::UnfinishedByte { at })?;
        self.advance();
        Ok(match (nibble(high), nibble(low)) {
            (Some(Nibble::Any), Some(Nibble::Any)) => MaskedByte::ANY,
            (Some(Nibble::Known(high)), Some(Nibble::Known(low))) => {
                MaskedByte::exactly(high << 4 | low)
            }
            (Some(Nibble::Known(high)), Some(Nibble::Any)) => MaskedByte {
                value: high << 4,
                mask: 0xf0,
            },
            (Some(Nibble::Any), Some(Nibble::Known(low))) => MaskedByte {
                value: low,
                mask: 0x0f,
            },
            _ => return Err(MalformedBody::UnexpectedCharacter { at }),
        })
    }
}

fn expand(branches: &[Vec<Branch>], at: usize) -> Result<Vec<Vec<MaskedByte>>, MalformedBody> {
    let mut strings = Vec::new();
    for branch in branches {
        let mut partial: Vec<Vec<MaskedByte>> = vec![Vec::new()];
        for item in branch {
            match item {
                Branch::Byte(byte) => {
                    for string in &mut partial {
                        string.push(*byte);
                    }
                }
                Branch::Group(nested) => {
                    let options: Vec<Vec<MaskedByte>> = expand(nested, at)?
                        .into_iter()
                        .filter(|option| !option.is_empty())
                        .collect();
                    let mut grown = Vec::new();
                    for prefix in &partial {
                        for option in &options {
                            let mut string = prefix.clone();
                            string.extend_from_slice(option);
                            grown.push(string);
                        }
                    }
                    if grown.len() > MOST_EXPANDED_ALTERNATIVES {
                        return Err(MalformedBody::TooManyAlternatives { at });
                    }
                    partial = grown;
                }
            }
        }
        strings.extend(partial);
        if strings.len() > MOST_EXPANDED_ALTERNATIVES {
            return Err(MalformedBody::TooManyAlternatives { at });
        }
    }
    Ok(strings)
}

enum Nibble {
    Known(u8),
    Any,
}

fn nibble(character: u8) -> Option<Nibble> {
    if character == b'?' {
        return Some(Nibble::Any);
    }
    char::from(character)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
        .map(Nibble::Known)
}

fn range_from(text: &[u8]) -> Option<(u32, Option<u32>)> {
    let number = |digits: &[u8]| -> Option<u32> {
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(digits).ok()?.parse().ok()
    };
    match text.iter().position(|byte| *byte == b'-') {
        None => {
            let exact = number(text)?;
            Some((exact, Some(exact)))
        }
        Some(dash) => {
            let low = text.get(..dash)?;
            let high = text.get(dash.checked_add(1)?..)?;
            if low.is_empty() && high.is_empty() {
                return None;
            }
            let minimum = if low.is_empty() { 0 } else { number(low)? };
            let maximum = if high.is_empty() {
                None
            } else {
                Some(number(high)?)
            };
            Some((minimum, maximum))
        }
    }
}
