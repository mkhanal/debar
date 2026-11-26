use std::fmt;

use regex_syntax::hir::{Hir, Look, Repetition};

use crate::regular_expression_classes::{
    ByteClass, ClassEscape, any_byte, class_escape, class_hir, folded_literal, not_newline,
    read_class,
};

const DEEPEST_NESTING: usize = 250;
const LARGEST_REPETITION: u32 = 65_535;
const NEWLINE: u8 = b'\n';

#[expect(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExpressionFlags {
    pub caseless: bool,
    pub dot_all: bool,
    pub multiline: bool,
    pub extended: bool,
    pub ungreedy: bool,
    pub dollar_end_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BacktrackingConstruct {
    Backreference,
    Lookaround,
    AtomicGroup,
    PossessiveQuantifier,
    Recursion,
    Conditional,
    MatchStartReset,
    ContinuationAnchor,
    NewlineSequence,
    UnicodeProperty,
    ControlVerb,
    Callout,
    QuantifiedAssertion,
    EndOfLineBeforeNewline,
    UnsupportedOption,
}

impl BacktrackingConstruct {
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Backreference => "a backreference",
            Self::Lookaround => "a lookahead or lookbehind assertion",
            Self::AtomicGroup => "an atomic group",
            Self::PossessiveQuantifier => "a possessive quantifier",
            Self::Recursion => "a recursion or subroutine call",
            Self::Conditional => "a conditional group",
            Self::MatchStartReset => "a match start reset",
            Self::ContinuationAnchor => "a continuation anchor",
            Self::NewlineSequence => "a newline sequence",
            Self::UnicodeProperty => "a Unicode property",
            Self::ControlVerb => "a control verb",
            Self::Callout => "a callout",
            Self::QuantifiedAssertion => "a quantified assertion",
            Self::EndOfLineBeforeNewline => {
                "an end-of-subject assertion followed by what can match the final newline"
            }
            Self::UnsupportedOption => "an inline option other than i, m, s, x and U",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedRegularExpression {
    UnmatchedOpeningParenthesis,
    UnmatchedClosingParenthesis,
    NothingToRepeat,
    RepetitionOutOfOrder,
    RepetitionTooLarge,
    UnterminatedClass,
    RangeOutOfOrder,
    InvalidRange,
    UnknownPosixClass,
    UnknownEscape(u8),
    MalformedEscape,
    MalformedGroupName,
    DuplicateGroupName,
    MalformedOption,
    TooDeep,
}

impl fmt::Display for MalformedRegularExpression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnmatchedOpeningParenthesis => formatter.write_str("a parenthesis is not closed"),
            Self::UnmatchedClosingParenthesis => {
                formatter.write_str("a closing parenthesis has no opening one")
            }
            Self::NothingToRepeat => formatter.write_str("a quantifier follows nothing repeatable"),
            Self::RepetitionOutOfOrder => {
                formatter.write_str("a repetition's bounds are out of order")
            }
            Self::RepetitionTooLarge => {
                write!(formatter, "a repetition bound exceeds {LARGEST_REPETITION}")
            }
            Self::UnterminatedClass => formatter.write_str("a character class is not closed"),
            Self::RangeOutOfOrder => formatter.write_str("a character class range is out of order"),
            Self::InvalidRange => formatter.write_str("a character class range is invalid"),
            Self::UnknownPosixClass => formatter.write_str("a POSIX class name is unknown"),
            Self::UnknownEscape(letter) => {
                write!(formatter, "the escape \\{} is unknown", char::from(*letter))
            }
            Self::MalformedEscape => formatter.write_str("an escape is malformed"),
            Self::MalformedGroupName => formatter.write_str("a group name is malformed"),
            Self::DuplicateGroupName => formatter.write_str("two groups have the same name"),
            Self::MalformedOption => formatter.write_str("an inline option is malformed"),
            Self::TooDeep => write!(
                formatter,
                "parentheses nest more than {DEEPEST_NESTING} deep"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Translation {
    Linear(Hir),
    NeedsBacktracking(BacktrackingConstruct),
}

pub fn translate(
    pattern: &[u8],
    flags: ExpressionFlags,
) -> Result<Translation, MalformedRegularExpression> {
    let mut parser = Parser {
        pattern,
        at: 0,
        captures: 0,
        names: Vec::new(),
        needs_backtracking: None,
    };
    let mut scoped = flags;
    let hir = parser.alternation(&mut scoped, 0)?;
    if parser.at < pattern.len() {
        return Err(MalformedRegularExpression::UnmatchedClosingParenthesis);
    }
    Ok(match parser.needs_backtracking {
        Some(construct) => Translation::NeedsBacktracking(construct),
        None => Translation::Linear(hir),
    })
}

struct Parser<'p> {
    pattern: &'p [u8],
    at: usize,
    captures: u32,
    names: Vec<&'p [u8]>,
    needs_backtracking: Option<BacktrackingConstruct>,
}

enum Atom {
    Item(Hir),
    Assertion(Hir),
    Nothing,
}

impl<'p> Parser<'p> {
    fn peek(&self) -> Option<u8> {
        self.pattern.get(self.at).copied()
    }

    fn peek_at(&self, distance: usize) -> Option<u8> {
        self.pattern.get(self.at.saturating_add(distance)).copied()
    }

    fn rest(&self) -> &'p [u8] {
        self.pattern.get(self.at..).unwrap_or_default()
    }

    fn advance(&mut self, count: usize) {
        self.at = self.at.saturating_add(count).min(self.pattern.len());
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.advance(1);
        Some(byte)
    }

    fn note(&mut self, construct: BacktrackingConstruct) {
        self.needs_backtracking.get_or_insert(construct);
    }

    fn alternation(
        &mut self,
        flags: &mut ExpressionFlags,
        depth: usize,
    ) -> Result<Hir, MalformedRegularExpression> {
        let mut branches = vec![self.concatenation(flags, depth)?];
        while self.peek() == Some(b'|') {
            self.advance(1);
            branches.push(self.concatenation(flags, depth)?);
        }
        Ok(Hir::alternation(branches))
    }

    fn concatenation(
        &mut self,
        flags: &mut ExpressionFlags,
        depth: usize,
    ) -> Result<Hir, MalformedRegularExpression> {
        let mut items: Vec<Hir> = Vec::new();
        let mut pending_end_of_subject = false;
        loop {
            self.skip_extended_space(*flags);
            match self.peek() {
                None | Some(b'|' | b')') => break,
                Some(_) => {}
            }
            let atom = self.atom(flags, depth)?;
            self.skip_extended_space(*flags);
            let item = match atom {
                Atom::Nothing => {
                    if self.quantifier_ahead() {
                        return Err(MalformedRegularExpression::NothingToRepeat);
                    }
                    continue;
                }
                Atom::Assertion(hir) => {
                    if self.quantifier_ahead() {
                        self.note(BacktrackingConstruct::QuantifiedAssertion);
                        self.quantifier(*flags, Hir::empty())?;
                    }
                    hir
                }
                Atom::Item(hir) => self.quantifier(*flags, hir)?,
            };
            if pending_end_of_subject && item.properties().minimum_len() != Some(0) {
                if can_start_with_newline(&item) {
                    self.note(BacktrackingConstruct::EndOfLineBeforeNewline);
                }
                pending_end_of_subject = false;
            }
            if is_end_before_final_newline(&item) {
                pending_end_of_subject = true;
            }
            items.push(item);
        }
        Ok(Hir::concat(items))
    }

    fn skip_extended_space(&mut self, flags: ExpressionFlags) {
        if !flags.extended {
            return;
        }
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') => self.advance(1),
                Some(b'#') => {
                    while let Some(byte) = self.next() {
                        if byte == NEWLINE {
                            break;
                        }
                    }
                }
                _ => return,
            }
        }
    }

    fn quantifier_ahead(&self) -> bool {
        match self.peek() {
            Some(b'*' | b'+' | b'?') => true,
            Some(b'{') => counted_repetition(self.rest()).is_some(),
            _ => false,
        }
    }

    fn quantifier(
        &mut self,
        flags: ExpressionFlags,
        item: Hir,
    ) -> Result<Hir, MalformedRegularExpression> {
        let (min, max) = match self.peek() {
            Some(b'*') => {
                self.advance(1);
                (0, None)
            }
            Some(b'+') => {
                self.advance(1);
                (1, None)
            }
            Some(b'?') => {
                self.advance(1);
                (0, Some(1))
            }
            Some(b'{') => match counted_repetition(self.rest()) {
                Some(counted) => {
                    self.advance(counted.length);
                    let min = counted.min?;
                    let max = counted.max.transpose()?;
                    if max.is_some_and(|max| max < min) {
                        return Err(MalformedRegularExpression::RepetitionOutOfOrder);
                    }
                    (min, max)
                }
                None => return Ok(item),
            },
            _ => return Ok(item),
        };
        let mut greedy = !flags.ungreedy;
        match self.peek() {
            Some(b'?') => {
                self.advance(1);
                greedy = !greedy;
            }
            Some(b'+') => {
                self.advance(1);
                self.note(BacktrackingConstruct::PossessiveQuantifier);
            }
            _ => {}
        }
        if self.quantifier_ahead() {
            return Err(MalformedRegularExpression::NothingToRepeat);
        }
        Ok(Hir::repetition(Repetition {
            min,
            max,
            greedy,
            sub: Box::new(item),
        }))
    }

    fn atom(
        &mut self,
        flags: &mut ExpressionFlags,
        depth: usize,
    ) -> Result<Atom, MalformedRegularExpression> {
        let Some(byte) = self.next() else {
            return Ok(Atom::Nothing);
        };
        Ok(match byte {
            b'(' => self.group(flags, depth)?,
            b'[' => {
                let (class, rest) = read_class(self.rest(), flags.caseless)?;
                self.advance(self.rest().len().saturating_sub(rest.len()));
                if class.needs_backtracking {
                    self.note(BacktrackingConstruct::UnicodeProperty);
                }
                Atom::Item(class_hir(&class.bytes))
            }
            b'.' => Atom::Item(if flags.dot_all {
                any_byte()
            } else {
                not_newline()
            }),
            b'^' => Atom::Assertion(Hir::look(if flags.multiline {
                Look::StartLF
            } else {
                Look::Start
            })),
            b'$' => Atom::Assertion(end_of_line(*flags)),
            b'\\' => self.escape(*flags)?,
            b'*' | b'+' | b'?' => return Err(MalformedRegularExpression::NothingToRepeat),
            b'{' if counted_repetition(
                self.pattern
                    .get(self.at.saturating_sub(1)..)
                    .unwrap_or_default(),
            )
            .is_some() =>
            {
                return Err(MalformedRegularExpression::NothingToRepeat);
            }
            b')' => return Err(MalformedRegularExpression::UnmatchedClosingParenthesis),
            literal => Atom::Item(folded_literal(literal, flags.caseless)),
        })
    }

    fn escape(&mut self, flags: ExpressionFlags) -> Result<Atom, MalformedRegularExpression> {
        let Some(letter) = self.peek() else {
            return Err(MalformedRegularExpression::MalformedEscape);
        };
        if letter.is_ascii_digit() && letter != b'0' {
            return self.digit_escape();
        }
        let look = |look| Ok(Atom::Assertion(Hir::look(look)));
        match letter {
            b'b' => {
                self.advance(1);
                return look(Look::WordAscii);
            }
            b'B' => {
                self.advance(1);
                return look(Look::WordAsciiNegate);
            }
            b'A' => {
                self.advance(1);
                return look(Look::Start);
            }
            b'z' => {
                self.advance(1);
                return look(Look::End);
            }
            b'Z' => {
                self.advance(1);
                return Ok(Atom::Assertion(end_before_final_newline()));
            }
            b'G' => {
                self.advance(1);
                self.note(BacktrackingConstruct::ContinuationAnchor);
                return Ok(Atom::Assertion(Hir::empty()));
            }
            b'K' => {
                self.advance(1);
                self.note(BacktrackingConstruct::MatchStartReset);
                return Ok(Atom::Assertion(Hir::empty()));
            }
            b'R' | b'X' => {
                self.advance(1);
                self.note(if letter == b'R' {
                    BacktrackingConstruct::NewlineSequence
                } else {
                    BacktrackingConstruct::UnicodeProperty
                });
                return Ok(Atom::Item(Hir::empty()));
            }
            b'g' | b'k' => {
                self.advance(1);
                self.skip_reference_name();
                self.note(BacktrackingConstruct::Backreference);
                return Ok(Atom::Item(Hir::empty()));
            }
            b'Q' => {
                self.advance(1);
                return Ok(Atom::Item(self.quoted(flags)));
            }
            b'E' => {
                self.advance(1);
                return Ok(Atom::Nothing);
            }
            b'N' => {
                self.advance(1);
                return Ok(Atom::Item(not_newline()));
            }
            b'C' => {
                self.advance(1);
                return Ok(Atom::Item(any_byte()));
            }
            _ => {}
        }
        let (escape, rest) = class_escape(self.rest(), false)?;
        self.advance(self.rest().len().saturating_sub(rest.len()));
        Ok(Atom::Item(match escape {
            ClassEscape::Byte(byte) => folded_literal(byte, flags.caseless),
            ClassEscape::Set(set) => class_hir(&set),
            ClassEscape::UnicodeProperty => {
                self.note(BacktrackingConstruct::UnicodeProperty);
                Hir::empty()
            }
        }))
    }

    fn digit_escape(&mut self) -> Result<Atom, MalformedRegularExpression> {
        let digits = self
            .rest()
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        let text = self.rest().get(..digits).unwrap_or_default();
        let value = text.iter().fold(0u32, |value, digit| {
            value
                .saturating_mul(10)
                .saturating_add(u32::from(digit.saturating_sub(b'0')))
        });
        let starts_with_eight_or_nine = matches!(text.first(), Some(b'8' | b'9'));
        if value < 10 || starts_with_eight_or_nine || value <= self.captures {
            self.advance(digits);
            self.note(BacktrackingConstruct::Backreference);
            return Ok(Atom::Item(Hir::empty()));
        }
        let (escape, rest) = class_escape(self.rest(), false)?;
        self.advance(self.rest().len().saturating_sub(rest.len()));
        match escape {
            ClassEscape::Byte(byte) => Ok(Atom::Item(Hir::literal(vec![byte]))),
            ClassEscape::Set(_) | ClassEscape::UnicodeProperty => {
                Err(MalformedRegularExpression::MalformedEscape)
            }
        }
    }

    fn skip_reference_name(&mut self) {
        let closing = match self.peek() {
            Some(b'{') => b'}',
            Some(b'<') => b'>',
            Some(b'\'') => b'\'',
            _ => {
                while matches!(self.peek(), Some(b'-' | b'+' | b'0'..=b'9')) {
                    self.advance(1);
                }
                return;
            }
        };
        self.advance(1);
        while let Some(byte) = self.next() {
            if byte == closing {
                return;
            }
        }
    }

    fn quoted(&mut self, flags: ExpressionFlags) -> Hir {
        let mut literals = Vec::new();
        while let Some(byte) = self.next() {
            if byte == b'\\' && self.peek() == Some(b'E') {
                self.advance(1);
                break;
            }
            literals.push(folded_literal(byte, flags.caseless));
        }
        Hir::concat(literals)
    }

    fn group(
        &mut self,
        flags: &mut ExpressionFlags,
        depth: usize,
    ) -> Result<Atom, MalformedRegularExpression> {
        let depth = depth.saturating_add(1);
        if depth > DEEPEST_NESTING {
            return Err(MalformedRegularExpression::TooDeep);
        }
        if self.peek() == Some(b'*') {
            self.note(BacktrackingConstruct::ControlVerb);
            self.skip_to_closing();
            return Ok(Atom::Assertion(Hir::empty()));
        }
        if self.peek() != Some(b'?') {
            self.captures = self.captures.saturating_add(1);
            return self.group_body(*flags, depth).map(Atom::Item);
        }
        self.advance(1);
        let Some(kind) = self.next() else {
            return Err(MalformedRegularExpression::UnmatchedOpeningParenthesis);
        };
        match kind {
            b'#' => {
                self.skip_to_closing();
                Ok(Atom::Nothing)
            }
            b':' | b'|' => self.group_body(*flags, depth).map(Atom::Item),
            b'>' => self.unexpressed_group(*flags, depth, BacktrackingConstruct::AtomicGroup),
            b'=' | b'!' => self.unexpressed_group(*flags, depth, BacktrackingConstruct::Lookaround),
            b'<' if matches!(self.peek(), Some(b'=' | b'!')) => {
                self.advance(1);
                self.unexpressed_group(*flags, depth, BacktrackingConstruct::Lookaround)
            }
            b'<' => self.named_group(b'>', *flags, depth),
            b'\'' => self.named_group(b'\'', *flags, depth),
            b'P' => match self.next() {
                Some(b'<') => self.named_group(b'>', *flags, depth),
                Some(b'=') => {
                    self.skip_to_closing();
                    self.note(BacktrackingConstruct::Backreference);
                    Ok(Atom::Item(Hir::empty()))
                }
                Some(b'>') => {
                    self.skip_to_closing();
                    self.note(BacktrackingConstruct::Recursion);
                    Ok(Atom::Item(Hir::empty()))
                }
                _ => Err(MalformedRegularExpression::MalformedGroupName),
            },
            b'R' | b'&' | b'+' | b'0'..=b'9' => {
                self.skip_to_closing();
                self.note(BacktrackingConstruct::Recursion);
                Ok(Atom::Item(Hir::empty()))
            }
            b'-' if self.peek().is_some_and(|byte| byte.is_ascii_digit()) => {
                self.skip_to_closing();
                self.note(BacktrackingConstruct::Recursion);
                Ok(Atom::Item(Hir::empty()))
            }
            b'(' => {
                self.skip_balanced();
                self.note(BacktrackingConstruct::Conditional);
                Ok(Atom::Item(Hir::empty()))
            }
            b'C' => {
                self.skip_to_closing();
                self.note(BacktrackingConstruct::Callout);
                Ok(Atom::Assertion(Hir::empty()))
            }
            _ => {
                self.at = self.at.saturating_sub(1);
                self.options(flags, depth)
            }
        }
    }

    fn options(
        &mut self,
        flags: &mut ExpressionFlags,
        depth: usize,
    ) -> Result<Atom, MalformedRegularExpression> {
        let mut changed = *flags;
        let mut turning_on = true;
        if self.peek() == Some(b'^') {
            self.advance(1);
            changed.caseless = false;
            changed.dot_all = false;
            changed.multiline = false;
            changed.extended = false;
            changed.ungreedy = false;
        }
        loop {
            let Some(letter) = self.next() else {
                return Err(MalformedRegularExpression::UnmatchedOpeningParenthesis);
            };
            match letter {
                b'-' if turning_on => turning_on = false,
                b'i' => changed.caseless = turning_on,
                b's' => changed.dot_all = turning_on,
                b'm' => changed.multiline = turning_on,
                b'x' => changed.extended = turning_on,
                b'U' => changed.ungreedy = turning_on,
                b'n' | b'J' => self.note(BacktrackingConstruct::UnsupportedOption),
                b')' => {
                    *flags = changed;
                    return Ok(Atom::Nothing);
                }
                b':' => return self.group_body(changed, depth).map(Atom::Item),
                _ => return Err(MalformedRegularExpression::MalformedOption),
            }
        }
    }

    fn named_group(
        &mut self,
        closing: u8,
        flags: ExpressionFlags,
        depth: usize,
    ) -> Result<Atom, MalformedRegularExpression> {
        let length = self
            .rest()
            .iter()
            .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
            .count();
        let name = self.rest().get(..length).unwrap_or_default();
        if name.is_empty()
            || name.first().is_some_and(u8::is_ascii_digit)
            || self.peek_at(length) != Some(closing)
        {
            return Err(MalformedRegularExpression::MalformedGroupName);
        }
        if self.names.contains(&name) {
            return Err(MalformedRegularExpression::DuplicateGroupName);
        }
        self.names.push(name);
        self.advance(length.saturating_add(1));
        self.captures = self.captures.saturating_add(1);
        self.group_body(flags, depth).map(Atom::Item)
    }

    fn group_body(
        &mut self,
        flags: ExpressionFlags,
        depth: usize,
    ) -> Result<Hir, MalformedRegularExpression> {
        let mut inner = flags;
        let hir = self.alternation(&mut inner, depth)?;
        if self.next() != Some(b')') {
            return Err(MalformedRegularExpression::UnmatchedOpeningParenthesis);
        }
        Ok(hir)
    }

    fn unexpressed_group(
        &mut self,
        flags: ExpressionFlags,
        depth: usize,
        construct: BacktrackingConstruct,
    ) -> Result<Atom, MalformedRegularExpression> {
        self.group_body(flags, depth)?;
        self.note(construct);
        Ok(if construct == BacktrackingConstruct::Lookaround {
            Atom::Assertion(Hir::empty())
        } else {
            Atom::Item(Hir::empty())
        })
    }

    fn skip_to_closing(&mut self) {
        while let Some(byte) = self.next() {
            if byte == b')' {
                return;
            }
        }
    }

    fn skip_balanced(&mut self) {
        let mut open: usize = 1;
        while let Some(byte) = self.next() {
            match byte {
                b'\\' => self.advance(1),
                b'(' => open = open.saturating_add(1),
                b')' => {
                    open = open.saturating_sub(1);
                    if open == 0 {
                        return;
                    }
                }
                _ => {}
            }
        }
    }
}

struct CountedRepetition {
    length: usize,
    min: Result<u32, MalformedRegularExpression>,
    max: Option<Result<u32, MalformedRegularExpression>>,
}

fn counted_repetition(text: &[u8]) -> Option<CountedRepetition> {
    let inner = text.strip_prefix(b"{")?;
    let close = inner.iter().position(|byte| *byte == b'}')?;
    let body = inner.get(..close)?;
    let (low, high) = match body.iter().position(|byte| *byte == b',') {
        Some(comma) => (
            body.get(..comma)?,
            Some(body.get(comma.saturating_add(1)..)?),
        ),
        None => (body, None),
    };
    if low.is_empty() || !low.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if high.is_some_and(|high| !high.iter().all(u8::is_ascii_digit)) {
        return None;
    }
    let bound = |digits: &[u8]| -> Result<u32, MalformedRegularExpression> {
        digits
            .iter()
            .try_fold(0u32, |value, digit| {
                value
                    .checked_mul(10)?
                    .checked_add(u32::from(digit.checked_sub(b'0')?))
            })
            .filter(|value| *value <= LARGEST_REPETITION)
            .ok_or(MalformedRegularExpression::RepetitionTooLarge)
    };
    let max = match high {
        None => Some(bound(low)),
        Some([]) => None,
        Some(high) => Some(bound(high)),
    };
    Some(CountedRepetition {
        length: close.saturating_add(2),
        min: bound(low),
        max,
    })
}

fn end_of_line(flags: ExpressionFlags) -> Hir {
    if flags.multiline {
        Hir::look(Look::EndLF)
    } else if flags.dollar_end_only {
        Hir::look(Look::End)
    } else {
        end_before_final_newline()
    }
}

fn end_before_final_newline() -> Hir {
    Hir::alternation(vec![
        Hir::look(Look::End),
        Hir::concat(vec![Hir::literal(vec![NEWLINE]), Hir::look(Look::End)]),
    ])
}

fn is_end_before_final_newline(hir: &Hir) -> bool {
    *hir == end_before_final_newline()
}

fn can_start_with_newline(hir: &Hir) -> bool {
    use regex_syntax::hir::HirKind;
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => false,
        HirKind::Literal(literal) => literal.0.first() == Some(&NEWLINE),
        HirKind::Class(class) => ByteClass::of_hir_class(class).contains(NEWLINE),
        HirKind::Repetition(repetition) => can_start_with_newline(&repetition.sub),
        HirKind::Capture(capture) => can_start_with_newline(&capture.sub),
        HirKind::Concat(items) => items.iter().any(can_start_with_newline),
        HirKind::Alternation(branches) => branches.iter().any(can_start_with_newline),
    }
}
