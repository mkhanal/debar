use std::fmt;

use debar_image::{
    Assertion, ByteSet, ExpressionForm, ExpressionTree, Greed, LookDirection, TreeRepetition,
};

use crate::regular_expression_classes::{ByteClass, ClassEscape, class_escape, read_class};

const DEEPEST_NESTING: usize = 250;
const LARGEST_REPETITION: u32 = 65_535;
const NEWLINE: u8 = b'\n';
const CASE_BIT: u8 = 0x20;

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
pub enum UnsupportedConstruct {
    Recursion,
    Conditional,
    MatchStartReset,
    ContinuationAnchor,
    NewlineSequence,
    UnicodeProperty,
    ControlVerb,
    Callout,
    QuantifiedAssertion,
    UnsupportedOption,
}

impl UnsupportedConstruct {
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Recursion => "a recursion or subroutine call",
            Self::Conditional => "a conditional group",
            Self::MatchStartReset => "a match start reset",
            Self::ContinuationAnchor => "a continuation anchor",
            Self::NewlineSequence => "a newline sequence",
            Self::UnicodeProperty => "a Unicode property",
            Self::ControlVerb => "a control verb",
            Self::Callout => "a callout",
            Self::QuantifiedAssertion => "a quantified assertion",
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
    UnknownGroupName,
    ReferenceToNoGroup,
    UnboundedLookbehind,
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
            Self::UnknownGroupName => {
                formatter.write_str("a backreference names a group that does not exist")
            }
            Self::UnboundedLookbehind => {
                formatter.write_str("a lookbehind assertion has no longest match")
            }
            Self::ReferenceToNoGroup => {
                formatter.write_str("a backreference numbers a group that does not exist")
            }
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
    Compiled(ExpressionForm),
    Unsupported(UnsupportedConstruct),
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
        named_references: Vec::new(),
        highest_reference: 0,
        unsupported: None,
    };
    let mut scoped = flags;
    let mut tree = parser.alternation(&mut scoped, 0)?;
    if parser.at < pattern.len() {
        return Err(MalformedRegularExpression::UnmatchedClosingParenthesis);
    }
    if let Some(construct) = parser.unsupported {
        return Ok(Translation::Unsupported(construct));
    }
    if parser.highest_reference > parser.captures {
        return Err(MalformedRegularExpression::ReferenceToNoGroup);
    }
    if !parser.named_references.is_empty() {
        let groups = parser
            .named_references
            .iter()
            .map(|name| parser.group_named(name))
            .collect::<Result<Vec<u32>, _>>()?;
        resolve_named_references(&mut tree, &groups, 0);
    }
    if has_unbounded_lookbehind(&tree, 0) {
        return Err(MalformedRegularExpression::UnboundedLookbehind);
    }
    Ok(Translation::Compiled(match tree.linear_form() {
        Ok(hir) => ExpressionForm::Linear(hir),
        Err(_) => ExpressionForm::Backtracking(tree),
    }))
}

const NAMED_REFERENCE_BASE: u32 = u32::MAX / 2;

fn has_unbounded_lookbehind(tree: &ExpressionTree, depth: usize) -> bool {
    if depth > DEEPEST_NESTING.saturating_mul(4) {
        return false;
    }
    let depth = depth.saturating_add(1);
    match tree {
        ExpressionTree::Lookaround {
            direction: LookDirection::Behind,
            item,
            ..
        } => item.longest_match().is_none() || has_unbounded_lookbehind(item, depth),
        ExpressionTree::Concat(items) | ExpressionTree::Alternation(items) => items
            .iter()
            .any(|item| has_unbounded_lookbehind(item, depth)),
        ExpressionTree::Repetition(repetition) => has_unbounded_lookbehind(&repetition.item, depth),
        ExpressionTree::Capture { item, .. }
        | ExpressionTree::Lookaround { item, .. }
        | ExpressionTree::Atomic(item) => has_unbounded_lookbehind(item, depth),
        ExpressionTree::Empty
        | ExpressionTree::Byte(_)
        | ExpressionTree::Backreference { .. }
        | ExpressionTree::Assertion(_) => false,
    }
}

fn resolve_named_references(tree: &mut ExpressionTree, groups: &[u32], depth: usize) {
    if depth > DEEPEST_NESTING.saturating_mul(4) {
        return;
    }
    let depth = depth.saturating_add(1);
    match tree {
        ExpressionTree::Backreference { group, .. } if *group >= NAMED_REFERENCE_BASE => {
            if let Some(resolved) = usize::try_from(group.saturating_sub(NAMED_REFERENCE_BASE))
                .ok()
                .and_then(|index| groups.get(index))
            {
                *group = *resolved;
            }
        }
        ExpressionTree::Concat(items) | ExpressionTree::Alternation(items) => {
            for item in items {
                resolve_named_references(item, groups, depth);
            }
        }
        ExpressionTree::Repetition(repetition) => {
            resolve_named_references(&mut repetition.item, groups, depth);
        }
        ExpressionTree::Capture { item, .. }
        | ExpressionTree::Lookaround { item, .. }
        | ExpressionTree::Atomic(item) => resolve_named_references(item, groups, depth),
        ExpressionTree::Empty
        | ExpressionTree::Byte(_)
        | ExpressionTree::Backreference { .. }
        | ExpressionTree::Assertion(_) => {}
    }
}

struct Parser<'p> {
    pattern: &'p [u8],
    at: usize,
    captures: u32,
    names: Vec<(&'p [u8], u32)>,
    named_references: Vec<&'p [u8]>,
    highest_reference: u32,
    unsupported: Option<UnsupportedConstruct>,
}

enum Atom {
    Item(ExpressionTree),
    Assertion(ExpressionTree),
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

    fn note(&mut self, construct: UnsupportedConstruct) {
        self.unsupported.get_or_insert(construct);
    }

    fn group_named(&self, name: &[u8]) -> Result<u32, MalformedRegularExpression> {
        self.names
            .iter()
            .find(|(known, _)| *known == name)
            .map(|(_, group)| *group)
            .ok_or(MalformedRegularExpression::UnknownGroupName)
    }

    fn numbered_reference(&mut self, group: u32, caseless: bool) -> Atom {
        self.highest_reference = self.highest_reference.max(group);
        Atom::Item(ExpressionTree::Backreference { group, caseless })
    }

    fn named_reference(&mut self, name: &'p [u8], caseless: bool) -> Atom {
        let index = u32::try_from(self.named_references.len()).unwrap_or(u32::MAX);
        self.named_references.push(name);
        Atom::Item(ExpressionTree::Backreference {
            group: NAMED_REFERENCE_BASE.saturating_add(index),
            caseless,
        })
    }

    fn alternation(
        &mut self,
        flags: &mut ExpressionFlags,
        depth: usize,
    ) -> Result<ExpressionTree, MalformedRegularExpression> {
        let mut branches = vec![self.concatenation(flags, depth)?];
        while self.peek() == Some(b'|') {
            self.advance(1);
            branches.push(self.concatenation(flags, depth)?);
        }
        Ok(if branches.len() == 1 {
            branches.pop().unwrap_or(ExpressionTree::Empty)
        } else {
            ExpressionTree::Alternation(branches)
        })
    }

    fn concatenation(
        &mut self,
        flags: &mut ExpressionFlags,
        depth: usize,
    ) -> Result<ExpressionTree, MalformedRegularExpression> {
        let mut items: Vec<ExpressionTree> = Vec::new();
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
                Atom::Assertion(tree) => {
                    if self.quantifier_ahead() {
                        self.note(UnsupportedConstruct::QuantifiedAssertion);
                        self.quantifier(*flags, ExpressionTree::Empty)?;
                    }
                    tree
                }
                Atom::Item(tree) => self.quantifier(*flags, tree)?,
            };
            items.push(item);
        }
        Ok(if items.len() == 1 {
            items.pop().unwrap_or(ExpressionTree::Empty)
        } else {
            ExpressionTree::Concat(items)
        })
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
        item: ExpressionTree,
    ) -> Result<ExpressionTree, MalformedRegularExpression> {
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
        let mut greed = if flags.ungreedy {
            Greed::Lazy
        } else {
            Greed::Greedy
        };
        match self.peek() {
            Some(b'?') => {
                self.advance(1);
                greed = if flags.ungreedy {
                    Greed::Greedy
                } else {
                    Greed::Lazy
                };
            }
            Some(b'+') => {
                self.advance(1);
                greed = Greed::Possessive;
            }
            _ => {}
        }
        if self.quantifier_ahead() {
            return Err(MalformedRegularExpression::NothingToRepeat);
        }
        Ok(ExpressionTree::Repetition(Box::new(TreeRepetition {
            min,
            max,
            greed,
            item,
        })))
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
                    self.note(UnsupportedConstruct::UnicodeProperty);
                }
                Atom::Item(ExpressionTree::Byte(byte_set(&class.bytes)))
            }
            b'.' => Atom::Item(if flags.dot_all {
                any_byte()
            } else {
                not_newline()
            }),
            b'^' => Atom::Assertion(ExpressionTree::Assertion(if flags.multiline {
                Assertion::LineStartNotAtSubjectEnd
            } else {
                Assertion::SubjectStart
            })),
            b'$' => Atom::Assertion(ExpressionTree::Assertion(end_of_line(*flags))),
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
            return self.digit_escape(flags);
        }
        let look = |assertion| Ok(Atom::Assertion(ExpressionTree::Assertion(assertion)));
        match letter {
            b'b' => {
                self.advance(1);
                return look(Assertion::WordBoundary);
            }
            b'B' => {
                self.advance(1);
                return look(Assertion::NotWordBoundary);
            }
            b'A' => {
                self.advance(1);
                return look(Assertion::SubjectStart);
            }
            b'z' => {
                self.advance(1);
                return look(Assertion::SubjectEnd);
            }
            b'Z' => {
                self.advance(1);
                return look(Assertion::SubjectEndOrBeforeFinalNewline);
            }
            b'G' => {
                self.advance(1);
                self.note(UnsupportedConstruct::ContinuationAnchor);
                return Ok(Atom::Assertion(ExpressionTree::Empty));
            }
            b'K' => {
                self.advance(1);
                self.note(UnsupportedConstruct::MatchStartReset);
                return Ok(Atom::Assertion(ExpressionTree::Empty));
            }
            b'R' | b'X' => {
                self.advance(1);
                self.note(if letter == b'R' {
                    UnsupportedConstruct::NewlineSequence
                } else {
                    UnsupportedConstruct::UnicodeProperty
                });
                return Ok(Atom::Item(ExpressionTree::Empty));
            }
            b'g' | b'k' => {
                self.advance(1);
                return self.reference_escape(letter, flags.caseless);
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
            ClassEscape::Set(set) => ExpressionTree::Byte(byte_set(&set)),
            ClassEscape::UnicodeProperty => {
                self.note(UnsupportedConstruct::UnicodeProperty);
                ExpressionTree::Empty
            }
        }))
    }

    fn digit_escape(&mut self, flags: ExpressionFlags) -> Result<Atom, MalformedRegularExpression> {
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
            return Ok(self.numbered_reference(value, flags.caseless));
        }
        let (escape, rest) = class_escape(self.rest(), false)?;
        self.advance(self.rest().len().saturating_sub(rest.len()));
        match escape {
            ClassEscape::Byte(byte) => Ok(Atom::Item(ExpressionTree::Byte(ByteSet::of([byte])))),
            ClassEscape::Set(_) | ClassEscape::UnicodeProperty => {
                Err(MalformedRegularExpression::MalformedEscape)
            }
        }
    }

    fn reference_escape(
        &mut self,
        letter: u8,
        caseless: bool,
    ) -> Result<Atom, MalformedRegularExpression> {
        let closing = match self.peek() {
            Some(b'{') => Some(b'}'),
            Some(b'<') => Some(b'>'),
            Some(b'\'') => Some(b'\''),
            _ => None,
        };
        let text = match closing {
            Some(closing) => {
                self.advance(1);
                let length = self
                    .rest()
                    .iter()
                    .position(|byte| *byte == closing)
                    .ok_or(MalformedRegularExpression::MalformedEscape)?;
                let text = self.rest().get(..length).unwrap_or_default();
                self.advance(length.saturating_add(1));
                text
            }
            None if letter == b'g' => {
                let length = self
                    .rest()
                    .iter()
                    .enumerate()
                    .take_while(|(position, byte)| {
                        byte.is_ascii_digit() || (*position == 0 && matches!(byte, b'-' | b'+'))
                    })
                    .count();
                let text = self.rest().get(..length).unwrap_or_default();
                self.advance(length);
                text
            }
            None => return Err(MalformedRegularExpression::MalformedEscape),
        };
        let numbered = letter == b'g'
            && !text.is_empty()
            && text
                .iter()
                .enumerate()
                .all(|(position, byte)| byte.is_ascii_digit() || (position == 0 && *byte == b'-'));
        if !numbered {
            if text.is_empty()
                || text.first().is_some_and(u8::is_ascii_digit)
                || !text
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                return Err(MalformedRegularExpression::MalformedGroupName);
            }
            return Ok(self.named_reference(text, caseless));
        }
        let (relative, digits) = match text.split_first() {
            Some((b'-', digits)) => (true, digits),
            _ => (false, text),
        };
        let value = digits
            .iter()
            .try_fold(0u32, |value, digit| {
                value
                    .checked_mul(10)?
                    .checked_add(u32::from(digit.checked_sub(b'0')?))
            })
            .ok_or(MalformedRegularExpression::ReferenceToNoGroup)?;
        let group = if relative {
            self.captures
                .checked_add(1)
                .and_then(|next| next.checked_sub(value))
                .filter(|group| *group > 0 && value > 0)
                .ok_or(MalformedRegularExpression::ReferenceToNoGroup)?
        } else {
            value
        };
        if group == 0 {
            return Err(MalformedRegularExpression::ReferenceToNoGroup);
        }
        Ok(self.numbered_reference(group, caseless))
    }

    fn quoted(&mut self, flags: ExpressionFlags) -> ExpressionTree {
        let mut literals = Vec::new();
        while let Some(byte) = self.next() {
            if byte == b'\\' && self.peek() == Some(b'E') {
                self.advance(1);
                break;
            }
            literals.push(folded_literal(byte, flags.caseless));
        }
        ExpressionTree::Concat(literals)
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
            self.note(UnsupportedConstruct::ControlVerb);
            self.skip_to_closing();
            return Ok(Atom::Assertion(ExpressionTree::Empty));
        }
        if self.peek() != Some(b'?') {
            return self.capture_group(*flags, depth);
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
            b'>' => {
                let item = self.group_body(*flags, depth)?;
                Ok(Atom::Item(ExpressionTree::Atomic(Box::new(item))))
            }
            b'=' | b'!' => self.lookaround(*flags, depth, LookDirection::Ahead, kind == b'!'),
            b'<' if matches!(self.peek(), Some(b'=' | b'!')) => {
                let negated = self.next() == Some(b'!');
                self.lookaround(*flags, depth, LookDirection::Behind, negated)
            }
            b'<' => self.named_group(b'>', *flags, depth),
            b'\'' => self.named_group(b'\'', *flags, depth),
            b'P' => match self.next() {
                Some(b'<') => self.named_group(b'>', *flags, depth),
                Some(b'=') => {
                    let length = self
                        .rest()
                        .iter()
                        .position(|byte| *byte == b')')
                        .ok_or(MalformedRegularExpression::UnmatchedOpeningParenthesis)?;
                    let name = self.rest().get(..length).unwrap_or_default();
                    self.advance(length.saturating_add(1));
                    if name.is_empty()
                        || name.first().is_some_and(u8::is_ascii_digit)
                        || !name
                            .iter()
                            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                    {
                        return Err(MalformedRegularExpression::MalformedGroupName);
                    }
                    Ok(self.named_reference(name, flags.caseless))
                }
                Some(b'>') => {
                    self.skip_to_closing();
                    self.note(UnsupportedConstruct::Recursion);
                    Ok(Atom::Item(ExpressionTree::Empty))
                }
                _ => Err(MalformedRegularExpression::MalformedGroupName),
            },
            b'R' | b'&' | b'+' | b'0'..=b'9' => {
                self.skip_to_closing();
                self.note(UnsupportedConstruct::Recursion);
                Ok(Atom::Item(ExpressionTree::Empty))
            }
            b'-' if self.peek().is_some_and(|byte| byte.is_ascii_digit()) => {
                self.skip_to_closing();
                self.note(UnsupportedConstruct::Recursion);
                Ok(Atom::Item(ExpressionTree::Empty))
            }
            b'(' => {
                self.skip_balanced();
                self.note(UnsupportedConstruct::Conditional);
                Ok(Atom::Item(ExpressionTree::Empty))
            }
            b'C' => {
                self.skip_to_closing();
                self.note(UnsupportedConstruct::Callout);
                Ok(Atom::Assertion(ExpressionTree::Empty))
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
                b'n' | b'J' => self.note(UnsupportedConstruct::UnsupportedOption),
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
        if self.names.iter().any(|(known, _)| *known == name) {
            return Err(MalformedRegularExpression::DuplicateGroupName);
        }
        self.names.push((name, self.captures.saturating_add(1)));
        self.advance(length.saturating_add(1));
        self.capture_group(flags, depth)
    }

    fn capture_group(
        &mut self,
        flags: ExpressionFlags,
        depth: usize,
    ) -> Result<Atom, MalformedRegularExpression> {
        self.captures = self.captures.saturating_add(1);
        let group = self.captures;
        let item = self.group_body(flags, depth)?;
        Ok(Atom::Item(ExpressionTree::Capture {
            group,
            item: Box::new(item),
        }))
    }

    fn group_body(
        &mut self,
        flags: ExpressionFlags,
        depth: usize,
    ) -> Result<ExpressionTree, MalformedRegularExpression> {
        let mut inner = flags;
        let tree = self.alternation(&mut inner, depth)?;
        if self.next() != Some(b')') {
            return Err(MalformedRegularExpression::UnmatchedOpeningParenthesis);
        }
        Ok(tree)
    }

    fn lookaround(
        &mut self,
        flags: ExpressionFlags,
        depth: usize,
        direction: LookDirection,
        negated: bool,
    ) -> Result<Atom, MalformedRegularExpression> {
        let item = self.group_body(flags, depth)?;
        Ok(Atom::Assertion(ExpressionTree::Lookaround {
            direction,
            negated,
            item: Box::new(item),
        }))
    }

    fn skip_to_closing(&mut self) {
        while let Some(byte) = self.next() {
            if byte == b')' {
                return;
            }
        }
    }

    fn skip_balanced(&mut self) {
        let mut open: usize = 2;
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

fn end_of_line(flags: ExpressionFlags) -> Assertion {
    if flags.multiline {
        Assertion::LineEnd
    } else if flags.dollar_end_only {
        Assertion::SubjectEnd
    } else {
        Assertion::SubjectEndOrBeforeFinalNewline
    }
}

fn byte_set(class: &ByteClass) -> ByteSet {
    ByteSet::of((0..=u8::MAX).filter(|byte| class.contains(*byte)))
}

fn any_byte() -> ExpressionTree {
    ExpressionTree::Byte(ByteSet::of(0..=u8::MAX))
}

fn not_newline() -> ExpressionTree {
    ExpressionTree::Byte(ByteSet::of((0..=u8::MAX).filter(|byte| *byte != NEWLINE)))
}

fn folded_literal(byte: u8, caseless: bool) -> ExpressionTree {
    if caseless && byte.is_ascii_alphabetic() {
        ExpressionTree::Byte(ByteSet::of([byte, byte ^ CASE_BIT]))
    } else {
        ExpressionTree::Byte(ByteSet::of([byte]))
    }
}
