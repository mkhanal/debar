use zerocopy::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::expression_automata::{AUTOMATON_ALIGNMENT, CompiledExpression, ExpressionNotCompiled};
use crate::logical_expression::{
    ExpressionMalformed, ExpressionNotCompiled as TriggerNotCompiled, ExpressionStep,
    expression_holds, holds_with_no_matches, postfix_steps,
};
use crate::logical_group::{LogicalSignatureId, StepEntry, step_entry, step_of};
use crate::model::{
    ByteComparison, ByteEncoding, ByteOrder, ExpressionAnchoring, ExpressionMatches, Placement,
    RegularExpressionSubsignature, ValueComparison,
};
use crate::pattern_group::{placement_fields, placement_of};

const PART_COUNT: usize = 7;
const ANCHORED_AT_SUBJECT_START: u8 = 1;
const EVERY_MATCH: u8 = 2;
const SEARCHING_FROM_PLACEMENT: u8 = 4;
const BOUNDED_BY_SHIFT: u8 = 8;
const UNCONDITIONAL: u8 = 16;
const TRIGGER_HOLDS_WITHOUT_MATCHES: u8 = 32;
const AUTOMATA_IN_IMAGE: u8 = 64;
const ENCODING_BINARY: u8 = 1;
const ENCODING_HEXADECIMAL_TEXT: u8 = 2;
const ENCODING_DECIMAL_TEXT: u8 = 3;
const ENCODING_HEXADECIMAL_OR_DECIMAL_TEXT: u8 = 4;
const ENCODING_NEVER_MATCHES: u8 = 5;
const ORDER_LITTLE: u8 = 1;
const ORDER_BIG: u8 = 2;
const VALUE_EQUAL: u8 = 1;
const VALUE_GREATER: u8 = 2;
const VALUE_LESS: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Expressions,
    Steps,
    Comparisons,
    Values,
    ImageHashes,
    Text,
    Automata,
}

const PARTS_IN_ORDER: [Part; PART_COUNT] = [
    Part::Expressions,
    Part::Steps,
    Part::Comparisons,
    Part::Values,
    Part::ImageHashes,
    Part::Text,
    Part::Automata,
];

impl Part {
    fn index(self) -> usize {
        PARTS_IN_ORDER
            .iter()
            .position(|part| *part == self)
            .unwrap_or(0)
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct Extent {
    offset: U32,
    length: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Header {
    parts: [Extent; PART_COUNT],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct ExpressionEntry {
    signature: U32,
    subsignature: U16,
    flags: u8,
    placement: u8,
    distance: U32,
    shift: U32,
    section: U32,
    first_step: U32,
    step_count: U32,
    text: Extent,
    forward: Extent,
    reverse: Extent,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct ComparisonEntry {
    signature: U32,
    subsignature: U16,
    reference: U16,
    encoding: u8,
    order: u8,
    exact: u8,
    value_count: u8,
    length: U32,
    displacement: U64,
    first_value: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct ValueEntry {
    kind: u8,
    reserved: [u8; 7],
    value: U64,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct ImageHashEntry {
    hash: U64,
    signature: U32,
    subsignature: U16,
    reserved: U16,
}

pub struct PendingExpression {
    pub signature: LogicalSignatureId,
    pub subsignature: u16,
    pub expression: RegularExpressionSubsignature,
    pub subsignature_count: usize,
}

pub struct PendingComparison {
    pub signature: LogicalSignatureId,
    pub subsignature: u16,
    pub comparison: ByteComparison,
}

pub struct PendingImageHash {
    pub signature: LogicalSignatureId,
    pub subsignature: u16,
    pub hash: u64,
}

#[derive(Default)]
pub struct PendingPlugIns {
    pub expressions: Vec<PendingExpression>,
    pub comparisons: Vec<PendingComparison>,
    pub image_hashes: Vec<PendingImageHash>,
}

impl PendingPlugIns {
    pub fn is_empty(&self) -> bool {
        self.expressions.is_empty() && self.comparisons.is_empty() && self.image_hashes.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlugInsNotBuilt {
    BeyondThirtyTwoBits,
    Trigger(TriggerNotCompiled),
    Expression(ExpressionNotCompiled),
}

fn too_large<T>(_: T) -> PlugInsNotBuilt {
    PlugInsNotBuilt::BeyondThirtyTwoBits
}

fn extent(start: usize, length: usize) -> Result<Extent, PlugInsNotBuilt> {
    Ok(Extent {
        offset: U32::new(u32::try_from(start).map_err(too_large)?),
        length: U32::new(u32::try_from(length).map_err(too_large)?),
    })
}

fn padded_to_alignment(bytes: &mut Vec<u8>) {
    while !bytes.len().is_multiple_of(AUTOMATON_ALIGNMENT) {
        bytes.push(0);
    }
}

#[derive(Default)]
struct Parts {
    expressions: Vec<ExpressionEntry>,
    steps: Vec<StepEntry>,
    comparisons: Vec<ComparisonEntry>,
    values: Vec<ValueEntry>,
    image_hashes: Vec<ImageHashEntry>,
    text: Vec<u8>,
    automata: Vec<u8>,
}

pub fn build(pending: &PendingPlugIns) -> Result<Vec<u8>, PlugInsNotBuilt> {
    let mut parts = Parts::default();
    for expression in &pending.expressions {
        parts.add_expression(expression)?;
    }
    for comparison in &pending.comparisons {
        parts.add_comparison(comparison)?;
    }
    let mut hashes: Vec<&PendingImageHash> = pending.image_hashes.iter().collect();
    hashes.sort_by_key(|hash| (hash.hash, hash.signature, hash.subsignature));
    parts.image_hashes = hashes
        .into_iter()
        .map(|hash| ImageHashEntry {
            hash: U64::new(hash.hash),
            signature: U32::new(hash.signature.0),
            subsignature: U16::new(hash.subsignature),
            reserved: U16::new(0),
        })
        .collect();
    assemble(parts)
}

fn assemble(parts: Parts) -> Result<Vec<u8>, PlugInsNotBuilt> {
    let contents: [Vec<u8>; PART_COUNT] = [
        parts.expressions.as_bytes().to_vec(),
        parts.steps.as_bytes().to_vec(),
        parts.comparisons.as_bytes().to_vec(),
        parts.values.as_bytes().to_vec(),
        parts.image_hashes.as_bytes().to_vec(),
        parts.text,
        parts.automata,
    ];
    let mut bytes = vec![0u8; std::mem::size_of::<Header>()];
    let mut header = Header {
        parts: [Extent {
            offset: U32::new(0),
            length: U32::new(0),
        }; PART_COUNT],
    };
    for (slot, part) in header.parts.iter_mut().zip(contents) {
        padded_to_alignment(&mut bytes);
        *slot = extent(bytes.len(), part.len())?;
        bytes.extend(part);
    }
    let header_bytes = header.as_bytes();
    if let Some(prefix) = bytes.get_mut(..header_bytes.len()) {
        prefix.copy_from_slice(header_bytes);
    }
    Ok(bytes)
}

impl Parts {
    fn add_text(&mut self, text: &str) -> Result<Extent, PlugInsNotBuilt> {
        let start = self.text.len();
        self.text.extend_from_slice(text.as_bytes());
        extent(start, text.len())
    }

    fn add_automaton(&mut self, automaton: &[u8]) -> Result<Extent, PlugInsNotBuilt> {
        padded_to_alignment(&mut self.automata);
        let start = self.automata.len();
        self.automata.extend_from_slice(automaton);
        extent(start, automaton.len())
    }

    fn add_steps(&mut self, steps: &[ExpressionStep]) -> Result<(u32, u32), PlugInsNotBuilt> {
        let first = u32::try_from(self.steps.len()).map_err(too_large)?;
        self.steps.extend(steps.iter().map(step_entry));
        Ok((first, u32::try_from(steps.len()).map_err(too_large)?))
    }

    fn add_expression(&mut self, pending: &PendingExpression) -> Result<(), PlugInsNotBuilt> {
        let expression = &pending.expression;
        let mut flags = 0;
        let (first_step, step_count) = match &expression.trigger {
            None => {
                flags |= UNCONDITIONAL;
                (0, 0)
            }
            Some(trigger) => {
                let steps = postfix_steps(trigger, pending.subsignature_count)
                    .map_err(PlugInsNotBuilt::Trigger)?;
                if holds_with_no_matches(&steps) {
                    flags |= TRIGGER_HOLDS_WITHOUT_MATCHES;
                }
                self.add_steps(&steps)?
            }
        };
        flags |= match expression.anchoring {
            ExpressionAnchoring::AtAnUnshiftedPlacement => 0,
            ExpressionAnchoring::NeverAtThePlacement => SEARCHING_FROM_PLACEMENT,
            ExpressionAnchoring::AtTheSubjectStart => ANCHORED_AT_SUBJECT_START,
        };
        if expression.matches == ExpressionMatches::EveryOneNotOverlapping {
            flags |= EVERY_MATCH;
        }
        if expression.bounded_by_shift {
            flags |= BOUNDED_BY_SHIFT;
        }
        let built = crate::expression_automata::build(&expression.expression)
            .map_err(PlugInsNotBuilt::Expression)?;
        let text = self.add_text(&built.text)?;
        let empty = extent(0, 0)?;
        let (forward, reverse) = match built.compiled {
            CompiledExpression::InImage { forward, reverse } => {
                flags |= AUTOMATA_IN_IMAGE;
                (self.add_automaton(&forward)?, self.add_automaton(&reverse)?)
            }
            CompiledExpression::FromText => (empty, empty),
        };
        let placement = placement_fields(expression.placement);
        self.expressions.push(ExpressionEntry {
            signature: U32::new(pending.signature.0),
            subsignature: U16::new(pending.subsignature),
            flags,
            placement: placement.code,
            distance: U32::new(placement.distance),
            shift: U32::new(placement.shift),
            section: U32::new(placement.section),
            first_step: U32::new(first_step),
            step_count: U32::new(step_count),
            text,
            forward,
            reverse,
        });
        Ok(())
    }

    fn add_comparison(&mut self, pending: &PendingComparison) -> Result<(), PlugInsNotBuilt> {
        let comparison = &pending.comparison;
        let order_code = |order: ByteOrder| match order {
            ByteOrder::Little => ORDER_LITTLE,
            ByteOrder::Big => ORDER_BIG,
        };
        let (encoding, order) = match comparison.encoding {
            ByteEncoding::Binary(order) => (ENCODING_BINARY, order_code(order)),
            ByteEncoding::HexadecimalText(order) => (ENCODING_HEXADECIMAL_TEXT, order_code(order)),
            ByteEncoding::DecimalText => (ENCODING_DECIMAL_TEXT, ORDER_BIG),
            ByteEncoding::HexadecimalOrDecimalText(order) => {
                (ENCODING_HEXADECIMAL_OR_DECIMAL_TEXT, order_code(order))
            }
            ByteEncoding::NeverMatches => (ENCODING_NEVER_MATCHES, 0),
        };
        let first_value = u32::try_from(self.values.len()).map_err(too_large)?;
        for value in &comparison.comparisons {
            let (kind, value) = match value {
                ValueComparison::Equal(value) => (VALUE_EQUAL, *value),
                ValueComparison::Greater(value) => (VALUE_GREATER, *value),
                ValueComparison::Less(value) => (VALUE_LESS, *value),
            };
            self.values.push(ValueEntry {
                kind,
                reserved: [0; 7],
                value: U64::new(u64::from_le_bytes(value.to_le_bytes())),
            });
        }
        self.comparisons.push(ComparisonEntry {
            signature: U32::new(pending.signature.0),
            subsignature: U16::new(pending.subsignature),
            reference: U16::new(comparison.subsignature),
            encoding,
            order,
            exact: u8::from(comparison.exact),
            value_count: u8::try_from(comparison.comparisons.len()).map_err(too_large)?,
            length: U32::new(comparison.length),
            displacement: U64::new(u64::from_le_bytes(comparison.displacement.to_le_bytes())),
            first_value: U32::new(first_value),
        });
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlugInsMalformed {
    Layout,
    Expression,
    Comparison,
}

#[derive(Debug, Clone, Copy)]
pub struct ExpressionRecord<'m> {
    pub signature: LogicalSignatureId,
    pub subsignature: u16,
    pub placement: Placement,
    pub anchoring: ExpressionAnchoring,
    pub matches: ExpressionMatches,
    pub bounded_by_shift: bool,
    pub unconditional: bool,
    pub trigger_holds_without_matches: bool,
    pub automata: Option<(&'m [u8], &'m [u8])>,
    text: &'m [u8],
    first_step: u32,
    step_count: u32,
}

impl<'m> ExpressionRecord<'m> {
    pub fn text(&self) -> Result<&'m str, PlugInsMalformed> {
        std::str::from_utf8(self.text).map_err(|_| PlugInsMalformed::Expression)
    }
}

#[derive(Clone, Copy)]
pub struct PlugInSubsignatures<'m> {
    expressions: &'m [ExpressionEntry],
    steps: &'m [StepEntry],
    comparisons: &'m [ComparisonEntry],
    values: &'m [ValueEntry],
    image_hashes: &'m [ImageHashEntry],
    text: &'m [u8],
    automata: &'m [u8],
}

fn layout<E>(_: E) -> PlugInsMalformed {
    PlugInsMalformed::Layout
}

fn slice_of(bytes: &[u8], extent: Extent) -> Option<&[u8]> {
    let start = usize::try_from(extent.offset.get()).ok()?;
    let end = start.checked_add(usize::try_from(extent.length.get()).ok()?)?;
    bytes.get(start..end)
}

impl<'m> PlugInSubsignatures<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, PlugInsMalformed> {
        let (header, _) = Header::ref_from_prefix(bytes).map_err(layout)?;
        let part = |part: Part| -> Result<&'m [u8], PlugInsMalformed> {
            header
                .parts
                .get(part.index())
                .and_then(|extent| slice_of(bytes, *extent))
                .ok_or(PlugInsMalformed::Layout)
        };
        Ok(Self {
            expressions: <[ExpressionEntry]>::ref_from_bytes(part(Part::Expressions)?)
                .map_err(layout)?,
            steps: <[StepEntry]>::ref_from_bytes(part(Part::Steps)?).map_err(layout)?,
            comparisons: <[ComparisonEntry]>::ref_from_bytes(part(Part::Comparisons)?)
                .map_err(layout)?,
            values: <[ValueEntry]>::ref_from_bytes(part(Part::Values)?).map_err(layout)?,
            image_hashes: <[ImageHashEntry]>::ref_from_bytes(part(Part::ImageHashes)?)
                .map_err(layout)?,
            text: part(Part::Text)?,
            automata: part(Part::Automata)?,
        })
    }

    #[must_use]
    pub fn expression_count(&self) -> usize {
        self.expressions.len()
    }

    #[must_use]
    pub fn comparison_count(&self) -> usize {
        self.comparisons.len()
    }

    #[must_use]
    pub fn image_hash_count(&self) -> usize {
        self.image_hashes.len()
    }

    #[must_use]
    pub fn automata_bytes(&self) -> usize {
        self.automata.len()
    }

    pub fn expressions(
        &self,
    ) -> impl Iterator<Item = Result<ExpressionRecord<'m>, PlugInsMalformed>> + 'm {
        let text = self.text;
        let automata = self.automata;
        self.expressions
            .iter()
            .map(move |entry| expression_record(entry, text, automata))
    }

    pub fn trigger_holds(
        &self,
        record: &ExpressionRecord<'m>,
        matches_of: impl Fn(u16) -> u64,
    ) -> Result<bool, PlugInsMalformed> {
        if record.unconditional {
            return Ok(true);
        }
        let first = usize::try_from(record.first_step).map_err(layout)?;
        let count = usize::try_from(record.step_count).map_err(layout)?;
        let steps = self
            .steps
            .get(
                first
                    ..first
                        .checked_add(count)
                        .ok_or(PlugInsMalformed::Expression)?,
            )
            .ok_or(PlugInsMalformed::Expression)?;
        expression_holds(steps.iter().map(step_of), matches_of)
            .map_err(|ExpressionMalformed| PlugInsMalformed::Expression)
    }

    pub fn comparisons(
        &self,
    ) -> impl Iterator<Item = Result<ComparisonRecord, PlugInsMalformed>> + 'm {
        let values = self.values;
        self.comparisons
            .iter()
            .map(move |entry| comparison_record(entry, values))
    }

    pub fn image_hash_subsignatures(
        &self,
        hash: u64,
    ) -> impl Iterator<Item = (LogicalSignatureId, u16)> + 'm {
        let first = self
            .image_hashes
            .partition_point(|entry| entry.hash.get() < hash);
        self.image_hashes
            .get(first..)
            .unwrap_or_default()
            .iter()
            .take_while(move |entry| entry.hash.get() == hash)
            .map(|entry| {
                (
                    LogicalSignatureId(entry.signature.get()),
                    entry.subsignature.get(),
                )
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonRecord {
    pub signature: LogicalSignatureId,
    pub subsignature: u16,
    pub comparison: ByteComparison,
}

fn expression_record<'m>(
    entry: &ExpressionEntry,
    text: &'m [u8],
    automata: &'m [u8],
) -> Result<ExpressionRecord<'m>, PlugInsMalformed> {
    let flags = entry.flags;
    let has = |flag: u8| flags & flag != 0;
    let text = slice_of(text, entry.text).ok_or(PlugInsMalformed::Expression)?;
    let automata = if has(AUTOMATA_IN_IMAGE) {
        Some((
            slice_of(automata, entry.forward).ok_or(PlugInsMalformed::Expression)?,
            slice_of(automata, entry.reverse).ok_or(PlugInsMalformed::Expression)?,
        ))
    } else {
        None
    };
    Ok(ExpressionRecord {
        signature: LogicalSignatureId(entry.signature.get()),
        subsignature: entry.subsignature.get(),
        placement: placement_of(
            entry.placement,
            entry.distance.get(),
            entry.shift.get(),
            entry.section.get(),
        )
        .ok_or(PlugInsMalformed::Expression)?,
        anchoring: if has(ANCHORED_AT_SUBJECT_START) {
            ExpressionAnchoring::AtTheSubjectStart
        } else if has(SEARCHING_FROM_PLACEMENT) {
            ExpressionAnchoring::NeverAtThePlacement
        } else {
            ExpressionAnchoring::AtAnUnshiftedPlacement
        },
        matches: if has(EVERY_MATCH) {
            ExpressionMatches::EveryOneNotOverlapping
        } else {
            ExpressionMatches::First
        },
        bounded_by_shift: has(BOUNDED_BY_SHIFT),
        unconditional: has(UNCONDITIONAL),
        trigger_holds_without_matches: has(TRIGGER_HOLDS_WITHOUT_MATCHES),
        text,
        automata,
        first_step: entry.first_step.get(),
        step_count: entry.step_count.get(),
    })
}

fn comparison_record(
    entry: &ComparisonEntry,
    values: &[ValueEntry],
) -> Result<ComparisonRecord, PlugInsMalformed> {
    let order = match entry.order {
        ORDER_LITTLE => Some(ByteOrder::Little),
        ORDER_BIG => Some(ByteOrder::Big),
        _ => None,
    };
    let encoding = match (entry.encoding, order) {
        (ENCODING_BINARY, Some(order)) => ByteEncoding::Binary(order),
        (ENCODING_HEXADECIMAL_TEXT, Some(order)) => ByteEncoding::HexadecimalText(order),
        (ENCODING_DECIMAL_TEXT, _) => ByteEncoding::DecimalText,
        (ENCODING_HEXADECIMAL_OR_DECIMAL_TEXT, Some(order)) => {
            ByteEncoding::HexadecimalOrDecimalText(order)
        }
        (ENCODING_NEVER_MATCHES, _) => ByteEncoding::NeverMatches,
        _ => return Err(PlugInsMalformed::Comparison),
    };
    let first = usize::try_from(entry.first_value.get()).map_err(layout)?;
    let comparisons = values
        .get(first..first.saturating_add(usize::from(entry.value_count)))
        .ok_or(PlugInsMalformed::Comparison)?
        .iter()
        .map(|value| {
            let number = i64::from_le_bytes(value.value.get().to_le_bytes());
            match value.kind {
                VALUE_EQUAL => Ok(ValueComparison::Equal(number)),
                VALUE_GREATER => Ok(ValueComparison::Greater(number)),
                VALUE_LESS => Ok(ValueComparison::Less(number)),
                _ => Err(PlugInsMalformed::Comparison),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ComparisonRecord {
        signature: LogicalSignatureId(entry.signature.get()),
        subsignature: entry.subsignature.get(),
        comparison: ByteComparison {
            subsignature: entry.reference.get(),
            displacement: i64::from_le_bytes(entry.displacement.get().to_le_bytes()),
            encoding,
            length: entry.length.get(),
            exact: entry.exact != 0,
            comparisons,
        },
    })
}
