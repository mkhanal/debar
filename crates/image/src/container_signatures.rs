use zerocopy::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::expression_automata::{AUTOMATON_ALIGNMENT, ExpressionNotCompiled, build_search};
use crate::model::{KindCondition, SizeCondition};
use crate::names::NameId;
use crate::object_kind::ObjectKind;
use regex_syntax::hir::Hir;

const ANY_KIND: u16 = u16::MAX;
const SIZE_ANY: u8 = 0;
const SIZE_EXACTLY: u8 = 1;
const SIZE_BETWEEN: u8 = 2;
const UNBOUNDED: u32 = 0;
const ENCRYPTED_ANY: u8 = 0;
const ENCRYPTED_NO: u8 = 1;
const ENCRYPTED_YES: u8 = 2;
const HAS_ENTRY_NAME: u8 = 1;
const ENTRY_NAME_IN_IMAGE: u8 = 2;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct SizeEntry {
    kind: u8,
    lowest: U32,
    highest: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
struct ContainerEntry {
    name: U32,
    container: U16,
    encrypted: u8,
    flags: u8,
    container_size: SizeEntry,
    compressed_size: SizeEntry,
    real_size: SizeEntry,
    position: SizeEntry,
    text_start: U32,
    text_length: U32,
    automaton_start: U32,
    automaton_length: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Header {
    count: U32,
    text_offset: U32,
    text_length: U32,
    automata_offset: U32,
    automata_length: U32,
}

pub struct PendingContainerSignature {
    pub name: NameId,
    pub container: KindCondition,
    pub container_size: SizeCondition,
    pub entry_name: Option<Hir>,
    pub compressed_size: SizeCondition,
    pub real_size: SizeCondition,
    pub encrypted: Option<bool>,
    pub position: SizeCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerSignaturesNotBuilt {
    BeyondThirtyTwoBits,
    EntryName(ExpressionNotCompiled),
}

fn too_large<T>(_: T) -> ContainerSignaturesNotBuilt {
    ContainerSignaturesNotBuilt::BeyondThirtyTwoBits
}

fn size_entry(condition: SizeCondition) -> SizeEntry {
    let (kind, lowest, highest) = match condition {
        SizeCondition::Any => (SIZE_ANY, 0, 0),
        SizeCondition::Exactly(value) => (SIZE_EXACTLY, value, value),
        SizeCondition::Between { lowest, highest } => (
            SIZE_BETWEEN,
            lowest.unwrap_or(UNBOUNDED),
            highest.unwrap_or(UNBOUNDED),
        ),
    };
    SizeEntry {
        kind,
        lowest: U32::new(lowest),
        highest: U32::new(highest),
    }
}

fn size_condition(entry: &SizeEntry) -> Option<SizeCondition> {
    let bound = |value: u32| (value != UNBOUNDED).then_some(value);
    match entry.kind {
        SIZE_ANY => Some(SizeCondition::Any),
        SIZE_EXACTLY => Some(SizeCondition::Exactly(entry.lowest.get())),
        SIZE_BETWEEN => Some(SizeCondition::Between {
            lowest: bound(entry.lowest.get()),
            highest: bound(entry.highest.get()),
        }),
        _ => None,
    }
}

fn u32_of(value: usize) -> Result<U32, ContainerSignaturesNotBuilt> {
    Ok(U32::new(u32::try_from(value).map_err(too_large)?))
}

pub fn build(
    signatures_in_test_order: &[PendingContainerSignature],
) -> Result<Vec<u8>, ContainerSignaturesNotBuilt> {
    let mut entries = Vec::with_capacity(signatures_in_test_order.len());
    let mut text = Vec::new();
    let mut automata: Vec<u8> = Vec::new();
    for signature in signatures_in_test_order {
        let mut flags = 0;
        let (mut text_start, mut text_length, mut automaton_start, mut automaton_length) =
            (0, 0, 0, 0);
        if let Some(entry_name) = &signature.entry_name {
            flags |= HAS_ENTRY_NAME;
            let built = build_search(entry_name).map_err(ContainerSignaturesNotBuilt::EntryName)?;
            text_start = text.len();
            text_length = built.text.len();
            text.extend_from_slice(built.text.as_bytes());
            if let Some(automaton) = built.automaton {
                flags |= ENTRY_NAME_IN_IMAGE;
                while !automata.len().is_multiple_of(AUTOMATON_ALIGNMENT) {
                    automata.push(0);
                }
                automaton_start = automata.len();
                automaton_length = automaton.len();
                automata.extend(automaton);
            }
        }
        entries.push(ContainerEntry {
            name: U32::new(signature.name.0),
            container: U16::new(match signature.container {
                KindCondition::AnyKind => ANY_KIND,
                KindCondition::Kind(kind) => kind.code(),
            }),
            encrypted: match signature.encrypted {
                None => ENCRYPTED_ANY,
                Some(false) => ENCRYPTED_NO,
                Some(true) => ENCRYPTED_YES,
            },
            flags,
            container_size: size_entry(signature.container_size),
            compressed_size: size_entry(signature.compressed_size),
            real_size: size_entry(signature.real_size),
            position: size_entry(signature.position),
            text_start: u32_of(text_start)?,
            text_length: u32_of(text_length)?,
            automaton_start: u32_of(automaton_start)?,
            automaton_length: u32_of(automaton_length)?,
        });
    }
    let mut bytes = vec![0u8; std::mem::size_of::<Header>()];
    bytes.extend_from_slice(entries.as_bytes());
    let text_offset = bytes.len();
    bytes.extend_from_slice(&text);
    while !bytes.len().is_multiple_of(AUTOMATON_ALIGNMENT) {
        bytes.push(0);
    }
    let automata_offset = bytes.len();
    bytes.extend_from_slice(&automata);
    let header = Header {
        count: u32_of(entries.len())?,
        text_offset: u32_of(text_offset)?,
        text_length: u32_of(text.len())?,
        automata_offset: u32_of(automata_offset)?,
        automata_length: u32_of(automata.len())?,
    };
    if let Some(prefix) = bytes.get_mut(..std::mem::size_of::<Header>()) {
        prefix.copy_from_slice(header.as_bytes());
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerSignaturesMalformed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryNameExpression<'m> {
    pub text: &'m str,
    pub automaton: Option<&'m [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerSignatureRecord<'m> {
    pub name: NameId,
    pub container: KindCondition,
    pub container_size: SizeCondition,
    pub entry_name: Option<EntryNameExpression<'m>>,
    pub compressed_size: SizeCondition,
    pub real_size: SizeCondition,
    pub encrypted: Option<bool>,
    pub position: SizeCondition,
}

#[derive(Clone, Copy)]
pub struct ContainerSignatures<'m> {
    entries: &'m [ContainerEntry],
    text: &'m [u8],
    automata: &'m [u8],
}

fn region(bytes: &[u8], offset: U32, length: U32) -> Option<&[u8]> {
    let start = usize::try_from(offset.get()).ok()?;
    bytes.get(start..start.checked_add(usize::try_from(length.get()).ok()?)?)
}

impl<'m> ContainerSignatures<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, ContainerSignaturesMalformed> {
        let (header, rest) =
            Header::ref_from_prefix(bytes).map_err(|_| ContainerSignaturesMalformed)?;
        let count =
            usize::try_from(header.count.get()).map_err(|_| ContainerSignaturesMalformed)?;
        let (entries, _) = <[ContainerEntry]>::ref_from_prefix_with_elems(rest, count)
            .map_err(|_| ContainerSignaturesMalformed)?;
        Ok(Self {
            entries,
            text: region(bytes, header.text_offset, header.text_length)
                .ok_or(ContainerSignaturesMalformed)?,
            automata: region(bytes, header.automata_offset, header.automata_length)
                .ok_or(ContainerSignaturesMalformed)?,
        })
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    pub fn in_test_order(
        &self,
    ) -> impl Iterator<Item = Result<ContainerSignatureRecord<'m>, ContainerSignaturesMalformed>> + 'm
    {
        let text = self.text;
        let automata = self.automata;
        self.entries
            .iter()
            .map(move |entry| record_of(entry, text, automata).ok_or(ContainerSignaturesMalformed))
    }
}

fn record_of<'m>(
    entry: &ContainerEntry,
    text: &'m [u8],
    automata: &'m [u8],
) -> Option<ContainerSignatureRecord<'m>> {
    let entry_name = if entry.flags & HAS_ENTRY_NAME == 0 {
        None
    } else {
        Some(EntryNameExpression {
            text: std::str::from_utf8(region(text, entry.text_start, entry.text_length)?).ok()?,
            automaton: if entry.flags & ENTRY_NAME_IN_IMAGE == 0 {
                None
            } else {
                Some(region(
                    automata,
                    entry.automaton_start,
                    entry.automaton_length,
                )?)
            },
        })
    };
    let container = match entry.container.get() {
        ANY_KIND => KindCondition::AnyKind,
        code => KindCondition::Kind(ObjectKind::from_code(code)?),
    };
    Some(ContainerSignatureRecord {
        name: NameId(entry.name.get()),
        container,
        container_size: size_condition(&entry.container_size)?,
        entry_name,
        compressed_size: size_condition(&entry.compressed_size)?,
        real_size: size_condition(&entry.real_size)?,
        encrypted: match entry.encrypted {
            ENCRYPTED_ANY => None,
            ENCRYPTED_NO => Some(false),
            ENCRYPTED_YES => Some(true),
            _ => return None,
        },
        position: size_condition(&entry.position)?,
    })
}
