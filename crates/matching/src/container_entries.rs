use std::fmt;

use debar_image::{
    AutomatonMalformed, ContainerSignatureRecord, EntryNameExpression, Image, ImageError,
    Indicator, KindCondition, ObjectKind, automaton_in_place, compile_text,
};
use regex_automata::Input;
use regex_automata::dfa::Automaton;
use zerocopy::IntoBytes;

use crate::pattern_scan::PatternDetection;
use crate::plug_in_matching::aligned_copy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerEntry<'e> {
    pub container: ObjectKind,
    pub container_size: u64,
    pub name: Option<&'e [u8]>,
    pub compressed_size: u64,
    pub real_size: u64,
    pub encrypted: bool,
    pub position: u64,
}

#[derive(Debug)]
pub enum ContainerEntryError {
    Image(ImageError),
    EntryNameExpression,
}

impl fmt::Display for ContainerEntryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image(error) => write!(formatter, "{error}"),
            Self::EntryNameExpression => {
                formatter.write_str("a container signature's entry name expression is malformed")
            }
        }
    }
}

impl std::error::Error for ContainerEntryError {}

impl From<ImageError> for ContainerEntryError {
    fn from(error: ImageError) -> Self {
        Self::Image(error)
    }
}

pub fn container_entry_detections(
    image: &Image<'_>,
    entry: &ContainerEntry<'_>,
    every_match: bool,
) -> Result<Vec<PatternDetection>, ContainerEntryError> {
    let Some(signatures) = image.container_signatures()? else {
        return Ok(Vec::new());
    };
    let mut detections = Vec::new();
    for record in signatures.in_test_order() {
        let record = record.map_err(|_| ImageError::ContainerSignaturesMalformed)?;
        if !holds(&record, entry)? {
            continue;
        }
        let name = image.signature_name(record.name)?;
        let strong = name.indicator == Indicator::Strong;
        detections.push(PatternDetection {
            name: name.text,
            indicator: name.indicator,
        });
        if strong && !every_match {
            break;
        }
    }
    Ok(detections)
}

fn holds(
    record: &ContainerSignatureRecord<'_>,
    entry: &ContainerEntry<'_>,
) -> Result<bool, ContainerEntryError> {
    let container_holds = match record.container {
        KindCondition::AnyKind => true,
        KindCondition::Kind(kind) => kind == entry.container,
    };
    let facts_hold = container_holds
        && record
            .encrypted
            .is_none_or(|encrypted| encrypted == entry.encrypted)
        && record.container_size.holds(entry.container_size)
        && record.compressed_size.holds(entry.compressed_size)
        && record.real_size.holds(entry.real_size)
        && record.position.holds(entry.position);
    if !facts_hold {
        return Ok(false);
    }
    match (record.entry_name, entry.name) {
        (None, _) => Ok(true),
        (Some(_), None) => Ok(false),
        (Some(expression), Some(name)) => name_matches(expression, name)
            .map_err(|AutomatonMalformed| ContainerEntryError::EntryNameExpression),
    }
}

fn name_matches(
    expression: EntryNameExpression<'_>,
    name: &[u8],
) -> Result<bool, AutomatonMalformed> {
    let Some(bytes) = expression.automaton else {
        return Ok(compile_text(expression.text)?.is_match(name));
    };
    let copy;
    let automaton = if let Ok(automaton) = automaton_in_place(bytes) {
        automaton
    } else {
        copy = aligned_copy(bytes);
        automaton_in_place(copy.as_bytes())?
    };
    automaton
        .try_search_fwd(&Input::new(name).earliest(true))
        .map(|found| found.is_some())
        .map_err(|_| AutomatonMalformed)
}
