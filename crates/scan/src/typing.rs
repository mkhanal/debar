use std::fmt;

use debar_image::{
    ByteSet, Image, ImageError, KindsMalformed, MagicMalformed, MagicTable, ObjectKind,
    ObjectKinds, TypingRules,
};
use debar_matching::{
    GroupSelection, ObjectContext, PatternRequest, PatternScan, PatternScanError, PatternSettings,
    TypeFound, UnwantedCategories,
};

const LITTLE_ENDIAN_MARK: [u8; 2] = [0xff, 0xfe];
const BIG_ENDIAN_MARK: [u8; 2] = [0xfe, 0xff];
const NOT_A_CHARACTER: u16 = 0xfffe;
const NARROW_CHARACTERS: u16 = 128;
const WIDE_HIGH_BYTE_SHIFT: u32 = 4;

#[derive(Debug)]
pub enum TypingError {
    Image(ImageError),
    Kinds(KindsMalformed),
    Magic(MagicMalformed),
    Patterns(PatternScanError),
    NoKinds,
}

impl fmt::Display for TypingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image(error) => write!(formatter, "{error}"),
            Self::Kinds(error) => write!(formatter, "the object kinds are malformed: {error:?}"),
            Self::Magic(error) => write!(formatter, "the type magic is malformed: {error:?}"),
            Self::Patterns(error) => write!(formatter, "{error}"),
            Self::NoKinds => write!(formatter, "the image does not describe any object kind"),
        }
    }
}

impl std::error::Error for TypingError {}

impl From<ImageError> for TypingError {
    fn from(error: ImageError) -> Self {
        Self::Image(error)
    }
}

impl From<PatternScanError> for TypingError {
    fn from(error: PatternScanError) -> Self {
        Self::Patterns(error)
    }
}

pub fn kind_from_first_bytes(image: &Image<'_>, object: &[u8]) -> Result<ObjectKind, TypingError> {
    let kinds = image.object_kinds()?.ok_or(TypingError::NoKinds)?;
    let rules = kinds.typing_rules();
    let prefix_length = usize::try_from(rules.prefix_length).unwrap_or(usize::MAX);
    let first_bytes = object.get(..prefix_length).unwrap_or(object);
    if let Some(magic) = image.type_magic()?
        && let Some(kind) = magic
            .first_match(MagicTable::Files, first_bytes)
            .map_err(TypingError::Magic)?
    {
        return Ok(kind);
    }
    let text_kind = text_kind(first_bytes, &rules.text_bytes);
    if let Some(found) = recognised_in(image, &kinds, first_bytes, text_kind)? {
        return Ok(found);
    }
    Ok(wide_text_kind(image, &kinds, &rules, first_bytes)?.unwrap_or(text_kind))
}

pub fn kind_after_full_scan(
    image: &Image<'_>,
    kind: ObjectKind,
    types_found: &[TypeFound],
) -> Result<ObjectKind, TypingError> {
    let kinds = image.object_kinds()?.ok_or(TypingError::NoKinds)?;
    let Some(winner) = winning_kind(&kinds, types_found)? else {
        return Ok(kind);
    };
    let retypes = kinds
        .describe(winner)
        .map_err(TypingError::Kinds)?
        .is_some_and(|description| description.retypes_when_found_in(kind));
    Ok(if retypes { winner } else { kind })
}

fn text_kind(first_bytes: &[u8], text_bytes: &ByteSet) -> ObjectKind {
    if first_bytes.iter().all(|byte| text_bytes.contains(*byte)) {
        return ObjectKind::Text;
    }
    wide_text(first_bytes, text_bytes).unwrap_or(ObjectKind::BinaryData)
}

fn wide_text(first_bytes: &[u8], text_bytes: &ByteSet) -> Option<ObjectKind> {
    if first_bytes.len() < 2 {
        return None;
    }
    let mark = first_bytes.get(..2)?;
    let little_endian = mark == LITTLE_ENDIAN_MARK;
    let marked = little_endian || mark == BIG_ENDIAN_MARK;
    let mut unexpected = 0usize;
    for [first, second] in first_bytes.get(2..)?.as_chunks::<2>().0 {
        let character = if little_endian {
            u16::from_le_bytes([*first, *second])
        } else {
            u16::from_be_bytes([*first, *second])
        };
        if character == NOT_A_CHARACTER {
            return None;
        }
        let narrow_but_not_text = character < NARROW_CHARACTERS
            && u8::try_from(character).is_ok_and(|byte| !text_bytes.contains(byte));
        if narrow_but_not_text {
            if !marked {
                return None;
            }
            unexpected = unexpected.saturating_add(1);
        }
    }
    if marked && unexpected >= first_bytes.len() / 2 {
        return None;
    }
    Some(if little_endian {
        ObjectKind::TextUtf16LittleEndian
    } else {
        ObjectKind::TextUtf16BigEndian
    })
}

fn wide_text_kind(
    image: &Image<'_>,
    kinds: &ObjectKinds<'_>,
    rules: &TypingRules,
    first_bytes: &[u8],
) -> Result<Option<ObjectKind>, TypingError> {
    let Some(retry) = rules.wide_text_retry else {
        return Ok(None);
    };
    let narrowed: Vec<u8> = first_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[low, high]| {
            let low = i32::from(i8::from_le_bytes([*low]));
            let high = i32::from(*high).wrapping_shl(WIDE_HIGH_BYTE_SHIFT);
            let [narrow, ..] = high.wrapping_add(low).to_le_bytes();
            narrow
        })
        .collect();
    let found = recognition_winner(image, kinds, &narrowed, ObjectKind::Text)?;
    Ok((found == Some(retry.found)).then_some(retry.becomes))
}

fn recognised_in(
    image: &Image<'_>,
    kinds: &ObjectKinds<'_>,
    first_bytes: &[u8],
    current: ObjectKind,
) -> Result<Option<ObjectKind>, TypingError> {
    let Some(winner) = recognition_winner(image, kinds, first_bytes, current)? else {
        return Ok(None);
    };
    let left_for_the_full_scan = kinds
        .describe(winner)
        .map_err(TypingError::Kinds)?
        .is_some_and(|description| description.recognition.left_for_the_full_scan);
    Ok((!left_for_the_full_scan).then_some(winner))
}

fn recognition_winner(
    image: &Image<'_>,
    kinds: &ObjectKinds<'_>,
    bytes: &[u8],
    current: ObjectKind,
) -> Result<Option<ObjectKind>, TypingError> {
    if kinds.typing_rules().recognition_group.is_none() {
        return Ok(None);
    }
    let request = PatternRequest {
        selection: GroupSelection::TypeRecognitionOnly(current),
        settings: PatternSettings {
            potentially_unwanted: false,
            unwanted_categories: UnwantedCategories::Every,
            every_match: true,
        },
        object_length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        context: ObjectContext::TOP_LEVEL,
    };
    let mut scan = PatternScan::new(image, request, || None)?;
    scan.feed(bytes)?;
    winning_kind(kinds, &scan.finish()?.into_outcomes()?.types_found)
}

fn winning_kind(
    kinds: &ObjectKinds<'_>,
    types_found: &[TypeFound],
) -> Result<Option<ObjectKind>, TypingError> {
    let mut winner: Option<(ObjectKind, u32)> = None;
    for found in types_found {
        let Some(description) = kinds.describe(found.kind).map_err(TypingError::Kinds)? else {
            continue;
        };
        let rank = description.recognition;
        if rank.ends_recognition {
            return Ok(Some(found.kind));
        }
        let outranks = winner.is_none_or(|(_, priority)| rank.priority > priority);
        if outranks || rank.always_replaces {
            winner = Some((found.kind, rank.priority));
        }
    }
    Ok(winner.map(|(kind, _)| kind))
}
