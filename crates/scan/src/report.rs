use std::fmt;

use debar_formats::{Fact, Limit};
use debar_image::{ImageError, ObjectKind};
use debar_matching::{ContainerEntryError, PatternScanError};
use debar_platform::input::InputError;

use crate::typing::TypingError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LayerId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    NothingFound,
    Trusted,
    StrongIndicator,
    PotentiallyUnwanted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reported {
    pub name: String,
    pub layer: LayerId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitEvent {
    pub limit: Limit,
    pub layer: LayerId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectFact {
    pub layer: LayerId,
    pub fact: Fact,
}

#[derive(Debug)]
pub enum ScanFailure {
    Input(InputError),
    Image(ImageError),
    Patterns(PatternScanError),
    Typing(TypingError),
    KindNotDescribed(ObjectKind),
    ContainerEntries(ContainerEntryError),
    PartOutsideItsObject {
        offset: u64,
        length: u64,
        object_length: u64,
    },
    ProducedBeyondRoom {
        length: u64,
        room: u64,
    },
    ModuleOutputsBeyondBound {
        most: u64,
    },
}

impl fmt::Display for ScanFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => write!(formatter, "{error}"),
            Self::Image(error) => write!(formatter, "cannot use the image: {error}"),
            Self::Patterns(error) => write!(formatter, "cannot match the patterns: {error}"),
            Self::Typing(error) => write!(formatter, "cannot type the object: {error}"),
            Self::KindNotDescribed(kind) => {
                write!(formatter, "the image does not describe the kind {kind:?}")
            }
            Self::ContainerEntries(error) => {
                write!(formatter, "cannot test a container entry: {error}")
            }
            Self::PartOutsideItsObject {
                offset,
                length,
                object_length,
            } => write!(
                formatter,
                "a format module gave a part of {length} bytes at {offset}, beyond the {object_length} bytes of its object"
            ),
            Self::ProducedBeyondRoom { length, room } => write!(
                formatter,
                "a format module produced {length} bytes to hold where {room} bytes were left to it"
            ),
            Self::ModuleOutputsBeyondBound { most } => write!(
                formatter,
                "format modules gave more than {most} views, entries and facts in one scan"
            ),
        }
    }
}

impl std::error::Error for ScanFailure {}

impl From<InputError> for ScanFailure {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl From<ImageError> for ScanFailure {
    fn from(error: ImageError) -> Self {
        Self::Image(error)
    }
}

impl From<PatternScanError> for ScanFailure {
    fn from(error: PatternScanError) -> Self {
        match error {
            PatternScanError::Input(error) => Self::Input(error),
            error => Self::Patterns(error),
        }
    }
}

impl From<ContainerEntryError> for ScanFailure {
    fn from(error: ContainerEntryError) -> Self {
        Self::ContainerEntries(error)
    }
}

impl From<TypingError> for ScanFailure {
    fn from(error: TypingError) -> Self {
        Self::Typing(error)
    }
}

#[derive(Debug)]
pub enum Completion {
    Complete,
    Incomplete(ScanFailure),
}

#[derive(Debug)]
pub struct ScanReport {
    pub verdict: Verdict,
    pub reported: Vec<Reported>,
    pub completion: Completion,
    pub limits: Vec<LimitEvent>,
    pub facts: Vec<ObjectFact>,
    pub work_spent: u64,
}
