use std::fmt;

use debar_image::{ImageError, ObjectKind};
use debar_matching::PatternScanError;
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
pub enum Limit {
    LargestFile,
    LargestScan,
    MostFiles,
    DeepestLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitEvent {
    pub limit: Limit,
    pub layer: LayerId,
}

#[derive(Debug)]
pub enum ScanFailure {
    Input(InputError),
    Image(ImageError),
    Patterns(PatternScanError),
    Typing(TypingError),
    KindNotDescribed(ObjectKind),
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
}
