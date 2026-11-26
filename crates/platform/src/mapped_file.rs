use std::fmt;
use std::fs::File;
use std::io;
use std::ops::Range;
use std::path::{Path, PathBuf};

use memmap2::{Advice, Mmap};

pub struct MappedFile {
    contents: Contents,
}

enum Contents {
    Empty,
    Mapped(Mmap),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedAccess {
    Random,
    Sequential,
    SoonNeeded,
}

#[derive(Debug)]
pub enum MappingError {
    Open { path: PathBuf, reason: io::Error },
    Map { path: PathBuf, reason: io::Error },
    RangeOutsideTheFile { range: Range<usize>, length: usize },
    Advise { reason: io::Error },
}

impl fmt::Display for MappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, reason } => {
                write!(formatter, "cannot open {}: {reason}", path.display())
            }
            Self::Map { path, reason } => {
                write!(
                    formatter,
                    "cannot map {} into memory: {reason}",
                    path.display()
                )
            }
            Self::RangeOutsideTheFile { range, length } => write!(
                formatter,
                "the range {range:?} is outside a mapped file of {length} bytes"
            ),
            Self::Advise { reason } => {
                write!(
                    formatter,
                    "the kernel refused advice on a mapping: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for MappingError {}

impl MappedFile {
    pub fn open(path: &Path) -> Result<Self, MappingError> {
        let file = File::open(path).map_err(|reason| MappingError::Open {
            path: path.to_path_buf(),
            reason,
        })?;
        let length = file
            .metadata()
            .map_err(|reason| MappingError::Open {
                path: path.to_path_buf(),
                reason,
            })?
            .len();
        if length == 0 {
            return Ok(Self {
                contents: Contents::Empty,
            });
        }
        // SAFETY: the mapping is read-only and shared, and only files that are
        // never modified or truncated once written are mapped: an image is
        // written under another name and renamed into place. A file changed
        // in place while mapped would change the bytes under the returned
        // slices, and truncating it would raise SIGBUS on access.
        let mapping = unsafe { Mmap::map(&file) }.map_err(|reason| MappingError::Map {
            path: path.to_path_buf(),
            reason,
        })?;
        Ok(Self {
            contents: Contents::Mapped(mapping),
        })
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match &self.contents {
            Contents::Empty => &[],
            Contents::Mapped(mapping) => mapping,
        }
    }

    pub fn advise(&self, range: Range<usize>, access: ExpectedAccess) -> Result<(), MappingError> {
        let length = self.bytes().len();
        if range.start > range.end || range.end > length {
            return Err(MappingError::RangeOutsideTheFile { range, length });
        }
        let Contents::Mapped(mapping) = &self.contents else {
            return Ok(());
        };
        if range.is_empty() {
            return Ok(());
        }
        let advice = match access {
            ExpectedAccess::Random => Advice::Random,
            ExpectedAccess::Sequential => Advice::Sequential,
            ExpectedAccess::SoonNeeded => Advice::WillNeed,
        };
        mapping
            .advise_range(advice, range.start, range.len())
            .map_err(|reason| MappingError::Advise { reason })
    }
}
