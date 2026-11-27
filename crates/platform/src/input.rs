use std::cell::Cell;
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum InputError {
    Unopenable {
        path: PathBuf,
        reason: io::Error,
    },
    Directory {
        path: PathBuf,
    },
    StreamTooLarge {
        largest: u64,
    },
    Unreadable {
        offset: u64,
        reason: io::Error,
    },
    ChangedWhileScanned {
        length_when_opened: u64,
        ended_at: u64,
    },
    BeyondTheEnd {
        offset: u64,
        wanted: u64,
        length: u64,
    },
    AllowanceSpent {
        allowance: u64,
    },
}

impl fmt::Display for InputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unopenable { path, reason } => {
                write!(
                    formatter,
                    "cannot open {} to scan it: {reason}",
                    path.display()
                )
            }
            Self::Directory { path } => {
                write!(formatter, "{} is a directory, not a file", path.display())
            }
            Self::StreamTooLarge { largest } => write!(
                formatter,
                "the scanned stream is longer than the {largest} bytes Debar holds of a stream"
            ),
            Self::Unreadable { offset, reason } => {
                write!(
                    formatter,
                    "cannot read the scanned file at {offset}: {reason}"
                )
            }
            Self::ChangedWhileScanned {
                length_when_opened,
                ended_at,
            } => write!(
                formatter,
                "the scanned file changed while it was scanned: it was {length_when_opened} bytes when opened and ended at {ended_at}"
            ),
            Self::BeyondTheEnd {
                offset,
                wanted,
                length,
            } => write!(
                formatter,
                "a read of {wanted} bytes at {offset} reaches beyond the {length} bytes of the object"
            ),
            Self::AllowanceSpent { allowance } => write!(
                formatter,
                "scanning read more than the {allowance} bytes this scan is allowed to read"
            ),
        }
    }
}

impl std::error::Error for InputError {}

pub trait ObjectBytes {
    fn length(&self) -> u64;

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError>;
}

impl ObjectBytes for [u8] {
    fn length(&self) -> u64 {
        u64::try_from(self.len()).unwrap_or(u64::MAX)
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        let wanted = u64::try_from(into.len()).unwrap_or(u64::MAX);
        let held = usize::try_from(offset)
            .ok()
            .and_then(|start| self.get(start..start.checked_add(into.len())?))
            .ok_or(InputError::BeyondTheEnd {
                offset,
                wanted,
                length: ObjectBytes::length(self),
            })?;
        into.copy_from_slice(held);
        Ok(())
    }
}

impl<T: ObjectBytes + ?Sized> ObjectBytes for &T {
    fn length(&self) -> u64 {
        T::length(self)
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        T::read_at(self, offset, into)
    }
}

impl ObjectBytes for ScannedFile {
    fn length(&self) -> u64 {
        ScannedFile::length(self)
    }

    fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        ScannedFile::read_at(self, offset, into)
    }
}

pub const LARGEST_STREAM_HELD: u64 = 16 * 1024 * 1024;

enum Content {
    File(File),
    HeldStream(Vec<u8>),
}

pub struct ScannedFile {
    content: Content,
    length: u64,
    remaining_allowance: Cell<u64>,
    allowance: u64,
}

impl ScannedFile {
    pub fn open(path: &Path, allowance: u64) -> Result<Self, InputError> {
        let unopenable = |reason| InputError::Unopenable {
            path: path.to_path_buf(),
            reason,
        };
        let file = File::open(path).map_err(unopenable)?;
        let metadata = file.metadata().map_err(unopenable)?;
        if metadata.is_dir() {
            return Err(InputError::Directory {
                path: path.to_path_buf(),
            });
        }
        let (content, length) = if metadata.is_file() {
            (Content::File(file), metadata.len())
        } else {
            let held = held_stream(file, allowance.min(LARGEST_STREAM_HELD))?;
            let length = u64::try_from(held.len()).unwrap_or(u64::MAX);
            (Content::HeldStream(held), length)
        };
        Ok(Self {
            content,
            length,
            remaining_allowance: Cell::new(allowance),
            allowance,
        })
    }

    #[must_use]
    pub fn length(&self) -> u64 {
        self.length
    }

    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.allowance
            .saturating_sub(self.remaining_allowance.get())
    }

    #[inline(never)]
    pub fn read_at(&self, offset: u64, into: &mut [u8]) -> Result<(), InputError> {
        let wanted = u64::try_from(into.len()).unwrap_or(u64::MAX);
        offset
            .checked_add(wanted)
            .filter(|end| *end <= self.length)
            .ok_or(InputError::BeyondTheEnd {
                offset,
                wanted,
                length: self.length,
            })?;
        let remaining = self.remaining_allowance.get().checked_sub(wanted).ok_or(
            InputError::AllowanceSpent {
                allowance: self.allowance,
            },
        )?;
        self.remaining_allowance.set(remaining);
        let file = match &self.content {
            Content::File(file) => file,
            Content::HeldStream(held) => {
                let start = usize::try_from(offset).unwrap_or(usize::MAX);
                let held = held.get(start..start.saturating_add(into.len())).ok_or(
                    InputError::BeyondTheEnd {
                        offset,
                        wanted,
                        length: self.length,
                    },
                )?;
                into.copy_from_slice(held);
                return Ok(());
            }
        };
        let mut filled = 0usize;
        while let Some(unfilled) = into.get_mut(filled..).filter(|rest| !rest.is_empty()) {
            let position = offset.saturating_add(u64::try_from(filled).unwrap_or(u64::MAX));
            match file.read_at(unfilled, position) {
                Ok(0) => {
                    return Err(InputError::ChangedWhileScanned {
                        length_when_opened: self.length,
                        ended_at: position,
                    });
                }
                Ok(read) => filled = filled.saturating_add(read),
                Err(reason) if reason.kind() == io::ErrorKind::Interrupted => {}
                Err(reason) => {
                    return Err(InputError::Unreadable {
                        offset: position,
                        reason,
                    });
                }
            }
        }
        Ok(())
    }
}

fn held_stream(stream: File, largest: u64) -> Result<Vec<u8>, InputError> {
    let mut held = Vec::new();
    stream
        .take(largest.saturating_add(1))
        .read_to_end(&mut held)
        .map_err(|reason| InputError::Unreadable { offset: 0, reason })?;
    if u64::try_from(held.len()).unwrap_or(u64::MAX) > largest {
        return Err(InputError::StreamTooLarge { largest });
    }
    Ok(held)
}
