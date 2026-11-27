use debar_platform::input::InputError;

use crate::ole2::directory::{DirectoryEntry, EntryIndex, EntryType, entry_at};
use crate::ole2::sectors::Sectors;
use crate::ole2::visited::Visited;

const DEEPEST_WALKED_LEVEL: u32 = 100;
const MOST_STREAMS_WALKED: u64 = 100_000;
const FIRST_ENTRY: EntryIndex = EntryIndex(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolderId(pub usize);

pub const TOP_FOLDER: FolderId = FolderId(0);

pub enum Visit {
    Root {
        entry: DirectoryEntry,
    },
    Dropped {
        entry: DirectoryEntry,
    },
    Storage {
        entry: DirectoryEntry,
        folder: FolderId,
        inner: FolderId,
    },
    Stream {
        entry: DirectoryEntry,
        folder: FolderId,
    },
    Ended(WalkEnd),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkEnd {
    Loop { at: EntryIndex },
    TooDeep,
}

pub struct Walk {
    frames: Vec<Frame>,
    visited: Visited,
    folders: usize,
    finished: bool,
}

struct Frame {
    level: u32,
    folder: FolderId,
    pending: Vec<EntryIndex>,
    checked: bool,
}

impl Walk {
    pub fn new(sectors: &Sectors<'_>) -> Self {
        Self {
            frames: vec![Frame::starting_at(FIRST_ENTRY, 0, TOP_FOLDER)],
            visited: Visited::new(sectors.geometry().highest_unit_number),
            folders: 1,
            finished: false,
        }
    }

    pub fn next(
        &mut self,
        sectors: &Sectors<'_>,
        streams_counted: u64,
        most_storage_levels: u32,
    ) -> Result<Option<Visit>, InputError> {
        while !self.finished {
            let Some(frame) = self.frames.last_mut() else {
                self.finished = true;
                break;
            };
            if !frame.checked {
                frame.checked = true;
                if frame.level > DEEPEST_WALKED_LEVEL || streams_counted > MOST_STREAMS_WALKED {
                    self.frames.pop();
                    continue;
                }
                if frame.level > most_storage_levels {
                    self.finished = true;
                    return Ok(Some(Visit::Ended(WalkEnd::TooDeep)));
                }
            }
            let Some(index) = frame.pending.pop() else {
                self.frames.pop();
                continue;
            };
            let Some(entry) = entry_at(sectors, index)? else {
                continue;
            };
            if !self.visited.first_visit(index.0) {
                self.finished = true;
                return Ok(Some(Visit::Ended(WalkEnd::Loop { at: index })));
            }
            return Ok(Some(self.visit(sectors, entry, streams_counted)));
        }
        Ok(None)
    }

    fn visit(
        &mut self,
        sectors: &Sectors<'_>,
        entry: DirectoryEntry,
        streams_counted: u64,
    ) -> Visit {
        let Some(frame) = self.frames.last_mut() else {
            return Visit::Dropped { entry };
        };
        let level = frame.level;
        let folder = frame.folder;
        let accepted_root = entry.index == FIRST_ENTRY && level == 0 && streams_counted == 0;
        let (child_level, child_folder) = match entry.entry_type {
            EntryType::Root if accepted_root => (level.saturating_add(1), folder),
            EntryType::Stream => (level, folder),
            EntryType::Storage => (level.saturating_add(1), FolderId(self.folders)),
            EntryType::Root | EntryType::Unknown => {
                return Visit::Dropped { entry };
            }
        };
        frame.pending.extend(entry.left);
        frame.pending.extend(entry.right);
        if let Some(child) = entry.child {
            self.frames
                .push(Frame::starting_at(child, child_level, child_folder));
        }
        match entry.entry_type {
            EntryType::Stream => Visit::Stream { entry, folder },
            EntryType::Storage => {
                self.folders = self.folders.saturating_add(1);
                Visit::Storage {
                    entry,
                    folder,
                    inner: child_folder,
                }
            }
            EntryType::Root => {
                sectors.set_mini_stream_start(entry.start_sector());
                Visit::Root { entry }
            }
            EntryType::Unknown => Visit::Dropped { entry },
        }
    }
}

impl Frame {
    fn starting_at(index: EntryIndex, level: u32, folder: FolderId) -> Self {
        Self {
            level,
            folder,
            pending: vec![index],
            checked: false,
        }
    }
}
