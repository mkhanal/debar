use debar_formats::{Limit, Room};

use crate::settings::Limits;

pub(crate) struct Ledger {
    limits: Limits,
    files: u64,
    scanned_bytes: u64,
}

impl Ledger {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            limits,
            files: 0,
            scanned_bytes: 0,
        }
    }

    pub(crate) fn admits_a_level_below(&self, depth: u32) -> Result<(), Limit> {
        if depth >= self.limits.deepest_level {
            return Err(Limit::DeepestLevel);
        }
        Ok(())
    }

    pub(crate) fn count(&mut self, length: u64) -> Result<(), Limit> {
        self.admit(length)?;
        self.files = self.files.saturating_add(1);
        self.scanned_bytes = self.scanned_bytes.saturating_add(length);
        Ok(())
    }

    pub(crate) fn admit(&self, needed: u64) -> Result<(), Limit> {
        self.room().admit(needed)
    }

    pub(crate) fn room(&self) -> Room {
        Room {
            largest_file: self.limits.largest_file,
            scan_bytes_left: self
                .limits
                .largest_scan
                .map(|largest| largest.saturating_sub(self.scanned_bytes)),
            files_left: self
                .limits
                .most_files
                .map(|most| most.saturating_sub(self.files)),
        }
    }
}
