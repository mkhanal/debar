use debar_formats::{Limit, Room};
use debar_matching::WorkMeter;

use crate::scan_time::work_meter_for;
use crate::settings::Limits;

pub(crate) struct Ledger {
    limits: Limits,
    files: u64,
    scanned_bytes: u64,
    work: WorkMeter,
}

impl Ledger {
    pub(crate) const fn new(limits: Limits) -> Self {
        Self {
            limits,
            files: 0,
            scanned_bytes: 0,
            work: work_meter_for(limits.longest_scan),
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

    pub(crate) const fn work(&mut self) -> &mut WorkMeter {
        &mut self.work
    }

    pub(crate) const fn scan_time_spent(&self) -> bool {
        self.work.ran_out()
    }

    pub(crate) const fn work_spent(&self) -> u64 {
        self.work.spent()
    }

    pub(crate) fn room(&self) -> Room {
        Room {
            scan_time_spent: self.scan_time_spent(),
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
