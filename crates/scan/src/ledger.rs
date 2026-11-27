use crate::report::Limit;
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

    pub(crate) fn count(&mut self, length: u64) -> Result<(), Limit> {
        self.admit(length)?;
        self.files = self.files.saturating_add(1);
        self.scanned_bytes = self.scanned_bytes.saturating_add(length);
        Ok(())
    }

    fn admit(&self, needed: u64) -> Result<(), Limit> {
        if self
            .limits
            .largest_scan
            .is_some_and(|largest| needed > largest.saturating_sub(self.scanned_bytes))
        {
            return Err(Limit::LargestScan);
        }
        if self
            .limits
            .largest_file
            .is_some_and(|largest| needed > largest)
        {
            return Err(Limit::LargestFile);
        }
        if self
            .limits
            .most_files
            .is_some_and(|most| self.files >= most)
        {
            return Err(Limit::MostFiles);
        }
        Ok(())
    }
}
