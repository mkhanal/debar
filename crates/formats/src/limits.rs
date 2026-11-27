#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    LargestFile,
    LargestScan,
    MostFiles,
    DeepestLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Room {
    pub largest_file: Option<u64>,
    pub scan_bytes_left: Option<u64>,
    pub files_left: Option<u64>,
}

impl Room {
    pub fn admit(&self, needed: u64) -> Result<(), Limit> {
        if self.scan_bytes_left.is_some_and(|left| needed > left) {
            return Err(Limit::LargestScan);
        }
        if self.largest_file.is_some_and(|largest| needed > largest) {
            return Err(Limit::LargestFile);
        }
        if self.files_left == Some(0) {
            return Err(Limit::MostFiles);
        }
        Ok(())
    }
}
