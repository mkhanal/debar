use debar_matching::{HashSettings, UnwantedCategories};

const MEBIBYTE: u64 = 1024 * 1024;
pub const DEFAULT_LARGEST_FILE: u64 = 100 * MEBIBYTE;
pub const DEFAULT_LARGEST_SCAN: u64 = 400 * MEBIBYTE;
pub const DEFAULT_MOST_FILES: u64 = 10_000;
pub const DEFAULT_DEEPEST_LEVEL: u32 = 16;
pub const DEFAULT_LARGEST_OBJECT_FOR_REGULAR_EXPRESSIONS: u64 = 100 * MEBIBYTE;
const READS_OF_EACH_COUNTED_BYTE: u64 = 8;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Matching {
    #[default]
    FirstMatch,
    EveryMatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub largest_file: Option<u64>,
    pub largest_scan: Option<u64>,
    pub most_files: Option<u64>,
    pub deepest_level: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            largest_file: Some(DEFAULT_LARGEST_FILE),
            largest_scan: Some(DEFAULT_LARGEST_SCAN),
            most_files: Some(DEFAULT_MOST_FILES),
            deepest_level: DEFAULT_DEEPEST_LEVEL,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanSettings<'s> {
    pub matching: Matching,
    pub heuristic_precedence: bool,
    pub potentially_unwanted: bool,
    pub unwanted_categories: UnwantedCategories<'s>,
    pub largest_object_for_regular_expressions: Option<u64>,
    pub limits: Limits,
    pub alert_on_limits: bool,
}

impl<'s> ScanSettings<'s> {
    #[must_use]
    pub fn read_allowance(&self) -> u64 {
        self.limits.largest_scan.map_or(u64::MAX, |largest| {
            largest.saturating_mul(READS_OF_EACH_COUNTED_BYTE)
        })
    }

    pub(crate) fn hashes(&self) -> HashSettings<'s> {
        HashSettings {
            potentially_unwanted: self.potentially_unwanted,
            unwanted_categories: self.unwanted_categories,
        }
    }
}
