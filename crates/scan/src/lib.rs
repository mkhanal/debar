#![forbid(unsafe_code)]

mod evidence;
mod format_modules;
mod layers;
mod ledger;
mod object_bytes;
mod own_bytes;
mod report;
mod scan;
mod scan_time;
mod settings;
mod typing;

pub use debar_formats::Limit;
pub use format_modules::FormatModules;
pub use object_bytes::ObjectBytes;
pub use report::{
    Completion, LayerId, LimitEvent, ObjectFact, Reported, ScanFailure, ScanReport, Verdict,
};
pub use scan::{
    FinishedObject, LARGEST_OBJECT_LEFT_UNSCANNED, MOST_PRODUCED_BYTES_HELD,
    MOST_UNCOUNTED_MODULE_OUTPUTS, ObjectObserver, Unobserved, scan, scan_with_modules,
};
pub use scan_time::{DEFAULT_LONGEST_SCAN, ScanTime};
pub use settings::{
    DEFAULT_DEEPEST_LEVEL, DEFAULT_LARGEST_FILE, DEFAULT_LARGEST_OBJECT_FOR_REGULAR_EXPRESSIONS,
    DEFAULT_LARGEST_SCAN, DEFAULT_MOST_FILES, Facts, Limits, Matching, ScanSettings,
};
pub use typing::{TypingError, kind_after_full_scan, kind_from_first_bytes};
