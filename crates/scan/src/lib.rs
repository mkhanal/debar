#![forbid(unsafe_code)]

mod evidence;
mod layers;
mod ledger;
mod object_bytes;
mod own_bytes;
mod report;
mod scan;
mod settings;
mod typing;

pub use object_bytes::ObjectBytes;
pub use report::{
    Completion, LayerId, Limit, LimitEvent, Reported, ScanFailure, ScanReport, Verdict,
};
pub use scan::{FinishedObject, LARGEST_OBJECT_LEFT_UNSCANNED, ObjectObserver, Unobserved, scan};
pub use settings::{
    DEFAULT_LARGEST_FILE, DEFAULT_LARGEST_OBJECT_FOR_REGULAR_EXPRESSIONS, DEFAULT_LARGEST_SCAN,
    DEFAULT_MOST_FILES, Limits, Matching, ScanSettings,
};
pub use typing::{TypingError, kind_after_full_scan, kind_from_first_bytes};
