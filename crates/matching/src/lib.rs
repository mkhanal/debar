#![forbid(unsafe_code)]

mod backtracking_search;
mod byte_values;
mod container_entries;
mod digests;
mod executable_layout;
mod hash_lookup;
mod logical_state;
mod part_ends;
mod pattern_scan;
mod plug_in_matching;
mod second_pass_search;

pub use second_pass_search::largest_armed_search_bytes;
mod verification;

pub use backtracking_search::{BacktrackingBounds, BacktrackingSearch, backtracking_search};
pub use container_entries::{ContainerEntry, ContainerEntryError, container_entry_detections};
pub use digests::{DigestNeed, DigestsInProgress, ObjectDigests};
pub use executable_layout::{ExecutableLayout, ExecutableSection};
pub use hash_lookup::{
    HashDetection, HashSettings, Trust, executable_section_detections,
    executable_section_digest_need, whole_object_detections, whole_object_digest_need,
    whole_object_trust, whole_object_trust_digest_need,
};
pub use logical_state::{LogicalFindings, ObjectContext, UnwantedCategories};
pub use pattern_scan::{
    GroupSelection, PatternDetection, PatternOutcomes, PatternRequest, PatternScan,
    PatternScanError, PatternSettings, ScanEnd, ScanProgress, TypeFound, scan_object,
};
