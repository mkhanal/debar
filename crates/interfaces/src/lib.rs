mod comparison_report;
mod object_scan;
mod scan_measurement;

pub use comparison_report::{ComparisonReportError, write_comparison_report};
pub use debar_matching::UnwantedCategories;
pub use object_scan::{DEFAULT_LARGEST_OBJECT_FOR_REGULAR_EXPRESSIONS, ScanSettings};
pub use scan_measurement::{ScanMeasurementError, measure_scan};
