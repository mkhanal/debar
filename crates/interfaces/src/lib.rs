mod comparison_report;
mod scan_measurement;

pub use comparison_report::{ComparisonReportError, write_comparison_report};
pub use scan_measurement::{ScanMeasurementError, measure_scan};
