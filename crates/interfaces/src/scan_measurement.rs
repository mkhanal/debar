use std::fmt;
use std::path::{Path, PathBuf};

use debar_platform::filesystem::{FilesystemError, regular_files_under};
use debar_platform::input::{InputError, ScannedFile};
use debar_platform::mapped_file::{MappedFile, MappingError};
use debar_platform::stopwatch::Stopwatch;
use debar_scan::{Completion, Limit, ScanFailure, ScanSettings, Unobserved, scan};
use serde_json::{Value, json};

use crate::comparison_report::{ReadyImageError, ready_image};

#[derive(Debug)]
pub enum ScanMeasurementError {
    Mapping(MappingError),
    Image(ReadyImageError),
    Listing(FilesystemError),
    Input(InputError),
    Scan { path: PathBuf, error: ScanFailure },
}

impl fmt::Display for ScanMeasurementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping(error) => write!(formatter, "cannot map the image: {error}"),
            Self::Image(error) => write!(formatter, "cannot use the image: {error:?}"),
            Self::Listing(error) => write!(formatter, "{error}"),
            Self::Input(error) => write!(formatter, "{error}"),
            Self::Scan { path, error } => write!(formatter, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for ScanMeasurementError {}

pub fn measure_scan(image_path: &Path, inputs: &[PathBuf]) -> Result<Value, ScanMeasurementError> {
    let mapped = MappedFile::open(image_path).map_err(ScanMeasurementError::Mapping)?;
    let image = ready_image(&mapped).map_err(ScanMeasurementError::Image)?;
    let mut files = Vec::new();
    for input in inputs {
        files.extend(regular_files_under(input).map_err(ScanMeasurementError::Listing)?);
    }
    let settings = ScanSettings::default();
    let mut scanned_bytes: u64 = 0;
    let mut detections: usize = 0;
    let mut work_units: u64 = 0;
    let mut cut_by_the_scan_time_limit: usize = 0;
    let stopwatch = Stopwatch::start();
    for path in &files {
        let file = ScannedFile::open(path, settings.read_allowance())
            .map_err(ScanMeasurementError::Input)?;
        let report = scan(&image, &file, &settings, &mut Unobserved);
        if let Completion::Incomplete(error) = report.completion {
            return Err(ScanMeasurementError::Scan {
                path: path.clone(),
                error,
            });
        }
        detections = detections.saturating_add(report.reported.len());
        work_units = work_units.saturating_add(report.work_spent);
        if report
            .limits
            .iter()
            .any(|reached| reached.limit == Limit::ScanTime)
        {
            cut_by_the_scan_time_limit = cut_by_the_scan_time_limit.saturating_add(1);
        }
        scanned_bytes = scanned_bytes.saturating_add(file.length());
    }
    let scanning = stopwatch.elapsed().as_secs_f64();
    let mebibytes = f64::from(u32::try_from(scanned_bytes / 1024).unwrap_or(u32::MAX)) / 1024.0;
    Ok(json!({
        "files": files.len(),
        "bytes": scanned_bytes,
        "scanning_seconds": scanning,
        "mebibytes_per_second": mebibytes / scanning.max(f64::EPSILON),
        "detections": detections,
        "work_units": work_units,
        "cut_by_the_scan_time_limit": cut_by_the_scan_time_limit,
    }))
}
