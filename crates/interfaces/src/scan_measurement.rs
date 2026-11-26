use std::fmt;
use std::path::{Path, PathBuf};

use debar_platform::filesystem::{FilesystemError, regular_files_under};
use debar_platform::input::{UnreadableObject, read_scanned_file};
use debar_platform::mapped_file::{MappedFile, MappingError};
use debar_platform::stopwatch::Stopwatch;
use serde_json::{Value, json};

use crate::comparison_report::{ReadyImageError, ready_image};
use crate::object_scan::{ObjectScanError, scan_top_level_object};

#[derive(Debug)]
pub enum ScanMeasurementError {
    Mapping(MappingError),
    Image(ReadyImageError),
    Listing(FilesystemError),
    Input(UnreadableObject),
    Scan {
        path: PathBuf,
        error: ObjectScanError,
    },
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
    let mut scanned_bytes: u64 = 0;
    let mut detections: usize = 0;
    let mut reading = std::time::Duration::ZERO;
    let stopwatch = Stopwatch::start();
    for path in &files {
        let read = Stopwatch::start();
        let object = read_scanned_file(path).map_err(ScanMeasurementError::Input)?;
        reading = reading.saturating_add(read.elapsed());
        let outcome =
            scan_top_level_object(&image, &object).map_err(|error| ScanMeasurementError::Scan {
                path: path.clone(),
                error,
            })?;
        detections = detections.saturating_add(outcome.detections.len());
        scanned_bytes = scanned_bytes.saturating_add(u64::try_from(object.len()).unwrap_or(0));
    }
    let scanning = stopwatch.elapsed().saturating_sub(reading).as_secs_f64();
    let mebibytes = f64::from(u32::try_from(scanned_bytes / 1024).unwrap_or(u32::MAX)) / 1024.0;
    Ok(json!({
        "files": files.len(),
        "bytes": scanned_bytes,
        "scanning_seconds": scanning,
        "mebibytes_per_second": mebibytes / scanning.max(f64::EPSILON),
        "detections": detections,
    }))
}
