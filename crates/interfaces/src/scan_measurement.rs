use std::fmt;
use std::path::{Path, PathBuf};

use debar_platform::filesystem::{FilesystemError, regular_files_under};
use debar_platform::input::{InputError, ScannedFile};
use debar_platform::mapped_file::{MappedFile, MappingError};
use debar_platform::stopwatch::Stopwatch;
use debar_platform::threads::{ThreadCount, ThreadsError, each_in_parallel};
use debar_scan::{
    Completion, Limit, ScanFailure, ScanReport, ScanSettings, Unobserved, Verdict, scan,
};
use serde_json::{Value, json};

use crate::comparison_report::{ReadyImageError, ready_image, verdict_name};

#[derive(Debug)]
pub enum ScanMeasurementError {
    Mapping(MappingError),
    Image(ReadyImageError),
    Listing(FilesystemError),
    Input(InputError),
    Scan { path: PathBuf, error: ScanFailure },
    Threads(ThreadsError),
}

impl fmt::Display for ScanMeasurementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping(error) => write!(formatter, "cannot map the image: {error}"),
            Self::Image(error) => write!(formatter, "cannot use the image: {error:?}"),
            Self::Listing(error) => write!(formatter, "{error}"),
            Self::Input(error) => write!(formatter, "{error}"),
            Self::Scan { path, error } => write!(formatter, "{}: {error}", path.display()),
            Self::Threads(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ScanMeasurementError {}

pub fn measure_scan(
    image_path: &Path,
    threads: ThreadCount,
    inputs: &[PathBuf],
) -> Result<Value, ScanMeasurementError> {
    let mapped = MappedFile::open(image_path).map_err(ScanMeasurementError::Mapping)?;
    let image = ready_image(&mapped).map_err(ScanMeasurementError::Image)?;
    let mut files = Vec::new();
    for input in inputs {
        files.extend(regular_files_under(input).map_err(ScanMeasurementError::Listing)?);
    }
    let settings = ScanSettings::default();
    let stopwatch = Stopwatch::start();
    let scans = each_in_parallel(&files, threads, |path| {
        let file = ScannedFile::open(path, settings.read_allowance())
            .map_err(ScanMeasurementError::Input)?;
        let report = scan(&image, &file, &settings, &mut Unobserved);
        Ok(FileScan {
            bytes: file.length(),
            bytes_read: file.bytes_read(),
            bytes_read_again: file.bytes_read_again(),
            report,
        })
    })
    .map_err(ScanMeasurementError::Threads)?;
    let scanning = stopwatch.elapsed().as_secs_f64();
    let mut scanned_bytes: u64 = 0;
    let mut bytes_read: u64 = 0;
    let mut bytes_read_again: u64 = 0;
    let mut detections: usize = 0;
    let mut work_units: u64 = 0;
    let mut cut_by_the_scan_time_limit: usize = 0;
    let mut detected = Vec::new();
    for (path, scanned) in files.iter().zip(scans) {
        let FileScan {
            bytes,
            bytes_read: read,
            bytes_read_again: read_again,
            report,
        } = scanned?;
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
        scanned_bytes = scanned_bytes.saturating_add(bytes);
        bytes_read = bytes_read.saturating_add(read);
        bytes_read_again = bytes_read_again.saturating_add(read_again);
        if !report.reported.is_empty() || report.verdict != Verdict::NothingFound {
            detected.push(json!({
                "path": path.to_string_lossy(),
                "verdict": verdict_name(report.verdict),
                "detections": report
                    .reported
                    .iter()
                    .map(|reported| reported.name.as_str())
                    .collect::<Vec<_>>(),
            }));
        }
    }
    let mebibytes = f64::from(u32::try_from(scanned_bytes / 1024).unwrap_or(u32::MAX)) / 1024.0;
    Ok(json!({
        "threads": threads.get(),
        "files": files.len(),
        "bytes": scanned_bytes,
        "bytes_read": bytes_read,
        "bytes_read_again": bytes_read_again,
        "scanning_seconds": scanning,
        "mebibytes_per_second": mebibytes / scanning.max(f64::EPSILON),
        "detections": detections,
        "work_units": work_units,
        "cut_by_the_scan_time_limit": cut_by_the_scan_time_limit,
        "detected": detected,
    }))
}

struct FileScan {
    bytes: u64,
    bytes_read: u64,
    bytes_read_again: u64,
    report: ScanReport,
}
