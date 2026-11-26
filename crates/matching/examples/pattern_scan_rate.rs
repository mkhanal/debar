use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use debar_image::Image;
use debar_matching::{PatternScan, PatternSettings};
use debar_platform::command_line::arguments;
use debar_platform::input::read_scanned_file;
use debar_platform::mapped_file::MappedFile;
use debar_platform::stopwatch::Stopwatch;

const CHUNK_LENGTH: usize = 128 * 1024;

fn main() -> ExitCode {
    let mut paths = arguments().into_iter().map(PathBuf::from);
    let Some(image) = paths.next() else {
        eprintln!(
            "usage: pattern_scan_rate IMAGE FILE...\n  Scans each FILE as one object against the image's pattern signatures and reports the rate."
        );
        return ExitCode::from(2);
    };
    let files: Vec<PathBuf> = paths.collect();
    match measure(&image, &files) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("pattern_scan_rate: {reason}");
            ExitCode::FAILURE
        }
    }
}

fn measure(image_path: &Path, files: &[PathBuf]) -> Result<String, Box<dyn std::error::Error>> {
    let mapped = MappedFile::open(image_path)?;
    let image = Image::open(mapped.bytes())?;
    let settings = PatternSettings {
        potentially_unwanted: false,
        every_match: true,
    };
    let mut scanned_bytes: u64 = 0;
    let mut detections = 0usize;
    let mut scanning = Duration::ZERO;
    for path in files {
        let object = read_scanned_file(path)?;
        let length = u64::try_from(object.len())?;
        let stopwatch = Stopwatch::start();
        let mut scan = PatternScan::new(&image, settings, length)?;
        for chunk in object.chunks(CHUNK_LENGTH) {
            scan.feed(chunk)?;
        }
        detections = detections.saturating_add(scan.finish()?.len());
        scanning = scanning.saturating_add(stopwatch.elapsed());
        scanned_bytes = scanned_bytes.saturating_add(length);
    }
    let mebibytes = f64::from(u32::try_from(scanned_bytes / 1024)?) / 1024.0;
    Ok(format!(
        "{} files, {mebibytes:.1} MiB in {:.3} s: {:.1} MiB/s; {detections} detections",
        files.len(),
        scanning.as_secs_f64(),
        mebibytes / scanning.as_secs_f64().max(f64::EPSILON)
    ))
}
