use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use debar_image::{Image, ObjectKind};
use debar_matching::{
    GroupSelection, ObjectContext, PatternRequest, PatternSettings, UnwantedCategories, scan_object,
};
use debar_platform::command_line::arguments;
use debar_platform::input::ScannedFile;
use debar_platform::mapped_file::MappedFile;
use debar_platform::stopwatch::Stopwatch;

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
        unwanted_categories: UnwantedCategories::Every,
        every_match: true,
        largest_object_for_regular_expressions: None,
    };
    let mut scanned_bytes: u64 = 0;
    let mut detections = 0usize;
    let mut scanning = Duration::ZERO;
    for path in files {
        let file = ScannedFile::open(path, u64::MAX)?;
        let length = file.length();
        let mut object = vec![0; usize::try_from(length)?];
        file.read_at(0, &mut object)?;
        let stopwatch = Stopwatch::start();
        let request = PatternRequest {
            selection: GroupSelection::ForKind(ObjectKind::BinaryData),
            settings,
            object_length: length,
            context: ObjectContext::TOP_LEVEL,
            image_fuzzy_hash: None,
        };
        let outcomes = scan_object(&image, request, || None, &object)?;
        detections = detections
            .saturating_add(outcomes.detections.len())
            .saturating_add(outcomes.logical.detections.len());
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
