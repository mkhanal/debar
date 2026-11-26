use std::fmt;
use std::path::Path;

use debar_image::{Image, ImageError, ObjectKind};
use debar_platform::filesystem::{FilesystemError, write_file_atomically};
use debar_platform::input::{UnreadableObject, read_scanned_file};
use debar_platform::mapped_file::{ExpectedAccess, MappedFile, MappingError};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::object_scan::{ObjectScanError, ScanSettings, Verdict, scan_top_level_object};

const REPORT_SCHEMA_VERSION: u32 = 1;
const SCANNER_NAME: &str = "Debar";

#[derive(Debug)]
pub enum ComparisonReportError {
    Mapping(MappingError),
    Image(ImageError),
    Scan(ObjectScanError),
    KindNotDescribed(ObjectKind),
    Input(UnreadableObject),
    InputTooLarge,
    Report(FilesystemError),
}

impl fmt::Display for ComparisonReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping(error) => write!(formatter, "cannot map the image: {error}"),
            Self::Image(error) => write!(formatter, "cannot use the image: {error}"),
            Self::Scan(error) => write!(formatter, "{error}"),
            Self::KindNotDescribed(kind) => {
                write!(formatter, "the image does not describe the kind {kind:?}")
            }
            Self::Input(error) => write!(formatter, "{error}"),
            Self::InputTooLarge => write!(formatter, "the input is larger than 2^64 bytes"),
            Self::Report(error) => write!(formatter, "cannot write the report: {error}"),
        }
    }
}

impl std::error::Error for ComparisonReportError {}

pub fn write_comparison_report(
    image_path: &Path,
    input: &Path,
    report: &Path,
    settings: ScanSettings<'_>,
) -> Result<(), ComparisonReportError> {
    let mapped = MappedFile::open(image_path).map_err(ComparisonReportError::Mapping)?;
    let image = ready_image(&mapped).map_err(|error| match error {
        ReadyImageError::Mapping(error) => ComparisonReportError::Mapping(error),
        ReadyImageError::Image(error) => ComparisonReportError::Image(error),
    })?;
    let object = read_scanned_file(input).map_err(ComparisonReportError::Input)?;
    let record = top_level_record(&image, &object, settings)?;
    write_file_atomically(report, format!("{record}\n").as_bytes())
        .map_err(ComparisonReportError::Report)
}

#[derive(Debug)]
pub enum ReadyImageError {
    Mapping(MappingError),
    Image(ImageError),
}

pub fn ready_image(mapped: &MappedFile) -> Result<Image<'_>, ReadyImageError> {
    mapped
        .advise(0..mapped.bytes().len(), ExpectedAccess::Random)
        .map_err(ReadyImageError::Mapping)?;
    Image::open(mapped.bytes()).map_err(ReadyImageError::Image)
}

fn top_level_record(
    image: &Image<'_>,
    object: &[u8],
    settings: ScanSettings<'_>,
) -> Result<Value, ComparisonReportError> {
    let size = u64::try_from(object.len()).map_err(|_| ComparisonReportError::InputTooLarge)?;
    let scanned =
        scan_top_level_object(image, object, settings).map_err(ComparisonReportError::Scan)?;
    let type_name = scanned
        .kind
        .map(|kind| format_name(image, kind))
        .transpose()?;
    Ok(json!({
        "schema": REPORT_SCHEMA_VERSION,
        "id": 0,
        "parent": null,
        "depth": 0,
        "type": type_name,
        "size": size,
        "sha256": lowercase_hex(&Sha256::digest(object)),
        "detections": scanned.detections,
        "verdict": match scanned.verdict {
            Verdict::NothingFound => "nothing_found",
            Verdict::Trusted => "trusted",
            Verdict::StrongIndicator => "strong_indicator",
            Verdict::PotentiallyUnwanted => "potentially_unwanted",
        },
        "scanner": scanner(image).map_err(ComparisonReportError::Image)?,
    }))
}

fn format_name(image: &Image<'_>, kind: ObjectKind) -> Result<String, ComparisonReportError> {
    image
        .object_kinds()
        .map_err(ComparisonReportError::Image)?
        .and_then(|kinds| kinds.describe(kind).ok().flatten())
        .map(|description| description.format_name.to_owned())
        .ok_or(ComparisonReportError::KindNotDescribed(kind))
}

fn scanner(image: &Image<'_>) -> Result<Value, ImageError> {
    let mut databases = image.databases()?;
    databases.sort_by(|left, right| left.name.cmp(&right.name));
    let databases: Vec<Value> = databases
        .iter()
        .map(|database| json!({ "name": database.name, "version": database.version }))
        .collect();
    Ok(json!({
        "name": SCANNER_NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "databases": databases,
    }))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}
