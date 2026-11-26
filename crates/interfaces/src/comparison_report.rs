use std::fmt;
use std::path::Path;

use debar_image::{Image, ImageError, Indicator, SectionKind};
use debar_matching::{
    HashSettings, ObjectDigests, PatternScan, PatternScanError, PatternSettings, Trust,
    whole_object_detections, whole_object_digest_need, whole_object_trust,
};
use debar_platform::filesystem::{FilesystemError, write_file_atomically};
use debar_platform::input::{UnreadableObject, read_scanned_file};
use debar_platform::mapped_file::{ExpectedAccess, MappedFile, MappingError};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const REPORT_SCHEMA_VERSION: u32 = 1;
const SCANNER_NAME: &str = "Debar";
const LARGEST_OBJECT_LEFT_UNSCANNED: u64 = 5;
const CHUNK_LENGTH: usize = 128 * 1024;

#[derive(Debug)]
pub enum ComparisonReportError {
    Mapping(MappingError),
    Image(ImageError),
    Patterns(PatternScanError),
    Input(UnreadableObject),
    InputTooLarge,
    Report(FilesystemError),
}

impl fmt::Display for ComparisonReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping(error) => write!(formatter, "cannot map the image: {error}"),
            Self::Image(error) => write!(formatter, "cannot use the image: {error}"),
            Self::Patterns(error) => write!(formatter, "cannot match the patterns: {error}"),
            Self::Input(error) => write!(formatter, "{error}"),
            Self::InputTooLarge => write!(formatter, "the input is larger than 2^64 bytes"),
            Self::Report(error) => write!(formatter, "cannot write the report: {error}"),
        }
    }
}

impl std::error::Error for ComparisonReportError {}

enum Verdict {
    NothingFound,
    Trusted,
    StrongIndicator,
    PotentiallyUnwanted,
}

pub fn write_comparison_report(
    image_path: &Path,
    input: &Path,
    report: &Path,
) -> Result<(), ComparisonReportError> {
    let mapped = MappedFile::open(image_path).map_err(ComparisonReportError::Mapping)?;
    let image = ready_image(&mapped)?;
    let object = read_scanned_file(input).map_err(ComparisonReportError::Input)?;
    let record = top_level_record(&image, &object)?;
    write_file_atomically(report, format!("{record}\n").as_bytes())
        .map_err(ComparisonReportError::Report)
}

fn ready_image(mapped: &MappedFile) -> Result<Image<'_>, ComparisonReportError> {
    let image = Image::open(mapped.bytes()).map_err(ComparisonReportError::Image)?;
    for section in image.sections() {
        if matches!(
            section.kind,
            SectionKind::HashFilter | SectionKind::HashEntries | SectionKind::PatternGroup
        ) {
            mapped
                .advise(section.range.clone(), ExpectedAccess::Random)
                .map_err(ComparisonReportError::Mapping)?;
        }
    }
    Ok(image)
}

fn top_level_record(image: &Image<'_>, object: &[u8]) -> Result<Value, ComparisonReportError> {
    let size = u64::try_from(object.len()).map_err(|_| ComparisonReportError::InputTooLarge)?;
    let (detections, verdict) = if size <= LARGEST_OBJECT_LEFT_UNSCANNED {
        (Vec::new(), Verdict::NothingFound)
    } else {
        scan_outcome(image, object, size)?
    };
    Ok(json!({
        "schema": REPORT_SCHEMA_VERSION,
        "id": 0,
        "parent": null,
        "depth": 0,
        "type": null,
        "size": size,
        "sha256": lowercase_hex(&Sha256::digest(object)),
        "detections": detections,
        "verdict": match verdict {
            Verdict::NothingFound => "nothing_found",
            Verdict::Trusted => "trusted",
            Verdict::StrongIndicator => "strong_indicator",
            Verdict::PotentiallyUnwanted => "potentially_unwanted",
        },
        "scanner": scanner(image).map_err(ComparisonReportError::Image)?,
    }))
}

struct Found {
    name: String,
    indicator: Indicator,
}

fn scan_outcome(
    image: &Image<'_>,
    object: &[u8],
    size: u64,
) -> Result<(Vec<String>, Verdict), ComparisonReportError> {
    let mut found = pattern_detections(image, object, size)?;
    let need = whole_object_digest_need(image, size, HashSettings::default())
        .map_err(ComparisonReportError::Image)?;
    let digests = ObjectDigests::of(object, need);
    found.extend(hash_detections(image, size, &digests).map_err(ComparisonReportError::Image)?);
    verdict_of(image, size, &digests, &found).map_err(ComparisonReportError::Image)
}

fn pattern_detections(
    image: &Image<'_>,
    object: &[u8],
    size: u64,
) -> Result<Vec<Found>, ComparisonReportError> {
    let settings = PatternSettings {
        potentially_unwanted: false,
        every_match: true,
    };
    let mut scan =
        PatternScan::new(image, settings, size).map_err(ComparisonReportError::Patterns)?;
    for chunk in object.chunks(CHUNK_LENGTH) {
        scan.feed(chunk).map_err(ComparisonReportError::Patterns)?;
    }
    Ok(scan
        .finish()
        .map_err(ComparisonReportError::Patterns)?
        .into_iter()
        .map(|detection| Found {
            name: detection.name,
            indicator: detection.indicator,
        })
        .collect())
}

fn hash_detections(
    image: &Image<'_>,
    size: u64,
    digests: &ObjectDigests,
) -> Result<Vec<Found>, ImageError> {
    Ok(
        whole_object_detections(image, size, digests, HashSettings::default())?
            .into_iter()
            .map(|detection| Found {
                name: detection.name,
                indicator: detection.indicator,
            })
            .collect(),
    )
}

fn verdict_of(
    image: &Image<'_>,
    size: u64,
    digests: &ObjectDigests,
    found: &[Found],
) -> Result<(Vec<String>, Verdict), ImageError> {
    let reported = |indicator| {
        found
            .iter()
            .filter(move |detection| detection.indicator == indicator)
            .map(|detection| detection.name.clone())
    };
    let strong: Vec<String> = reported(Indicator::Strong).collect();
    let unwanted: Vec<String> = reported(Indicator::PotentiallyUnwanted).collect();
    if strong.is_empty() && unwanted.is_empty() {
        return Ok((Vec::new(), Verdict::NothingFound));
    }
    if whole_object_trust(image, size, digests)? == Trust::Trusted {
        return Ok((Vec::new(), Verdict::Trusted));
    }
    let verdict = if strong.is_empty() {
        Verdict::PotentiallyUnwanted
    } else {
        Verdict::StrongIndicator
    };
    Ok((strong.into_iter().chain(unwanted).collect(), verdict))
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
