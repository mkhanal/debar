use std::fmt;
use std::path::Path;

use debar_image::{Image, ImageError, Indicator, SectionKind};
use debar_image::{ObjectKind, OwnBytes};
use debar_matching::{
    GroupSelection, HashSettings, ObjectDigests, PatternRequest, PatternScan, PatternScanError,
    PatternSettings, Trust, TypeFound, whole_object_detections, whole_object_digest_need,
    whole_object_trust,
};
use debar_platform::filesystem::{FilesystemError, write_file_atomically};
use debar_platform::input::{UnreadableObject, read_scanned_file};
use debar_platform::mapped_file::{ExpectedAccess, MappedFile, MappingError};
use debar_scan::{TypingError, kind_after_full_scan, kind_from_first_bytes};
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
    Typing(TypingError),
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
            Self::Patterns(error) => write!(formatter, "cannot match the patterns: {error}"),
            Self::Typing(error) => write!(formatter, "cannot type the object: {error}"),
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
    let (kind, detections, verdict) = if size <= LARGEST_OBJECT_LEFT_UNSCANNED {
        (None, Vec::new(), Verdict::NothingFound)
    } else {
        let scanned = scan_outcome(image, object, size)?;
        (Some(scanned.kind), scanned.detections, scanned.verdict)
    };
    let type_name = kind.map(|kind| format_name(image, kind)).transpose()?;
    Ok(json!({
        "schema": REPORT_SCHEMA_VERSION,
        "id": 0,
        "parent": null,
        "depth": 0,
        "type": type_name,
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

fn format_name(image: &Image<'_>, kind: ObjectKind) -> Result<String, ComparisonReportError> {
    image
        .object_kinds()
        .map_err(ComparisonReportError::Image)?
        .and_then(|kinds| kinds.describe(kind).ok().flatten())
        .map(|description| description.format_name.to_owned())
        .ok_or(ComparisonReportError::KindNotDescribed(kind))
}

struct Found {
    name: String,
    indicator: Indicator,
}

struct ScanOutcome {
    kind: ObjectKind,
    detections: Vec<String>,
    verdict: Verdict,
}

fn scan_outcome(
    image: &Image<'_>,
    object: &[u8],
    size: u64,
) -> Result<ScanOutcome, ComparisonReportError> {
    let kind = kind_from_first_bytes(image, object).map_err(ComparisonReportError::Typing)?;
    let own_bytes = image
        .object_kinds()
        .map_err(ComparisonReportError::Image)?
        .and_then(|kinds| kinds.describe(kind).ok().flatten())
        .ok_or(ComparisonReportError::KindNotDescribed(kind))?
        .own_bytes;
    let OwnBytes::Matched {
        as_kind,
        recognising_types,
    } = own_bytes
    else {
        return Ok(ScanOutcome {
            kind,
            detections: Vec::new(),
            verdict: Verdict::NothingFound,
        });
    };
    let matched_as = as_kind.unwrap_or(kind);
    let selection = if recognising_types {
        GroupSelection::ForKindRecognisingTypes(matched_as)
    } else {
        GroupSelection::ForKind(matched_as)
    };
    let (mut found, types_found) = pattern_detections(image, object, size, selection)?;
    let kind =
        kind_after_full_scan(image, kind, &types_found).map_err(ComparisonReportError::Typing)?;
    let need = whole_object_digest_need(image, size, HashSettings::default())
        .map_err(ComparisonReportError::Image)?;
    let digests = ObjectDigests::of(object, need);
    found.extend(hash_detections(image, size, &digests).map_err(ComparisonReportError::Image)?);
    let (detections, verdict) =
        verdict_of(image, size, &digests, &found).map_err(ComparisonReportError::Image)?;
    Ok(ScanOutcome {
        kind,
        detections,
        verdict,
    })
}

fn pattern_detections(
    image: &Image<'_>,
    object: &[u8],
    size: u64,
    selection: GroupSelection,
) -> Result<(Vec<Found>, Vec<TypeFound>), ComparisonReportError> {
    let request = PatternRequest {
        selection,
        settings: PatternSettings {
            potentially_unwanted: false,
            every_match: true,
        },
        object_length: size,
    };
    let mut scan =
        PatternScan::new(image, request, || None).map_err(ComparisonReportError::Patterns)?;
    for chunk in object.chunks(CHUNK_LENGTH) {
        scan.feed(chunk).map_err(ComparisonReportError::Patterns)?;
    }
    let outcomes = scan.finish().map_err(ComparisonReportError::Patterns)?;
    let found = outcomes
        .detections
        .into_iter()
        .map(|detection| Found {
            name: detection.name,
            indicator: detection.indicator,
        })
        .collect();
    Ok((found, outcomes.types_found))
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
