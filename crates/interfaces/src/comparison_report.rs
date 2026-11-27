use std::fmt;
use std::path::Path;

use debar_image::{Image, ImageError, ObjectKind};
use debar_platform::filesystem::{FilesystemError, write_file_atomically};
use debar_platform::input::{InputError, ScannedFile};
use debar_platform::mapped_file::{ExpectedAccess, MappedFile, MappingError};
use debar_scan::{
    Completion, FinishedObject, LayerId, ObjectBytes, ObjectObserver, ScanFailure, ScanReport,
    ScanSettings, Verdict, scan,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const REPORT_SCHEMA_VERSION: u32 = 1;
const SCANNER_NAME: &str = "Debar";
const HASHED_CHUNK_LENGTH: usize = 128 * 1024;

#[derive(Debug)]
pub enum ComparisonReportError {
    Mapping(MappingError),
    Image(ImageError),
    Scan(ScanFailure),
    KindNotDescribed(ObjectKind),
    Input(InputError),
    Report(FilesystemError),
}

impl fmt::Display for ComparisonReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping(error) => write!(formatter, "cannot map the image: {error}"),
            Self::Image(error) => write!(formatter, "cannot use the image: {error}"),
            Self::Scan(error) => write!(formatter, "the scan could not finish: {error}"),
            Self::KindNotDescribed(kind) => {
                write!(formatter, "the image does not describe the kind {kind:?}")
            }
            Self::Input(error) => write!(formatter, "{error}"),
            Self::Report(error) => write!(formatter, "cannot write the report: {error}"),
        }
    }
}

impl std::error::Error for ComparisonReportError {}

pub fn write_comparison_report(
    image_path: &Path,
    input: &Path,
    report: &Path,
    settings: &ScanSettings<'_>,
) -> Result<(), ComparisonReportError> {
    let mapped = MappedFile::open(image_path).map_err(ComparisonReportError::Mapping)?;
    let image = ready_image(&mapped).map_err(|error| match error {
        ReadyImageError::Mapping(error) => ComparisonReportError::Mapping(error),
        ReadyImageError::Image(error) => ComparisonReportError::Image(error),
    })?;
    let file = ScannedFile::open(input, settings.read_allowance())
        .map_err(ComparisonReportError::Input)?;
    let mut records = ObjectRecords::default();
    let scanned = scan(&image, &file, settings, &mut records);
    if let Completion::Incomplete(failure) = scanned.completion {
        return Err(ComparisonReportError::Scan(failure));
    }
    let lines = report_lines(&image, records, &scanned)?;
    write_file_atomically(report, lines.as_bytes()).map_err(ComparisonReportError::Report)
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

struct ObjectRecord {
    layer: LayerId,
    parent: Option<LayerId>,
    depth: u32,
    kind: Option<ObjectKind>,
    size: u64,
    sha256: Result<String, InputError>,
}

impl ObjectRecord {
    fn is_reached(&self) -> bool {
        self.parent.is_none() || self.kind.is_some()
    }
}

#[derive(Default)]
struct ObjectRecords {
    objects: Vec<ObjectRecord>,
    views: Vec<(LayerId, LayerId)>,
}

impl ObjectRecords {
    fn nearest_reached(&self, layer: LayerId) -> Option<LayerId> {
        let mut looking_at = Some(self.object_holding(layer));
        while let Some(layer) = looking_at {
            let record = self.objects.iter().find(|record| record.layer == layer)?;
            if record.is_reached() {
                return Some(layer);
            }
            looking_at = record.parent;
        }
        None
    }

    fn object_holding(&self, layer: LayerId) -> LayerId {
        let mut holding = layer;
        while let Some((_, of)) = self.views.iter().find(|(view, _)| *view == holding) {
            holding = *of;
        }
        holding
    }
}

impl ObjectObserver for ObjectRecords {
    fn view_pushed(&mut self, view: LayerId, of: LayerId) {
        self.views.push((view, of));
    }

    fn object_finished(&mut self, object: &FinishedObject<'_>) {
        self.objects.push(ObjectRecord {
            layer: object.layer,
            parent: object.parent,
            depth: object.depth,
            kind: object.kind,
            size: object.bytes.length(),
            sha256: sha256_of(object.bytes),
        });
    }
}

fn sha256_of(bytes: &dyn ObjectBytes) -> Result<String, InputError> {
    let mut digest = Sha256::new();
    let mut chunk = vec![0u8; HASHED_CHUNK_LENGTH];
    let mut offset = 0u64;
    while offset < bytes.length() {
        let wanted = bytes
            .length()
            .saturating_sub(offset)
            .min(u64::try_from(HASHED_CHUNK_LENGTH).unwrap_or(u64::MAX));
        let filled = chunk
            .get_mut(..usize::try_from(wanted).unwrap_or(HASHED_CHUNK_LENGTH))
            .unwrap_or_default();
        bytes.read_again_at(offset, filled)?;
        digest.update(&*filled);
        offset = offset.saturating_add(wanted);
    }
    Ok(lowercase_hex(&digest.finalize()))
}

fn report_lines(
    image: &Image<'_>,
    mut records: ObjectRecords,
    scanned: &ScanReport,
) -> Result<String, ComparisonReportError> {
    records.objects.sort_by_key(|record| record.layer);
    let attributed: Vec<Option<LayerId>> = scanned
        .reported
        .iter()
        .map(|reported| records.nearest_reached(reported.object))
        .collect();
    let mut lines = String::new();
    for record in records.objects.into_iter().filter(ObjectRecord::is_reached) {
        let detections: Vec<&str> = scanned
            .reported
            .iter()
            .zip(&attributed)
            .filter(|(_, object)| **object == Some(record.layer))
            .map(|(reported, _)| reported.name.as_str())
            .collect();
        let type_name = record
            .kind
            .map(|kind| format_name(image, kind))
            .transpose()?;
        let mut line = json!({
            "schema": REPORT_SCHEMA_VERSION,
            "id": record.layer.0,
            "parent": record.parent.map(|parent| parent.0),
            "depth": record.depth,
            "type": type_name,
            "size": record.size,
            "sha256": record.sha256.map_err(ComparisonReportError::Input)?,
            "detections": detections,
        });
        if record.parent.is_none()
            && let Some(fields) = line.as_object_mut()
        {
            fields.insert("verdict".to_owned(), verdict_name(scanned.verdict).into());
            fields.insert(
                "scanner".to_owned(),
                scanner(image).map_err(ComparisonReportError::Image)?,
            );
        }
        lines.push_str(&line.to_string());
        lines.push('\n');
    }
    Ok(lines)
}

pub(crate) fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::NothingFound => "nothing_found",
        Verdict::Trusted => "trusted",
        Verdict::StrongIndicator => "strong_indicator",
        Verdict::PotentiallyUnwanted => "potentially_unwanted",
    }
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
