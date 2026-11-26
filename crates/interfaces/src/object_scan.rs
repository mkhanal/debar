use std::fmt;

use debar_image::{Image, ImageError, Indicator, ObjectKind, OwnBytes};
use debar_matching::{
    GroupSelection, HashSettings, ObjectContext, ObjectDigests, PatternDetection, PatternOutcomes,
    PatternRequest, PatternScanError, PatternSettings, Trust, UnwantedCategories, scan_object,
    whole_object_detections, whole_object_digest_need, whole_object_trust,
};
use debar_scan::{TypingError, kind_after_full_scan, kind_from_first_bytes};

pub const LARGEST_OBJECT_LEFT_UNSCANNED: u64 = 5;

#[derive(Debug)]
pub enum ObjectScanError {
    Image(ImageError),
    Patterns(PatternScanError),
    Typing(TypingError),
    KindNotDescribed(ObjectKind),
}

impl fmt::Display for ObjectScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image(error) => write!(formatter, "cannot use the image: {error}"),
            Self::Patterns(error) => write!(formatter, "cannot match the patterns: {error}"),
            Self::Typing(error) => write!(formatter, "cannot type the object: {error}"),
            Self::KindNotDescribed(kind) => {
                write!(formatter, "the image does not describe the kind {kind:?}")
            }
        }
    }
}

impl std::error::Error for ObjectScanError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    NothingFound,
    Trusted,
    StrongIndicator,
    PotentiallyUnwanted,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanSettings<'s> {
    pub potentially_unwanted: bool,
    pub unwanted_categories: UnwantedCategories<'s>,
}

impl<'s> ScanSettings<'s> {
    fn hashes(self) -> HashSettings<'s> {
        HashSettings {
            potentially_unwanted: self.potentially_unwanted,
            unwanted_categories: self.unwanted_categories,
        }
    }
}

pub struct ScanOutcome {
    pub kind: Option<ObjectKind>,
    pub detections: Vec<String>,
    pub verdict: Verdict,
}

struct Found {
    name: String,
    indicator: Indicator,
}

pub fn scan_top_level_object(
    image: &Image<'_>,
    object: &[u8],
    settings: ScanSettings<'_>,
) -> Result<ScanOutcome, ObjectScanError> {
    let size = u64::try_from(object.len()).unwrap_or(u64::MAX);
    if size <= LARGEST_OBJECT_LEFT_UNSCANNED {
        return Ok(ScanOutcome {
            kind: None,
            detections: Vec::new(),
            verdict: Verdict::NothingFound,
        });
    }
    let kind = kind_from_first_bytes(image, object).map_err(ObjectScanError::Typing)?;
    let own_bytes = image
        .object_kinds()
        .map_err(ObjectScanError::Image)?
        .and_then(|kinds| kinds.describe(kind).ok().flatten())
        .ok_or(ObjectScanError::KindNotDescribed(kind))?
        .own_bytes;
    let OwnBytes::Matched {
        as_kind,
        recognising_types,
    } = own_bytes
    else {
        return Ok(ScanOutcome {
            kind: Some(kind),
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
    let outcomes = pattern_outcomes(image, object, size, selection, settings)?;
    let kind = kind_after_full_scan(image, kind, &outcomes.types_found)
        .map_err(ObjectScanError::Typing)?;
    let need =
        whole_object_digest_need(image, size, settings.hashes()).map_err(ObjectScanError::Image)?;
    let digests = ObjectDigests::of(object, need);
    let mut found = found_from(outcomes.detections);
    found.extend(
        hash_detections(image, size, &digests, settings.hashes())
            .map_err(ObjectScanError::Image)?,
    );
    found.extend(found_from(outcomes.logical.detections));
    let (detections, verdict) =
        verdict_of(image, size, &digests, &found).map_err(ObjectScanError::Image)?;
    Ok(ScanOutcome {
        kind: Some(kind),
        detections,
        verdict,
    })
}

fn found_from(detections: Vec<PatternDetection>) -> Vec<Found> {
    detections
        .into_iter()
        .map(|detection| Found {
            name: detection.name,
            indicator: detection.indicator,
        })
        .collect()
}

fn pattern_outcomes(
    image: &Image<'_>,
    object: &[u8],
    size: u64,
    selection: GroupSelection,
    settings: ScanSettings<'_>,
) -> Result<PatternOutcomes, ObjectScanError> {
    let request = PatternRequest {
        selection,
        settings: PatternSettings {
            potentially_unwanted: settings.potentially_unwanted,
            unwanted_categories: settings.unwanted_categories,
            every_match: true,
        },
        object_length: size,
        context: ObjectContext::TOP_LEVEL,
    };
    scan_object(image, request, || None, object).map_err(ObjectScanError::Patterns)
}

fn hash_detections(
    image: &Image<'_>,
    size: u64,
    digests: &ObjectDigests,
    settings: HashSettings<'_>,
) -> Result<Vec<Found>, ImageError> {
    Ok(whole_object_detections(image, size, digests, settings)?
        .into_iter()
        .map(|detection| Found {
            name: detection.name,
            indicator: detection.indicator,
        })
        .collect())
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
