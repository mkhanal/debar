use debar_image::{BuildError, EngineAlert, ImageBuilder, Indicator};

const ENGINE_ALERT_NAMES: [(EngineAlert, &str); 7] = [
    (
        EngineAlert::ScanSizeLimitExceeded,
        "Heuristics.Limits.Exceeded.MaxScanSize",
    ),
    (
        EngineAlert::FileSizeLimitExceeded,
        "Heuristics.Limits.Exceeded.MaxFileSize",
    ),
    (
        EngineAlert::FileCountLimitExceeded,
        "Heuristics.Limits.Exceeded.MaxFiles",
    ),
    (
        EngineAlert::RecursionLimitExceeded,
        "Heuristics.Limits.Exceeded.MaxRecursion",
    ),
    (
        EngineAlert::ScanTimeLimitExceeded,
        "Heuristics.Limits.Exceeded.MaxScanTime",
    ),
    (
        EngineAlert::OverlappingParts,
        "Heuristics.Zip.OverlappingFiles",
    ),
    (
        EngineAlert::ObfuscatedNames,
        "Heuristics.PDF.ObfuscatedNameObject",
    ),
];

pub fn name_engine_alerts(image: &mut ImageBuilder) -> Result<(), BuildError> {
    for (alert, name) in ENGINE_ALERT_NAMES {
        image.name_engine_alert(alert, name, Indicator::PotentiallyUnwanted)?;
    }
    Ok(())
}
