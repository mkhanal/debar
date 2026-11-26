use debar_clamav_signatures::{Account, FileAccount, LineOutcome};
use debar_image::{Image, ImageError, Provenance, SectionKind, SignatureGroup};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub fn account_report(account: &Account, image: &[u8]) -> Result<Value, ImageError> {
    let opened = Image::open(image)?;
    let recognition_group = opened
        .object_kinds()?
        .and_then(|kinds| kinds.typing_rules().recognition_group);
    let sections: Vec<Value> = opened
        .sections()
        .iter()
        .map(|section| {
            let recognises_types = section.kind == SectionKind::PatternGroup
                && recognition_group.is_some_and(|group| group.0 == section.qualifier);
            let window_overlap = if section.kind == SectionKind::PatternGroup {
                opened
                    .pattern_group(SignatureGroup(section.qualifier))
                    .ok()
                    .flatten()
                    .and_then(|group| group.report_windows())
                    .map(|windows| windows.overlap)
            } else {
                None
            };
            let logical = if section.kind == SectionKind::LogicalGroup {
                opened
                    .logical_group(SignatureGroup(section.qualifier))
                    .ok()
                    .flatten()
                    .map(|group| {
                        json!({
                            "subsignatures": group.subsignature_count(),
                            "counted_subsignatures": group.counted_subsignature_count(),
                            "counted_matches_at_most": group.counted_matches_at_most(),
                            "second_pass_subsignatures": group.second_pass_subsignature_count(),
                        })
                    })
            } else {
                None
            };
            json!({
                "window_overlap": window_overlap,
                "logical": logical,
                "kind": if recognises_types {
                    "type recognition signatures"
                } else {
                    section_kind_name(section.kind)
                },
                "qualifier": format!("{:#08x}", section.qualifier),
                "bytes": section.range.len(),
                "items": section.item_count,
            })
        })
        .collect();
    let databases: Vec<Value> = opened
        .databases()?
        .iter()
        .map(|database| {
            json!({
                "name": database.name,
                "version": database.version,
                "declared_signatures": database.declared_signature_count,
                "functionality_level": database.functionality_level,
                "provenance": match database.provenance {
                    Provenance::SignedContainerNotYetVerified => "signed container, signature not yet verified",
                    Provenance::UnsignedFile => "unsigned file",
                },
            })
        })
        .collect();
    let files: Vec<Value> = account.files.iter().map(file_report).collect();
    let totals: serde_json::Map<String, Value> = LineOutcome::ALL
        .iter()
        .map(|outcome| {
            let count: usize = account.files.iter().map(|file| file.count(*outcome)).sum();
            (outcome_name(*outcome).to_owned(), json!(count))
        })
        .collect();
    Ok(json!({
        "image": {
            "bytes": image.len(),
            "sha256": lowercase_hex(&Sha256::digest(image)),
            "sections": sections,
        },
        "databases": databases,
        "line_totals": totals,
        "files": files,
        "not_databases": account.not_databases,
    }))
}

fn file_report(file: &FileAccount) -> Value {
    let counts: serde_json::Map<String, Value> = LineOutcome::ALL
        .iter()
        .map(|outcome| {
            (
                outcome_name(*outcome).to_owned(),
                json!(file.count(*outcome)),
            )
        })
        .collect();
    let listed: Vec<Value> = file
        .lines
        .iter()
        .zip(1usize..)
        .filter(|(outcome, _)| {
            matches!(
                outcome,
                LineOutcome::OutsideFunctionalityLevel | LineOutcome::Ignored
            )
        })
        .map(|(outcome, line)| json!({ "line": line, "outcome": outcome_name(*outcome) }))
        .collect();
    json!({
        "file": file.file,
        "member": file.member,
        "kind": file.kind,
        "lines": file.lines.len(),
        "outcomes": counts,
        "lines_not_compiled": listed,
    })
}

fn outcome_name(outcome: LineOutcome) -> &'static str {
    match outcome {
        LineOutcome::Compiled => "compiled",
        LineOutcome::OutsideFunctionalityLevel => "outside_functionality_level",
        LineOutcome::Ignored => "ignored",
        LineOutcome::Comment => "comment",
        LineOutcome::NotASignature => "not_a_signature",
        LineOutcome::TargetNotLoaded => "target_not_loaded",
        LineOutcome::NotLoaded => "not_loaded",
        LineOutcome::NeverReports => "never_reports",
        LineOutcome::ShadowedByDuplicate => "shadowed_by_duplicate",
        LineOutcome::NotYetCompiled => "not_yet_compiled",
    }
}

fn section_kind_name(kind: SectionKind) -> &'static str {
    match kind {
        SectionKind::Databases => "databases",
        SectionKind::HashSizes => "hash sizes",
        SectionKind::HashFilter => "hash filter",
        SectionKind::HashEntries => "hash entries",
        SectionKind::PatternGroup => "pattern signatures",
        SectionKind::Names => "names",
        SectionKind::ObjectKinds => "object kinds",
        SectionKind::TypeMagic => "type magic",
        SectionKind::LogicalGroup => "logical signatures",
        SectionKind::UnwantedCategories => "categories of potentially unwanted signatures",
        SectionKind::SelectionFilters => "filters of the signature groups each kind selects",
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}
