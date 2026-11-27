use debar_clamav_signatures::{Account, FileAccount, LineOutcome};
use debar_image::{
    Image, ImageError, Provenance, RecordedForm, SectionExtent, SectionKind, SignatureGroup,
};
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
        .map(|section| section_report(&opened, section, recognition_group))
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
                    Provenance::DetachedSignatureVerified => "signed container, detached signature verified",
                    Provenance::HeaderSignatureVerified => "signed container, header signature verified",
                    Provenance::IndexSignatureVerified => "signed container, index signature verified",
                    Provenance::UnsignedContainer => "unsigned container",
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

fn section_report(
    opened: &Image<'_>,
    section: &SectionExtent,
    recognition_group: Option<SignatureGroup>,
) -> Value {
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
    let plug_ins = (section.kind == SectionKind::PlugInSubsignatures)
        .then(|| plug_in_report(opened, SignatureGroup(section.qualifier)))
        .flatten();
    let triggered_programs = (section.kind == SectionKind::SignaturePrograms)
        .then(|| {
            opened.signature_programs().ok().flatten().map(|programs| {
                programs
                    .programs()
                    .filter(|program| program.as_ref().is_ok_and(|program| program.triggered))
                    .count()
            })
        })
        .flatten();
    json!({
        "triggered_programs": triggered_programs,
        "plug_in_subsignatures": plug_ins,
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
}

fn plug_in_report(image: &Image<'_>, group: SignatureGroup) -> Option<Value> {
    let plug_ins = image.plug_in_subsignatures(group).ok().flatten()?;
    let form_count = |wanted: fn(&RecordedForm<'_>) -> bool| {
        plug_ins
            .expressions()
            .filter(|record| record.as_ref().is_ok_and(|record| wanted(&record.form)))
            .count()
    };
    let in_image = form_count(|form| matches!(form, RecordedForm::Automata { .. }));
    let backtracking = form_count(|form| matches!(form, RecordedForm::Backtracking(_)));
    Some(json!({
        "regular_expressions": plug_ins.expression_count(),
        "regular_expressions_with_automata_in_image": in_image,
        "regular_expressions_needing_backtracking": backtracking,
        "automata_bytes": plug_ins.automata_bytes(),
        "byte_comparisons": plug_ins.comparison_count(),
        "image_hashes": plug_ins.image_hash_count(),
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
                LineOutcome::OutsideFunctionalityLevel
                    | LineOutcome::Ignored
                    | LineOutcome::NotYetCompiled
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
        SectionKind::PlugInSubsignatures => {
            "regular expressions, byte comparisons and image hashes"
        }
        SectionKind::ContainerSignatures => "container signatures",
        SectionKind::EngineFeatures => "engine features",
        SectionKind::CertificateRules => "certificate rules",
        SectionKind::IconSignatures => "icon signatures",
        SectionKind::UrlRules => "URL rules",
        SectionKind::SignaturePrograms => "signature programs",
        SectionKind::EngineAlerts => "names of the alerts the engine raises",
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}
