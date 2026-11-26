use std::path::PathBuf;
use std::process::ExitCode;

use debar_image::{Image, ObjectKind, SignatureGroup};
use debar_matching::largest_armed_search_bytes;
use debar_platform::command_line::arguments;
use debar_platform::mapped_file::MappedFile;

const BITS_PER_BYTE: u64 = 8;
const MAP_ENTRY_BYTES: u64 = 64;
const COUNTED_START_BYTES: u64 = 8;
const ARMED_ENTRY_BYTES: u64 = 4;

fn main() -> ExitCode {
    let Some(path) = arguments().into_iter().next().map(PathBuf::from) else {
        eprintln!(
            "usage: logical_state_bound IMAGE\n  Prints, per object kind, the most per-scan logical state a scan can hold."
        );
        return ExitCode::from(2);
    };
    match bound(&path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("logical_state_bound: {reason}");
            ExitCode::FAILURE
        }
    }
}

fn group_bound(
    image: &Image<'_>,
    group: SignatureGroup,
) -> Result<u64, Box<dyn std::error::Error>> {
    let patterns = image
        .pattern_group(group)?
        .map_or(0, |view| view.all_signature_count());
    let Some(logical) = image.logical_group(group)? else {
        return Ok(u64::try_from(patterns)? / BITS_PER_BYTE);
    };
    let subsignatures = u64::try_from(logical.subsignature_count())?;
    let signatures = u64::try_from(logical.signature_count())?;
    Ok([
        u64::try_from(patterns)? / BITS_PER_BYTE,
        subsignatures / BITS_PER_BYTE,
        signatures / BITS_PER_BYTE,
        signatures.saturating_mul(ARMED_ENTRY_BYTES),
        u64::from(logical.counted_subsignature_count()).saturating_mul(MAP_ENTRY_BYTES),
        logical
            .counted_matches_at_most()
            .saturating_mul(COUNTED_START_BYTES),
    ]
    .into_iter()
    .fold(0u64, u64::saturating_add))
}

fn bound(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let mapped = MappedFile::open(path)?;
    let image = Image::open(mapped.bytes())?;
    let search = u64::try_from(largest_armed_search_bytes()?)?;
    let kinds = image
        .object_kinds()?
        .ok_or("the image describes no kinds")?;
    let mut largest = (0u64, ObjectKind::Untyped);
    for kind in kinds.described() {
        let kind = kind.map_err(|reason| format!("{reason:?}"))?;
        let Some(description) = kinds
            .describe(kind)
            .map_err(|reason| format!("{reason:?}"))?
        else {
            continue;
        };
        let mut total = search;
        for group in description.groups() {
            total = total.saturating_add(group_bound(&image, group)?);
        }
        if total > largest.0 {
            largest = (total, kind);
        }
    }
    println!(
        "largest per-scan logical state: {} bytes ({} KiB) for {:?}, of which the search of a second pass is at most {} bytes",
        largest.0,
        largest.0 / 1024,
        largest.1,
        search
    );
    Ok(())
}
