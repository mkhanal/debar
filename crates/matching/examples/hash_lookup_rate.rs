use std::path::PathBuf;
use std::process::ExitCode;

use debar_image::Image;
use debar_matching::{
    HashSettings, ObjectDigests, executable_section_detections, executable_section_digest_need,
    whole_object_detections, whole_object_digest_need,
};
use debar_platform::command_line::arguments;
use debar_platform::mapped_file::MappedFile;
use debar_platform::stopwatch::Stopwatch;

const LOOKUPS: u32 = 2_000_000;
const SECTION_ALIGNMENT: u64 = 512;

fn main() -> ExitCode {
    let Some(path) = arguments().into_iter().next().map(PathBuf::from) else {
        eprintln!("usage: hash_lookup_rate IMAGE");
        return ExitCode::from(2);
    };
    match measure(&path) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("hash_lookup_rate: {reason}");
            ExitCode::FAILURE
        }
    }
}

fn measure(path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    let mapped = MappedFile::open(path)?;
    let image = Image::open(mapped.bytes())?;
    let settings = HashSettings::default();
    let mut found = 0usize;
    let mut digested = 0usize;
    let stopwatch = Stopwatch::start();
    for index in 0..LOOKUPS {
        let size = SECTION_ALIGNMENT.saturating_mul(u64::from(index % 4_000).saturating_add(1));
        let need = executable_section_digest_need(&image, size, settings)?;
        let digests = pseudo_random_digests(index, need);
        digested = digested.saturating_add(usize::from(!need.is_empty()));
        found = found
            .saturating_add(executable_section_detections(&image, size, &digests, settings)?.len());
    }
    let sections = stopwatch.elapsed();
    let stopwatch = Stopwatch::start();
    for index in 0..LOOKUPS {
        let size = u64::from(index % 200_000).saturating_add(6);
        let need = whole_object_digest_need(&image, size, settings)?;
        let digests = pseudo_random_digests(index, need);
        found =
            found.saturating_add(whole_object_detections(&image, size, &digests, settings)?.len());
    }
    let whole_objects = stopwatch.elapsed();
    let rate = |elapsed: std::time::Duration| f64::from(LOOKUPS) / elapsed.as_secs_f64();
    Ok(format!(
        "section lookups (need + lookup, digest given): {:.0}/s ({digested} of {LOOKUPS} sizes needed a digest)\n\
         whole-object lookups (need + lookup, digest given): {:.0}/s\nmatches: {found}",
        rate(sections),
        rate(whole_objects)
    ))
}

fn pseudo_random_digests(seed: u32, need: debar_matching::DigestNeed) -> ObjectDigests {
    let mut state = u64::from(seed).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state.to_le_bytes()
    };
    let mut md5 = [0u8; 16];
    md5[..8].copy_from_slice(&next());
    md5[8..].copy_from_slice(&next());
    let mut sha256 = [0u8; 32];
    for chunk in sha256.chunks_mut(8) {
        chunk.copy_from_slice(&next());
    }
    ObjectDigests {
        md5: need.md5.then_some(md5),
        sha1: None,
        sha256: need.sha256.then_some(sha256),
    }
}
