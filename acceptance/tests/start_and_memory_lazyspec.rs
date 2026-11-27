#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use acceptance::largest_file::{LARGEST_FILE, expressions_to_the_end, matched_only_to_the_end};
use acceptance::{
    instructions_to_scan_one_small_file, median_seconds_to_scan_one_small_file, memory_once_ready,
    official_image, peak_heap_bytes_to_scan, scratch_directory, write_file,
};

const READY_BUDGET_INSTRUCTIONS: u64 = 50_000_000;
const IMAGE_RESIDENT_ONCE_READY_BYTES: u64 = 512 * 1024;
const PRIVATE_MEMORY_BUDGET_BYTES: u64 = 64 * 1024 * 1024;
const SCAN_MEMORY_BUDGET_BYTES: u64 = 32 * 1024 * 1024;

#[test]
fn debar_is_ready_to_scan_within_50_ms_of_starting_with_every_pinned_database_in_its_image() {
    const REQUIREMENT: &str =
        "Debar Is Ready To Scan Within 50 ms Of Starting, With Every Pinned Database In Its Image";
    let official = official_image().unwrap();
    let directory = scratch_directory("ready-within-budget").unwrap();

    let instructions = instructions_to_scan_one_small_file(&official.image, &directory).unwrap();
    let memory = memory_once_ready(&official.image, &directory).unwrap();
    let median = median_seconds_to_scan_one_small_file(&official.image, &directory).unwrap();

    println!("{REQUIREMENT}: wall-clock median, recorded and not gated: {median:.4} s");
    println!("instructions to start, become ready and scan one small file: {instructions}");
    println!(
        "image bytes resident once ready: {}",
        memory.image_resident_bytes
    );
    assert!(
        instructions <= READY_BUDGET_INSTRUCTIONS,
        "{REQUIREMENT}: {instructions} instructions"
    );
    assert!(
        memory.image_resident_bytes <= IMAGE_RESIDENT_ONCE_READY_BYTES,
        "{REQUIREMENT}: {} image bytes resident",
        memory.image_resident_bytes
    );
}

#[test]
fn debar_holds_at_most_64_mib_of_private_memory_once_ready() {
    const REQUIREMENT: &str = "Debar Holds At Most 64 MiB Of Private Memory Once Ready";
    let official = official_image().unwrap();
    let directory = scratch_directory("private-memory").unwrap();

    let memory = memory_once_ready(&official.image, &directory).unwrap();

    println!("private bytes once ready: {}", memory.private_bytes);
    assert!(
        memory.private_bytes <= PRIVATE_MEMORY_BUDGET_BYTES,
        "{REQUIREMENT}: {} private bytes",
        memory.private_bytes
    );
}

#[test]
fn scanning_one_file_holds_at_most_32_mib_of_memory() {
    const REQUIREMENT: &str = "Scanning One File Holds At Most 32 MiB Of Memory";
    let directory = scratch_directory("memory-per-scan").unwrap();
    let compiled = expressions_to_the_end(&directory).unwrap();
    let largest = matched_only_to_the_end(&directory, LARGEST_FILE).unwrap();
    let unscanned = directory.join("unscanned");
    write_file(&unscanned, b"MARK").unwrap();

    let scanning = peak_heap_bytes_to_scan(&compiled.image, &largest, &directory).unwrap();
    let not_scanning = peak_heap_bytes_to_scan(&compiled.image, &unscanned, &directory).unwrap();
    let held_for_the_scan = scanning.saturating_sub(not_scanning);

    println!("peak heap bytes held for a scan of {LARGEST_FILE} bytes: {held_for_the_scan}");
    assert!(
        held_for_the_scan <= SCAN_MEMORY_BUDGET_BYTES,
        "{REQUIREMENT}: {held_for_the_scan} bytes"
    );
}
