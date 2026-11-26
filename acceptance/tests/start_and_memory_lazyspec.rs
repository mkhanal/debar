#![allow(clippy::unwrap_used)]

use acceptance::{
    instructions_to_scan_one_small_file, median_seconds_to_scan_one_small_file, memory_once_ready,
    official_image, scratch_directory,
};

const READY_BUDGET_INSTRUCTIONS: u64 = 50_000_000;
const IMAGE_RESIDENT_ONCE_READY_BYTES: u64 = 512 * 1024;
const PRIVATE_MEMORY_BUDGET_BYTES: u64 = 64 * 1024 * 1024;

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
