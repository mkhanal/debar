#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use acceptance::official_image;
use acceptance::scan_speed::{
    BEST_MEASURED_RECORD, BEST_MEASURED_TOLERANCE, Calibration, TIMES_THE_REFERENCE_REQUIRED,
    as_float, best_measured, measured_scan_speed, this_architecture,
};
use acceptance::small_object_cost::{
    BEST_SMALL_OBJECT_RECORD, best_small_object_cost, measured_small_object_cost,
};

#[test]
fn debar_scans_at_least_twice_as_fast_as_the_reference_scanner() {
    const REQUIREMENT: &str = "Debar Scans At Least Twice As Fast As The Reference Scanner";
    let official = official_image().unwrap();
    let mut failures = Vec::new();
    for measured in measured_scan_speed(&official.image).unwrap() {
        let kind = &measured.kind;
        let per_mebibyte = measured.instructions_per_mebibyte;
        let budget = Calibration::of(kind)
            .unwrap()
            .instructions_per_mebibyte_at(TIMES_THE_REFERENCE_REQUIRED);
        println!(
            "{kind}: {} bytes, {per_mebibyte:.0} instructions per MiB, budget {budget:.0} ({:.0}% of it)",
            measured.bytes,
            100.0 * per_mebibyte / budget
        );
        if per_mebibyte > budget {
            failures.push(format!("{kind}: {per_mebibyte:.0} > {budget:.0}"));
        }
    }
    assert!(failures.is_empty(), "{REQUIREMENT}: {failures:?}");
}

#[test]
fn debar_never_scans_slower_than_its_best_measured_speed() {
    const REQUIREMENT: &str = "Debar Never Scans Slower Than Its Best Measured Speed";
    let official = official_image().unwrap();
    let mut failures = Vec::new();
    for measured in measured_scan_speed(&official.image).unwrap() {
        let kind = &measured.kind;
        let per_mebibyte = measured.instructions_per_mebibyte;
        let best = as_float(best_measured(kind).unwrap());
        let ceiling = best * (1.0 + BEST_MEASURED_TOLERANCE);
        let floor = best / (1.0 + BEST_MEASURED_TOLERANCE);
        println!("{kind}: {per_mebibyte:.0} instructions per MiB, best recorded {best:.0}");
        if per_mebibyte > ceiling {
            failures.push(format!(
                "{kind} scans slower than its best: {per_mebibyte:.0} > {ceiling:.0}"
            ));
        } else if per_mebibyte < floor {
            failures.push(format!(
                "{kind} scans faster than its record: set {} {kind} to {per_mebibyte:.0} in {BEST_MEASURED_RECORD}",
                this_architecture()
            ));
        }
    }
    assert!(failures.is_empty(), "{REQUIREMENT}: {failures:?}");
}

#[test]
fn debar_never_spends_more_on_a_small_object_than_its_best_measured_cost() {
    const REQUIREMENT: &str =
        "Debar Never Spends More On A Small Object Than Its Best Measured Cost";
    let official = official_image().unwrap();
    let mut failures = Vec::new();
    for measured in measured_small_object_cost(&official.image).unwrap() {
        let kind = &measured.kind;
        let per_object = measured.instructions_per_object;
        let best = as_float(best_small_object_cost(kind).unwrap());
        let ceiling = best * (1.0 + BEST_MEASURED_TOLERANCE);
        let floor = best / (1.0 + BEST_MEASURED_TOLERANCE);
        println!(
            "{kind}: {} objects, {per_object:.0} instructions per object, best recorded {best:.0}",
            measured.objects
        );
        if per_object > ceiling {
            failures.push(format!(
                "{kind} spends more per small object than its best: {per_object:.0} > {ceiling:.0}"
            ));
        } else if per_object < floor {
            failures.push(format!(
                "{kind} spends less per small object than its record: set {} {kind} to {per_object:.0} in {BEST_SMALL_OBJECT_RECORD}",
                this_architecture()
            ));
        }
    }
    assert!(failures.is_empty(), "{REQUIREMENT}: {failures:?}");
}
