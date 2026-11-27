#![forbid(unsafe_code)]
#![no_main]

#[path = "../tests/modules/test_container.rs"]
mod test_container;

use std::alloc::System;
use std::sync::OnceLock;

use cap::Cap;
use debar_formats::FormatModule;
use debar_image::Image;
use debar_scan::{
    Facts, FinishedObject, FormatModules, Limits, Matching, ObjectObserver, ScanSettings,
    scan_with_modules,
};
use libfuzzer_sys::fuzz_target;
use test_container::{MAGIC, TEST_CONTAINER_MODULE, add_body, test_container_image_builder};

#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, usize::MAX);

const MEMORY_BOUND_BYTES: usize = 32 * 1024 * 1024;
const FILE_SIZE_STEP: u64 = 32 * 1024;
const SCAN_SIZE_STEP: u64 = 128 * 1024;
const MODULES: &[&dyn FormatModule] = &[&TEST_CONTAINER_MODULE];
const SETTINGS_BYTES: usize = 4;

fn image() -> &'static [u8] {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        let mut builder = test_container_image_builder().unwrap();
        add_body(&mut builder, "Test.Body", b"BODY").unwrap();
        builder.finish().unwrap()
    })
}

struct Bounds {
    deepest_level: u32,
    most_files: u64,
    finished: u64,
}

impl ObjectObserver for Bounds {
    fn object_finished(&mut self, object: &FinishedObject<'_>) {
        assert!(
            object.depth <= self.deepest_level,
            "an object at depth {} is beyond the deepest level {}",
            object.depth,
            self.deepest_level
        );
        self.finished = self.finished.saturating_add(1);
        assert!(
            self.finished <= self.most_files,
            "{} objects finished where {} files are allowed",
            self.finished,
            self.most_files
        );
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((chosen, rest)) = input.split_first_chunk::<SETTINGS_BYTES>() else {
        return;
    };
    let [flags, file_steps, scan_steps, files] = *chosen;
    let object = if flags & 1 == 1 {
        let mut container = MAGIC.to_vec();
        container.extend_from_slice(&[0; 4]);
        container.extend_from_slice(rest);
        container
    } else {
        rest.to_vec()
    };
    let limits = Limits {
        largest_file: Some(FILE_SIZE_STEP.saturating_mul(u64::from(file_steps) + 1)),
        largest_scan: Some(SCAN_SIZE_STEP.saturating_mul(u64::from(scan_steps) + 1)),
        most_files: Some(u64::from(files % 64) + 1),
        deepest_level: u32::from(flags >> 3),
    };
    let settings = ScanSettings {
        matching: if flags & 2 == 2 {
            Matching::EveryMatch
        } else {
            Matching::FirstMatch
        },
        alert_on_limits: flags & 4 == 4,
        facts: Facts::Gathered,
        limits,
        ..ScanSettings::default()
    };
    let image = Image::open(image()).unwrap();
    let mut bounds = Bounds {
        deepest_level: limits.deepest_level,
        most_files: limits.most_files.unwrap_or(u64::MAX),
        finished: 0,
    };

    ALLOCATOR
        .set_limit(ALLOCATOR.allocated().saturating_add(MEMORY_BOUND_BYTES))
        .unwrap();
    let report = scan_with_modules(
        &image,
        &object.as_slice(),
        &settings,
        FormatModules::new(MODULES),
        &mut bounds,
    );
    ALLOCATOR.set_limit(usize::MAX).unwrap();
    drop(report);
});
