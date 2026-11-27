#![forbid(unsafe_code)]
#![no_main]

use debar_clamav_signatures::{DatabaseFile, compile};
use debar_image::ImageBuilder;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let files = [DatabaseFile {
        name: "a.cdb",
        contents: data,
    }];
    let mut builder = ImageBuilder::new();
    if compile(&files, &mut builder).is_ok() {
        let _ = builder.finish();
    }
});
