#![forbid(unsafe_code)]
#![no_main]

use debar_clamav_signatures::{DatabaseFile, compile};
use debar_image::ImageBuilder;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (name, contents) = match data.split_first() {
        Some((choice, rest)) if choice % 2 == 0 => ("a.ldb", rest),
        Some((_, rest)) => ("a.ldu", rest),
        None => return,
    };
    let files = [DatabaseFile { name, contents }];
    let mut builder = ImageBuilder::new();
    if compile(&files, &mut builder).is_ok() {
        let _ = builder.finish();
    }
});
