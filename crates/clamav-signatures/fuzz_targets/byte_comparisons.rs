#![forbid(unsafe_code)]
#![no_main]

use debar_clamav_signatures::{DatabaseFile, compile};
use debar_image::ImageBuilder;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut line = b"Fuzz.Compared;Target:0;1;41424344;".to_vec();
    line.extend(data.iter().copied().filter(|byte| !matches!(byte, b'\n' | b';')));
    line.push(b'\n');
    let files = [DatabaseFile {
        name: "a.ldb",
        contents: &line,
    }];
    let mut builder = ImageBuilder::new();
    if compile(&files, &mut builder).is_ok() {
        let _ = builder.finish();
    }
});
