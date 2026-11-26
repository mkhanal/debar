#![no_main]

use debar_clamav_signatures::{DatabaseFile, compile};
use debar_image::ImageBuilder;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(split) = data.iter().position(|byte| *byte == b'\n') else {
        return;
    };
    let (pattern, flags) = data.split_at(split);
    let mut line = b"Fuzz.Regular;Target:0;0&1;41424344;0/".to_vec();
    line.extend(pattern.iter().copied().filter(|byte| *byte != b'\n'));
    line.push(b'/');
    line.extend(flags.iter().copied().filter(|byte| *byte != b'\n'));
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
