#![no_main]

use debar_clamav_signatures::{DatabaseFile, compile};
use debar_image::ImageBuilder;
use libfuzzer_sys::fuzz_target;

const SUBSIGNATURES: usize = 64;

fuzz_target!(|expression: &[u8]| {
    if expression.iter().any(|byte| matches!(byte, b';' | b'\n' | b'/')) {
        return;
    }
    let mut line = b"Fuzz.Expression;Target:0;".to_vec();
    line.extend_from_slice(expression);
    for index in 0..SUBSIGNATURES {
        line.extend_from_slice(format!(";4142{:04x}", index).as_bytes());
    }
    line.push(b'\n');
    let files = [DatabaseFile {
        name: "a.ldb",
        contents: &line,
    }];
    for subsignatures in [1usize, SUBSIGNATURES] {
        let mut trimmed = b"Fuzz.Expression;Target:0;".to_vec();
        trimmed.extend_from_slice(expression);
        for index in 0..subsignatures {
            trimmed.extend_from_slice(format!(";4142{:04x}", index).as_bytes());
        }
        trimmed.push(b'\n');
        let files = [DatabaseFile {
            name: "a.ldb",
            contents: &trimmed,
        }];
        let mut builder = ImageBuilder::new();
        if compile(&files, &mut builder).is_ok() {
            let _ = builder.finish();
        }
    }
    let mut builder = ImageBuilder::new();
    if compile(&files, &mut builder).is_ok() {
        let _ = builder.finish();
    }
});
