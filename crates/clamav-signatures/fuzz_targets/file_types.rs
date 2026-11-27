#![forbid(unsafe_code)]
#![no_main]

use debar_clamav_signatures::{DatabaseFile, compile};
use debar_image::{Image, ImageBuilder};
use debar_scan::{kind_after_full_scan, kind_from_first_bytes};
use libfuzzer_sys::fuzz_target;

const OBJECT_SEPARATOR: &[u8] = b"\n--object--\n";

fuzz_target!(|data: &[u8]| {
    let (database, object) = match data
        .windows(OBJECT_SEPARATOR.len())
        .position(|window| window == OBJECT_SEPARATOR)
    {
        Some(at) => (&data[..at], &data[at + OBJECT_SEPARATOR.len()..]),
        None => (data, &b"<html><body>an object to type</body></html>"[..]),
    };
    let files = [DatabaseFile {
        name: "fuzzed.ftm",
        contents: database,
    }];
    let mut builder = ImageBuilder::new();
    if compile(&files, &mut builder).is_err() {
        return;
    }
    let Ok(bytes) = builder.finish() else {
        return;
    };
    let image = Image::open(&bytes).expect("a built image opens");
    let kind = kind_from_first_bytes(&image, object).expect("an object is typed");
    kind_after_full_scan(&image, kind, &[]).expect("a full scan's findings are weighed");
});
