#![no_main]

use debar_clamav_signatures::{DatabaseFile, compile};
use debar_image::ImageBuilder;
use libfuzzer_sys::fuzz_target;

const FILE_SEPARATOR: &[u8] = b"\xff\x00\xff";
const FILE_NAMES: [&str; 19] = [
    "a.hdb", "a.hsb", "a.hdu", "a.hsu", "a.mdb", "a.msb", "a.mdu", "a.msu", "a.fp", "a.sfp",
    "a.ign", "a.ign2", "b.ign2", "b.hdb", "a.ndb", "a.cbc", "a.ftm", "a.ldb", "a.ndu",
];

fuzz_target!(|data: &[u8]| {
    let mut files = Vec::new();
    let mut rest = data;
    while let Some((&choice, after)) = rest.split_first() {
        let end = after
            .windows(FILE_SEPARATOR.len())
            .position(|window| window == FILE_SEPARATOR)
            .unwrap_or(after.len());
        let (contents, next) = after.split_at(end);
        let name = FILE_NAMES[usize::from(choice) % FILE_NAMES.len()];
        files.push(DatabaseFile { name, contents });
        rest = next.get(FILE_SEPARATOR.len()..).unwrap_or_default();
    }
    let mut builder = ImageBuilder::new();
    if compile(&files, &mut builder).is_ok() {
        let _ = builder.finish();
    }
});
