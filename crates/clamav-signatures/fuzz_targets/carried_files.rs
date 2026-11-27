#![forbid(unsafe_code)]
#![no_main]

use debar_clamav_signatures::{DatabaseFile, compile};
use debar_image::ImageBuilder;
use libfuzzer_sys::fuzz_target;

const NAMES: [&str; 7] = [
    "daily.cfg",
    "local.crb",
    "local.idb",
    "local.pdb",
    "local.wdb",
    "local.gdb",
    "local.ign2",
];

fuzz_target!(|data: &[u8]| {
    let Some((selector, contents)) = data.split_first() else {
        return;
    };
    let name = NAMES[usize::from(*selector) % NAMES.len()];
    let files = [
        DatabaseFile { name, contents },
        DatabaseFile {
            name: "other.idb",
            contents: contents.get(contents.len() / 2..).unwrap_or_default(),
        },
    ];
    let mut builder = ImageBuilder::new();
    if compile(&files, &mut builder).is_ok() {
        let _ = builder.finish();
    }
});
