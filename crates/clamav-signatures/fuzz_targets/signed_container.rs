#![no_main]

use debar_clamav_signatures::{DatabaseFile, compile};
use debar_image::ImageBuilder;
use libfuzzer_sys::fuzz_target;
use md5::{Digest as _, Md5};

const HEADER_LENGTH: usize = 512;

fuzz_target!(|payload: &[u8]| {
    let digest: String = Md5::digest(payload).iter().map(|byte| format!("{byte:02x}")).collect();
    let mut container =
        format!("ClamAV-VDB:01 Jan 2026 00-00 +0000:1:1:90:{digest}:signature:fuzz:1").into_bytes();
    container.resize(HEADER_LENGTH, b' ');
    container.extend_from_slice(payload);
    let files = [DatabaseFile {
        name: "daily.cvd",
        contents: &container,
    }];
    let mut builder = ImageBuilder::new();
    if compile(&files, &mut builder).is_ok() {
        let _ = builder.finish();
    }
});
