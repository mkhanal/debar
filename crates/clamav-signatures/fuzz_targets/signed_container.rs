#![no_main]

use debar_clamav_signatures::{DatabaseFile, compile};
use debar_image::ImageBuilder;
use libfuzzer_sys::fuzz_target;
use md5::{Digest as _, Md5};

const HEADER_LENGTH: usize = 512;
const SEPARATOR: u8 = 0xff;

fn header(kind_signature: &[u8], payload: &[u8]) -> Vec<u8> {
    let digest: String = Md5::digest(payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut container =
        format!("ClamAV-VDB:01 Jan 2026 00-00 +0000:1:1:90:{digest}:").into_bytes();
    container.extend(kind_signature.iter().filter(|byte| **byte != b':').take(200));
    container.extend_from_slice(b":fuzz:1");
    container.resize(HEADER_LENGTH, b' ');
    container.truncate(HEADER_LENGTH);
    container.extend_from_slice(payload);
    container
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(3, |byte| *byte == SEPARATOR);
    let signature = parts.next().unwrap_or_default();
    let detached = parts.next().unwrap_or_default();
    let payload = parts.next().unwrap_or_default();
    let container = header(signature, payload);
    for name in ["daily.cvd", "daily.cld", "daily.cud"] {
        let files = [
            DatabaseFile {
                name,
                contents: &container,
            },
            DatabaseFile {
                name: "daily-1.cvd.sign",
                contents: detached,
            },
        ];
        let mut builder = ImageBuilder::new();
        if compile(&files, &mut builder).is_ok() {
            let _ = builder.finish();
        }
    }
});
