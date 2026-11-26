#![no_main]

use debar_clamav_signatures::{DatabaseFile, compile};
use debar_image::{Image, ImageBuilder, ObjectKind};
use debar_matching::{
    ExecutableLayout, ExecutableSection, GroupSelection, PatternRequest, PatternScan,
    PatternSettings,
};
use libfuzzer_sys::fuzz_target;

const OBJECT_SEPARATOR: &[u8] = b"\n--object--\n";

fuzz_target!(|data: &[u8]| {
    let (database, object) = match data
        .windows(OBJECT_SEPARATOR.len())
        .position(|window| window == OBJECT_SEPARATOR)
    {
        Some(at) => (&data[..at], &data[at + OBJECT_SEPARATOR.len()..]),
        None => (data, &b"an object to scan"[..]),
    };
    let files = [DatabaseFile {
        name: "fuzzed.ndb",
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
    let settings = PatternSettings {
        potentially_unwanted: true,
        every_match: true,
    };
    let layout = ExecutableLayout {
        entry_point: 9,
        sections: vec![
            ExecutableSection {
                start: 0,
                length: 12,
            },
            ExecutableSection {
                start: 12,
                length: 40,
            },
        ],
        version_information: vec![3],
    };
    for kind in [
        ObjectKind::Untyped,
        ObjectKind::WindowsExecutable,
        ObjectKind::Elf,
        ObjectKind::Text,
    ] {
        let request = PatternRequest {
            selection: GroupSelection::ForKindRecognisingTypes(kind),
            settings,
            object_length: object.len() as u64,
        };
        let layout = layout.clone();
        let mut scan = PatternScan::new(&image, request, || Some(layout)).expect("the scan starts");
        for chunk in object.chunks(7) {
            scan.feed(chunk).expect("a chunk is accepted");
        }
        scan.finish().expect("the scan finishes");
    }
});
