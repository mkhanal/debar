#![forbid(unsafe_code)]
#![no_main]

use debar_clamav_signatures::{DatabaseFile, compile};
use debar_image::{Image, ImageBuilder, ObjectKind};
use debar_matching::{
    ContainerEntry, GroupSelection, ObjectContext, PatternRequest, PatternSettings,
    UnwantedCategories, container_entry_detections, scan_object,
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const SIGNATURES: &str = "\
Fuzz.Regular;Target:0;0&1;4142;0/a(b|c)*?d$/g
Fuzz.Anchored;Target:0;1;4142;EOF-4:0/[^\\n]{2}\\s/
Fuzz.Bounded;Target:0;1;4142;2,8:0/b.c/e
Fuzz.Binary;Target:0;1;4142;0(>>2#ib2#>256)
Fuzz.Text;Target:0;1;4142;0(<<1#al4#=0x1f)
Fuzz.Image;Target:0;0;fuzzy_img#0102030405060708
";
const CONTAINERS: &str = "\
Fuzz.Name:CL_TYPE_ZIP:*:(?i)e+vil\\.(exe|scr)$:*:*:*:*:*:*
Fuzz.Sizes:*:10-0:*:0-20:5:0:2:*:*
";

fn image() -> &'static [u8] {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        let files = [
            DatabaseFile {
                name: "fuzz.ldb",
                contents: SIGNATURES.as_bytes(),
            },
            DatabaseFile {
                name: "fuzz.cdb",
                contents: CONTAINERS.as_bytes(),
            },
        ];
        let mut builder = ImageBuilder::new();
        compile(&files, &mut builder).expect("the fuzz databases compile");
        builder.finish().expect("the fuzz image builds")
    })
}

fuzz_target!(|data: &[u8]| {
    let image = Image::open(image()).expect("the fuzz image opens");
    let Some((&choice, object)) = data.split_first() else {
        return;
    };
    let request = PatternRequest {
        selection: GroupSelection::ForKind(ObjectKind::BinaryData),
        settings: PatternSettings {
            potentially_unwanted: false,
            unwanted_categories: UnwantedCategories::Every,
            every_match: true,
            largest_object_for_regular_expressions: (choice & 1 == 0).then_some(64),
        },
        object_length: object.len() as u64,
        context: ObjectContext::TOP_LEVEL,
        image_fuzzy_hash: (choice & 2 == 0).then_some(0x0102_0304_0506_0708),
    };
    let _ = scan_object(&image, request, || None, object);
    let entry = ContainerEntry {
        container: ObjectKind::Zip,
        container_size: u64::from(choice),
        name: Some(object),
        compressed_size: object.len() as u64,
        real_size: u64::from(choice >> 2),
        encrypted: choice & 4 == 0,
        position: u64::from(choice & 3),
    };
    container_entry_detections(&image, &entry, choice & 8 == 0).expect("container entries match");
});
