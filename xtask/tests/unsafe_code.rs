#![forbid(unsafe_code)]

use serde_json::json;
use xtask::requirements::TextFile;
use xtask::unsafe_code::{
    CrateRoot, UNSAFE_BLOCKS, UnsafeCodeFinding, UnsafeModule, UnsafeUse, crate_roots,
    roots_without_the_promise, unsafe_inventory_findings, unsafe_uses,
};

fn file(path: &str, text: &str) -> TextFile {
    TextFile {
        path: path.to_owned(),
        text: text.to_owned(),
    }
}

fn root(package: &str, is_library: bool, path: &str, text: &str) -> (CrateRoot, TextFile) {
    (
        CrateRoot {
            package: package.to_owned(),
            is_library,
            path: path.to_owned(),
        },
        file(path, text),
    )
}

const PROMISING_ROOT: &str = "#![forbid(unsafe_code)]\n#![no_main]\n\nfn main() {}\n";

#[test]
fn a_root_forbidding_unsafe_code_keeps_the_promise() {
    let roots = [root(
        "debar-image",
        true,
        "crates/image/src/lib.rs",
        PROMISING_ROOT,
    )];

    assert_eq!(roots_without_the_promise(&roots), vec![]);
}

#[test]
fn a_root_that_does_not_forbid_unsafe_code_is_reported() {
    let roots = [
        root(
            "debar-image",
            true,
            "crates/image/src/lib.rs",
            "pub mod image;\n",
        ),
        root(
            "debar-image",
            false,
            "crates/image/tests/image.rs",
            "#![deny(unsafe_code)]\n",
        ),
    ];

    assert_eq!(
        roots_without_the_promise(&roots),
        vec![
            UnsafeCodeFinding::RootDoesNotForbidUnsafeCode {
                root: "crates/image/src/lib.rs".to_owned()
            },
            UnsafeCodeFinding::RootDoesNotForbidUnsafeCode {
                root: "crates/image/tests/image.rs".to_owned()
            },
        ]
    );
}

#[test]
fn the_promise_in_a_comment_or_after_the_first_item_does_not_count() {
    let roots = [
        root(
            "xtask",
            false,
            "xtask/src/main.rs",
            "// #![forbid(unsafe_code)]\nfn main() {}\n",
        ),
        root(
            "xtask",
            true,
            "xtask/src/lib.rs",
            "pub mod tasks;\n#![forbid(unsafe_code)]\n",
        ),
    ];

    assert_eq!(roots_without_the_promise(&roots).len(), 2);
}

#[test]
fn only_the_platform_library_is_spared_the_promise() {
    let roots = [
        root(
            "debar-platform",
            true,
            "crates/platform/src/lib.rs",
            "pub mod input;\n",
        ),
        root(
            "debar-platform",
            false,
            "crates/platform/tests/input.rs",
            "fn input() {}\n",
        ),
    ];

    assert_eq!(
        roots_without_the_promise(&roots),
        vec![UnsafeCodeFinding::RootDoesNotForbidUnsafeCode {
            root: "crates/platform/tests/input.rs".to_owned()
        }]
    );
}

#[test]
fn every_target_of_every_package_is_a_crate_root() {
    let metadata = json!({
        "version": 1,
        "packages": [{
            "name": "debar-matching",
            "targets": [
                { "kind": ["lib"], "src_path": "/work/crates/matching/src/lib.rs" },
                { "kind": ["example"], "src_path": "/work/crates/matching/examples/rate.rs" },
                { "kind": ["custom-build"], "src_path": "/work/crates/matching/build.rs" },
                { "kind": ["bin"], "src_path": "/work/fuzz/../crates/matching/fuzz_targets/scan.rs" }
            ]
        }]
    })
    .to_string();

    let roots = crate_roots(&metadata, "/work/").unwrap();

    assert_eq!(
        roots,
        vec![
            CrateRoot {
                package: "debar-matching".to_owned(),
                is_library: true,
                path: "crates/matching/src/lib.rs".to_owned(),
            },
            CrateRoot {
                package: "debar-matching".to_owned(),
                is_library: false,
                path: "crates/matching/examples/rate.rs".to_owned(),
            },
            CrateRoot {
                package: "debar-matching".to_owned(),
                is_library: false,
                path: "crates/matching/build.rs".to_owned(),
            },
            CrateRoot {
                package: "debar-matching".to_owned(),
                is_library: false,
                path: "crates/matching/fuzz_targets/scan.rs".to_owned(),
            },
        ]
    );
}

#[test]
fn unsafe_blocks_and_unsafe_items_are_found_with_their_lines() {
    let source = "fn map() {\n    let a = unsafe { first() };\n}\nunsafe fn second() {}\nunsafe impl Send for Gate {}\n#[unsafe(no_mangle)]\nextern \"C\" fn third() {}\n";

    assert_eq!(
        unsafe_uses(source),
        vec![
            UnsafeUse::Block { line: 2 },
            UnsafeUse::Item { line: 4 },
            UnsafeUse::Item { line: 5 },
            UnsafeUse::Item { line: 6 },
        ]
    );
}

#[test]
fn unsafe_in_comments_strings_and_longer_names_is_not_unsafe_code() {
    let source = r##"
// unsafe { this is a comment }
/* unsafe { a /* nested */ block comment } */
const LINT: &str = "unsafe_code = \"forbid\" and unsafe { in a string }";
const RAW: &str = r#"unsafe { "in a raw string" }"#;
const BYTES: &[u8] = b"unsafe {";
const QUOTE: char = '"';
fn unsafe_code_is_forbidden<'a>(not_unsafe: &'a str) -> &'a str { not_unsafe }
"##;

    assert_eq!(unsafe_uses(source), vec![]);
}

#[test]
fn a_block_after_a_line_break_is_still_a_block() {
    assert_eq!(
        unsafe_uses("let a = unsafe\n    { first() };\n"),
        vec![UnsafeUse::Block { line: 1 }]
    );
}

const INVENTORY: [UnsafeModule; 1] = [UnsafeModule {
    path: "crates/platform/src/mapped_file.rs",
    blocks: 1,
}];

#[test]
fn unsafe_blocks_where_the_inventory_lists_them_are_accepted() {
    let sources = [
        file(
            "crates/platform/src/mapped_file.rs",
            "fn map() { unsafe { map() } }\n",
        ),
        file("crates/image/src/lib.rs", "fn read() {}\n"),
    ];

    assert_eq!(unsafe_inventory_findings(&sources, &INVENTORY), vec![]);
}

#[test]
fn an_unsafe_block_in_a_file_the_inventory_does_not_list_is_reported() {
    let sources = [
        file(
            "crates/platform/src/mapped_file.rs",
            "fn map() { unsafe { map() } }\n",
        ),
        file(
            "crates/image/src/lib.rs",
            "fn read() { unsafe { read() } }\n",
        ),
    ];

    assert_eq!(
        unsafe_inventory_findings(&sources, &INVENTORY),
        vec![UnsafeCodeFinding::UnsafeBlocksNotInTheInventory {
            path: "crates/image/src/lib.rs".to_owned(),
            found: 1,
        }]
    );
}

#[test]
fn a_listed_file_with_a_different_number_of_blocks_is_reported() {
    let sources = [file(
        "crates/platform/src/mapped_file.rs",
        "fn map() { unsafe { map() }; unsafe { advise() } }\n",
    )];

    assert_eq!(
        unsafe_inventory_findings(&sources, &INVENTORY),
        vec![UnsafeCodeFinding::UnsafeBlockCountDiffers {
            path: "crates/platform/src/mapped_file.rs".to_owned(),
            listed: 1,
            found: 2,
        }]
    );
}

#[test]
fn a_listed_file_that_is_gone_is_reported() {
    assert_eq!(
        unsafe_inventory_findings(&[], &INVENTORY),
        vec![UnsafeCodeFinding::UnsafeBlockCountDiffers {
            path: "crates/platform/src/mapped_file.rs".to_owned(),
            listed: 1,
            found: 0,
        }]
    );
}

#[test]
fn an_unsafe_function_or_implementation_is_reported_even_in_a_listed_file() {
    let sources = [file(
        "crates/platform/src/mapped_file.rs",
        "fn map() { unsafe { map() } }\npub unsafe fn raw() {}\n",
    )];

    assert_eq!(
        unsafe_inventory_findings(&sources, &INVENTORY),
        vec![UnsafeCodeFinding::UnsafeItem {
            path: "crates/platform/src/mapped_file.rs".to_owned(),
            line: 2,
        }]
    );
}

#[test]
fn every_listed_module_is_in_the_platform_crate() {
    assert!(
        UNSAFE_BLOCKS
            .iter()
            .all(|module| module.path.starts_with("crates/platform/src/"))
    );
}

#[test]
fn the_committed_inventory_matches_the_platform_crate() {
    let sources: Vec<TextFile> = UNSAFE_BLOCKS
        .iter()
        .map(|module| {
            file(
                module.path,
                &std::fs::read_to_string(format!(
                    "{}/../{}",
                    env!("CARGO_MANIFEST_DIR"),
                    module.path
                ))
                .unwrap(),
            )
        })
        .collect();

    assert_eq!(unsafe_inventory_findings(&sources, &UNSAFE_BLOCKS), vec![]);
}
