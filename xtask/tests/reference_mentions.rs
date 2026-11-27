#![forbid(unsafe_code)]

use xtask::reference_mentions::{COMPARISON_WORKFLOW, REFERENCE_SCANNER_NAMES, mentions};

fn every_name() -> impl Iterator<Item = &'static str> {
    REFERENCE_SCANNER_NAMES.iter().copied()
}

#[test]
fn a_file_naming_the_reference_scanner_outside_the_allowed_paths_is_reported() {
    for name in every_name() {
        let content = format!("first line\nwe behave like {name} here\n");

        let found = mentions("crates/scan/src/verdict.rs", content.as_bytes());

        assert_eq!(found.len(), 1, "{name}");
        assert_eq!(found[0].path, "crates/scan/src/verdict.rs");
        assert_eq!(found[0].line, Some(2));
    }
}

#[test]
fn a_mention_is_found_whatever_its_case() {
    for name in every_name() {
        let content = name.to_uppercase();

        assert_eq!(
            mentions("architecture-overview/DECISIONS.md", content.as_bytes()).len(),
            1,
            "{name}"
        );
    }
}

#[test]
fn a_file_whose_path_names_the_reference_scanner_is_reported() {
    for name in every_name() {
        let path = format!("crates/{name}/src/lib.rs");
        let found = mentions(&path, b"");

        assert!(found.iter().any(|mention| mention.line.is_none()), "{path}");
    }
}

#[test]
fn a_file_without_a_mention_is_accepted() {
    assert_eq!(mentions("README.md", b"Debar scans files."), vec![]);
    assert_eq!(
        mentions("crates/platform/src/lib.rs", b"pub fn open() {}"),
        vec![]
    );
}

#[test]
fn the_product_description_may_name_the_supported_format_and_interface() {
    for name in every_name() {
        assert_eq!(mentions("PRODUCT.md", name.as_bytes()), vec![]);
        assert_eq!(mentions("README.md", name.as_bytes()), vec![]);
    }
}

#[test]
fn a_specification_may_name_the_compatibility_surface() {
    for name in every_name() {
        assert_eq!(
            mentions("specs/commands.lazyspec.md", name.as_bytes()),
            vec![]
        );
    }
}

#[test]
fn the_compatibility_part_may_name_the_scanner_it_translates() {
    let compatibility_part = format!("crates/compat-{}/src/lib.rs", REFERENCE_SCANNER_NAMES[0]);

    for name in every_name() {
        assert_eq!(mentions(&compatibility_part, name.as_bytes()), vec![]);
    }
}

#[test]
fn a_file_merely_beside_an_allowed_path_is_still_checked() {
    let name = REFERENCE_SCANNER_NAMES[0];

    assert_eq!(mentions("PRODUCT.md.orig", name.as_bytes()).len(), 1);
    assert_eq!(mentions("specs-old/notes.md", name.as_bytes()).len(), 1);
    assert_eq!(mentions("docs/specs/notes.md", name.as_bytes()).len(), 1);
}

#[test]
fn a_binary_file_naming_the_reference_scanner_is_reported() {
    let mut content = vec![0x00, 0xff, 0xfe];
    content.extend_from_slice(REFERENCE_SCANNER_NAMES[0].as_bytes());

    assert_eq!(mentions("crates/image/tests/sample.bin", &content).len(), 1);
}

#[test]
fn naming_the_part_that_supports_the_format_is_not_a_mention() {
    let part = format!("{}-signatures", REFERENCE_SCANNER_NAMES[0]);
    let lines = [
        format!("members = [\"crates/{part}\"]"),
        format!("{{ crate = \"debar-{part}\", wrappers = [] }}"),
        format!("use debar_{}::read;", part.replace('-', "_")),
    ];

    for line in lines {
        assert_eq!(mentions("Cargo.toml", line.as_bytes()), vec![], "{line}");
    }
}

#[test]
fn a_mention_beside_the_part_name_is_still_reported() {
    let name = REFERENCE_SCANNER_NAMES[0];
    let line = format!("debar-{name}-signatures reads what {name} reads");

    assert_eq!(mentions("Cargo.toml", line.as_bytes()).len(), 1);
}

#[test]
fn only_the_workflow_dedicated_to_comparison_may_name_the_harness_it_calls() {
    let line = format!(
        "uses: mkhanal/debar-{}-harness/.github/workflows/compare.yml@0123abcd",
        REFERENCE_SCANNER_NAMES[0]
    );

    assert_eq!(mentions(COMPARISON_WORKFLOW, line.as_bytes()), vec![]);
    assert_eq!(
        mentions(".github/workflows/checks.yml", line.as_bytes()).len(),
        1
    );
    assert_eq!(
        mentions(".github/workflows/comparison.yml.orig", line.as_bytes()).len(),
        1
    );
}
