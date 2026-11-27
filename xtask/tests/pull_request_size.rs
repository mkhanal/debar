#![allow(clippy::unwrap_used)]

use xtask::board_items::{BoardField, FieldType, FieldUpdate, FieldValue};
use xtask::pull_request_size::{
    ChangedFile, PullRequestSize, is_lockfile, parse_changed_files, pull_request_size, size_updates,
};

fn changed(path: &str, additions: u64, deletions: u64) -> ChangedFile {
    ChangedFile {
        path: path.to_owned(),
        additions,
        deletions,
    }
}

fn number_field(id: u64, name: &str) -> BoardField {
    BoardField {
        id,
        node_id: format!("PVTF_{id}"),
        name: name.to_owned(),
        data_type: FieldType::Number,
        options: Vec::new(),
    }
}

#[test]
fn a_cargo_lockfile_is_recognised_anywhere_in_the_tree() {
    assert!(is_lockfile("Cargo.lock"));
    assert!(is_lockfile("fuzz/Cargo.lock"));
    assert!(!is_lockfile("Cargo.toml"));
    assert!(!is_lockfile("docs/Cargo.lock.md"));
}

#[test]
fn the_size_counts_additions_deletions_and_files_leaving_out_lockfiles() {
    let files = [
        changed("crates/scan/src/layers.rs", 40, 2),
        changed("crates/scan/tests/layers.rs", 30, 0),
        changed("Cargo.lock", 300, 120),
    ];

    assert_eq!(
        pull_request_size(&files),
        PullRequestSize {
            lines_changed: 72,
            files_changed: 2,
        }
    );
}

#[test]
fn the_size_is_zero_when_only_a_lockfile_changed() {
    assert_eq!(
        pull_request_size(&[changed("fuzz/Cargo.lock", 3, 3)]),
        PullRequestSize {
            lines_changed: 0,
            files_changed: 0,
        }
    );
}

#[test]
fn the_size_is_written_to_the_board_as_lines_and_files_changed() {
    let fields = [
        number_field(7, "Lines changed"),
        number_field(8, "Files changed"),
    ];
    let size = PullRequestSize {
        lines_changed: 72,
        files_changed: 2,
    };

    assert_eq!(
        size_updates(&fields, size).unwrap(),
        [
            FieldUpdate {
                field_id: 7,
                value: FieldValue::Number(72),
            },
            FieldUpdate {
                field_id: 8,
                value: FieldValue::Number(2),
            },
        ]
    );
}

#[test]
fn recording_the_size_fails_naming_the_field_when_the_board_lacks_it() {
    let fields = [number_field(7, "Lines changed")];
    let size = PullRequestSize {
        lines_changed: 1,
        files_changed: 1,
    };

    assert_eq!(
        size_updates(&fields, size).unwrap_err().to_string(),
        "project \"Debar\" has no number \"Files changed\" field"
    );
}

#[test]
fn the_changed_files_are_read_across_every_page() {
    let pages = r#"[{"filename":"a.rs","additions":1,"deletions":2,"status":"modified"}]
[{"filename":"b.rs","additions":3,"deletions":0}]"#;

    assert_eq!(
        parse_changed_files(pages).unwrap(),
        [changed("a.rs", 1, 2), changed("b.rs", 3, 0)]
    );
}

#[test]
fn no_files_are_read_from_an_empty_listing() {
    assert_eq!(parse_changed_files("").unwrap(), []);
}

#[test]
fn a_changed_file_missing_a_count_is_refused() {
    assert!(parse_changed_files(r#"[{"filename":"a.rs","additions":1}]"#).is_err());
}
