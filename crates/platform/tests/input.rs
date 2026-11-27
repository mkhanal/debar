#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::PathBuf;

use debar_platform::input::{InputError, ScannedFile};

fn scanned_file(test: &str, contents: &[u8]) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test);
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("scanned");
    std::fs::write(&path, contents).unwrap();
    path
}

#[test]
fn a_read_returns_the_bytes_at_its_offset() {
    let contents: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
    let file = ScannedFile::open(&scanned_file("read_at", &contents), u64::MAX).unwrap();
    let mut read = [0u8; 100];

    file.read_at(5_000, &mut read).unwrap();

    assert_eq!(file.length(), 10_000);
    assert_eq!(read.as_slice(), &contents[5_000..5_100]);
}

#[test]
fn a_read_beyond_the_length_when_opened_is_refused() {
    let file = ScannedFile::open(&scanned_file("beyond", b"0123456789"), u64::MAX).unwrap();
    let mut read = [0u8; 4];

    let refused = file.read_at(8, &mut read);

    assert!(matches!(
        refused,
        Err(InputError::BeyondTheEnd {
            offset: 8,
            wanted: 4,
            length: 10
        })
    ));
}

#[test]
fn every_read_is_counted_against_the_allowance() {
    let file = ScannedFile::open(&scanned_file("allowance", b"0123456789"), 15).unwrap();
    let mut read = [0u8; 10];

    file.read_at(0, &mut read).unwrap();
    let refused = file.read_at(0, &mut read);

    assert_eq!(file.bytes_read(), 10);
    assert!(matches!(
        refused,
        Err(InputError::AllowanceSpent { allowance: 15 })
    ));
}

#[test]
fn a_file_cut_short_while_scanned_is_a_failure_not_a_shorter_object() {
    let path = scanned_file("truncated", b"0123456789");
    let file = ScannedFile::open(&path, u64::MAX).unwrap();
    std::fs::write(&path, b"01234").unwrap();
    let mut read = [0u8; 10];

    let refused = file.read_at(0, &mut read);

    assert!(matches!(
        refused,
        Err(InputError::ChangedWhileScanned {
            length_when_opened: 10,
            ended_at: 5
        })
    ));
}

#[test]
fn a_directory_is_not_scanned_as_a_file() {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("directory_input");
    std::fs::create_dir_all(&directory).unwrap();

    let refused = ScannedFile::open(&directory, u64::MAX);

    assert!(matches!(refused, Err(InputError::Directory { .. })));
}
