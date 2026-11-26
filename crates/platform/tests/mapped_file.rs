#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::PathBuf;

use debar_platform::filesystem::{read_file, regular_files_in, write_file_atomically};
use debar_platform::mapped_file::{ExpectedAccess, MappedFile, MappingError};

fn write(path: &std::path::Path, contents: &[u8]) {
    std::fs::write(path, contents).unwrap();
}

fn scratch_directory(test: &str) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test);
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

#[test]
#[cfg_attr(miri, ignore = "Miri does not support file-backed memory mappings")]
fn a_mapped_file_shows_the_bytes_written_to_it() {
    let path = scratch_directory("mapped_bytes").join("image");
    let contents: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
    write(&path, &contents);

    let mapped = MappedFile::open(&path).unwrap();

    assert_eq!(mapped.bytes(), contents.as_slice());
}

#[test]
fn an_empty_file_maps_to_no_bytes() {
    let path = scratch_directory("mapped_empty").join("image");
    write(&path, &[]);

    let mapped = MappedFile::open(&path).unwrap();

    assert_eq!(mapped.bytes(), []);
    assert!(mapped.advise(0..0, ExpectedAccess::Random).is_ok());
}

#[test]
fn a_missing_file_cannot_be_mapped() {
    let path = scratch_directory("mapped_missing").join("absent");

    assert!(matches!(
        MappedFile::open(&path),
        Err(MappingError::Open { .. })
    ));
}

#[test]
#[cfg_attr(miri, ignore = "Miri does not support file-backed memory mappings")]
fn advice_is_accepted_inside_the_file_and_refused_outside_it() {
    let path = scratch_directory("mapped_advice").join("image");
    write(&path, &vec![7u8; 3 * 4096 + 17]);
    let mapped = MappedFile::open(&path).unwrap();

    for access in [
        ExpectedAccess::Random,
        ExpectedAccess::Sequential,
        ExpectedAccess::SoonNeeded,
    ] {
        assert!(mapped.advise(4096..8192, access).is_ok());
        assert!(mapped.advise(100..3 * 4096 + 17, access).is_ok());
    }
    assert!(matches!(
        mapped.advise(0..3 * 4096 + 18, ExpectedAccess::Random),
        Err(MappingError::RangeOutsideTheFile { .. })
    ));
}

#[test]
#[cfg_attr(miri, ignore = "Miri cannot flush a directory to disk")]
fn an_atomic_write_replaces_the_whole_file_and_leaves_nothing_beside_it() {
    let directory = scratch_directory("atomic_write");
    let path = directory.join("image");
    write_file_atomically(&path, b"first, longer contents").unwrap();

    write_file_atomically(&path, b"second").unwrap();

    assert_eq!(read_file(&path).unwrap(), b"second");
    assert_eq!(regular_files_in(&directory).unwrap(), vec![path]);
}

#[test]
fn a_directory_lists_its_regular_files_in_name_order() {
    let directory = scratch_directory("listing");
    for name in ["b.db", "a.db", "c.db"] {
        write(&directory.join(name), name.as_bytes());
    }
    std::fs::create_dir(directory.join("nested")).unwrap();

    let names: Vec<String> = regular_files_in(&directory)
        .unwrap()
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();

    assert_eq!(names, ["a.db", "b.db", "c.db"]);
}
