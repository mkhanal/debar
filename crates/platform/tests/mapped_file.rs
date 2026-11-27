#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use debar_platform::filesystem::{
    publish_read_only_file, read_file, regular_files_in, write_file_atomically,
};
use debar_platform::mapped_file::{ExpectedAccess, MappedFile, MappingError};

const ANOTHER_USER: u32 = 54_321;

fn write(path: &std::path::Path, contents: &[u8]) {
    std::fs::write(path, contents).unwrap();
}

fn publish(path: &std::path::Path, contents: &[u8]) {
    publish_read_only_file(path, contents).unwrap();
}

fn permission_bits(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
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
    publish(&path, &contents);

    let mapped = MappedFile::open(&path).unwrap();

    assert_eq!(mapped.bytes(), contents.as_slice());
}

#[test]
fn an_empty_file_maps_to_no_bytes() {
    let path = scratch_directory("mapped_empty").join("image");
    write(&path, &[]);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();

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
    publish(&path, &vec![7u8; 3 * 4096 + 17]);
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
fn a_file_anyone_may_write_is_never_mapped() {
    let path = scratch_directory("mapped_writable").join("image");
    write(&path, b"bytes that could change beneath the mapping");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert!(matches!(
        MappedFile::open(&path),
        Err(MappingError::Writable { mode: 0o644, .. })
    ));
}

#[test]
fn a_file_only_its_owner_may_write_is_never_mapped() {
    let path = scratch_directory("mapped_owner_writable").join("image");
    write(&path, b"bytes its owner could change");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    assert!(matches!(
        MappedFile::open(&path),
        Err(MappingError::Writable { .. })
    ));
}

#[test]
#[cfg_attr(miri, ignore = "Miri cannot flush a directory to disk")]
fn a_file_owned_by_another_user_is_never_mapped() {
    let directory = std::env::temp_dir().join(format!("mapped_foreign-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("image");
    publish(&path, b"bytes another user could make writable");
    std::os::unix::fs::chown(&path, Some(ANOTHER_USER), None).unwrap();

    assert!(matches!(
        MappedFile::open(&path),
        Err(MappingError::OwnedByAnotherUser {
            owner: ANOTHER_USER,
            ..
        })
    ));
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn a_directory_is_never_mapped() {
    let directory = scratch_directory("mapped_directory");

    assert!(matches!(
        MappedFile::open(&directory),
        Err(MappingError::NotARegularFile { .. })
    ));
}

#[test]
#[cfg_attr(miri, ignore = "Miri cannot flush a directory to disk")]
fn a_published_file_can_be_written_by_no_one_and_replaces_the_one_before() {
    let directory = scratch_directory("published");
    let path = directory.join("image");
    publish(&path, b"first, longer contents");

    publish(&path, b"second");

    assert_eq!(read_file(&path).unwrap(), b"second");
    assert_eq!(permission_bits(&path), 0o444);
    assert_eq!(regular_files_in(&directory).unwrap(), vec![path]);
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
