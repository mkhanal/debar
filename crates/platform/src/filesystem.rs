use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct FilesystemError {
    pub operation: Operation,
    pub path: PathBuf,
    pub reason: io::Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    ListDirectory,
    Read,
    Write,
    Sync,
    Rename,
}

impl fmt::Display for FilesystemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match self.operation {
            Operation::ListDirectory => "list the directory",
            Operation::Read => "read",
            Operation::Write => "write",
            Operation::Sync => "flush to disk",
            Operation::Rename => "move into place",
        };
        write!(
            formatter,
            "cannot {action} {}: {}",
            self.path.display(),
            self.reason
        )
    }
}

impl std::error::Error for FilesystemError {}

pub fn regular_files_in(directory: &Path) -> Result<Vec<PathBuf>, FilesystemError> {
    let failed = |reason| FilesystemError {
        operation: Operation::ListDirectory,
        path: directory.to_path_buf(),
        reason,
    };
    let mut files = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(failed)? {
        let entry = entry.map_err(failed)?;
        if entry.file_type().map_err(failed)?.is_file() {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

pub fn regular_files_under(path: &Path) -> Result<Vec<PathBuf>, FilesystemError> {
    let failed = |path: &Path| {
        let path = path.to_path_buf();
        move |reason| FilesystemError {
            operation: Operation::ListDirectory,
            path,
            reason,
        }
    };
    let mut files = Vec::new();
    let mut directories = Vec::new();
    let kind = std::fs::symlink_metadata(path)
        .map_err(failed(path))?
        .file_type();
    if kind.is_file() {
        files.push(path.to_path_buf());
    } else if kind.is_dir() {
        directories.push(path.to_path_buf());
    }
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory).map_err(failed(&directory))? {
            let entry = entry.map_err(failed(&directory))?;
            let kind = entry.file_type().map_err(failed(&directory))?;
            if kind.is_file() {
                files.push(entry.path());
            } else if kind.is_dir() {
                directories.push(entry.path());
            }
        }
    }
    files.sort();
    Ok(files)
}

pub fn read_file(path: &Path) -> Result<Vec<u8>, FilesystemError> {
    std::fs::read(path).map_err(|reason| FilesystemError {
        operation: Operation::Read,
        path: path.to_path_buf(),
        reason,
    })
}

const READABLE_AND_WRITABLE_BY_ALL_BEFORE_THE_UMASK: u32 = 0o666;
const READABLE_BY_ALL_AND_WRITABLE_BY_NONE: u32 = 0o444;

pub fn write_file_atomically(path: &Path, contents: &[u8]) -> Result<(), FilesystemError> {
    write_then_move_into_place(
        path,
        contents,
        READABLE_AND_WRITABLE_BY_ALL_BEFORE_THE_UMASK,
    )
}

pub fn publish_read_only_file(path: &Path, contents: &[u8]) -> Result<(), FilesystemError> {
    write_then_move_into_place(path, contents, READABLE_BY_ALL_AND_WRITABLE_BY_NONE)
}

fn write_then_move_into_place(
    path: &Path,
    contents: &[u8],
    permissions: u32,
) -> Result<(), FilesystemError> {
    let partial = partial_path(path);
    match std::fs::remove_file(&partial) {
        Err(reason) if reason.kind() != io::ErrorKind::NotFound => {
            return Err(failed(Operation::Write, &partial)(reason));
        }
        _ => {}
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(permissions)
        .open(&partial)
        .map_err(failed(Operation::Write, &partial))?;
    file.write_all(contents)
        .map_err(failed(Operation::Write, &partial))?;
    file.sync_all().map_err(failed(Operation::Sync, &partial))?;
    drop(file);
    std::fs::rename(&partial, path).map_err(failed(Operation::Rename, path))?;
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(failed(Operation::Sync, directory))
}

fn partial_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".partial-{}", std::process::id()));
    path.with_file_name(name)
}

fn failed(operation: Operation, at: &Path) -> impl FnOnce(io::Error) -> FilesystemError {
    let path = at.to_path_buf();
    move |reason| FilesystemError {
        operation,
        path,
        reason,
    }
}
