use std::fmt;
use std::fs::File;
use std::io::{self, Write};
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

pub fn read_file(path: &Path) -> Result<Vec<u8>, FilesystemError> {
    std::fs::read(path).map_err(|reason| FilesystemError {
        operation: Operation::Read,
        path: path.to_path_buf(),
        reason,
    })
}

pub fn write_file_atomically(path: &Path, contents: &[u8]) -> Result<(), FilesystemError> {
    let partial = partial_path(path);
    let mut file = File::create(&partial).map_err(failed(Operation::Write, &partial))?;
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
