use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct UnreadableObject {
    pub path: PathBuf,
    pub reason: io::Error,
}

impl fmt::Display for UnreadableObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cannot read {} to scan it: {}",
            self.path.display(),
            self.reason
        )
    }
}

impl std::error::Error for UnreadableObject {}

#[inline(never)]
pub fn read_scanned_file(path: &Path) -> Result<Vec<u8>, UnreadableObject> {
    std::fs::read(path).map_err(|reason| UnreadableObject {
        path: path.to_path_buf(),
        reason,
    })
}
