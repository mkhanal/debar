#![forbid(unsafe_code)]

mod account_report;

use std::fmt;
use std::path::{Path, PathBuf};

use debar_clamav_signatures::{Account, DatabaseError, DatabaseFile, compile};
use debar_image::{BuildError, Image, ImageBuilder, ImageError};
use debar_platform::filesystem::{
    FilesystemError, publish_read_only_file, read_file, regular_files_in, write_file_atomically,
};

pub use account_report::account_report;

#[derive(Debug)]
pub enum CompileError {
    Filesystem(FilesystemError),
    FileNameNotText(PathBuf),
    Database(DatabaseError),
    Build(BuildError),
    BuiltImageUnreadable(ImageError),
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Filesystem(error) => write!(formatter, "{error}"),
            Self::FileNameNotText(path) => {
                write!(formatter, "{} has a name that is not UTF-8", path.display())
            }
            Self::Database(error) => write!(formatter, "cannot compile the databases: {error}"),
            Self::Build(error) => write!(formatter, "cannot build the image: {error}"),
            Self::BuiltImageUnreadable(error) => {
                write!(formatter, "the image just built does not open: {error}")
            }
        }
    }
}

impl std::error::Error for CompileError {}

pub struct Compilation {
    pub image: Vec<u8>,
    pub account: Account,
}

pub fn compile_directory(directory: &Path) -> Result<Compilation, CompileError> {
    let mut contents = Vec::new();
    for path in regular_files_in(directory).map_err(CompileError::Filesystem)? {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| CompileError::FileNameNotText(path.clone()))?
            .to_owned();
        contents.push((name, read_file(&path).map_err(CompileError::Filesystem)?));
    }
    let files: Vec<DatabaseFile<'_>> = contents
        .iter()
        .map(|(name, contents)| DatabaseFile { name, contents })
        .collect();
    let mut builder = ImageBuilder::new();
    let account = compile(&files, &mut builder).map_err(CompileError::Database)?;
    let image = builder.finish().map_err(CompileError::Build)?;
    Image::open(&image).map_err(CompileError::BuiltImageUnreadable)?;
    Ok(Compilation { image, account })
}

pub fn compile_to_files(
    databases: &Path,
    image_path: &Path,
    report_path: &Path,
) -> Result<Compilation, CompileError> {
    let compilation = compile_directory(databases)?;
    let report = account_report(&compilation.account, &compilation.image)
        .map_err(CompileError::BuiltImageUnreadable)?;
    publish_read_only_file(image_path, &compilation.image).map_err(CompileError::Filesystem)?;
    write_file_atomically(report_path, report.to_string().as_bytes())
        .map_err(CompileError::Filesystem)?;
    Ok(compilation)
}
