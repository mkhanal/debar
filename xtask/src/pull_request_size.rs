use crate::board_items::{
    BoardError, BoardField, FieldType, FieldUpdate, FieldValue, require_field,
};
use crate::github_responses::{ResponseError, pages};
use crate::response_fields::{number, text};

pub const LOCKFILES: [&str; 1] = ["Cargo.lock"];
pub const LINES_CHANGED_FIELD: &str = "Lines changed";
pub const FILES_CHANGED_FIELD: &str = "Files changed";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangedFile {
    pub path: String,
    pub additions: u64,
    pub deletions: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PullRequestSize {
    pub lines_changed: u64,
    pub files_changed: u64,
}

#[must_use]
pub fn is_lockfile(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    LOCKFILES.contains(&name)
}

#[must_use]
pub fn pull_request_size(files: &[ChangedFile]) -> PullRequestSize {
    files.iter().filter(|file| !is_lockfile(&file.path)).fold(
        PullRequestSize {
            lines_changed: 0,
            files_changed: 0,
        },
        |size, file| PullRequestSize {
            lines_changed: size
                .lines_changed
                .saturating_add(file.additions)
                .saturating_add(file.deletions),
            files_changed: size.files_changed.saturating_add(1),
        },
    )
}

pub fn size_updates(
    fields: &[BoardField],
    size: PullRequestSize,
) -> Result<Vec<FieldUpdate>, BoardError> {
    Ok(vec![
        FieldUpdate {
            field_id: require_field(fields, LINES_CHANGED_FIELD, &FieldType::Number)?.id,
            value: FieldValue::Number(size.lines_changed),
        },
        FieldUpdate {
            field_id: require_field(fields, FILES_CHANGED_FIELD, &FieldType::Number)?.id,
            value: FieldValue::Number(size.files_changed),
        },
    ])
}

pub fn parse_changed_files(listing: &str) -> Result<Vec<ChangedFile>, ResponseError> {
    pages(listing)?
        .iter()
        .map(|file| {
            Ok(ChangedFile {
                path: text(file, "filename")?.to_owned(),
                additions: number(file, "additions")?,
                deletions: number(file, "deletions")?,
            })
        })
        .collect()
}
