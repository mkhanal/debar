mod account;
mod container;
mod database_files;
mod hash_lines;
mod ignore_list;
mod line_text;
mod numbers;

pub use account::{Account, FileAccount, LineOutcome};
pub use container::ContainerError;
pub use database_files::{DatabaseError, DatabaseFile, compile};
pub use hash_lines::MalformedLine;

pub const FUNCTIONALITY_LEVEL: i64 = 234;
