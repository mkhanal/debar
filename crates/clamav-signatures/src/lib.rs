mod account;
mod body_pattern;
mod container;
mod database_files;
mod extended_lines;
mod file_type_lines;
mod hash_duplicates;
mod hash_lines;
mod ignore_list;
mod line_text;
mod logical_expression;
mod logical_lines;
mod numbers;
mod type_names;

pub use account::{Account, FileAccount, LineOutcome};
pub use body_pattern::MalformedBody;
pub use container::ContainerError;
pub use database_files::{DatabaseError, DatabaseFile, compile};
pub use extended_lines::MalformedExtendedLine;
pub use file_type_lines::MalformedFileTypeLine;
pub use hash_lines::MalformedLine;
pub use logical_expression::MalformedExpression;
pub use logical_lines::{MalformedLogicalLine, MalformedSubsignature};

pub const FUNCTIONALITY_LEVEL: i64 = 234;
