use std::fmt;

use serde_json::Value;

use crate::board_items::BoardError;
use crate::github_responses::ResponseError;
use crate::response_fields::MalformedResponse;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskExit {
    Done,
    NotClaimable,
    QueueEmpty,
}

impl TaskExit {
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Done => 0,
            Self::NotClaimable => 3,
            Self::QueueEmpty => 4,
        }
    }
}

#[derive(Debug)]
pub struct TaskReport {
    pub exit: TaskExit,
    pub output: String,
}

impl TaskReport {
    #[must_use]
    pub fn json(exit: TaskExit, report: &Value) -> Self {
        let output = serde_json::to_string_pretty(report).map_or_else(
            |error| format!("{{\"unprintable\": \"{error}\"}}"),
            |text| format!("{text}\n"),
        );
        Self { exit, output }
    }

    #[must_use]
    pub fn text(output: String) -> Self {
        Self {
            exit: TaskExit::Done,
            output,
        }
    }
}

#[derive(Debug)]
pub enum TaskError {
    Usage(String),
    Failed(String),
}

impl TaskError {
    #[must_use]
    pub fn code(&self) -> u8 {
        match self {
            Self::Failed(_) => 1,
            Self::Usage(_) => 2,
        }
    }
}

impl fmt::Display for TaskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(reason) | Self::Failed(reason) => write!(formatter, "{reason}"),
        }
    }
}

impl From<BoardError> for TaskError {
    fn from(error: BoardError) -> Self {
        Self::Failed(error.to_string())
    }
}

impl From<ResponseError> for TaskError {
    fn from(error: ResponseError) -> Self {
        Self::Failed(error.to_string())
    }
}

impl From<MalformedResponse> for TaskError {
    fn from(error: MalformedResponse) -> Self {
        Self::Failed(error.to_string())
    }
}

pub fn issue_numbers(arguments: &[String]) -> Result<Vec<u64>, TaskError> {
    if arguments.is_empty() {
        return Err(TaskError::Usage(
            "expected one or more issue numbers".to_owned(),
        ));
    }
    arguments
        .iter()
        .map(|argument| {
            argument
                .trim_start_matches('#')
                .parse()
                .map_err(|_| TaskError::Usage(format!("\"{argument}\" is not an issue number")))
        })
        .collect()
}
