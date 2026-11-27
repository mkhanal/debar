#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use xtask::task_arguments::TaskArguments;
use xtask::task_outcome::{TaskError, issue_numbers};

fn words(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn options_flags_and_issue_numbers_are_read_in_any_order() {
    let parsed = TaskArguments::parse(
        &words("12 --branch fix/depth 14 --peek"),
        &["branch"],
        &["peek"],
    )
    .unwrap();

    assert_eq!(parsed.positionals, ["12", "14"]);
    assert_eq!(parsed.value("branch"), Some("fix/depth"));
    assert!(parsed.flag("peek"));
}

#[test]
fn an_unknown_option_is_a_usage_error() {
    assert!(matches!(
        TaskArguments::parse(&words("12 --force"), &["branch"], &[]),
        Err(TaskError::Usage(_))
    ));
}

#[test]
fn an_option_without_its_value_is_a_usage_error() {
    assert!(matches!(
        TaskArguments::parse(&words("12 --branch"), &["branch"], &[]),
        Err(TaskError::Usage(_))
    ));
}

#[test]
fn issue_numbers_may_be_written_with_a_hash() {
    assert_eq!(issue_numbers(&words("#12 14")).unwrap(), [12, 14]);
}

#[test]
fn no_issue_number_is_a_usage_error() {
    assert!(matches!(issue_numbers(&[]), Err(TaskError::Usage(_))));
}

#[test]
fn a_word_that_is_not_an_issue_number_is_a_usage_error() {
    assert!(matches!(
        issue_numbers(&words("twelve")),
        Err(TaskError::Usage(_))
    ));
}
