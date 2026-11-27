use serde_json::{Value, json};

use crate::board::{
    OpenBoard, find_board, find_issue_item, issues_held_by, item_id, read_issue_item, record_claim,
    replace_select_options, set_fields,
};
use crate::board_items::{Board, FieldType, require_field};
use crate::claims::{ClaimCheck, IssueState, check_before_claim, settle_after_claim, work_status};
use crate::github::{
    Repository, assign_only_claimant, branch_exists, branch_pull_request, current_branch,
    mark_ready_for_review, publish_branch, pull_request_files, read_content, read_issue,
};
use crate::pull_request_size::{pull_request_size, size_updates};
use crate::task_arguments::TaskArguments;
use crate::task_outcome::{TaskError, TaskExit, TaskReport, issue_numbers};
use crate::work_classification::{
    AREA_FIELD, Classification, area_options_adding, classification_options, classification_updates,
};

struct IssueRead {
    state: IssueState,
    item_id: Option<u64>,
}

fn read_claim(
    repository: &Repository,
    board: &Board,
    number: u64,
    branch: &str,
) -> Result<IssueRead, TaskError> {
    let issue = read_issue(repository, number)?;
    let item = find_issue_item(board, number)?;
    let claiming_branch = item.as_ref().and_then(|item| item.branch.clone());
    let claiming_branch_exists = match claiming_branch.as_deref() {
        None => false,
        Some(claimed) if claimed == branch => true,
        Some(claimed) => branch_exists(repository, claimed)?,
    };
    Ok(IssueRead {
        state: IssueState {
            number: issue.number,
            url: issue.url,
            open: issue.open,
            claiming_branch,
            claiming_branch_exists,
            open_pull_requests: item
                .as_ref()
                .map_or_else(Vec::new, |item| item.open_pull_requests.clone()),
        },
        item_id: item.map(|item| item.item_id),
    })
}

fn checked(url: &str, check: &ClaimCheck) -> Value {
    let mut report = json!({ "issue": url });
    if let (Some(fields), Value::Object(outcome)) = (report.as_object_mut(), check.to_json()) {
        fields.extend(outcome);
    }
    report
}

pub fn claim(arguments: &[String]) -> Result<TaskReport, TaskError> {
    let parsed = TaskArguments::parse(arguments, &["branch"], &[])?;
    let numbers = issue_numbers(&parsed.positionals)?;
    let branch = match parsed.value("branch") {
        Some(branch) => branch.to_owned(),
        None => current_branch()?,
    };
    claim_issues(&numbers, &branch)
}

fn claim_issues(numbers: &[u64], branch: &str) -> Result<TaskReport, TaskError> {
    let repository = Repository::current()?;
    if branch.is_empty() || branch == repository.default_branch {
        return Err(TaskError::Usage(format!(
            "claim from a work branch, not \"{}\"",
            if branch.is_empty() {
                "a detached HEAD"
            } else {
                branch
            }
        )));
    }
    let OpenBoard { board, .. } = find_board(&repository)?;
    let reads = numbers
        .iter()
        .map(|number| read_claim(&repository, &board, *number, branch))
        .collect::<Result<Vec<_>, _>>()?;
    let blocked: Vec<Value> = reads
        .iter()
        .map(|read| (read, check_before_claim(&read.state, branch)))
        .filter(|(_, check)| *check != ClaimCheck::Free)
        .map(|(read, check)| checked(&read.state.url, &check))
        .collect();
    if !blocked.is_empty() {
        return Ok(TaskReport::json(
            TaskExit::NotClaimable,
            &json!({ "branch": branch, "outcome": "not claimed", "blocked": blocked }),
        ));
    }
    if !branch_exists(&repository, branch)? {
        publish_branch(&repository, branch)?;
    }
    let status = work_status(
        branch_pull_request(&repository, branch)?.map(|pull_request| pull_request.readiness),
    );
    for read in &reads {
        let item = match read.item_id {
            Some(known) => known,
            None => item_id(&repository, &board, read.state.number)?,
        };
        record_claim(&board, item, branch, status)?;
        assign_only_claimant(&repository, read.state.number)?;
    }
    let mut claimed = Vec::new();
    let mut lost = Vec::new();
    for number in numbers {
        let after = read_claim(&repository, &board, *number, branch)?;
        match settle_after_claim(&after.state, branch) {
            ClaimCheck::Free => claimed.push(after.state.url),
            check => lost.push(checked(&after.state.url, &check)),
        }
    }
    let exit = if lost.is_empty() {
        TaskExit::Done
    } else {
        TaskExit::NotClaimable
    };
    Ok(TaskReport::json(
        exit,
        &json!({ "branch": branch, "status": status.name(), "claimed": claimed, "lost": lost }),
    ))
}

pub fn check_claim(arguments: &[String]) -> Result<TaskReport, TaskError> {
    let numbers = issue_numbers(&TaskArguments::parse(arguments, &[], &[])?.positionals)?;
    let repository = Repository::current()?;
    let OpenBoard { board, .. } = find_board(&repository)?;
    let branch = current_branch()?;
    let mut lost = Vec::new();
    for number in numbers {
        let check = settle_after_claim(&read_issue_item(&board, number)?.state(|_| true), &branch);
        if check != ClaimCheck::Free {
            let mut report = json!({ "issue": number });
            if let (Some(fields), Value::Object(outcome)) =
                (report.as_object_mut(), check.to_json())
            {
                fields.extend(outcome);
            }
            lost.push(report);
        }
    }
    let exit = if lost.is_empty() {
        TaskExit::Done
    } else {
        TaskExit::NotClaimable
    };
    Ok(TaskReport::json(
        exit,
        &json!({ "branch": branch, "holds": lost.is_empty(), "lost": lost }),
    ))
}

pub fn classify_work(arguments: &[String]) -> Result<TaskReport, TaskError> {
    let parsed = TaskArguments::parse(
        arguments,
        &[
            "theme",
            "kind",
            "area",
            "impact",
            "why",
            "add-area",
            "area-description",
        ],
        &["options"],
    )?;
    let classification = Classification {
        theme: parsed.value("theme").map(str::to_owned),
        kind: parsed.value("kind").map(str::to_owned),
        area: parsed.value("area").map(str::to_owned),
        impact: parsed.value("impact").map(str::to_owned),
        why: parsed.value("why").map(str::to_owned),
    };
    let classifying = !parsed.positionals.is_empty() || !classification.is_empty();
    let adding = parsed.value("add-area").is_some() || parsed.value("area-description").is_some();
    if parsed.flag("options") {
        if classifying || adding {
            return Err(TaskError::Usage(
                "--options takes no other arguments".to_owned(),
            ));
        }
        let repository = Repository::current()?;
        return Ok(TaskReport::text(classification_options(
            &find_board(&repository)?.fields,
        )?));
    }
    if adding {
        if classifying {
            return Err(TaskError::Usage(
                "--add-area takes only --area-description".to_owned(),
            ));
        }
        let (Some(name), Some(description)) = (
            parsed
                .value("add-area")
                .map(str::trim)
                .filter(|name| !name.is_empty()),
            parsed
                .value("area-description")
                .map(str::trim)
                .filter(|description| !description.is_empty()),
        ) else {
            return Err(TaskError::Usage(
                "expected both a non-empty --add-area name and --area-description".to_owned(),
            ));
        };
        return add_area(name, description);
    }
    let [item] = parsed.positionals.as_slice() else {
        return Err(TaskError::Usage(
            "expected one issue or pull request number".to_owned(),
        ));
    };
    let number = issue_numbers(std::slice::from_ref(item))?
        .first()
        .copied()
        .ok_or_else(|| TaskError::Usage("expected one issue or pull request number".to_owned()))?;
    if classification.is_empty() {
        return Err(TaskError::Usage(
            "expected at least one field to set".to_owned(),
        ));
    }
    let repository = Repository::current()?;
    let OpenBoard { board, fields } = find_board(&repository)?;
    let updates = classification_updates(&fields, &classification)?;
    let content = read_content(&repository, number)?;
    set_fields(&board, item_id(&repository, &board, number)?, &updates)?;
    let classified = json!({
        "item": content.url,
        "theme": classification.theme,
        "kind": classification.kind,
        "area": classification.area,
        "impact": classification.impact,
        "why": classification.why,
    });
    Ok(TaskReport::json(TaskExit::Done, &classified))
}

fn add_area(name: &str, description: &str) -> Result<TaskReport, TaskError> {
    let repository = Repository::current()?;
    let OpenBoard { fields, .. } = find_board(&repository)?;
    let area = require_field(&fields, AREA_FIELD, &FieldType::SingleSelect)?;
    let updated = replace_select_options(area, &area_options_adding(area, name, description)?)?;
    let kept = area.options.iter().all(|before| {
        updated
            .iter()
            .any(|after| after.id.is_some() && after.id == before.id)
    });
    let added = updated.iter().find(|option| option.name == name);
    match (kept, added) {
        (true, Some(added)) => Ok(TaskReport::json(
            TaskExit::Done,
            &json!({ "added": added.to_json() }),
        )),
        _ => Err(TaskError::Failed(format!(
            "{AREA_FIELD} options after the update do not match: {}",
            updated
                .iter()
                .map(|option| option.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

pub fn record_pull_request_size(arguments: &[String]) -> Result<TaskReport, TaskError> {
    TaskArguments::parse(arguments, &[], &[])?;
    let repository = Repository::current()?;
    let branch = current_branch()?;
    let pull_request = branch_pull_request(&repository, &branch)?.ok_or_else(|| {
        TaskError::Failed(format!("branch \"{branch}\" has no open pull request"))
    })?;
    let OpenBoard { board, fields } = find_board(&repository)?;
    let size = pull_request_size(&pull_request_files(&repository, pull_request.number)?);
    set_fields(
        &board,
        item_id(&repository, &board, pull_request.number)?,
        &size_updates(&fields, size)?,
    )?;
    Ok(TaskReport::json(
        TaskExit::Done,
        &json!({
            "pullRequest": pull_request.number,
            "linesChanged": size.lines_changed,
            "filesChanged": size.files_changed,
        }),
    ))
}

pub fn ready_for_review(arguments: &[String]) -> Result<TaskReport, TaskError> {
    TaskArguments::parse(arguments, &[], &[])?;
    let repository = Repository::current()?;
    let branch = current_branch()?;
    let pull_request = branch_pull_request(&repository, &branch)?.ok_or_else(|| {
        TaskError::Failed(format!("branch \"{branch}\" has no open pull request"))
    })?;
    let OpenBoard { board, fields } = find_board(&repository)?;
    let issues = issues_held_by(&board, &branch)?;
    if issues.is_empty() {
        return Err(TaskError::Failed(format!(
            "branch \"{branch}\" holds no issue on the board"
        )));
    }
    let files = pull_request_files(&repository, pull_request.number)?;
    if pull_request.readiness == crate::claims::PullRequestReadiness::Draft {
        mark_ready_for_review(pull_request.number)?;
    }
    set_fields(
        &board,
        item_id(&repository, &board, pull_request.number)?,
        &size_updates(&fields, pull_request_size(&files))?,
    )?;
    claim_issues(&issues, &branch)
}
