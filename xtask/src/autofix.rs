use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use crate::autofix_queue::{
    AGENT_BLOCKED_LABEL, Readiness, RemoteBranchAfterHandBack, StartingPoint,
    WAITING_FOR_A_PERSON_LABELS, branch_name, claimed_item_must_be_released, draft_branch_name,
    holds_for_hand_back, is_handed_back, outcomes_json, queue, readiness_of_item,
    remote_branch_after_hand_back, starting_point, still_held_after_claim,
};
use crate::board::{
    OpenBoard, board_issues, find_board, read_issue_item, read_item, record_claim, release_claim,
};
use crate::board_items::{Board, IssueItem};
use crate::claims::BoardStatus;
use crate::github::{
    Repository, add_issue_label, assign_only_claimant, create_branch, current_branch,
    delete_remote_branch, fetch_branches, git, issue_comments, local_branch_exists, move_branch,
    post_issue_comment, remote_branches,
};
use crate::issue_brief::{IssueView, issue_brief as brief_text};
use crate::task_arguments::TaskArguments;
use crate::task_outcome::{TaskError, TaskExit, TaskReport, issue_numbers};

const OPEN_ISSUES: &str = "is:issue is:open";

fn board_query(include_blocked: bool) -> String {
    if include_blocked {
        OPEN_ISSUES.to_owned()
    } else {
        let excluded: Vec<String> = WAITING_FOR_A_PERSON_LABELS
            .iter()
            .map(|label| format!("-label:{label}"))
            .collect();
        format!("{OPEN_ISSUES} {}", excluded.join(" "))
    }
}

enum ClaimAttempt {
    Claimed { resumes_draft: Option<String> },
    BranchTaken,
    Lost,
}

pub fn claim_next(arguments: &[String]) -> Result<TaskReport, TaskError> {
    let parsed = TaskArguments::parse(arguments, &[], &["include-blocked", "peek"])?;
    let include_blocked = parsed.flag("include-blocked");
    if parsed.flag("peek") {
        if include_blocked || !parsed.positionals.is_empty() {
            return Err(TaskError::Usage("--peek takes nothing else".to_owned()));
        }
        return peek_at_queue();
    }
    let only = match parsed.positionals.as_slice() {
        [] if include_blocked => {
            return Err(TaskError::Usage(
                "--include-blocked needs the issue named".to_owned(),
            ));
        }
        [] => None,
        positionals @ [_] => Some(one_issue_number(positionals)?),
        _ => {
            return Err(TaskError::Usage(
                "expected at most one issue number".to_owned(),
            ));
        }
    };
    if !git(&["status", "--porcelain"])?.is_empty() {
        return Err(TaskError::Failed(
            "the working tree has changes; run from a clean worktree".to_owned(),
        ));
    }
    let repository = Repository::current()?;
    let OpenBoard { board, .. } = find_board(&repository)?;
    let base = repository.base();
    fetch_branches(&[&repository.default_branch])?;
    let live = remote_branches()?;
    let live_branches: BTreeSet<String> = live.keys().cloned().collect();
    let query = only.map_or_else(
        || board_query(include_blocked),
        |number| format!("#{number}"),
    );
    let candidates: Vec<IssueItem> = queue(
        &board_issues(&board, &query)?,
        include_blocked,
        &live_branches,
    )
    .into_iter()
    .filter(|candidate| only.is_none_or(|number| candidate.number == number))
    .collect();
    let mut passed_over: Vec<&str> = Vec::new();
    for candidate in candidates {
        let branch = branch_name(candidate.number);
        if local_branch_exists(&branch)? {
            return Err(TaskError::Failed(format!(
                "a local branch \"{branch}\" is left from an earlier run; delete it (git branch -D {branch}) once nothing on it is needed"
            )));
        }
        let item = read_item(&board, candidate.number, candidate.item_id)?;
        let readiness = readiness_of_item(&item, &branch, &live_branches, include_blocked);
        if readiness != Readiness::Free {
            passed_over.push(readiness.outcome());
            continue;
        }
        let start = starting_point(item.number, &live, &git(&["rev-parse", &base])?);
        match attempt_claim(&repository, &board, &item, &start, &base)? {
            ClaimAttempt::Claimed { resumes_draft } => {
                return Ok(TaskReport::json(
                    TaskExit::Done,
                    &json!({
                        "outcome": "claimed",
                        "issue": item.number,
                        "title": item.title,
                        "branch": branch,
                        "resumesDraft": resumes_draft,
                        "passedOver": outcomes_json(&passed_over),
                    }),
                ));
            }
            ClaimAttempt::BranchTaken => passed_over.push("branch taken"),
            ClaimAttempt::Lost => passed_over.push("lost"),
        }
    }
    Ok(TaskReport::json(
        TaskExit::QueueEmpty,
        &json!({ "outcome": "queue empty", "passedOver": outcomes_json(&passed_over) }),
    ))
}

fn peek_at_queue() -> Result<TaskReport, TaskError> {
    let repository = Repository::current()?;
    let OpenBoard { board, .. } = find_board(&repository)?;
    let live_branches: BTreeSet<String> = remote_branches()?.into_keys().collect();
    let waiting = queue(
        &board_issues(&board, &board_query(false))?,
        false,
        &live_branches,
    );
    let numbers: Vec<u64> = waiting.iter().map(|item| item.number).collect();
    let (exit, outcome) = if numbers.is_empty() {
        (TaskExit::QueueEmpty, "queue empty")
    } else {
        (TaskExit::Done, "waiting")
    };
    Ok(TaskReport::json(
        exit,
        &json!({ "outcome": outcome, "issues": numbers }),
    ))
}

fn attempt_claim(
    repository: &Repository,
    board: &Board,
    item: &IssueItem,
    start: &StartingPoint,
    base: &str,
) -> Result<ClaimAttempt, TaskError> {
    let branch = branch_name(item.number);
    if !create_branch(repository, &branch, &start.sha)? {
        return Ok(ClaimAttempt::BranchTaken);
    }
    match finish_claim(repository, board, item, start, base, &branch) {
        Ok(attempt) => Ok(attempt),
        Err(error) => match undo_claim(repository, board, item, &branch, base, None) {
            Ok(()) => Err(error),
            Err(undo_error) => Err(TaskError::Failed(format!(
                "claiming #{} failed ({error}) and undoing it failed too ({undo_error}); delete branch {branch} and set the issue to Open by hand",
                item.number
            ))),
        },
    }
}

fn finish_claim(
    repository: &Repository,
    board: &Board,
    item: &IssueItem,
    start: &StartingPoint,
    base: &str,
    branch: &str,
) -> Result<ClaimAttempt, TaskError> {
    record_claim(board, item.item_id, branch, BoardStatus::InProgress)?;
    let after = read_item(board, item.number, item.item_id)?;
    if !still_held_after_claim(&after, branch) {
        undo_claim(repository, board, item, branch, base, Some(&after))?;
        return Ok(ClaimAttempt::Lost);
    }
    assign_only_claimant(repository, item.number)?;
    if let Some(draft) = &start.resumes_draft {
        delete_remote_branch(repository, draft)?;
    }
    fetch_branches(&[branch])?;
    git(&[
        "switch",
        "--quiet",
        "--create",
        branch,
        &format!("origin/{branch}"),
    ])?;
    Ok(ClaimAttempt::Claimed {
        resumes_draft: start.resumes_draft.clone(),
    })
}

fn undo_claim(
    repository: &Repository,
    board: &Board,
    item: &IssueItem,
    branch: &str,
    base: &str,
    current: Option<&IssueItem>,
) -> Result<(), TaskError> {
    if current_branch()? == branch {
        git(&["switch", "--quiet", "--detach", base])?;
    }
    if local_branch_exists(branch)? {
        git(&["branch", "--quiet", "--delete", "--force", branch])?;
    }
    delete_remote_branch(repository, branch)?;
    let held = match current {
        Some(current) => current.clone(),
        None => read_item(board, item.number, item.item_id)?,
    };
    if claimed_item_must_be_released(&held, branch) {
        release_claim(board, item.item_id)?;
    }
    Ok(())
}

fn one_issue_number(positionals: &[String]) -> Result<u64, TaskError> {
    match issue_numbers(positionals)?.as_slice() {
        [number] => Ok(*number),
        _ => Err(TaskError::Usage("expected one issue number".to_owned())),
    }
}

fn hand_back_comment(parsed: &TaskArguments) -> Result<Option<String>, TaskError> {
    match (parsed.flag("release-only"), parsed.value("body-file")) {
        (true, Some(_)) => Err(TaskError::Usage(
            "--release-only takes no --body-file".to_owned(),
        )),
        (true, None) => Ok(None),
        (false, None) => Err(TaskError::Usage(
            "expected --body-file or --release-only".to_owned(),
        )),
        (false, Some(path)) => {
            let body = std::fs::read_to_string(path)
                .map_err(|error| TaskError::Usage(format!("cannot read {path}: {error}")))?
                .trim()
                .to_owned();
            if body.is_empty() {
                return Err(TaskError::Usage(format!("{path} is empty")));
            }
            Ok(Some(body))
        }
    }
}

pub fn hand_back(arguments: &[String]) -> Result<TaskReport, TaskError> {
    let parsed = TaskArguments::parse(arguments, &["body-file"], &["release-only"])?;
    let number = one_issue_number(&parsed.positionals)?;
    let body = hand_back_comment(&parsed)?;
    let repository = Repository::current()?;
    let OpenBoard { board, .. } = find_board(&repository)?;
    let branch = branch_name(number);
    let draft = draft_branch_name(number);
    let item = read_issue_item(&board, number)?;
    if !holds_for_hand_back(&item.state(|_| true), &branch) {
        return Ok(TaskReport::json(
            TaskExit::NotClaimable,
            &json!({
                "issue": number,
                "branch": branch,
                "handedBack": false,
                "reason": format!("{branch} does not hold #{number}"),
            }),
        ));
    }
    if item
        .open_pull_requests
        .iter()
        .any(|pull_request| pull_request.branch == branch)
    {
        return Err(TaskError::Failed(format!(
            "branch \"{branch}\" has an open pull request; a hand-back has none"
        )));
    }
    let live = remote_branches()?;
    let pushed = live.get(&branch).cloned();
    let base = repository.base();
    match &pushed {
        Some(_) => fetch_branches(&[&repository.default_branch, &branch])?,
        None => fetch_branches(&[&repository.default_branch])?,
    }
    refuse_unpushed_work(&branch, pushed.is_some(), &base)?;
    let keeps_draft = keeps_a_draft(&live, &branch, &draft, pushed.is_some(), &base)?;
    if let (Some(branch_sha), true) = (&pushed, keeps_draft) {
        if live.contains_key(&draft) {
            move_branch(&repository, &draft, branch_sha)?;
        } else {
            create_branch(&repository, &draft, branch_sha)?;
        }
    }
    if let Some(body) = &body {
        let comment = if keeps_draft {
            format!(
                "{body}\n\nThe work so far is on branch `{draft}`; the next run resumes from it."
            )
        } else {
            body.clone()
        };
        let retrying = is_handed_back(&item.labels);
        if !retrying {
            add_issue_label(&repository, number, AGENT_BLOCKED_LABEL)?;
        }
        let already_posted = retrying
            && issue_comments(&repository, number)?
                .iter()
                .any(|posted| posted.body.trim() == comment);
        if !already_posted {
            post_issue_comment(&repository, number, &comment)?;
        }
    }
    if pushed.is_some() {
        delete_remote_branch(&repository, &branch)?;
    }
    if current_branch()? == branch {
        git(&["switch", "--quiet", "--detach", &base])?;
    }
    if local_branch_exists(&branch)? {
        git(&["branch", "--quiet", "--delete", "--force", &branch])?;
    }
    release_claim(&board, item.item_id)?;
    Ok(TaskReport::json(
        TaskExit::Done,
        &json!({
            "issue": item.url,
            "branch": branch,
            "handedBack": body.is_some(),
            "released": true,
            "draft": if keeps_draft { Some(draft) } else { None },
        }),
    ))
}

fn commits_between(range: &str) -> Result<u64, TaskError> {
    git(&["rev-list", "--count", range])?
        .parse()
        .map_err(|_| TaskError::Failed(format!("git did not count the commits in {range}")))
}

fn refuse_unpushed_work(branch: &str, pushed: bool, base: &str) -> Result<(), TaskError> {
    if !local_branch_exists(branch)? {
        return Ok(());
    }
    let since = if pushed {
        format!("origin/{branch}")
    } else {
        base.to_owned()
    };
    let unpushed = commits_between(&format!("{since}..{branch}"))?;
    if unpushed > 0 {
        return Err(TaskError::Failed(format!(
            "{branch} has {unpushed} commit(s) not pushed: push them (git push origin {branch}) to keep them as the draft, or delete the local branch to discard them, then run again"
        )));
    }
    Ok(())
}

fn keeps_a_draft(
    live: &BTreeMap<String, String>,
    branch: &str,
    draft: &str,
    pushed: bool,
    base: &str,
) -> Result<bool, TaskError> {
    if !pushed {
        return Ok(live.contains_key(draft));
    }
    let ahead = commits_between(&format!("{base}..origin/{branch}"))?;
    Ok(remote_branch_after_hand_back(ahead) == RemoteBranchAfterHandBack::KeepAsDraft)
}

pub fn issue_brief(arguments: &[String]) -> Result<TaskReport, TaskError> {
    let number = one_issue_number(&TaskArguments::parse(arguments, &[], &[])?.positionals)?;
    let repository = Repository::current()?;
    let OpenBoard { board, .. } = find_board(&repository)?;
    let item = read_issue_item(&board, number)?;
    let view = IssueView {
        number: item.number,
        title: item.title.clone(),
        url: item.url.clone(),
        body: item.body.clone().unwrap_or_default(),
        labels: item.labels.clone(),
        comments: issue_comments(&repository, number)?,
        closing_pull_requests: item.closing_pull_requests.clone(),
        sub_issues: item.sub_issues,
    };
    let commits: Vec<String> = git(&[
        "log",
        "--format=%h %s",
        &format!("{}..HEAD", repository.base()),
    ])?
    .lines()
    .filter(|line| !line.is_empty())
    .map(str::to_owned)
    .collect();
    Ok(TaskReport::text(brief_text(
        &view,
        &current_branch()?,
        &commits,
    )))
}
