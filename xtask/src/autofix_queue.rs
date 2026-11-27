use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::board_items::IssueItem;
use crate::claims::{
    BoardStatus, ClaimCheck, Holder, IssueState, check_before_claim, holders_other_than,
    settle_after_claim,
};

pub const AUTOFIX_BRANCH_PREFIX: &str = "autofix/";
pub const AGENT_BLOCKED_LABEL: &str = "agent-blocked";
pub const NEEDS_DECISION_LABEL: &str = "needs-decision";
pub const WAITING_FOR_A_PERSON_LABELS: [&str; 2] = [AGENT_BLOCKED_LABEL, NEEDS_DECISION_LABEL];
const DRAFT_SUFFIX: &str = "-draft";

#[must_use]
pub fn branch_name(issue: u64) -> String {
    format!("{AUTOFIX_BRANCH_PREFIX}{issue}")
}

#[must_use]
pub fn draft_branch_name(issue: u64) -> String {
    format!("{}{DRAFT_SUFFIX}", branch_name(issue))
}

#[must_use]
pub fn is_handed_back(labels: &[String]) -> bool {
    labels.iter().any(|label| label == AGENT_BLOCKED_LABEL)
}

#[must_use]
pub fn is_blocked(labels: &[String]) -> bool {
    labels
        .iter()
        .any(|label| WAITING_FOR_A_PERSON_LABELS.contains(&label.as_str()))
}

fn held_by_a_gone_branch(item: &IssueItem, live_branches: &BTreeSet<String>) -> bool {
    item.status.as_deref() == Some(BoardStatus::InProgress.name())
        && item
            .branch
            .as_ref()
            .is_some_and(|branch| !live_branches.contains(branch))
}

fn held_by_another_branch(item: &IssueItem) -> bool {
    let own = branch_name(item.number);
    item.open_pull_requests
        .iter()
        .any(|pull_request| pull_request.branch != own)
}

#[must_use]
pub fn queue(
    items: &[IssueItem],
    include_blocked: bool,
    live_branches: &BTreeSet<String>,
) -> Vec<IssueItem> {
    let mut waiting: Vec<IssueItem> = items
        .iter()
        .filter(|item| {
            item.open
                && (item.status.as_deref() == Some(BoardStatus::Open.name())
                    || held_by_a_gone_branch(item, live_branches))
        })
        .filter(|item| include_blocked || !is_blocked(&item.labels))
        .filter(|item| !held_by_another_branch(item))
        .cloned()
        .collect();
    waiting.sort_by_key(|item| std::cmp::Reverse(item.number));
    waiting
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Readiness {
    Free,
    Closed,
    Blocked,
    Held { holders: Vec<Holder> },
}

impl Readiness {
    #[must_use]
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Closed => "closed",
            Self::Blocked => "blocked",
            Self::Held { .. } => "held",
        }
    }
}

#[must_use]
pub fn readiness_before_claim(
    issue: &IssueState,
    labels: &[String],
    branch: &str,
    include_blocked: bool,
) -> Readiness {
    if !include_blocked && is_blocked(labels) {
        return Readiness::Blocked;
    }
    match check_before_claim(issue, branch) {
        ClaimCheck::Free => Readiness::Free,
        ClaimCheck::Closed => Readiness::Closed,
        ClaimCheck::Held { holders } => Readiness::Held { holders },
    }
}

#[must_use]
pub fn readiness_of_item(
    item: &IssueItem,
    branch: &str,
    live_branches: &BTreeSet<String>,
    include_blocked: bool,
) -> Readiness {
    readiness_before_claim(
        &item.state(|candidate| live_branches.contains(candidate)),
        &item.labels,
        branch,
        include_blocked,
    )
}

#[must_use]
pub fn still_held_after_claim(item: &IssueItem, branch: &str) -> bool {
    settle_after_claim(&item.state(|_| true), branch) == ClaimCheck::Free
}

#[must_use]
pub fn claimed_item_must_be_released(item: &IssueItem, branch: &str) -> bool {
    item.branch.as_deref() == Some(branch)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartingPoint {
    pub sha: String,
    pub resumes_draft: Option<String>,
}

#[must_use]
pub fn starting_point(
    issue: u64,
    live_branches: &BTreeMap<String, String>,
    base_sha: &str,
) -> StartingPoint {
    let draft = draft_branch_name(issue);
    match live_branches.get(&draft) {
        Some(draft_sha) => StartingPoint {
            sha: draft_sha.clone(),
            resumes_draft: Some(draft),
        },
        None => StartingPoint {
            sha: base_sha.to_owned(),
            resumes_draft: None,
        },
    }
}

#[must_use]
pub fn holds_for_hand_back(issue: &IssueState, branch: &str) -> bool {
    issue.open
        && issue
            .claiming_branch
            .as_deref()
            .is_none_or(|claimed| claimed == branch)
        && holders_other_than(issue, branch).is_empty()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteBranchAfterHandBack {
    Delete,
    KeepAsDraft,
}

#[must_use]
pub fn remote_branch_after_hand_back(commits_ahead_of_default: u64) -> RemoteBranchAfterHandBack {
    if commits_ahead_of_default == 0 {
        RemoteBranchAfterHandBack::Delete
    } else {
        RemoteBranchAfterHandBack::KeepAsDraft
    }
}

#[must_use]
pub fn count_outcomes(outcomes: &[&str]) -> BTreeMap<String, usize> {
    let mut counted = BTreeMap::new();
    for outcome in outcomes {
        let count: &mut usize = counted.entry((*outcome).to_owned()).or_default();
        *count = count.saturating_add(1);
    }
    counted
}

#[must_use]
pub fn outcomes_json(outcomes: &[&str]) -> Value {
    json!(count_outcomes(outcomes))
}
