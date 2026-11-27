use std::collections::BTreeSet;

use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoardStatus {
    Open,
    InProgress,
    InReview,
    Done,
}

impl BoardStatus {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::InProgress => "In Progress",
            Self::InReview => "In Review",
            Self::Done => "Done",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PullRequestReadiness {
    Draft,
    ReadyForReview,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullRequestClaim {
    pub number: u64,
    pub url: String,
    pub author: String,
    pub branch: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueState {
    pub number: u64,
    pub url: String,
    pub open: bool,
    pub claiming_branch: Option<String>,
    pub claiming_branch_exists: bool,
    pub open_pull_requests: Vec<PullRequestClaim>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holder {
    pub branch: String,
    pub pull_request: Option<PullRequestClaim>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimCheck {
    Closed,
    Held { holders: Vec<Holder> },
    Free,
}

#[must_use]
pub fn holders_other_than(issue: &IssueState, branch: &str) -> Vec<Holder> {
    let live_claim = issue
        .claiming_branch
        .as_deref()
        .filter(|_| issue.claiming_branch_exists);
    let branches: BTreeSet<&str> = live_claim
        .into_iter()
        .chain(
            issue
                .open_pull_requests
                .iter()
                .map(|pull_request| pull_request.branch.as_str()),
        )
        .filter(|claimed| *claimed != branch)
        .collect();
    branches
        .into_iter()
        .map(|claimed| Holder {
            branch: claimed.to_owned(),
            pull_request: issue
                .open_pull_requests
                .iter()
                .find(|pull_request| pull_request.branch == claimed)
                .cloned(),
        })
        .collect()
}

#[must_use]
pub fn check_before_claim(issue: &IssueState, branch: &str) -> ClaimCheck {
    if !issue.open {
        return ClaimCheck::Closed;
    }
    let holders = holders_other_than(issue, branch);
    if holders.is_empty() {
        ClaimCheck::Free
    } else {
        ClaimCheck::Held { holders }
    }
}

#[must_use]
pub fn settle_after_claim(issue: &IssueState, branch: &str) -> ClaimCheck {
    let check = check_before_claim(issue, branch);
    if check != ClaimCheck::Free || issue.claiming_branch.as_deref() == Some(branch) {
        return check;
    }
    let overwritten = IssueState {
        claiming_branch_exists: true,
        ..issue.clone()
    };
    ClaimCheck::Held {
        holders: holders_other_than(&overwritten, branch),
    }
}

#[must_use]
pub fn work_status(branch_pull_request: Option<PullRequestReadiness>) -> BoardStatus {
    match branch_pull_request {
        Some(PullRequestReadiness::ReadyForReview) => BoardStatus::InReview,
        Some(PullRequestReadiness::Draft) | None => BoardStatus::InProgress,
    }
}

impl ClaimCheck {
    #[must_use]
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Held { .. } => "held",
            Self::Free => "free",
        }
    }

    #[must_use]
    pub fn to_json(&self) -> Value {
        match self {
            Self::Closed | Self::Free => json!({ "outcome": self.outcome() }),
            Self::Held { holders } => json!({
                "outcome": self.outcome(),
                "holders": holders.iter().map(Holder::to_json).collect::<Vec<_>>(),
            }),
        }
    }
}

impl Holder {
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "branch": self.branch,
            "pullRequest": self.pull_request.as_ref().map(PullRequestClaim::to_json),
        })
    }
}

impl PullRequestClaim {
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "number": self.number,
            "url": self.url,
            "author": self.author,
            "branch": self.branch,
            "updatedAt": self.updated_at,
        })
    }
}
