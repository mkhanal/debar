#![forbid(unsafe_code)]
#![allow(clippy::panic)]

use xtask::claims::{
    BoardStatus, ClaimCheck, Holder, IssueState, PullRequestClaim, PullRequestReadiness,
    check_before_claim, settle_after_claim, work_status,
};

fn open_issue() -> IssueState {
    IssueState {
        number: 540,
        url: "https://github.com/acme/scanner/issues/540".to_owned(),
        open: true,
        claiming_branch: None,
        claiming_branch_exists: false,
        open_pull_requests: Vec::new(),
    }
}

fn pull_request() -> PullRequestClaim {
    PullRequestClaim {
        number: 601,
        url: "https://github.com/acme/scanner/pull/601".to_owned(),
        author: "vivek".to_owned(),
        branch: "fix/archive-depth".to_owned(),
        updated_at: "2026-10-27T09:00:00Z".to_owned(),
    }
}

fn claimed_by(branch: &str, exists: bool) -> IssueState {
    IssueState {
        claiming_branch: Some(branch.to_owned()),
        claiming_branch_exists: exists,
        ..open_issue()
    }
}

fn held_by(branch: &str, pull_request: Option<PullRequestClaim>) -> ClaimCheck {
    ClaimCheck::Held {
        holders: vec![Holder {
            branch: branch.to_owned(),
            pull_request,
        }],
    }
}

#[test]
fn an_issue_no_branch_or_pull_request_holds_is_free() {
    assert_eq!(
        check_before_claim(&open_issue(), "fix/dst"),
        ClaimCheck::Free
    );
}

#[test]
fn a_closed_issue_cannot_be_claimed() {
    let closed = IssueState {
        open: false,
        ..open_issue()
    };

    assert_eq!(check_before_claim(&closed, "fix/dst"), ClaimCheck::Closed);
}

#[test]
fn an_issue_is_held_by_another_branch_recorded_on_the_board() {
    assert_eq!(
        check_before_claim(&claimed_by("feat/time-zones", true), "fix/dst"),
        held_by("feat/time-zones", None)
    );
}

#[test]
fn an_issue_is_free_once_the_recorded_branch_has_been_deleted() {
    assert_eq!(
        check_before_claim(&claimed_by("feat/time-zones", false), "fix/dst"),
        ClaimCheck::Free
    );
}

#[test]
fn an_issue_is_held_by_an_open_pull_request_that_closes_it_from_any_author() {
    let issue = IssueState {
        open_pull_requests: vec![pull_request()],
        ..open_issue()
    };

    assert_eq!(
        check_before_claim(&issue, "fix/dst"),
        held_by("fix/archive-depth", Some(pull_request()))
    );
}

#[test]
fn a_recorded_branch_and_its_pull_request_are_one_holder() {
    let issue = IssueState {
        open_pull_requests: vec![pull_request()],
        ..claimed_by("fix/archive-depth", true)
    };

    assert_eq!(
        check_before_claim(&issue, "fix/dst"),
        held_by("fix/archive-depth", Some(pull_request()))
    );
}

#[test]
fn holders_are_reported_in_branch_order() {
    let issue = IssueState {
        open_pull_requests: vec![pull_request()],
        ..claimed_by("chore/zz-last", true)
    };

    let ClaimCheck::Held { holders } = check_before_claim(&issue, "fix/dst") else {
        panic!("expected the issue to be held");
    };
    let branches: Vec<&str> = holders
        .iter()
        .map(|holder| holder.branch.as_str())
        .collect();

    assert_eq!(branches, ["chore/zz-last", "fix/archive-depth"]);
}

#[test]
fn an_issue_this_branch_already_holds_is_free_so_related_issues_can_share_a_branch() {
    assert_eq!(
        check_before_claim(&claimed_by("fix/dst", true), "fix/dst"),
        ClaimCheck::Free
    );
}

#[test]
fn a_claim_is_kept_when_the_board_still_records_this_branch() {
    assert_eq!(
        settle_after_claim(&claimed_by("fix/dst", true), "fix/dst"),
        ClaimCheck::Free
    );
}

#[test]
fn a_claim_is_lost_when_a_later_claim_overwrote_the_branch() {
    assert_eq!(
        settle_after_claim(&claimed_by("feat/time-zones", true), "fix/dst"),
        held_by("feat/time-zones", None)
    );
}

#[test]
fn a_claim_is_lost_to_a_later_claim_even_before_its_branch_is_seen() {
    assert_eq!(
        settle_after_claim(&claimed_by("feat/time-zones", false), "fix/dst"),
        held_by("feat/time-zones", None)
    );
}

#[test]
fn a_claim_records_in_progress_while_the_branch_has_no_pull_request() {
    assert_eq!(work_status(None), BoardStatus::InProgress);
}

#[test]
fn a_claim_records_in_progress_while_the_pull_request_is_a_draft() {
    assert_eq!(
        work_status(Some(PullRequestReadiness::Draft)),
        BoardStatus::InProgress
    );
}

#[test]
fn a_claim_records_in_review_once_the_pull_request_is_ready_for_review() {
    assert_eq!(
        work_status(Some(PullRequestReadiness::ReadyForReview)),
        BoardStatus::InReview
    );
}

#[test]
fn board_statuses_carry_the_names_on_the_board() {
    let names: Vec<&str> = [
        BoardStatus::Open,
        BoardStatus::InProgress,
        BoardStatus::InReview,
        BoardStatus::Done,
    ]
    .into_iter()
    .map(BoardStatus::name)
    .collect();

    assert_eq!(names, ["Open", "In Progress", "In Review", "Done"]);
}
