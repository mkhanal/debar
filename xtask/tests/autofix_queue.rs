#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use xtask::autofix_queue::{
    Readiness, RemoteBranchAfterHandBack, StartingPoint, branch_name,
    claimed_item_must_be_released, count_outcomes, draft_branch_name, holds_for_hand_back, queue,
    readiness_of_item, remote_branch_after_hand_back, starting_point, still_held_after_claim,
};
use xtask::board_items::IssueItem;
use xtask::claims::{Holder, PullRequestClaim};

fn item(number: u64) -> IssueItem {
    IssueItem {
        item_id: number.saturating_add(1000),
        number,
        title: format!("Issue {number}"),
        url: format!("https://github.com/acme/scanner/issues/{number}"),
        body: None,
        labels: Vec::new(),
        open: true,
        status: Some("Open".to_owned()),
        branch: None,
        open_pull_requests: Vec::new(),
        closing_pull_requests: Vec::new(),
        sub_issues: 0,
    }
}

fn with_status(number: u64, status: &str, branch: Option<&str>) -> IssueItem {
    IssueItem {
        status: Some(status.to_owned()),
        branch: branch.map(str::to_owned),
        ..item(number)
    }
}

fn blocked(number: u64) -> IssueItem {
    IssueItem {
        labels: vec!["agent-blocked".to_owned()],
        ..item(number)
    }
}

fn pull_request_from(branch: &str) -> PullRequestClaim {
    PullRequestClaim {
        number: 80,
        url: "https://github.com/acme/scanner/pull/80".to_owned(),
        author: "vivek".to_owned(),
        branch: branch.to_owned(),
        updated_at: "2026-11-20T10:00:00Z".to_owned(),
    }
}

fn with_pull_request(number: u64, branch: &str) -> IssueItem {
    IssueItem {
        open_pull_requests: vec![pull_request_from(branch)],
        ..item(number)
    }
}

fn live(branches: &[&str]) -> BTreeSet<String> {
    branches.iter().map(|branch| (*branch).to_owned()).collect()
}

fn numbers(items: &[IssueItem]) -> Vec<u64> {
    items.iter().map(|each| each.number).collect()
}

fn queued(items: &[IssueItem], include_blocked: bool, branches: &[&str]) -> Vec<u64> {
    numbers(&queue(items, include_blocked, &live(branches)))
}

#[test]
fn the_queue_holds_every_open_issue_newest_first() {
    assert_eq!(queued(&[item(3), item(9), item(5)], false, &[]), [9, 5, 3]);
}

#[test]
fn the_queue_leaves_out_issues_in_any_other_status() {
    let items = [
        item(1),
        with_status(2, "In Progress", Some("fix/two")),
        with_status(3, "In Review", Some("fix/three")),
        with_status(4, "Done", None),
    ];

    assert_eq!(queued(&items, false, &["fix/two", "fix/three"]), [1]);
}

#[test]
fn the_queue_leaves_out_an_issue_an_agent_handed_back_for_a_scheduled_run() {
    assert_eq!(queued(&[item(1), blocked(2)], false, &[]), [1]);
}

#[test]
fn the_queue_leaves_out_an_issue_waiting_for_a_persons_decision_for_a_scheduled_run() {
    let waiting = IssueItem {
        labels: vec!["needs-decision".to_owned()],
        ..item(2)
    };

    assert_eq!(queued(&[item(1), waiting], false, &[]), [1]);
}

#[test]
fn the_queue_holds_an_issue_an_agent_handed_back_when_a_person_asks_for_it() {
    assert_eq!(queued(&[item(1), blocked(2)], true, &[]), [2, 1]);
}

#[test]
fn the_queue_leaves_out_a_closed_issue() {
    let closed = IssueItem {
        open: false,
        ..item(2)
    };

    assert_eq!(queued(&[item(1), closed], false, &[]), [1]);
}

#[test]
fn the_queue_leaves_out_an_issue_without_a_status() {
    let unsorted = IssueItem {
        status: None,
        ..item(2)
    };

    assert_eq!(queued(&[item(1), unsorted], false, &[]), [1]);
}

#[test]
fn the_queue_leaves_out_an_issue_with_an_open_pull_request_from_another_branch() {
    assert_eq!(
        queued(&[item(1), with_pull_request(2, "fix/two")], false, &[]),
        [1]
    );
}

#[test]
fn the_queue_keeps_an_issue_whose_only_open_pull_request_is_from_its_autofix_branch() {
    assert_eq!(
        queued(&[with_pull_request(2, "autofix/2")], false, &[]),
        [2]
    );
}

#[test]
fn an_issue_is_worked_on_a_branch_named_by_its_number_alone() {
    assert_eq!(branch_name(42), "autofix/42");
}

#[test]
fn a_hand_back_keeps_its_work_on_a_draft_named_after_the_branch() {
    assert_eq!(draft_branch_name(42), "autofix/42-draft");
}

#[test]
fn an_issue_a_dead_run_held_is_back_in_the_queue_once_its_branch_is_gone() {
    let held = with_status(7, "In Progress", Some("autofix/7"));

    assert_eq!(queued(&[held], false, &[]), [7]);
}

#[test]
fn an_issue_stays_out_of_the_queue_while_the_branch_holding_it_is_live() {
    let held = with_status(7, "In Progress", Some("autofix/7"));

    assert_eq!(queued(&[held], false, &["autofix/7"]), Vec::<u64>::new());
}

#[test]
fn an_issue_a_person_holds_on_a_live_branch_stays_out_of_the_queue() {
    let held = with_status(7, "In Progress", Some("fix/seven"));

    assert_eq!(queued(&[held], false, &["fix/seven"]), Vec::<u64>::new());
}

#[test]
fn an_issue_is_back_in_the_queue_once_the_persons_branch_holding_it_is_deleted() {
    let held = with_status(7, "In Progress", Some("fix/seven"));

    assert_eq!(queued(&[held], false, &[]), [7]);
}

#[test]
fn a_hand_back_is_allowed_to_the_run_holding_the_issue() {
    let held = with_status(7, "In Progress", Some("autofix/7"));

    assert!(holds_for_hand_back(&held.state(|_| true), "autofix/7"));
}

#[test]
fn a_hand_back_is_allowed_again_after_one_that_stopped_part_way_released_the_claim() {
    assert!(holds_for_hand_back(&item(7).state(|_| true), "autofix/7"));
}

#[test]
fn a_hand_back_is_refused_once_a_person_holds_the_issue_on_another_branch() {
    let held = with_status(7, "In Progress", Some("fix/seven"));

    assert!(!holds_for_hand_back(&held.state(|_| true), "autofix/7"));
}

#[test]
fn a_hand_back_is_refused_once_a_pull_request_from_another_branch_closes_the_issue() {
    let held = IssueItem {
        open_pull_requests: vec![pull_request_from("fix/seven")],
        ..with_status(7, "In Progress", Some("autofix/7"))
    };

    assert!(!holds_for_hand_back(&held.state(|_| true), "autofix/7"));
}

#[test]
fn an_item_read_just_before_claiming_is_free_when_open_unlabelled_and_unheld() {
    assert_eq!(
        readiness_of_item(&item(7), "autofix/7", &live(&[]), false),
        Readiness::Free
    );
}

#[test]
fn an_item_read_just_before_claiming_is_blocked_once_a_hand_back_labelled_it() {
    assert_eq!(
        readiness_of_item(&blocked(7), "autofix/7", &live(&[]), false),
        Readiness::Blocked
    );
}

#[test]
fn an_item_handed_back_is_free_when_a_person_asks_for_it() {
    assert_eq!(
        readiness_of_item(&blocked(7), "autofix/7", &live(&[]), true),
        Readiness::Free
    );
}

#[test]
fn an_item_read_just_before_claiming_is_held_by_another_live_branch() {
    let held = with_status(7, "In Progress", Some("fix/seven"));

    assert_eq!(
        readiness_of_item(&held, "autofix/7", &live(&["fix/seven"]), false),
        Readiness::Held {
            holders: vec![Holder {
                branch: "fix/seven".to_owned(),
                pull_request: None,
            }],
        }
    );
}

#[test]
fn an_item_read_just_before_claiming_is_free_when_the_board_names_a_branch_that_is_gone() {
    let held = with_status(7, "In Progress", Some("fix/seven"));

    assert_eq!(
        readiness_of_item(&held, "autofix/7", &live(&[]), false),
        Readiness::Free
    );
}

#[test]
fn an_item_read_just_before_claiming_is_held_when_a_pull_request_from_another_branch_appeared() {
    assert_eq!(
        readiness_of_item(
            &with_pull_request(7, "fix/seven"),
            "autofix/7",
            &live(&[]),
            false
        ),
        Readiness::Held {
            holders: vec![Holder {
                branch: "fix/seven".to_owned(),
                pull_request: Some(pull_request_from("fix/seven")),
            }],
        }
    );
}

#[test]
fn an_item_read_just_before_claiming_is_closed_once_someone_closed_it() {
    let closed = IssueItem {
        open: false,
        ..item(7)
    };

    assert_eq!(
        readiness_of_item(&closed, "autofix/7", &live(&[]), false),
        Readiness::Closed
    );
}

#[test]
fn a_claim_still_holds_when_the_board_names_our_branch() {
    let after = with_status(7, "In Progress", Some("autofix/7"));

    assert!(still_held_after_claim(&after, "autofix/7"));
}

#[test]
fn a_claim_is_lost_when_another_branch_replaced_ours_on_the_board() {
    let after = with_status(7, "In Progress", Some("fix/seven"));

    assert!(!still_held_after_claim(&after, "autofix/7"));
}

#[test]
fn a_claim_is_lost_when_a_pull_request_from_another_branch_appeared() {
    let after = IssueItem {
        open_pull_requests: vec![pull_request_from("fix/seven")],
        ..with_status(7, "In Progress", Some("autofix/7"))
    };

    assert!(!still_held_after_claim(&after, "autofix/7"));
}

#[test]
fn a_claim_is_lost_when_the_issue_was_closed() {
    let after = IssueItem {
        open: false,
        ..with_status(7, "In Progress", Some("autofix/7"))
    };

    assert!(!still_held_after_claim(&after, "autofix/7"));
}

#[test]
fn an_undone_claim_releases_the_item_only_while_the_branch_field_names_our_branch() {
    let ours = with_status(7, "In Progress", Some("autofix/7"));
    let theirs = with_status(7, "In Progress", Some("fix/seven"));

    assert!(claimed_item_must_be_released(&ours, "autofix/7"));
    assert!(!claimed_item_must_be_released(&theirs, "autofix/7"));
}

#[test]
fn a_remote_branch_with_no_work_is_deleted_after_a_hand_back() {
    assert_eq!(
        remote_branch_after_hand_back(0),
        RemoteBranchAfterHandBack::Delete
    );
}

#[test]
fn a_remote_branch_carrying_work_is_kept_as_a_draft_after_a_hand_back() {
    assert_eq!(
        remote_branch_after_hand_back(3),
        RemoteBranchAfterHandBack::KeepAsDraft
    );
}

#[test]
fn a_run_reports_the_issues_it_passed_over_as_a_count_per_reason() {
    let counted = count_outcomes(&["held", "branch taken", "held"]);

    assert_eq!(
        counted.into_iter().collect::<Vec<_>>(),
        [("branch taken".to_owned(), 1), ("held".to_owned(), 2)]
    );
}

#[test]
fn a_claimed_branch_starts_at_the_default_branch_when_no_draft_is_live() {
    let branches = BTreeMap::from([("main".to_owned(), "aaa".to_owned())]);

    assert_eq!(
        starting_point(7, &branches, "aaa"),
        StartingPoint {
            sha: "aaa".to_owned(),
            resumes_draft: None,
        }
    );
}

#[test]
fn a_claimed_branch_starts_at_the_drafts_head_when_an_earlier_hand_back_kept_one() {
    let branches = BTreeMap::from([
        ("main".to_owned(), "aaa".to_owned()),
        ("autofix/7-draft".to_owned(), "bbb".to_owned()),
    ]);

    assert_eq!(
        starting_point(7, &branches, "aaa"),
        StartingPoint {
            sha: "bbb".to_owned(),
            resumes_draft: Some("autofix/7-draft".to_owned()),
        }
    );
}
