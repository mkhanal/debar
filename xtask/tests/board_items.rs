#![allow(clippy::unwrap_used)]

use serde_json::{Value, json};
use xtask::board_items::{Board, BoardError, BoardField, IssueItem, OwnerKind, ProjectOwner};
use xtask::claims::PullRequestClaim;

const STATUS: u64 = 11;
const BRANCH: u64 = 12;
const LINKED: u64 = 13;

fn fields_listing() -> Value {
    json!([
        {"id": 10, "node_id": "PVTF_title", "name": "Title", "data_type": "title"},
        {"id": STATUS, "node_id": "PVTSSF_status", "name": "Status", "data_type": "single_select", "options": [
            {"id": "f75ad846", "name": {"raw": "Open", "html": "Open"}, "description": {"raw": "Not yet claimed", "html": "Not yet claimed"}, "color": "GRAY"},
            {"id": "47fc9ee4", "name": "In Progress", "description": "Claimed", "color": "YELLOW"}
        ]},
        {"id": BRANCH, "node_id": "PVTF_branch", "name": "Branch", "data_type": "text"},
        {"id": LINKED, "node_id": "PVTF_linked", "name": "Linked pull requests", "data_type": "linked_pull_requests"}
    ])
}

fn owner() -> ProjectOwner {
    ProjectOwner {
        login: "acme".to_owned(),
        kind: OwnerKind::User,
    }
}

fn board() -> Board {
    let fields = BoardField::listing(&fields_listing()).unwrap();
    Board::from_fields(owner(), 2, &fields).unwrap()
}

fn issue_item(branch: &Value, linked: &Value) -> Value {
    json!({
        "id": 319_861_936,
        "content_type": "Issue",
        "content": {
            "number": 7,
            "title": "Scan nested archives to the depth limit",
            "html_url": "https://github.com/acme/scanner/issues/7",
            "state": "open",
            "body": "Who needs it, and how to tell it is done.",
            "labels": [{"name": "agent-blocked"}],
            "sub_issues_summary": {"total": 2}
        },
        "fields": [
            {"id": STATUS, "name": "Status", "value": {"id": "f75ad846", "name": {"raw": "Open", "html": "Open"}}},
            {"id": BRANCH, "name": "Branch", "value": branch},
            {"id": LINKED, "name": "Linked pull requests", "value": linked}
        ]
    })
}

fn linked_pull_request(state: &str) -> Value {
    json!({
        "number": 9,
        "state": state,
        "html_url": "https://github.com/acme/scanner/pull/9",
        "head": {"ref": "fix/archive-depth"},
        "user": {"login": "vivek"},
        "updated_at": "2026-11-20T10:00:00Z"
    })
}

#[test]
fn a_board_finds_its_status_branch_and_linked_pull_request_fields() {
    let board = board();

    assert_eq!(board.status_field_id, STATUS);
    assert_eq!(board.branch_field_id, BRANCH);
    assert_eq!(board.linked_pull_requests_field_id, LINKED);
    assert_eq!(board.status_option("In Progress").unwrap(), "47fc9ee4");
}

#[test]
fn a_board_reads_option_names_given_as_rich_text() {
    assert_eq!(board().status_option("Open").unwrap(), "f75ad846");
}

#[test]
fn a_board_without_a_branch_field_names_the_missing_field() {
    let fields: Vec<BoardField> = BoardField::listing(&fields_listing())
        .unwrap()
        .into_iter()
        .filter(|field| field.name != "Branch")
        .collect();

    let error = Board::from_fields(owner(), 2, &fields).unwrap_err();

    assert_eq!(
        error.to_string(),
        "project \"Debar\" has no text \"Branch\" field"
    );
}

#[test]
fn a_status_that_is_not_an_option_is_refused_with_the_options() {
    let error = board().status_option("Blocked").unwrap_err();

    assert_eq!(
        error,
        BoardError::NotAnOption {
            field: "Status".to_owned(),
            value: "Blocked".to_owned(),
            options: vec!["Open".to_owned(), "In Progress".to_owned()],
        }
    );
}

#[test]
fn a_project_owned_by_a_user_is_reached_under_users() {
    assert_eq!(board().project_path(), "users/acme/projectsV2/2");
}

#[test]
fn a_project_owned_by_an_organization_is_reached_under_orgs() {
    let fields = BoardField::listing(&fields_listing()).unwrap();
    let owner = ProjectOwner {
        login: "acme".to_owned(),
        kind: OwnerKind::Organization,
    };

    let board = Board::from_fields(owner, 1, &fields).unwrap();

    assert_eq!(board.project_path(), "orgs/acme/projectsV2/1");
}

#[test]
fn an_issue_item_reads_its_claim_from_the_board_fields() {
    let item = IssueItem::from_board_item(
        &board(),
        &issue_item(
            &json!({"raw": "fix/archive-depth", "html": "fix/archive-depth"}),
            &json!([linked_pull_request("open")]),
        ),
    )
    .unwrap()
    .unwrap();

    assert_eq!(item.item_id, 319_861_936);
    assert_eq!(item.number, 7);
    assert_eq!(item.status.as_deref(), Some("Open"));
    assert_eq!(item.branch.as_deref(), Some("fix/archive-depth"));
    assert_eq!(item.labels, ["agent-blocked"]);
    assert_eq!(item.sub_issues, 2);
    assert!(item.open);
    assert_eq!(
        item.open_pull_requests,
        [PullRequestClaim {
            number: 9,
            url: "https://github.com/acme/scanner/pull/9".to_owned(),
            author: "vivek".to_owned(),
            branch: "fix/archive-depth".to_owned(),
            updated_at: "2026-11-20T10:00:00Z".to_owned(),
        }]
    );
}

#[test]
fn a_closed_pull_request_links_to_an_issue_but_does_not_hold_it() {
    let item = IssueItem::from_board_item(
        &board(),
        &issue_item(&Value::Null, &json!([linked_pull_request("closed")])),
    )
    .unwrap()
    .unwrap();

    assert_eq!(item.open_pull_requests, []);
    assert_eq!(item.closing_pull_requests, [9]);
    assert_eq!(item.branch, None);
}

#[test]
fn an_issue_with_no_linked_pull_requests_reads_as_none() {
    let item = IssueItem::from_board_item(&board(), &issue_item(&Value::Null, &Value::Null))
        .unwrap()
        .unwrap();

    assert_eq!(item.closing_pull_requests, Vec::<u64>::new());
}

#[test]
fn a_pull_request_on_the_board_is_not_an_issue_item() {
    let pull_request = json!({"id": 5, "content_type": "PullRequest", "content": {}, "fields": []});

    assert_eq!(
        IssueItem::from_board_item(&board(), &pull_request).unwrap(),
        None
    );
}

#[test]
fn a_board_item_missing_a_requested_field_is_an_error() {
    let mut item = issue_item(&Value::Null, &Value::Null);
    item["fields"] = json!([]);

    assert!(IssueItem::from_board_item(&board(), &item).is_err());
}

#[test]
fn an_issue_item_states_its_claim_with_the_branches_that_still_exist() {
    let item = IssueItem::from_board_item(
        &board(),
        &issue_item(&json!({"raw": "fix/archive-depth"}), &Value::Null),
    )
    .unwrap()
    .unwrap();

    assert!(item.state(|_| true).claiming_branch_exists);
    assert!(!item.state(|_| false).claiming_branch_exists);
}
