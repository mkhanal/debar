#![forbid(unsafe_code)]

use xtask::issue_brief::{IssueComment, IssueView, issue_brief};

fn issue() -> IssueView {
    IssueView {
        number: 1080,
        title: "Scan nested archives to the depth limit".to_owned(),
        url: "https://github.com/acme/scanner/issues/1080".to_owned(),
        body: "**Done when.** The harness agrees.\n".to_owned(),
        labels: vec!["bug".to_owned(), "needs-decision".to_owned()],
        comments: Vec::new(),
        closing_pull_requests: Vec::new(),
        sub_issues: 0,
    }
}

#[test]
fn the_brief_gives_the_title_labels_branch_and_description() {
    assert_eq!(
        issue_brief(&issue(), "autofix/1080", &[]),
        [
            "# #1080 Scan nested archives to the depth limit",
            "",
            "https://github.com/acme/scanner/issues/1080",
            "Labels: bug, needs-decision",
            "Branch: autofix/1080, no commits yet",
            "",
            "## Issue",
            "",
            "**Done when.** The harness agrees.",
            "",
        ]
        .join("\n")
    );
}

#[test]
fn the_brief_gives_every_comment_in_order_with_its_author_and_day() {
    let commented = IssueView {
        comments: vec![
            IssueComment {
                author: "mkhanal".to_owned(),
                created_at: "2026-11-17T22:00:00Z".to_owned(),
                body: "**Questions**\n1. Which limit?".to_owned(),
            },
            IssueComment {
                author: "vivek".to_owned(),
                created_at: "2026-11-18T08:30:00Z".to_owned(),
                body: "The reference's default.".to_owned(),
            },
        ],
        ..issue()
    };

    assert!(issue_brief(&commented, "autofix/1080", &[]).contains(
        "## Comment by mkhanal, 2026-11-17\n\n**Questions**\n1. Which limit?\n\n## Comment by vivek, 2026-11-18\n\nThe reference's default.\n"
    ));
}

#[test]
fn the_brief_lists_the_commits_a_resumed_draft_brought_onto_the_branch() {
    let commits = ["abc1234 Reproduce the depth limit".to_owned()];

    assert!(
        issue_brief(&issue(), "autofix/1080", &commits)
            .contains("Branch: autofix/1080\n- abc1234 Reproduce the depth limit\n")
    );
}

#[test]
fn the_brief_names_its_sub_issues_and_the_pull_requests_closing_it() {
    let parent = IssueView {
        sub_issues: 3,
        closing_pull_requests: vec![1200],
        ..issue()
    };

    assert!(
        issue_brief(&parent, "autofix/1080", &[])
            .contains("Sub-issues: 3\nPull requests closing it: #1200\n")
    );
}

#[test]
fn the_brief_says_so_when_the_issue_has_no_description() {
    let empty = IssueView {
        body: " ".to_owned(),
        ..issue()
    };

    assert!(issue_brief(&empty, "autofix/1080", &[]).contains("## Issue\n\n(no description)\n"));
}

#[test]
fn the_brief_says_so_when_the_issue_has_no_labels() {
    let unlabelled = IssueView {
        labels: Vec::new(),
        ..issue()
    };

    assert!(issue_brief(&unlabelled, "autofix/1080", &[]).contains("Labels: none\n"));
}
