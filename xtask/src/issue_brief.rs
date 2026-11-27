#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueComment {
    pub author: String,
    pub created_at: String,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueView {
    pub number: u64,
    pub title: String,
    pub url: String,
    pub body: String,
    pub labels: Vec<String>,
    pub comments: Vec<IssueComment>,
    pub closing_pull_requests: Vec<u64>,
    pub sub_issues: u64,
}

const DATE_LENGTH: usize = "yyyy-mm-dd".len();

#[must_use]
pub fn issue_brief(issue: &IssueView, branch: &str, commits_on_branch: &[String]) -> String {
    let mut lines = vec![
        format!("# #{} {}", issue.number, issue.title),
        String::new(),
        issue.url.clone(),
        format!(
            "Labels: {}",
            if issue.labels.is_empty() {
                "none".to_owned()
            } else {
                issue.labels.join(", ")
            }
        ),
    ];
    if issue.sub_issues > 0 {
        lines.push(format!("Sub-issues: {}", issue.sub_issues));
    }
    if !issue.closing_pull_requests.is_empty() {
        let numbers: Vec<String> = issue
            .closing_pull_requests
            .iter()
            .map(|number| format!("#{number}"))
            .collect();
        lines.push(format!("Pull requests closing it: {}", numbers.join(", ")));
    }
    lines.push(format!(
        "Branch: {branch}{}",
        if commits_on_branch.is_empty() {
            ", no commits yet"
        } else {
            ""
        }
    ));
    lines.extend(commits_on_branch.iter().map(|commit| format!("- {commit}")));
    let description = issue.body.trim();
    lines.extend([
        String::new(),
        "## Issue".to_owned(),
        String::new(),
        if description.is_empty() {
            "(no description)".to_owned()
        } else {
            description.to_owned()
        },
    ]);
    for comment in &issue.comments {
        let day: String = comment.created_at.chars().take(DATE_LENGTH).collect();
        lines.extend([
            String::new(),
            format!("## Comment by {}, {day}", comment.author),
            String::new(),
            comment.body.trim().to_owned(),
        ]);
    }
    format!("{}\n", lines.join("\n"))
}
