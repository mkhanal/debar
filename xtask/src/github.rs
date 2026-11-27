use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use crate::board_items::{OwnerKind, ProjectOwner};
use crate::claims::PullRequestReadiness;
use crate::github_responses::{
    pages, remote_branches as branches_in_listing, repository_path_of_remote,
};
use crate::issue_brief::IssueComment;
use crate::pull_request_size::{ChangedFile, parse_changed_files};
use crate::response_fields::{label_names, member, number, optional_text, text};
use crate::task_outcome::TaskError;

const NOT_FOUND: &str = "HTTP 404";
const REFERENCE_EXISTS: &str = "Reference already exists";
const PAGE_SIZE: &str = "100";
const OPEN_STATE: &str = "open";
const CREDENTIALS_FROM_GH: [&str; 4] = [
    "-c",
    "credential.helper=",
    "-c",
    "credential.helper=!gh auth git-credential",
];

#[derive(Debug)]
pub struct CommandFailure {
    pub command: String,
    pub detail: String,
}

impl CommandFailure {
    fn says(&self, text: &str) -> bool {
        self.detail.contains(text)
    }

    #[must_use]
    pub fn is_not_found(&self) -> bool {
        self.says(NOT_FOUND)
    }
}

impl From<CommandFailure> for TaskError {
    fn from(failure: CommandFailure) -> Self {
        Self::Failed(format!(
            "`{}` failed: {}",
            failure.command,
            failure.detail.trim()
        ))
    }
}

pub fn gh(arguments: &[&str], input: Option<&str>) -> Result<String, CommandFailure> {
    run("gh", arguments, input)
}

pub fn git(arguments: &[&str]) -> Result<String, CommandFailure> {
    run("git", arguments, None).map(|output| output.trim().to_owned())
}

pub fn git_over_the_network(arguments: &[&str]) -> Result<String, CommandFailure> {
    let mut with_credentials = CREDENTIALS_FROM_GH.to_vec();
    with_credentials.extend_from_slice(arguments);
    git(&with_credentials)
}

fn run(program: &str, arguments: &[&str], input: Option<&str>) -> Result<String, CommandFailure> {
    let command = format!("{program} {}", arguments.join(" "));
    let failure = |detail: String| CommandFailure {
        command: command.clone(),
        detail,
    };
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| failure(format!("cannot run {program}: {error}")))?;
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin
            .write_all(input.as_bytes())
            .map_err(|error| failure(format!("cannot write to {program}: {error}")))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| failure(format!("{program} did not finish: {error}")))?;
    if !output.status.success() {
        return Err(failure(format!(
            "{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| failure("printed text that is not UTF-8".to_owned()))
}

fn parse(output: &str) -> Result<Value, TaskError> {
    serde_json::from_str(output)
        .map_err(|error| TaskError::Failed(format!("GitHub answered with no JSON: {error}")))
}

fn query_arguments(query: &[(&str, &str)]) -> Vec<String> {
    query
        .iter()
        .flat_map(|(name, value)| ["-f".to_owned(), format!("{name}={value}")])
        .collect()
}

pub fn rest_get(path: &str, query: &[(&str, &str)]) -> Result<Value, TaskError> {
    let fields = query_arguments(query);
    let mut arguments = vec!["api", "--method", "GET", path];
    arguments.extend(fields.iter().map(String::as_str));
    parse(&gh(&arguments, None)?)
}

pub fn rest_pages(path: &str, query: &[(&str, &str)]) -> Result<Vec<Value>, TaskError> {
    let mut paged = query.to_vec();
    paged.push(("per_page", PAGE_SIZE));
    let fields = query_arguments(&paged);
    let mut arguments = vec!["api", "--method", "GET", "--paginate", path];
    arguments.extend(fields.iter().map(String::as_str));
    Ok(pages(&gh(&arguments, None)?)?)
}

pub fn rest_send(method: &str, path: &str, body: &Value) -> Result<Value, TaskError> {
    let output = gh(
        &["api", "--method", method, path, "--input", "-"],
        Some(&body.to_string()),
    )?;
    parse(&output)
}

pub fn graphql(query: &str, variables: &Value) -> Result<Value, TaskError> {
    let request = json!({ "query": query, "variables": variables });
    let response = parse(&gh(
        &["api", "graphql", "--input", "-"],
        Some(&request.to_string()),
    )?)?;
    Ok(member(&response, "data")?.clone())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repository {
    pub owner: ProjectOwner,
    pub name: String,
    pub default_branch: String,
}

impl Repository {
    pub fn current() -> Result<Self, TaskError> {
        let remote = repository_path_of_remote(&git(&["remote", "get-url", "origin"])?)?;
        let response = rest_get(&format!("repos/{}/{}", remote.owner, remote.name), &[])?;
        let owner = member(&response, "owner")?;
        let kind = match text(owner, "type")? {
            "Organization" => OwnerKind::Organization,
            _ => OwnerKind::User,
        };
        Ok(Self {
            owner: ProjectOwner {
                login: text(owner, "login")?.to_owned(),
                kind,
            },
            name: text(&response, "name")?.to_owned(),
            default_branch: text(&response, "default_branch")?.to_owned(),
        })
    }

    #[must_use]
    pub fn path(&self) -> String {
        format!("repos/{}/{}", self.owner.login, self.name)
    }

    fn issue_path(&self, number: u64) -> String {
        format!("{}/issues/{number}", self.path())
    }

    fn refs_path(&self) -> String {
        format!("{}/git/refs", self.path())
    }

    #[must_use]
    pub fn base(&self) -> String {
        format!("origin/{}", self.default_branch)
    }
}

pub struct IssueResponse {
    pub database_id: u64,
    pub number: u64,
    pub url: String,
    pub open: bool,
    pub labels: Vec<String>,
    pub is_pull_request: bool,
}

pub fn read_issue(repository: &Repository, number: u64) -> Result<IssueResponse, TaskError> {
    let issue = rest_get(&repository.issue_path(number), &[])?;
    Ok(IssueResponse {
        database_id: crate::response_fields::number(&issue, "id")?,
        number: crate::response_fields::number(&issue, "number")?,
        url: text(&issue, "html_url")?.to_owned(),
        open: text(&issue, "state")? == OPEN_STATE,
        labels: label_names(&issue)?,
        is_pull_request: issue
            .get("pull_request")
            .is_some_and(|value| !value.is_null()),
    })
}

pub struct BoardContent {
    pub content_type: &'static str,
    pub database_id: u64,
    pub url: String,
}

pub fn read_content(repository: &Repository, number: u64) -> Result<BoardContent, TaskError> {
    let issue = read_issue(repository, number)?;
    if !issue.is_pull_request {
        return Ok(BoardContent {
            content_type: "Issue",
            database_id: issue.database_id,
            url: issue.url,
        });
    }
    let pull_request = rest_get(&format!("{}/pulls/{number}", repository.path()), &[])?;
    Ok(BoardContent {
        content_type: "PullRequest",
        database_id: crate::response_fields::number(&pull_request, "id")?,
        url: text(&pull_request, "html_url")?.to_owned(),
    })
}

pub fn branch_exists(repository: &Repository, branch: &str) -> Result<bool, TaskError> {
    match gh(
        &[
            "api",
            "--method",
            "GET",
            &format!("{}/git/ref/heads/{branch}", repository.path()),
        ],
        None,
    ) {
        Ok(_) => Ok(true),
        Err(failure) if failure.is_not_found() => Ok(false),
        Err(failure) => Err(failure.into()),
    }
}

pub struct BranchPullRequest {
    pub number: u64,
    pub readiness: PullRequestReadiness,
    pub body: String,
}

pub fn branch_pull_request(
    repository: &Repository,
    branch: &str,
) -> Result<Option<BranchPullRequest>, TaskError> {
    let head = format!("{}:{branch}", repository.owner.login);
    let response = rest_get(
        &format!("{}/pulls", repository.path()),
        &[("state", OPEN_STATE), ("head", &head)],
    )?;
    let Some(pull_request) = response.as_array().and_then(|listing| listing.first()) else {
        return Ok(None);
    };
    let draft = member(pull_request, "draft")?.as_bool() == Some(true);
    Ok(Some(BranchPullRequest {
        number: number(pull_request, "number")?,
        readiness: if draft {
            PullRequestReadiness::Draft
        } else {
            PullRequestReadiness::ReadyForReview
        },
        body: optional_text(pull_request, "body")?.unwrap_or_default(),
    }))
}

pub fn current_branch() -> Result<String, TaskError> {
    Ok(git(&["branch", "--show-current"])?)
}

pub fn publish_branch(repository: &Repository, branch: &str) -> Result<(), TaskError> {
    git_over_the_network(&["fetch", "--quiet", "origin"])?;
    let base = git(&["merge-base", "HEAD", &repository.base()])?;
    if !create_branch(repository, branch, &base)? {
        return Err(TaskError::Failed(format!(
            "branch \"{branch}\" appeared on GitHub while it was being published"
        )));
    }
    Ok(())
}

pub fn create_branch(repository: &Repository, branch: &str, sha: &str) -> Result<bool, TaskError> {
    let reference = format!("ref=refs/heads/{branch}");
    let target = format!("sha={sha}");
    match gh(
        &[
            "api",
            "--method",
            "POST",
            &repository.refs_path(),
            "-f",
            &reference,
            "-f",
            &target,
        ],
        None,
    ) {
        Ok(_) => Ok(true),
        Err(failure) if failure.says(REFERENCE_EXISTS) => Ok(false),
        Err(failure) => Err(failure.into()),
    }
}

pub fn move_branch(repository: &Repository, branch: &str, sha: &str) -> Result<(), TaskError> {
    let target = format!("sha={sha}");
    gh(
        &[
            "api",
            "--method",
            "PATCH",
            &format!("{}/heads/{branch}", repository.refs_path()),
            "-f",
            &target,
            "-F",
            "force=true",
        ],
        None,
    )?;
    Ok(())
}

pub fn delete_remote_branch(repository: &Repository, branch: &str) -> Result<(), TaskError> {
    gh(
        &[
            "api",
            "--method",
            "DELETE",
            &format!("{}/heads/{branch}", repository.refs_path()),
        ],
        None,
    )?;
    Ok(())
}

pub fn remote_branches() -> Result<BTreeMap<String, String>, TaskError> {
    Ok(branches_in_listing(&git_over_the_network(&[
        "ls-remote",
        "--heads",
        "origin",
    ])?)?)
}

pub fn fetch_branches(branches: &[&str]) -> Result<(), TaskError> {
    let refspecs: Vec<String> = branches
        .iter()
        .map(|branch| format!("+refs/heads/{branch}:refs/remotes/origin/{branch}"))
        .collect();
    let mut arguments = vec!["fetch", "--quiet", "origin"];
    arguments.extend(refspecs.iter().map(String::as_str));
    git_over_the_network(&arguments)?;
    Ok(())
}

pub fn local_branch_exists(branch: &str) -> Result<bool, TaskError> {
    Ok(git(&["branch", "--list", "--format=%(refname:short)", branch])? == branch)
}

fn claimant_login() -> Result<String, TaskError> {
    Ok(text(&rest_get("user", &[])?, "login")?.to_owned())
}

pub fn assign_only_claimant(repository: &Repository, number: u64) -> Result<(), TaskError> {
    rest_send(
        "PATCH",
        &repository.issue_path(number),
        &json!({ "assignees": [claimant_login()?] }),
    )?;
    Ok(())
}

pub fn issue_comments(
    repository: &Repository,
    number: u64,
) -> Result<Vec<IssueComment>, TaskError> {
    rest_pages(&format!("{}/comments", repository.issue_path(number)), &[])?
        .iter()
        .map(|comment| {
            Ok(IssueComment {
                author: text(member(comment, "user")?, "login")?.to_owned(),
                created_at: text(comment, "created_at")?.to_owned(),
                body: optional_text(comment, "body")?.unwrap_or_default(),
            })
        })
        .collect()
}

pub fn post_issue_comment(
    repository: &Repository,
    number: u64,
    body: &str,
) -> Result<(), TaskError> {
    rest_send(
        "POST",
        &format!("{}/comments", repository.issue_path(number)),
        &json!({ "body": body }),
    )?;
    Ok(())
}

pub fn add_issue_label(repository: &Repository, number: u64, label: &str) -> Result<(), TaskError> {
    rest_send(
        "POST",
        &format!("{}/labels", repository.issue_path(number)),
        &json!({ "labels": [label] }),
    )?;
    Ok(())
}

pub fn pull_request_files(
    repository: &Repository,
    number: u64,
) -> Result<Vec<ChangedFile>, TaskError> {
    let listing = gh(
        &[
            "api",
            "--paginate",
            &format!(
                "{}/pulls/{number}/files?per_page={PAGE_SIZE}",
                repository.path()
            ),
        ],
        None,
    )?;
    Ok(parse_changed_files(&listing)?)
}

pub fn mark_ready_for_review(number: u64) -> Result<(), TaskError> {
    gh(&["pr", "ready", &number.to_string()], None)?;
    Ok(())
}
