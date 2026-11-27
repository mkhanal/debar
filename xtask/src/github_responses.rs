use std::collections::BTreeMap;
use std::fmt;

use serde_json::Value;

use crate::response_fields::MalformedResponse;

const HEADS_PREFIX: &str = "refs/heads/";
const GIT_SUFFIX: &str = ".git";

#[derive(Debug, PartialEq, Eq)]
pub enum ResponseError {
    NotARepositoryRemote(String),
    NotJson(String),
    NotAPage,
    NotABranchLine(String),
    Malformed(MalformedResponse),
}

impl fmt::Display for ResponseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotARepositoryRemote(remote) => write!(
                formatter,
                "cannot read a GitHub repository from remote \"{remote}\""
            ),
            Self::NotJson(reason) => write!(formatter, "GitHub answered with no JSON: {reason}"),
            Self::NotAPage => write!(formatter, "a page from GitHub was not a list"),
            Self::NotABranchLine(line) => {
                write!(
                    formatter,
                    "\"{line}\" is not a branch in a listing of heads"
                )
            }
            Self::Malformed(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ResponseError {}

impl From<MalformedResponse> for ResponseError {
    fn from(error: MalformedResponse) -> Self {
        Self::Malformed(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryPath {
    pub owner: String,
    pub name: String,
}

pub fn repository_path_of_remote(remote_url: &str) -> Result<RepositoryPath, ResponseError> {
    let remote = remote_url.trim();
    let refused = || ResponseError::NotARepositoryRemote(remote.to_owned());
    let without_suffix = remote.strip_suffix(GIT_SUFFIX).unwrap_or(remote);
    let (before_name, name) = without_suffix.rsplit_once('/').ok_or_else(refused)?;
    let (_, owner) = before_name.rsplit_once([':', '/']).ok_or_else(refused)?;
    if owner.is_empty() || name.is_empty() {
        return Err(refused());
    }
    Ok(RepositoryPath {
        owner: owner.to_owned(),
        name: name.to_owned(),
    })
}

pub fn pages(listing: &str) -> Result<Vec<Value>, ResponseError> {
    let mut entries = Vec::new();
    for page in serde_json::Deserializer::from_str(listing).into_iter::<Value>() {
        match page.map_err(|error| ResponseError::NotJson(error.to_string()))? {
            Value::Array(page) => entries.extend(page),
            _ => return Err(ResponseError::NotAPage),
        }
    }
    Ok(entries)
}

pub fn remote_branches(listing: &str) -> Result<BTreeMap<String, String>, ResponseError> {
    listing
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (sha, reference) = line
                .split_once('\t')
                .ok_or_else(|| ResponseError::NotABranchLine(line.to_owned()))?;
            let branch = reference
                .strip_prefix(HEADS_PREFIX)
                .ok_or_else(|| ResponseError::NotABranchLine(line.to_owned()))?;
            Ok((branch.to_owned(), sha.to_owned()))
        })
        .collect()
}
