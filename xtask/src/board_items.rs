use std::fmt;

use serde_json::{Value, json};

use crate::claims::{IssueState, PullRequestClaim};
use crate::response_fields::{
    MalformedResponse, label_names, list, member, number, optional_text, rich_text, text,
};

pub const BOARD_TITLE: &str = "Debar";
pub const STATUS_FIELD: &str = "Status";
pub const BRANCH_FIELD: &str = "Branch";
pub const LINKED_PULL_REQUESTS_FIELD: &str = "Linked pull requests";

const OPEN_STATE: &str = "open";
const ISSUE_CONTENT: &str = "Issue";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoardError {
    MissingField {
        name: String,
        data_type: FieldType,
    },
    NotAnOption {
        field: String,
        value: String,
        options: Vec<String>,
    },
    AreaExists {
        name: String,
    },
    ItemWithoutField {
        item_id: u64,
        field_id: u64,
    },
    Malformed(String),
}

impl fmt::Display for BoardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField { name, data_type } => write!(
                formatter,
                "project \"{BOARD_TITLE}\" has no {} \"{name}\" field",
                data_type.label()
            ),
            Self::NotAnOption {
                field,
                value,
                options,
            } => write!(
                formatter,
                "\"{value}\" is not one of the {field} options on \"{BOARD_TITLE}\": {}",
                options.join(", ")
            ),
            Self::AreaExists { name } => {
                write!(
                    formatter,
                    "Area \"{name}\" already exists on \"{BOARD_TITLE}\""
                )
            }
            Self::ItemWithoutField { item_id, field_id } => write!(
                formatter,
                "board item {item_id} came back without field {field_id}"
            ),
            Self::Malformed(reason) => write!(formatter, "{reason}"),
        }
    }
}

impl std::error::Error for BoardError {}

impl From<MalformedResponse> for BoardError {
    fn from(error: MalformedResponse) -> Self {
        Self::Malformed(error.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldType {
    Text,
    Number,
    SingleSelect,
    LinkedPullRequests,
    Other(String),
}

impl FieldType {
    fn from_data_type(data_type: &str) -> Self {
        match data_type.to_ascii_uppercase().as_str() {
            "TEXT" => Self::Text,
            "NUMBER" => Self::Number,
            "SINGLE_SELECT" => Self::SingleSelect,
            "LINKED_PULL_REQUESTS" => Self::LinkedPullRequests,
            other => Self::Other(other.to_owned()),
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Text => "text".to_owned(),
            Self::Number => "number".to_owned(),
            Self::SingleSelect => "single-select".to_owned(),
            Self::LinkedPullRequests => "linked pull requests".to_owned(),
            Self::Other(data_type) => data_type.to_ascii_lowercase(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectOption {
    pub id: Option<String>,
    pub name: String,
    pub color: String,
    pub description: String,
}

impl SelectOption {
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut option = json!({
            "name": self.name,
            "color": self.color,
            "description": self.description,
        });
        if let (Some(id), Some(fields)) = (&self.id, option.as_object_mut()) {
            fields.insert("id".to_owned(), Value::String(id.clone()));
        }
        option
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoardField {
    pub id: u64,
    pub node_id: String,
    pub name: String,
    pub data_type: FieldType,
    pub options: Vec<SelectOption>,
}

impl BoardField {
    pub fn listing(response: &Value) -> Result<Vec<Self>, BoardError> {
        response
            .as_array()
            .ok_or_else(|| BoardError::Malformed("the board's fields are not a list".to_owned()))?
            .iter()
            .map(Self::from_response)
            .collect()
    }

    fn from_response(field: &Value) -> Result<Self, BoardError> {
        let options = match field.get("options") {
            None | Some(Value::Null) => Vec::new(),
            Some(_) => list(field, "options")?
                .iter()
                .map(|option| {
                    Ok(SelectOption {
                        id: Some(text(option, "id")?.to_owned()),
                        name: rich_text(member(option, "name")?)?,
                        color: text(option, "color")?.to_owned(),
                        description: rich_text(member(option, "description")?)?,
                    })
                })
                .collect::<Result<_, MalformedResponse>>()?,
        };
        Ok(Self {
            id: number(field, "id")?,
            node_id: text(field, "node_id")?.to_owned(),
            name: text(field, "name")?.to_owned(),
            data_type: FieldType::from_data_type(text(field, "data_type")?),
            options,
        })
    }

    pub fn option_id(&self, value: &str) -> Result<String, BoardError> {
        self.options
            .iter()
            .find(|option| option.name == value)
            .and_then(|option| option.id.clone())
            .ok_or_else(|| BoardError::NotAnOption {
                field: self.name.clone(),
                value: value.to_owned(),
                options: self
                    .options
                    .iter()
                    .map(|option| option.name.clone())
                    .collect(),
            })
    }
}

pub fn require_field<'a>(
    fields: &'a [BoardField],
    name: &str,
    data_type: &FieldType,
) -> Result<&'a BoardField, BoardError> {
    fields
        .iter()
        .find(|field| field.name == name && field.data_type == *data_type)
        .ok_or_else(|| BoardError::MissingField {
            name: name.to_owned(),
            data_type: data_type.clone(),
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldValue {
    Text(String),
    Number(u64),
    SingleSelectOption(String),
    Cleared,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldUpdate {
    pub field_id: u64,
    pub value: FieldValue,
}

impl FieldUpdate {
    #[must_use]
    pub fn payload(&self) -> Value {
        let value = match &self.value {
            FieldValue::Text(text) | FieldValue::SingleSelectOption(text) => json!(text),
            FieldValue::Number(number) => json!(number),
            FieldValue::Cleared => Value::Null,
        };
        json!({ "id": self.field_id, "value": value })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerKind {
    User,
    Organization,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectOwner {
    pub login: String,
    pub kind: OwnerKind,
}

impl ProjectOwner {
    #[must_use]
    pub fn projects_path(&self) -> String {
        let collection = match self.kind {
            OwnerKind::User => "users",
            OwnerKind::Organization => "orgs",
        };
        format!("{collection}/{}/projectsV2", self.login)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Board {
    pub owner: ProjectOwner,
    pub project_number: u64,
    pub status_field_id: u64,
    pub status_field: BoardField,
    pub branch_field_id: u64,
    pub linked_pull_requests_field_id: u64,
}

impl Board {
    pub fn from_fields(
        owner: ProjectOwner,
        project_number: u64,
        fields: &[BoardField],
    ) -> Result<Self, BoardError> {
        let status = require_field(fields, STATUS_FIELD, &FieldType::SingleSelect)?;
        Ok(Self {
            owner,
            project_number,
            status_field_id: status.id,
            status_field: status.clone(),
            branch_field_id: require_field(fields, BRANCH_FIELD, &FieldType::Text)?.id,
            linked_pull_requests_field_id: require_field(
                fields,
                LINKED_PULL_REQUESTS_FIELD,
                &FieldType::LinkedPullRequests,
            )?
            .id,
        })
    }

    #[must_use]
    pub fn project_path(&self) -> String {
        format!("{}/{}", self.owner.projects_path(), self.project_number)
    }

    pub fn status_option(&self, status: &str) -> Result<String, BoardError> {
        self.status_field.option_id(status)
    }

    #[must_use]
    pub fn item_field_ids(&self) -> String {
        format!(
            "{},{},{}",
            self.status_field_id, self.branch_field_id, self.linked_pull_requests_field_id
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueItem {
    pub item_id: u64,
    pub number: u64,
    pub title: String,
    pub url: String,
    pub body: Option<String>,
    pub labels: Vec<String>,
    pub open: bool,
    pub status: Option<String>,
    pub branch: Option<String>,
    pub open_pull_requests: Vec<PullRequestClaim>,
    pub closing_pull_requests: Vec<u64>,
    pub sub_issues: u64,
}

impl IssueItem {
    pub fn from_board_item(board: &Board, item: &Value) -> Result<Option<Self>, BoardError> {
        if text(item, "content_type")? != ISSUE_CONTENT {
            return Ok(None);
        }
        let item_id = number(item, "id")?;
        let content = member(item, "content")?;
        let fields = list(item, "fields")?;
        let field = |field_id: u64| {
            fields
                .iter()
                .find(|entry| entry.get("id").and_then(Value::as_u64) == Some(field_id))
                .ok_or(BoardError::ItemWithoutField { item_id, field_id })
                .and_then(|entry| Ok(member(entry, "value")?))
        };
        let linked = linked_pull_requests(field(board.linked_pull_requests_field_id)?)?;
        Ok(Some(Self {
            item_id,
            number: number(content, "number")?,
            title: text(content, "title")?.to_owned(),
            url: text(content, "html_url")?.to_owned(),
            body: optional_text(content, "body")?,
            labels: label_names(content)?,
            open: text(content, "state")? == OPEN_STATE,
            status: selected_name(field(board.status_field_id)?)?,
            branch: text_value(field(board.branch_field_id)?)?,
            open_pull_requests: linked
                .iter()
                .filter(|linked| linked.open)
                .map(|linked| linked.claim.clone())
                .collect(),
            closing_pull_requests: linked.iter().map(|linked| linked.claim.number).collect(),
            sub_issues: number(member(content, "sub_issues_summary")?, "total")?,
        }))
    }

    #[must_use]
    pub fn state(&self, is_live: impl Fn(&str) -> bool) -> IssueState {
        IssueState {
            number: self.number,
            url: self.url.clone(),
            open: self.open,
            claiming_branch: self.branch.clone(),
            claiming_branch_exists: self.branch.as_deref().is_some_and(is_live),
            open_pull_requests: self.open_pull_requests.clone(),
        }
    }
}

pub fn issue_items(board: &Board, items: &[Value]) -> Result<Vec<IssueItem>, BoardError> {
    let mut issues = Vec::new();
    for item in items {
        if let Some(issue) = IssueItem::from_board_item(board, item)? {
            issues.push(issue);
        }
    }
    Ok(issues)
}

struct LinkedPullRequest {
    open: bool,
    claim: PullRequestClaim,
}

fn linked_pull_requests(value: &Value) -> Result<Vec<LinkedPullRequest>, BoardError> {
    let Some(pull_requests) = value.as_array() else {
        return if value.is_null() {
            Ok(Vec::new())
        } else {
            Err(BoardError::Malformed(
                "the linked pull requests are not a list".to_owned(),
            ))
        };
    };
    pull_requests
        .iter()
        .map(|pull_request| {
            Ok(LinkedPullRequest {
                open: text(pull_request, "state")? == OPEN_STATE,
                claim: PullRequestClaim {
                    number: number(pull_request, "number")?,
                    url: text(pull_request, "html_url")?.to_owned(),
                    author: text(member(pull_request, "user")?, "login")?.to_owned(),
                    branch: text(member(pull_request, "head")?, "ref")?.to_owned(),
                    updated_at: text(pull_request, "updated_at")?.to_owned(),
                },
            })
        })
        .collect()
}

fn text_value(value: &Value) -> Result<Option<String>, BoardError> {
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(rich_text(value)?))
}

fn selected_name(value: &Value) -> Result<Option<String>, BoardError> {
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(rich_text(member(value, "name")?)?))
}
