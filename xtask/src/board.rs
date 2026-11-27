use serde_json::{Value, json};

use crate::board_items::SelectOption;
use crate::board_items::{
    BOARD_TITLE, BRANCH_FIELD, Board, BoardField, FieldUpdate, FieldValue, IssueItem, issue_items,
};
use crate::claims::BoardStatus;
use crate::github::{Repository, graphql, read_content, rest_get, rest_pages, rest_send};
use crate::response_fields::{list, member, number, text};
use crate::task_outcome::TaskError;

const DRAFT_ISSUE_CONTENT: &str = "DraftIssue";

pub struct OpenBoard {
    pub board: Board,
    pub fields: Vec<BoardField>,
}

pub fn find_board(repository: &Repository) -> Result<OpenBoard, TaskError> {
    let projects = rest_pages(&repository.owner.projects_path(), &[("q", BOARD_TITLE)])?;
    let mut project_number = None;
    for project in &projects {
        if text(project, "title")? == BOARD_TITLE {
            project_number = Some(number(project, "number")?);
        }
    }
    let project_number = project_number.ok_or_else(|| {
        TaskError::Failed(format!(
            "no project titled \"{BOARD_TITLE}\" owned by {}",
            repository.owner.login
        ))
    })?;
    let fields = BoardField::listing(&Value::Array(rest_pages(
        &format!(
            "{}/{project_number}/fields",
            repository.owner.projects_path()
        ),
        &[],
    )?))?;
    let board = Board::from_fields(repository.owner.clone(), project_number, &fields)?;
    Ok(OpenBoard { board, fields })
}

fn items_path(board: &Board) -> String {
    format!("{}/items", board.project_path())
}

fn items_matching(board: &Board, query: &str) -> Result<Vec<Value>, TaskError> {
    rest_pages(
        &items_path(board),
        &[("q", query), ("fields", &board.item_field_ids())],
    )
}

pub fn board_issues(board: &Board, query: &str) -> Result<Vec<IssueItem>, TaskError> {
    Ok(issue_items(board, &items_matching(board, query)?)?)
}

pub fn find_issue_item(board: &Board, number: u64) -> Result<Option<IssueItem>, TaskError> {
    Ok(board_issues(board, &format!("#{number}"))?
        .into_iter()
        .find(|item| item.number == number))
}

pub fn read_issue_item(board: &Board, number: u64) -> Result<IssueItem, TaskError> {
    find_issue_item(board, number)?
        .ok_or_else(|| TaskError::Failed(format!("issue #{number} is not on the board")))
}

pub fn read_item(board: &Board, number: u64, item_id: u64) -> Result<IssueItem, TaskError> {
    let response = rest_get(
        &format!("{}/{item_id}", items_path(board)),
        &[("fields", &board.item_field_ids())],
    )?;
    match IssueItem::from_board_item(board, &response)? {
        Some(item) if item.number == number => Ok(item),
        _ => Err(TaskError::Failed(format!(
            "board item {item_id} is not issue #{number}"
        ))),
    }
}

fn existing_item_id(board: &Board, number: u64) -> Result<Option<u64>, TaskError> {
    for item in items_matching(board, &format!("#{number}"))? {
        if text(&item, "content_type")? == DRAFT_ISSUE_CONTENT {
            continue;
        }
        if crate::response_fields::number(member(&item, "content")?, "number")? == number {
            return Ok(Some(crate::response_fields::number(&item, "id")?));
        }
    }
    Ok(None)
}

pub fn item_id(repository: &Repository, board: &Board, number: u64) -> Result<u64, TaskError> {
    if let Some(existing) = existing_item_id(board, number)? {
        return Ok(existing);
    }
    let content = read_content(repository, number)?;
    let added = rest_send(
        "POST",
        &items_path(board),
        &json!({ "type": content.content_type, "id": content.database_id }),
    )?;
    Ok(crate::response_fields::number(&added, "id")?)
}

pub fn set_fields(board: &Board, item_id: u64, updates: &[FieldUpdate]) -> Result<(), TaskError> {
    rest_send(
        "PATCH",
        &format!("{}/{item_id}", items_path(board)),
        &json!({ "fields": updates.iter().map(FieldUpdate::payload).collect::<Vec<_>>() }),
    )?;
    Ok(())
}

fn status_update(board: &Board, status: BoardStatus) -> Result<FieldUpdate, TaskError> {
    Ok(FieldUpdate {
        field_id: board.status_field_id,
        value: FieldValue::SingleSelectOption(board.status_option(status.name())?),
    })
}

pub fn record_claim(
    board: &Board,
    item_id: u64,
    branch: &str,
    status: BoardStatus,
) -> Result<(), TaskError> {
    set_fields(
        board,
        item_id,
        &[
            FieldUpdate {
                field_id: board.branch_field_id,
                value: FieldValue::Text(branch.to_owned()),
            },
            status_update(board, status)?,
        ],
    )
}

pub fn release_claim(board: &Board, item_id: u64) -> Result<(), TaskError> {
    set_fields(
        board,
        item_id,
        &[
            status_update(board, BoardStatus::Open)?,
            FieldUpdate {
                field_id: board.branch_field_id,
                value: FieldValue::Cleared,
            },
        ],
    )
}

pub fn issues_held_by(board: &Board, branch: &str) -> Result<Vec<u64>, TaskError> {
    let query = format!(
        "{}:{}",
        BRANCH_FIELD.to_lowercase(),
        Value::String(branch.to_owned())
    );
    Ok(board_issues(board, &query)?
        .into_iter()
        .filter(|item| item.branch.as_deref() == Some(branch))
        .map(|item| item.number)
        .collect())
}

const UPDATE_OPTIONS_MUTATION: &str = "mutation($input: UpdateProjectV2FieldInput!) {
  updateProjectV2Field(input: $input) {
    projectV2Field {
      ... on ProjectV2SingleSelectField { id name options { id name color description } }
    }
  }
}";

pub fn replace_select_options(
    field: &BoardField,
    options: &[SelectOption],
) -> Result<Vec<SelectOption>, TaskError> {
    let data = graphql(
        UPDATE_OPTIONS_MUTATION,
        &json!({ "input": {
            "fieldId": field.node_id,
            "singleSelectOptions": options.iter().map(SelectOption::to_json).collect::<Vec<_>>(),
        }}),
    )?;
    let updated = member(member(&data, "updateProjectV2Field")?, "projectV2Field")?;
    Ok(list(updated, "options")?
        .iter()
        .map(|option| {
            Ok(SelectOption {
                id: Some(text(option, "id")?.to_owned()),
                name: text(option, "name")?.to_owned(),
                color: text(option, "color")?.to_owned(),
                description: text(option, "description")?.to_owned(),
            })
        })
        .collect::<Result<_, crate::response_fields::MalformedResponse>>()?)
}
