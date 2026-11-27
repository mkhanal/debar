use std::fmt;

use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
pub struct MalformedResponse {
    pub expected: String,
}

impl fmt::Display for MalformedResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GitHub answered without {}", self.expected)
    }
}

impl std::error::Error for MalformedResponse {}

pub fn member<'a>(value: &'a Value, key: &str) -> Result<&'a Value, MalformedResponse> {
    value.get(key).ok_or_else(|| missing(key))
}

pub fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, MalformedResponse> {
    member(value, key)?
        .as_str()
        .ok_or_else(|| missing(&format!("{key} as text")))
}

pub fn number(value: &Value, key: &str) -> Result<u64, MalformedResponse> {
    member(value, key)?
        .as_u64()
        .ok_or_else(|| missing(&format!("{key} as a whole number")))
}

pub fn list<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], MalformedResponse> {
    member(value, key)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| missing(&format!("{key} as a list")))
}

pub fn optional_text(value: &Value, key: &str) -> Result<Option<String>, MalformedResponse> {
    match member(value, key)? {
        Value::Null => Ok(None),
        Value::String(text) => Ok(Some(text.clone())),
        _ => Err(missing(&format!("{key} as text or null"))),
    }
}

pub fn rich_text(value: &Value) -> Result<String, MalformedResponse> {
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Object(_) => text(value, "raw").map(str::to_owned),
        _ => Err(missing("text, or rich text with its raw form")),
    }
}

pub fn label_names(value: &Value) -> Result<Vec<String>, MalformedResponse> {
    list(value, "labels")?
        .iter()
        .map(|label| text(label, "name").map(str::to_owned))
        .collect()
}

fn missing(expected: &str) -> MalformedResponse {
    MalformedResponse {
        expected: expected.to_owned(),
    }
}
