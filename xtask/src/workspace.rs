use std::fmt;

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    pub members: Vec<Member>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub manifest_path: String,
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub requirement: String,
    pub source: DependencySource,
    pub kind: DependencyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencySource {
    Registry,
    Git,
    Path,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyKind {
    Normal,
    Development,
    Build,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MetadataError {
    NotJson(String),
    MissingField(&'static str),
    UnknownDependencyKind(String),
}

impl fmt::Display for MetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotJson(reason) => write!(formatter, "cargo metadata is not JSON: {reason}"),
            Self::MissingField(field) => {
                write!(
                    formatter,
                    "cargo metadata has no `{field}` where one was expected"
                )
            }
            Self::UnknownDependencyKind(kind) => {
                write!(
                    formatter,
                    "cargo metadata names an unknown dependency kind `{kind}`"
                )
            }
        }
    }
}

impl Workspace {
    pub fn from_cargo_metadata(metadata: &str) -> Result<Self, MetadataError> {
        let metadata: Value = serde_json::from_str(metadata)
            .map_err(|error| MetadataError::NotJson(error.to_string()))?;
        let members = array_field(&metadata, "packages")?
            .iter()
            .map(member_from_package)
            .collect::<Result<_, _>>()?;
        Ok(Self { members })
    }
}

fn member_from_package(package: &Value) -> Result<Member, MetadataError> {
    Ok(Member {
        name: string_field(package, "name")?,
        manifest_path: string_field(package, "manifest_path")?,
        dependencies: array_field(package, "dependencies")?
            .iter()
            .map(dependency_from_metadata)
            .collect::<Result<_, _>>()?,
    })
}

fn dependency_from_metadata(dependency: &Value) -> Result<Dependency, MetadataError> {
    Ok(Dependency {
        name: string_field(dependency, "name")?,
        requirement: string_field(dependency, "req")?,
        source: dependency_source(dependency),
        kind: dependency_kind(dependency)?,
    })
}

fn dependency_source(dependency: &Value) -> DependencySource {
    match dependency.get("source").and_then(Value::as_str) {
        Some(source) if source.starts_with("git+") => DependencySource::Git,
        Some(_) => DependencySource::Registry,
        None => DependencySource::Path,
    }
}

fn dependency_kind(dependency: &Value) -> Result<DependencyKind, MetadataError> {
    match dependency.get("kind").and_then(Value::as_str) {
        None => Ok(DependencyKind::Normal),
        Some("dev") => Ok(DependencyKind::Development),
        Some("build") => Ok(DependencyKind::Build),
        Some(unknown) => Err(MetadataError::UnknownDependencyKind(unknown.to_owned())),
    }
}

fn string_field(object: &Value, field: &'static str) -> Result<String, MetadataError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(MetadataError::MissingField(field))
}

fn array_field<'a>(
    object: &'a Value,
    field: &'static str,
) -> Result<&'a Vec<Value>, MetadataError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or(MetadataError::MissingField(field))
}
