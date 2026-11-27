use std::fmt;

use serde_json::Value;
use toml::Table;

use crate::workspace::MetadataError;

pub const REVIEW_LIST: &str = "unsafe-reviews.toml";
pub const REVIEW_FIELDS: [&str; 4] = ["reached-by", "unsafe-code", "reviewed", "reviewed-on"];
pub const SOURCE_DIRECTORIES_NOT_BUILT_INTO_DEBAR: [&str; 5] =
    ["tests", "benches", "examples", "fuzz", "target"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPackage {
    pub name: String,
    pub version: String,
    pub directory: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyWithUnsafe {
    pub name: String,
    pub version: String,
    pub uses: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UnsafeReviewFinding {
    NotReviewed {
        name: String,
        version: String,
        uses: usize,
    },
    ReviewIncomplete {
        name: String,
        version: String,
    },
    ReviewOfNoDependencyWithUnsafe {
        name: String,
        version: String,
    },
}

impl fmt::Display for UnsafeReviewFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReviewed {
                name,
                version,
                uses,
            } => write!(
                formatter,
                "{name} {version} has {uses} unsafe block(s) or item(s) and no review in {REVIEW_LIST}; read them and record what they do and why they hold (Constitution §18)"
            ),
            Self::ReviewIncomplete { name, version } => write!(
                formatter,
                "the review of {name} {version} in {REVIEW_LIST} must fill in `reached-by`, `unsafe-code`, `reviewed` and `reviewed-on`"
            ),
            Self::ReviewOfNoDependencyWithUnsafe { name, version } => write!(
                formatter,
                "{REVIEW_LIST} reviews {name} {version}, which is not a dependency with unsafe code; remove the review"
            ),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReviewListNotToml(pub String);

impl fmt::Display for ReviewListNotToml {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{REVIEW_LIST} is not TOML: {}", self.0)
    }
}

struct Review {
    name: String,
    version: String,
    complete: bool,
}

pub fn registry_packages(metadata: &str) -> Result<Vec<RegistryPackage>, MetadataError> {
    let metadata: Value = serde_json::from_str(metadata)
        .map_err(|error| MetadataError::NotJson(error.to_string()))?;
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or(MetadataError::MissingField("packages"))?;
    let mut found = Vec::new();
    for package in packages {
        let from_registry = package
            .get("source")
            .and_then(Value::as_str)
            .is_some_and(|source| source.starts_with("registry+"));
        if !from_registry {
            continue;
        }
        let manifest = string_field(package, "manifest_path")?;
        found.push(RegistryPackage {
            name: string_field(package, "name")?,
            version: string_field(package, "version")?,
            directory: manifest
                .strip_suffix("/Cargo.toml")
                .unwrap_or(&manifest)
                .to_owned(),
        });
    }
    Ok(found)
}

pub fn unsafe_review_findings(
    dependencies: &[DependencyWithUnsafe],
    review_list: &str,
) -> Result<Vec<UnsafeReviewFinding>, ReviewListNotToml> {
    let reviews = reviews(review_list)?;
    let mut findings = Vec::new();
    for dependency in dependencies {
        if !reviews
            .iter()
            .any(|review| review.name == dependency.name && review.version == dependency.version)
        {
            findings.push(UnsafeReviewFinding::NotReviewed {
                name: dependency.name.clone(),
                version: dependency.version.clone(),
                uses: dependency.uses,
            });
        }
    }
    for review in &reviews {
        if !review.complete {
            findings.push(UnsafeReviewFinding::ReviewIncomplete {
                name: review.name.clone(),
                version: review.version.clone(),
            });
        }
        if !dependencies.iter().any(|dependency| {
            dependency.name == review.name && dependency.version == review.version
        }) {
            findings.push(UnsafeReviewFinding::ReviewOfNoDependencyWithUnsafe {
                name: review.name.clone(),
                version: review.version.clone(),
            });
        }
    }
    Ok(findings)
}

fn reviews(review_list: &str) -> Result<Vec<Review>, ReviewListNotToml> {
    let table = review_list
        .parse::<Table>()
        .map_err(|error| ReviewListNotToml(error.to_string()))?;
    let entries = match table.get("review") {
        None => return Ok(Vec::new()),
        Some(entries) => entries
            .as_array()
            .ok_or_else(|| ReviewListNotToml("`review` must be an array of tables".to_owned()))?,
    };
    entries
        .iter()
        .map(|entry| {
            let text = |key: &str| entry.get(key).and_then(toml::Value::as_str).unwrap_or("");
            if text("crate").is_empty() || text("version").is_empty() {
                return Err(ReviewListNotToml(
                    "every review names its `crate` and `version`".to_owned(),
                ));
            }
            Ok(Review {
                name: text("crate").to_owned(),
                version: text("version").to_owned(),
                complete: REVIEW_FIELDS
                    .iter()
                    .all(|field| !text(field).trim().is_empty()),
            })
        })
        .collect()
}

fn string_field(object: &Value, field: &'static str) -> Result<String, MetadataError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(MetadataError::MissingField(field))
}
