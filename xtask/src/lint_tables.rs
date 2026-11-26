use std::fmt;

use toml::{Table, Value};

pub struct MemberManifest {
    pub name: String,
    pub text: String,
}

pub struct LintExemption {
    pub member: &'static str,
    pub lints: &'static [ExemptLint],
}

pub struct ExemptLint {
    pub tool: &'static str,
    pub lint: &'static str,
    pub level: &'static str,
}

pub const FORBIDDEN_OUTSIDE_THE_EXEMPTIONS: [(&str, &str); 3] = [
    ("rust", "unsafe_code"),
    ("clippy", "disallowed_methods"),
    ("clippy", "disallowed_types"),
];

pub const LINT_EXEMPTIONS: [LintExemption; 3] = [
    LintExemption {
        member: "debar-platform",
        lints: &[
            ExemptLint {
                tool: "rust",
                lint: "unsafe_code",
                level: "allow",
            },
            ExemptLint {
                tool: "clippy",
                lint: "disallowed_methods",
                level: "allow",
            },
            ExemptLint {
                tool: "clippy",
                lint: "disallowed_types",
                level: "allow",
            },
        ],
    },
    LintExemption {
        member: "xtask",
        lints: OUTSIDE_THE_PRODUCT_EXEMPTIONS,
    },
    LintExemption {
        member: "acceptance",
        lints: OUTSIDE_THE_PRODUCT_EXEMPTIONS,
    },
];

const OUTSIDE_THE_PRODUCT_EXEMPTIONS: &[ExemptLint] = &[
    ExemptLint {
        tool: "clippy",
        lint: "disallowed_methods",
        level: "allow",
    },
    ExemptLint {
        tool: "clippy",
        lint: "disallowed_types",
        level: "allow",
    },
];

const CLIPPY_CONFIGURATION_NAMES: [&str; 2] = ["clippy.toml", ".clippy.toml"];
const ROOT_CLIPPY_CONFIGURATION: &str = "clippy.toml";

#[derive(Debug, PartialEq, Eq)]
pub enum LintTableFinding {
    WorkspaceDoesNotForbid { tool: String, lint: String },
    LeavesTheWorkspaceLints { member: String },
    ExemptionDiffers { member: String },
    ClippyConfigurationOutsideTheRoot { path: String },
}

impl fmt::Display for LintTableFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceDoesNotForbid { tool, lint } => write!(
                formatter,
                "[workspace.lints.{tool}] must set {lint} = \"forbid\", so no crate can allow it in code (Constitution §9)"
            ),
            Self::LeavesTheWorkspaceLints { member } => write!(
                formatter,
                "{member} must use `[lints] workspace = true`; only the crates in LINT_EXEMPTIONS in xtask/src/lint_tables.rs keep their own table"
            ),
            Self::ExemptionDiffers { member } => write!(
                formatter,
                "{member}'s lint table must equal [workspace.lints] except for its exemptions in xtask/src/lint_tables.rs"
            ),
            Self::ClippyConfigurationOutsideTheRoot { path } => write!(
                formatter,
                "{path} would replace the root clippy.toml for its crate and drop the gates (Constitution §9); keep one clippy.toml, at the root"
            ),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ManifestNotToml {
    pub manifest: String,
    pub reason: String,
}

impl fmt::Display for ManifestNotToml {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the manifest of {} is not TOML: {}",
            self.manifest, self.reason
        )
    }
}

pub fn lint_table_findings(
    workspace_manifest: &str,
    members: &[MemberManifest],
) -> Result<Vec<LintTableFinding>, ManifestNotToml> {
    let workspace_lints = table_at(
        &parse("the workspace", workspace_manifest)?,
        &["workspace", "lints"],
    );
    let mut findings = missing_workspace_prohibitions(&workspace_lints);
    for member in members {
        let member_lints = table_at(&parse(&member.name, &member.text)?, &["lints"]);
        findings.extend(member_lint_finding(member, &member_lints, &workspace_lints));
    }
    Ok(findings)
}

#[must_use]
pub fn clippy_configurations_outside_the_root(tracked_paths: &[String]) -> Vec<LintTableFinding> {
    tracked_paths
        .iter()
        .filter(|path| path.as_str() != ROOT_CLIPPY_CONFIGURATION)
        .filter(|path| {
            let file_name = path.rsplit('/').next().unwrap_or(path);
            CLIPPY_CONFIGURATION_NAMES.contains(&file_name)
        })
        .map(|path| LintTableFinding::ClippyConfigurationOutsideTheRoot { path: path.clone() })
        .collect()
}

fn missing_workspace_prohibitions(workspace_lints: &Table) -> Vec<LintTableFinding> {
    FORBIDDEN_OUTSIDE_THE_EXEMPTIONS
        .iter()
        .filter(|(tool, lint)| level(workspace_lints, tool, lint) != Some("forbid"))
        .map(|(tool, lint)| LintTableFinding::WorkspaceDoesNotForbid {
            tool: (*tool).to_owned(),
            lint: (*lint).to_owned(),
        })
        .collect()
}

fn member_lint_finding(
    member: &MemberManifest,
    member_lints: &Table,
    workspace_lints: &Table,
) -> Option<LintTableFinding> {
    match LINT_EXEMPTIONS
        .iter()
        .find(|exemption| exemption.member == member.name)
    {
        Some(exemption) => (*member_lints != exempted(workspace_lints, exemption)).then(|| {
            LintTableFinding::ExemptionDiffers {
                member: member.name.clone(),
            }
        }),
        None => (*member_lints != inherits_the_workspace()).then(|| {
            LintTableFinding::LeavesTheWorkspaceLints {
                member: member.name.clone(),
            }
        }),
    }
}

fn exempted(workspace_lints: &Table, exemption: &LintExemption) -> Table {
    let mut lints = workspace_lints.clone();
    for exempt in exemption.lints {
        if let Value::Table(tool_lints) = lints
            .entry(exempt.tool)
            .or_insert_with(|| Value::Table(Table::new()))
        {
            tool_lints.insert(
                exempt.lint.to_owned(),
                Value::String(exempt.level.to_owned()),
            );
        }
    }
    lints
}

fn inherits_the_workspace() -> Table {
    Table::from_iter([("workspace".to_owned(), Value::Boolean(true))])
}

fn level<'a>(lints: &'a Table, tool: &str, lint: &str) -> Option<&'a str> {
    match lints.get(tool)?.get(lint)? {
        Value::String(level) => Some(level),
        Value::Table(detailed) => detailed.get("level")?.as_str(),
        _ => None,
    }
}

fn parse(manifest: &str, text: &str) -> Result<Table, ManifestNotToml> {
    text.parse::<Table>().map_err(|error| ManifestNotToml {
        manifest: manifest.to_owned(),
        reason: error.to_string(),
    })
}

fn table_at(table: &Table, keys: &[&str]) -> Table {
    keys.iter()
        .try_fold(table, |current, key| current.get(*key)?.as_table())
        .cloned()
        .unwrap_or_default()
}
