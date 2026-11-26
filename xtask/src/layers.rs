use std::fmt;

use toml::{Table, Value};

use crate::workspace::{Member, Workspace};

pub const LAYERS_TOP_DOWN: [&str; 6] = [
    "debar-interfaces",
    "debar-scan",
    "debar-formats",
    "debar-matching",
    "debar-image",
    "debar-platform",
];

pub struct ToolBesideTheLayers {
    pub name: &'static str,
    pub may_use: &'static [&'static str],
}

pub const TOOLS_BESIDE_THE_LAYERS: [ToolBesideTheLayers; 2] = [
    ToolBesideTheLayers {
        name: "debar-updater",
        may_use: &["debar-compiler", "debar-image", "debar-platform"],
    },
    ToolBesideTheLayers {
        name: "debar-compiler",
        may_use: &["debar-image", "debar-platform"],
    },
];

pub const OUTSIDE_THE_PRODUCT: [&str; 1] = ["xtask"];

#[derive(Debug, PartialEq, Eq)]
pub enum LayerFinding {
    Unplaced {
        member: String,
    },
    ForbiddenDependency {
        user: String,
        used: String,
    },
    DenyWrappersDisagree {
        crate_name: String,
        expected: Vec<String>,
        found: Option<Vec<String>>,
    },
}

impl fmt::Display for LayerFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unplaced { member } => write!(
                formatter,
                "{member} is not in the layer table in xtask/src/layers.rs; place it in its layer before it is used"
            ),
            Self::ForbiddenDependency { user, used } => write!(
                formatter,
                "{user} depends on {used}; a layer uses only the layers below it (Constitution §10, architecture-overview/ARCHITECTURE.md)"
            ),
            Self::DenyWrappersDisagree {
                crate_name,
                expected,
                found,
            } => write!(
                formatter,
                "deny.toml must ban {crate_name} with wrappers = {expected:?}, the crates the layer table in xtask/src/layers.rs lets use it; it has {}",
                found
                    .as_ref()
                    .map_or_else(|| "no ban".to_owned(), |wrappers| format!("{wrappers:?}"))
            ),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DenyConfigurationNotToml(pub String);

impl fmt::Display for DenyConfigurationNotToml {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "deny.toml is not TOML: {}", self.0)
    }
}

enum Placement {
    Layer { depth_from_top: usize },
    Tool { may_use: &'static [&'static str] },
    OutsideTheProduct,
}

#[must_use]
pub fn layer_findings(workspace: &Workspace) -> Vec<LayerFinding> {
    let unplaced = workspace
        .members
        .iter()
        .filter(|member| placement(&member.name).is_none())
        .map(|member| LayerFinding::Unplaced {
            member: member.name.clone(),
        });
    let forbidden = workspace
        .members
        .iter()
        .flat_map(|user| forbidden_dependencies(user, workspace));
    unplaced.chain(forbidden).collect()
}

pub fn deny_wrapper_findings(
    deny_configuration: &str,
) -> Result<Vec<LayerFinding>, DenyConfigurationNotToml> {
    let configuration: Table = deny_configuration
        .parse()
        .map_err(|error: toml::de::Error| DenyConfigurationNotToml(error.to_string()))?;
    let bans = configuration
        .get("bans")
        .and_then(|bans| bans.get("deny"))
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    Ok(product_crates()
        .filter_map(|crate_name| {
            let expected = permitted_dependents(crate_name);
            let found = bans
                .iter()
                .find(|ban| ban.get("crate").and_then(Value::as_str) == Some(crate_name))
                .map(wrappers_of);
            (found.as_ref() != Some(&expected)).then(|| LayerFinding::DenyWrappersDisagree {
                crate_name: crate_name.to_owned(),
                expected,
                found,
            })
        })
        .collect())
}

fn product_crates() -> impl Iterator<Item = &'static str> {
    LAYERS_TOP_DOWN
        .into_iter()
        .chain(TOOLS_BESIDE_THE_LAYERS.iter().map(|tool| tool.name))
}

fn permitted_dependents(crate_name: &str) -> Vec<String> {
    let mut dependents: Vec<String> = product_crates()
        .filter(|dependent| may_use(dependent, crate_name))
        .map(str::to_owned)
        .collect();
    dependents.sort();
    dependents
}

fn wrappers_of(ban: &Value) -> Vec<String> {
    let mut wrappers: Vec<String> = ban
        .get("wrappers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    wrappers.sort();
    wrappers
}

fn forbidden_dependencies<'a>(
    user: &'a Member,
    workspace: &'a Workspace,
) -> impl Iterator<Item = LayerFinding> + 'a {
    user.dependencies
        .iter()
        .filter(|dependency| {
            workspace
                .members
                .iter()
                .any(|member| member.name == dependency.name)
        })
        .filter(|dependency| !may_use(&user.name, &dependency.name))
        .map(|dependency| LayerFinding::ForbiddenDependency {
            user: user.name.clone(),
            used: dependency.name.clone(),
        })
}

fn may_use(dependent: &str, dependency: &str) -> bool {
    let (Some(from), Some(to)) = (placement(dependent), placement(dependency)) else {
        return false;
    };
    match from {
        Placement::Layer { depth_from_top } => matches!(
            to,
            Placement::Layer { depth_from_top: used_depth } if used_depth > depth_from_top
        ),
        Placement::Tool { may_use } => may_use.contains(&dependency),
        Placement::OutsideTheProduct => false,
    }
}

fn placement(crate_name: &str) -> Option<Placement> {
    if let Some(depth_from_top) = LAYERS_TOP_DOWN
        .iter()
        .position(|layer| *layer == crate_name)
    {
        return Some(Placement::Layer { depth_from_top });
    }
    if let Some(tool) = TOOLS_BESIDE_THE_LAYERS
        .iter()
        .find(|tool| tool.name == crate_name)
    {
        return Some(Placement::Tool {
            may_use: tool.may_use,
        });
    }
    OUTSIDE_THE_PRODUCT
        .contains(&crate_name)
        .then_some(Placement::OutsideTheProduct)
}
