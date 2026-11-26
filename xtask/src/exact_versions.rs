use std::fmt;

use crate::workspace::{DependencySource, Workspace};

#[derive(Debug, PartialEq, Eq)]
pub struct LooseRequirement {
    pub member: String,
    pub dependency: String,
    pub requirement: String,
}

impl fmt::Display for LooseRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} depends on {} as `{}`; name one exact version, `=MAJOR.MINOR.PATCH` (CODING-GUIDELINES.md, \"Depend with care\")",
            self.member, self.dependency, self.requirement
        )
    }
}

#[must_use]
pub fn loose_requirements(workspace: &Workspace) -> Vec<LooseRequirement> {
    workspace
        .members
        .iter()
        .flat_map(|member| {
            member
                .dependencies
                .iter()
                .filter(|dependency| dependency.source != DependencySource::Path)
                .filter(|dependency| !names_one_exact_version(&dependency.requirement))
                .map(|dependency| LooseRequirement {
                    member: member.name.clone(),
                    dependency: dependency.name.clone(),
                    requirement: dependency.requirement.clone(),
                })
        })
        .collect()
}

fn names_one_exact_version(requirement: &str) -> bool {
    let Some(version) = requirement.strip_prefix('=') else {
        return false;
    };
    let release = version
        .split_once(['-', '+'])
        .map_or(version, |(release, _)| release);
    let numbers: Vec<&str> = release.split('.').collect();
    numbers.len() == 3
        && numbers
            .iter()
            .all(|number| !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()))
}
