#![forbid(unsafe_code)]

use xtask::exact_versions::loose_requirements;
use xtask::workspace::{Dependency, DependencyKind, DependencySource, Member, Workspace};

fn workspace_depending_on(requirement: &str, source: DependencySource) -> Workspace {
    Workspace {
        members: vec![Member {
            name: "debar-platform".to_owned(),
            manifest_path: "/work/crates/platform/Cargo.toml".to_owned(),
            dependencies: vec![Dependency {
                name: "memchr".to_owned(),
                requirement: requirement.to_owned(),
                source,
                kind: DependencyKind::Normal,
            }],
        }],
    }
}

#[test]
fn a_dependency_naming_one_exact_version_is_accepted() {
    let workspace = workspace_depending_on("=2.8.3", DependencySource::Registry);

    assert_eq!(loose_requirements(&workspace), vec![]);
}

#[test]
fn an_exact_prerelease_version_is_accepted() {
    let workspace = workspace_depending_on("=1.0.0-alpha.2", DependencySource::Registry);

    assert_eq!(loose_requirements(&workspace), vec![]);
}

#[test]
fn a_caret_requirement_is_reported() {
    let workspace = workspace_depending_on("^2.8.3", DependencySource::Registry);

    let loose = loose_requirements(&workspace);

    assert_eq!(loose.len(), 1);
    assert_eq!(loose[0].member, "debar-platform");
    assert_eq!(loose[0].dependency, "memchr");
    assert_eq!(loose[0].requirement, "^2.8.3");
}

#[test]
fn an_exact_requirement_missing_its_patch_number_is_reported() {
    let workspace = workspace_depending_on("=2.8", DependencySource::Registry);

    assert_eq!(loose_requirements(&workspace).len(), 1);
}

#[test]
fn a_range_of_versions_is_reported() {
    let workspace = workspace_depending_on(">=2.8.3, <3", DependencySource::Registry);

    assert_eq!(loose_requirements(&workspace).len(), 1);
}

#[test]
fn any_version_from_a_registry_is_reported() {
    let workspace = workspace_depending_on("*", DependencySource::Registry);

    assert_eq!(loose_requirements(&workspace).len(), 1);
}

#[test]
fn a_dependency_from_git_without_an_exact_version_is_reported() {
    let workspace = workspace_depending_on("*", DependencySource::Git);

    assert_eq!(loose_requirements(&workspace).len(), 1);
}

#[test]
fn a_path_dependency_inside_the_workspace_needs_no_version() {
    let workspace = workspace_depending_on("*", DependencySource::Path);

    assert_eq!(loose_requirements(&workspace), vec![]);
}
