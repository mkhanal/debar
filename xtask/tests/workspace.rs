#![forbid(unsafe_code)]

use serde_json::json;
use xtask::workspace::{DependencyKind, DependencySource, Workspace};

fn cargo_metadata_with_members(packages: &serde_json::Value) -> String {
    json!({ "packages": packages, "version": 1 }).to_string()
}

#[test]
fn members_and_their_dependencies_are_read_from_cargo_metadata() {
    let metadata = cargo_metadata_with_members(&json!([
        {
            "name": "debar-image",
            "manifest_path": "/work/crates/image/Cargo.toml",
            "dependencies": [
                { "name": "debar-platform", "req": "*", "kind": null, "source": null, "path": "/work/crates/platform" },
                { "name": "zerocopy", "req": "=0.8.27", "kind": null, "source": "registry+https://github.com/rust-lang/crates.io-index" },
                { "name": "proptest", "req": "=1.7.0", "kind": "dev", "source": "registry+https://github.com/rust-lang/crates.io-index" },
                { "name": "cc", "req": "=1.2.0", "kind": "build", "source": "git+https://example.invalid/cc" }
            ]
        }
    ]));

    let workspace = Workspace::from_cargo_metadata(&metadata).unwrap();

    assert_eq!(workspace.members.len(), 1);
    let member = &workspace.members[0];
    assert_eq!(member.name, "debar-image");
    assert_eq!(member.manifest_path, "/work/crates/image/Cargo.toml");
    let dependencies = &member.dependencies;
    assert_eq!(dependencies.len(), 4);
    assert_eq!(dependencies[0].name, "debar-platform");
    assert_eq!(dependencies[0].source, DependencySource::Path);
    assert_eq!(dependencies[0].kind, DependencyKind::Normal);
    assert_eq!(dependencies[1].requirement, "=0.8.27");
    assert_eq!(dependencies[1].source, DependencySource::Registry);
    assert_eq!(dependencies[2].kind, DependencyKind::Development);
    assert_eq!(dependencies[3].kind, DependencyKind::Build);
    assert_eq!(dependencies[3].source, DependencySource::Git);
}

#[test]
fn metadata_that_is_not_json_is_an_error() {
    assert!(Workspace::from_cargo_metadata("not json").is_err());
}

#[test]
fn metadata_without_packages_is_an_error() {
    assert!(Workspace::from_cargo_metadata(r#"{"version": 1}"#).is_err());
}

#[test]
fn a_dependency_of_an_unknown_kind_is_an_error() {
    let metadata = cargo_metadata_with_members(&json!([
        {
            "name": "debar-image",
            "manifest_path": "/work/crates/image/Cargo.toml",
            "dependencies": [
                { "name": "zerocopy", "req": "=0.8.27", "kind": "sideways", "source": "registry+https://github.com/rust-lang/crates.io-index" }
            ]
        }
    ]));

    assert!(Workspace::from_cargo_metadata(&metadata).is_err());
}
