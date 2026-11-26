use xtask::layers::{LayerFinding, deny_wrapper_findings, layer_findings};
use xtask::workspace::{Dependency, DependencyKind, DependencySource, Member, Workspace};

fn member(name: &str, uses: &[(&str, DependencyKind)]) -> Member {
    Member {
        name: name.to_owned(),
        manifest_path: format!("/work/{name}/Cargo.toml"),
        dependencies: uses
            .iter()
            .map(|(used, kind)| Dependency {
                name: (*used).to_owned(),
                requirement: "*".to_owned(),
                source: DependencySource::Path,
                kind: *kind,
            })
            .collect(),
    }
}

fn workspace(members: Vec<Member>) -> Workspace {
    Workspace { members }
}

#[test]
fn a_layer_may_use_any_layer_below_it() {
    let workspace = workspace(vec![
        member(
            "debar-scan",
            &[
                ("debar-formats", DependencyKind::Normal),
                ("debar-platform", DependencyKind::Normal),
            ],
        ),
        member("debar-formats", &[]),
        member("debar-platform", &[]),
    ]);

    assert_eq!(layer_findings(&workspace), vec![]);
}

#[test]
fn a_layer_using_the_layer_above_it_is_reported() {
    let workspace = workspace(vec![
        member("debar-image", &[]),
        member("debar-platform", &[("debar-image", DependencyKind::Normal)]),
    ]);

    assert_eq!(
        layer_findings(&workspace),
        vec![LayerFinding::ForbiddenDependency {
            user: "debar-platform".to_owned(),
            used: "debar-image".to_owned(),
        }]
    );
}

#[test]
fn an_upward_dependency_for_tests_alone_is_reported() {
    let workspace = workspace(vec![
        member("debar-scan", &[]),
        member(
            "debar-matching",
            &[("debar-scan", DependencyKind::Development)],
        ),
    ]);

    assert_eq!(layer_findings(&workspace).len(), 1);
}

#[test]
fn the_signature_compiler_may_use_the_image_and_the_platform() {
    let workspace = workspace(vec![
        member(
            "debar-compiler",
            &[
                ("debar-image", DependencyKind::Normal),
                ("debar-platform", DependencyKind::Normal),
            ],
        ),
        member("debar-image", &[]),
        member("debar-platform", &[]),
    ]);

    assert_eq!(layer_findings(&workspace), vec![]);
}

#[test]
fn the_signature_compiler_using_the_matching_engine_is_reported() {
    let workspace = workspace(vec![
        member(
            "debar-compiler",
            &[("debar-matching", DependencyKind::Normal)],
        ),
        member("debar-matching", &[]),
    ]);

    assert_eq!(layer_findings(&workspace).len(), 1);
}

#[test]
fn a_layer_using_a_tool_beside_the_layers_is_reported() {
    let workspace = workspace(vec![
        member(
            "debar-interfaces",
            &[("debar-compiler", DependencyKind::Normal)],
        ),
        member("debar-compiler", &[]),
    ]);

    assert_eq!(layer_findings(&workspace).len(), 1);
}

#[test]
fn a_product_crate_using_the_build_tasks_is_reported() {
    let workspace = workspace(vec![
        member("debar-platform", &[("xtask", DependencyKind::Build)]),
        member("xtask", &[]),
    ]);

    assert_eq!(layer_findings(&workspace).len(), 1);
}

#[test]
fn a_crate_missing_from_the_layer_table_is_reported() {
    let workspace = workspace(vec![member("debar-everything", &[])]);

    assert_eq!(
        layer_findings(&workspace),
        vec![LayerFinding::Unplaced {
            member: "debar-everything".to_owned(),
        }]
    );
}

#[test]
fn dependencies_from_outside_the_workspace_are_not_layer_edges() {
    let mut platform = member("debar-platform", &[]);
    platform.dependencies.push(Dependency {
        name: "memmap2".to_owned(),
        requirement: "=0.9.8".to_owned(),
        source: DependencySource::Registry,
        kind: DependencyKind::Normal,
    });

    assert_eq!(layer_findings(&workspace(vec![platform])), vec![]);
}

#[test]
fn the_committed_cargo_deny_wrappers_follow_the_layer_table() {
    assert_eq!(
        deny_wrapper_findings(include_str!("../../deny.toml")).unwrap(),
        vec![]
    );
}

#[test]
fn a_cargo_deny_wrapper_letting_a_lower_layer_use_a_higher_one_is_reported() {
    let deny = r#"
[bans]
deny = [
    { crate = "debar-image", wrappers = ["debar-platform"] },
]
"#;

    let findings = deny_wrapper_findings(deny).unwrap();

    assert!(findings.contains(&LayerFinding::DenyWrappersDisagree {
        crate_name: "debar-image".to_owned(),
        expected: vec![
            "debar-compiler".to_owned(),
            "debar-formats".to_owned(),
            "debar-interfaces".to_owned(),
            "debar-matching".to_owned(),
            "debar-scan".to_owned(),
            "debar-updater".to_owned(),
        ],
        found: Some(vec!["debar-platform".to_owned()]),
    }));
}

#[test]
fn a_layer_crate_missing_from_the_cargo_deny_bans_is_reported() {
    let findings = deny_wrapper_findings("[bans]\ndeny = []\n").unwrap();

    assert!(findings.contains(&LayerFinding::DenyWrappersDisagree {
        crate_name: "debar-interfaces".to_owned(),
        expected: vec![],
        found: None,
    }));
}
