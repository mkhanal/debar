#![forbid(unsafe_code)]

use xtask::lint_tables::{
    LintTableFinding, MemberManifest, clippy_configurations_outside_the_root, lint_table_findings,
};

const WORKSPACE_FORBIDDING_UNSAFE: &str = r#"
[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"
disallowed_methods = "forbid"
disallowed_types = "forbid"
"#;

const INHERITS_WORKSPACE_LINTS: &str = r#"
[package]
name = "debar-image"

[lints]
workspace = true
"#;

const PLATFORM_ALLOWING_ITS_GATES: &str = r#"
[package]
name = "debar-platform"

[lints.rust]
unsafe_code = "allow"

[lints.clippy]
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"
disallowed_methods = "allow"
disallowed_types = "allow"
"#;

fn manifest(name: &str, text: &str) -> MemberManifest {
    MemberManifest {
        name: name.to_owned(),
        text: text.to_owned(),
    }
}

#[test]
fn the_committed_workspace_forbids_unsafe_code_in_every_crate_but_the_platform_crate() {
    let members = [
        manifest(
            "debar-platform",
            include_str!("../../crates/platform/Cargo.toml"),
        ),
        manifest("xtask", include_str!("../../xtask/Cargo.toml")),
        manifest("debar-image", INHERITS_WORKSPACE_LINTS),
    ];

    let findings = lint_table_findings(include_str!("../../Cargo.toml"), &members).unwrap();

    assert_eq!(findings, vec![]);
}

#[test]
fn a_workspace_that_does_not_forbid_unsafe_code_is_reported() {
    let workspace =
        WORKSPACE_FORBIDDING_UNSAFE.replace(r#"unsafe_code = "forbid""#, r#"unsafe_code = "deny""#);

    let findings = lint_table_findings(&workspace, &[]).unwrap();

    assert_eq!(
        findings,
        vec![LintTableFinding::WorkspaceDoesNotForbid {
            tool: "rust".to_owned(),
            lint: "unsafe_code".to_owned(),
        }]
    );
}

#[test]
fn a_workspace_that_lets_the_gate_lints_be_allowed_in_code_is_reported() {
    let workspace = WORKSPACE_FORBIDDING_UNSAFE.replace(
        r#"disallowed_types = "forbid""#,
        r#"disallowed_types = "deny""#,
    );

    assert_eq!(lint_table_findings(&workspace, &[]).unwrap().len(), 1);
}

#[test]
fn a_crate_inheriting_the_workspace_lints_is_accepted() {
    let members = [manifest("debar-image", INHERITS_WORKSPACE_LINTS)];

    let findings = lint_table_findings(WORKSPACE_FORBIDDING_UNSAFE, &members).unwrap();

    assert_eq!(findings, vec![]);
}

#[test]
fn a_crate_with_its_own_lint_table_allowing_unsafe_code_is_reported() {
    let members = [manifest(
        "debar-image",
        &PLATFORM_ALLOWING_ITS_GATES.replace("debar-platform", "debar-image"),
    )];

    let findings = lint_table_findings(WORKSPACE_FORBIDDING_UNSAFE, &members).unwrap();

    assert_eq!(
        findings,
        vec![LintTableFinding::LeavesTheWorkspaceLints {
            member: "debar-image".to_owned(),
        }]
    );
}

#[test]
fn a_crate_without_a_lint_table_is_reported() {
    let members = [manifest(
        "debar-image",
        "[package]\nname = \"debar-image\"\n",
    )];

    let findings = lint_table_findings(WORKSPACE_FORBIDDING_UNSAFE, &members).unwrap();

    assert_eq!(findings.len(), 1);
}

#[test]
fn the_platform_crate_may_allow_unsafe_code_and_its_gates() {
    let members = [manifest("debar-platform", PLATFORM_ALLOWING_ITS_GATES)];

    let findings = lint_table_findings(WORKSPACE_FORBIDDING_UNSAFE, &members).unwrap();

    assert_eq!(findings, vec![]);
}

#[test]
fn the_platform_crate_relaxing_any_other_lint_is_reported() {
    let platform =
        PLATFORM_ALLOWING_ITS_GATES.replace(r#"unwrap_used = "deny""#, r#"unwrap_used = "allow""#);
    let members = [manifest("debar-platform", &platform)];

    let findings = lint_table_findings(WORKSPACE_FORBIDDING_UNSAFE, &members).unwrap();

    assert_eq!(
        findings,
        vec![LintTableFinding::ExemptionDiffers {
            member: "debar-platform".to_owned(),
        }]
    );
}

#[test]
fn the_build_tasks_allowing_unsafe_code_are_reported() {
    let xtask = PLATFORM_ALLOWING_ITS_GATES.replace("debar-platform", "xtask");
    let members = [manifest("xtask", &xtask)];

    assert_eq!(
        lint_table_findings(WORKSPACE_FORBIDDING_UNSAFE, &members)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_manifest_that_is_not_toml_is_an_error() {
    assert!(lint_table_findings("[workspace", &[]).is_err());
}

#[test]
fn a_clippy_configuration_beside_a_crate_is_reported() {
    let tracked = [
        "clippy.toml".to_owned(),
        "crates/image/clippy.toml".to_owned(),
        "crates/scan/.clippy.toml".to_owned(),
        "crates/scan/src/lib.rs".to_owned(),
    ];

    assert_eq!(
        clippy_configurations_outside_the_root(&tracked),
        vec![
            LintTableFinding::ClippyConfigurationOutsideTheRoot {
                path: "crates/image/clippy.toml".to_owned(),
            },
            LintTableFinding::ClippyConfigurationOutsideTheRoot {
                path: "crates/scan/.clippy.toml".to_owned(),
            },
        ]
    );
}
