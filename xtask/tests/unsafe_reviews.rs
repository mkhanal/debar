#![forbid(unsafe_code)]

use serde_json::json;
use xtask::unsafe_reviews::{
    DependencyWithUnsafe, RegistryPackage, UnsafeReviewFinding, registry_packages,
    unsafe_review_findings,
};

fn user(name: &str, version: &str, uses: usize) -> DependencyWithUnsafe {
    DependencyWithUnsafe {
        name: name.to_owned(),
        version: version.to_owned(),
        uses,
    }
}

const REVIEWS: &str = r#"
[[review]]
crate = "memchr"
version = "2.8.3"
reached-by = "the product"
reviewed-on = "2026-11-27"
unsafe-code = "SIMD searches over the haystack through raw pointers bounded by its length."
reviewed = "Read every block in src/arch and src/memchr.rs."
"#;

#[test]
fn a_dependency_whose_unsafe_code_was_reviewed_at_its_version_is_accepted() {
    let findings = unsafe_review_findings(&[user("memchr", "2.8.3", 412)], REVIEWS).unwrap();

    assert_eq!(findings, vec![]);
}

#[test]
fn a_dependency_with_unsafe_code_and_no_review_is_reported() {
    let findings = unsafe_review_findings(
        &[
            user("memchr", "2.8.3", 412),
            user("zerocopy", "0.8.63", 900),
        ],
        REVIEWS,
    )
    .unwrap();

    assert_eq!(
        findings,
        vec![UnsafeReviewFinding::NotReviewed {
            name: "zerocopy".to_owned(),
            version: "0.8.63".to_owned(),
            uses: 900,
        }]
    );
}

#[test]
fn a_review_of_another_version_does_not_count() {
    let findings = unsafe_review_findings(&[user("memchr", "2.8.4", 412)], REVIEWS).unwrap();

    assert_eq!(
        findings,
        vec![
            UnsafeReviewFinding::NotReviewed {
                name: "memchr".to_owned(),
                version: "2.8.4".to_owned(),
                uses: 412,
            },
            UnsafeReviewFinding::ReviewOfNoDependencyWithUnsafe {
                name: "memchr".to_owned(),
                version: "2.8.3".to_owned(),
            },
        ]
    );
}

#[test]
fn a_review_without_its_findings_is_reported() {
    let reviews = r#"
[[review]]
crate = "memchr"
version = "2.8.3"
reached-by = "the product"
reviewed-on = "2026-11-27"
unsafe-code = ""
reviewed = "Read it."
"#;

    let findings = unsafe_review_findings(&[user("memchr", "2.8.3", 412)], reviews).unwrap();

    assert_eq!(
        findings,
        vec![UnsafeReviewFinding::ReviewIncomplete {
            name: "memchr".to_owned(),
            version: "2.8.3".to_owned(),
        }]
    );
}

#[test]
fn a_review_list_that_is_not_toml_is_an_error() {
    assert!(unsafe_review_findings(&[], "[[review").is_err());
}

#[test]
fn only_packages_from_a_registry_are_dependencies_to_review() {
    let metadata = json!({
        "version": 1,
        "packages": [
            { "name": "memchr", "version": "2.8.3", "source": "registry+https://github.com/rust-lang/crates.io-index", "manifest_path": "/registry/memchr-2.8.3/Cargo.toml" },
            { "name": "debar-image", "version": "0.0.0", "source": null, "manifest_path": "/work/crates/image/Cargo.toml" }
        ]
    })
    .to_string();

    assert_eq!(
        registry_packages(&metadata).unwrap(),
        vec![RegistryPackage {
            name: "memchr".to_owned(),
            version: "2.8.3".to_owned(),
            directory: "/registry/memchr-2.8.3".to_owned(),
        }]
    );
}

#[test]
fn the_committed_review_list_is_toml_with_complete_reviews() {
    let reviews = include_str!("../../unsafe-reviews.toml");

    let findings = unsafe_review_findings(&[], reviews).unwrap();

    assert!(
        findings.iter().all(|finding| matches!(
            finding,
            UnsafeReviewFinding::ReviewOfNoDependencyWithUnsafe { .. }
        )),
        "{findings:?}"
    );
}
