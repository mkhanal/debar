#![forbid(unsafe_code)]

use xtask::requirements::{
    RequirementFinding, TextFile, is_married_test, is_specification, requirement_findings,
};

fn file(path: &str, text: &str) -> TextFile {
    TextFile {
        path: path.to_owned(),
        text: text.to_owned(),
    }
}

const SCANNING_SPECIFICATION: &str = "\
# Scanning

## A Clean File Has No Detections

- The verdict is clean.

## The Verdict Is The Same On Every Run
";

#[test]
fn specifications_are_the_lazyspec_files_directly_in_specs() {
    assert!(is_specification("specs/scanning.lazyspec.md"));
    assert!(is_specification("specs/scan-limits.lazyspec.md"));
    assert!(!is_specification("specs/drafts/scanning.lazyspec.md"));
    assert!(!is_specification("specs/scanning.md"));
    assert!(!is_specification("docs/scanning.lazyspec.md"));
}

#[test]
fn married_tests_are_rust_test_files_naming_lazyspec() {
    assert!(is_married_test("crates/scan/tests/scanning_lazyspec.rs"));
    assert!(is_married_test("crates/scan/tests/scan_limits_lazyspec.rs"));
    assert!(!is_married_test("crates/scan/tests/scanning.rs"));
    assert!(!is_married_test("crates/scan/src/scanning_lazyspec.rs"));
    assert!(!is_married_test("crates/scan/tests/scanning_lazyspec.md"));
}

#[test]
fn a_requirement_repeated_word_for_word_in_its_married_test_is_accepted() {
    let specifications = [file("specs/scanning.lazyspec.md", SCANNING_SPECIFICATION)];
    let tests = [file(
        "crates/scan/tests/scanning_lazyspec.rs",
        r#"
#[test]
fn a_clean_file_has_no_detections() {
    requirement("A Clean File Has No Detections");
}

#[test]
fn the_verdict_is_the_same_on_every_run() {
    requirement("The Verdict Is The Same On Every Run");
}
"#,
    )];

    assert_eq!(requirement_findings(&specifications, &tests), vec![]);
}

#[test]
fn a_requirement_missing_from_its_married_test_is_reported() {
    let specifications = [file("specs/scanning.lazyspec.md", SCANNING_SPECIFICATION)];
    let tests = [file(
        "crates/scan/tests/scanning_lazyspec.rs",
        r#"requirement("A Clean File Has No Detections");"#,
    )];

    assert_eq!(
        requirement_findings(&specifications, &tests),
        vec![RequirementFinding::Unmarried {
            specification: "specs/scanning.lazyspec.md".to_owned(),
            test: "crates/scan/tests/scanning_lazyspec.rs".to_owned(),
            requirement: "The Verdict Is The Same On Every Run".to_owned(),
        }]
    );
}

#[test]
fn a_requirement_repeated_with_different_words_is_reported() {
    let specifications = [file(
        "specs/scanning.lazyspec.md",
        "## A Clean File Has No Detections\n",
    )];
    let tests = [file(
        "crates/scan/tests/scanning_lazyspec.rs",
        "fn a_clean_file_has_no_detections() {}",
    )];

    assert_eq!(requirement_findings(&specifications, &tests).len(), 1);
}

#[test]
fn a_specification_without_a_married_test_is_reported() {
    let specifications = [file("specs/scanning.lazyspec.md", SCANNING_SPECIFICATION)];
    let tests = [file("crates/scan/tests/limits_lazyspec.rs", "")];

    assert_eq!(
        requirement_findings(&specifications, &tests),
        vec![RequirementFinding::NoMarriedTest {
            specification: "specs/scanning.lazyspec.md".to_owned(),
        }]
    );
}

#[test]
fn a_specification_married_to_two_test_files_is_reported() {
    let specifications = [file("specs/scanning.lazyspec.md", SCANNING_SPECIFICATION)];
    let both = "A Clean File Has No Detections The Verdict Is The Same On Every Run";
    let tests = [
        file("crates/scan/tests/scanning_lazyspec.rs", both),
        file("crates/interfaces/tests/scanning_lazyspec.rs", both),
    ];

    assert_eq!(
        requirement_findings(&specifications, &tests),
        vec![RequirementFinding::SeveralMarriedTests {
            specification: "specs/scanning.lazyspec.md".to_owned(),
            tests: vec![
                "crates/scan/tests/scanning_lazyspec.rs".to_owned(),
                "crates/interfaces/tests/scanning_lazyspec.rs".to_owned(),
            ],
        }]
    );
}

#[test]
fn a_hyphenated_specification_marries_the_test_joined_with_underscores() {
    let specifications = [file(
        "specs/scan-limits.lazyspec.md",
        "## Depth Is Bounded\n",
    )];
    let tests = [file(
        "crates/scan/tests/scan_limits_lazyspec.rs",
        r#"requirement("Depth Is Bounded");"#,
    )];

    assert_eq!(requirement_findings(&specifications, &tests), vec![]);
}

#[test]
fn a_requirement_marked_untestable_with_a_reason_needs_no_test() {
    let specifications = [file(
        "specs/scanning.lazyspec.md",
        "## Signatures Load Unchanged <!-- no-test: the publisher's servers are outside the project's reach -->\n",
    )];

    assert_eq!(requirement_findings(&specifications, &[]), vec![]);
}

#[test]
fn a_requirement_marked_untestable_without_a_reason_is_reported() {
    let specifications = [file(
        "specs/scanning.lazyspec.md",
        "## Signatures Load Unchanged <!-- no-test: -->\n",
    )];

    assert_eq!(
        requirement_findings(&specifications, &[]),
        vec![RequirementFinding::UntestableWithoutReason {
            specification: "specs/scanning.lazyspec.md".to_owned(),
            requirement: "Signatures Load Unchanged".to_owned(),
        }]
    );
}

#[test]
fn a_heading_inside_a_code_block_is_not_a_requirement() {
    let specifications = [file(
        "specs/scanning.lazyspec.md",
        "```\n## Not A Requirement\n```\n",
    )];

    assert_eq!(requirement_findings(&specifications, &[]), vec![]);
}

#[test]
fn deeper_headings_are_not_requirements() {
    let specifications = [file(
        "specs/scanning.lazyspec.md",
        "# Scanning\n### Detail\n",
    )];

    assert_eq!(requirement_findings(&specifications, &[]), vec![]);
}
