use std::fmt;

const SPECIFICATIONS_DIRECTORY: &str = "specs/";
const SPECIFICATION_SUFFIX: &str = ".lazyspec.md";
const MARRIED_TEST_DIRECTORY: &str = "tests";
const MARRIED_TEST_EXTENSION: &str = ".rs";
const MARRIAGE_WORD: &str = "lazyspec";
const REQUIREMENT_HEADING: &str = "## ";
const UNTESTABLE_MARK: &str = "<!-- no-test:";
const COMMENT_END: &str = "-->";
const CODE_FENCES: [&str; 2] = ["```", "~~~"];

pub struct TextFile {
    pub path: String,
    pub text: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RequirementFinding {
    NoMarriedTest {
        specification: String,
    },
    SeveralMarriedTests {
        specification: String,
        tests: Vec<String>,
    },
    Unmarried {
        specification: String,
        test: String,
        requirement: String,
    },
    UntestableWithoutReason {
        specification: String,
        requirement: String,
    },
}

impl fmt::Display for RequirementFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMarriedTest { specification } => write!(
                formatter,
                "{specification} has requirements but no married test file, `<crate>/tests/<stem>_lazyspec.rs` (Constitution §7)"
            ),
            Self::SeveralMarriedTests {
                specification,
                tests,
            } => write!(
                formatter,
                "{specification} is married to more than one test file: {}; one specification, one test file",
                tests.join(", ")
            ),
            Self::Unmarried {
                specification,
                test,
                requirement,
            } => write!(
                formatter,
                "\"{requirement}\" in {specification} does not appear word for word in {test} (Constitution §7)"
            ),
            Self::UntestableWithoutReason {
                specification,
                requirement,
            } => write!(
                formatter,
                "\"{requirement}\" in {specification} is marked no-test without a reason"
            ),
        }
    }
}

#[must_use]
pub fn is_specification(path: &str) -> bool {
    path.strip_prefix(SPECIFICATIONS_DIRECTORY)
        .and_then(|name| name.strip_suffix(SPECIFICATION_SUFFIX))
        .is_some_and(|stem| !stem.is_empty() && !stem.contains('/'))
}

#[must_use]
pub fn is_married_test(path: &str) -> bool {
    let mut components = path.rsplit('/');
    let file_name = components.next().unwrap_or_default();
    let directory = components.next().unwrap_or_default();
    directory == MARRIED_TEST_DIRECTORY
        && file_name
            .strip_suffix(MARRIED_TEST_EXTENSION)
            .is_some_and(|stem| name_token(stem).ends_with(MARRIAGE_WORD))
}

#[must_use]
pub fn requirement_findings(
    specifications: &[TextFile],
    married_tests: &[TextFile],
) -> Vec<RequirementFinding> {
    specifications
        .iter()
        .flat_map(|specification| specification_findings(specification, married_tests))
        .collect()
}

enum Requirement<'a> {
    Testable(&'a str),
    Untestable { name: &'a str, reason: &'a str },
}

fn specification_findings(
    specification: &TextFile,
    married_tests: &[TextFile],
) -> Vec<RequirementFinding> {
    let requirements = requirements_in(&specification.text);
    let mut findings: Vec<RequirementFinding> = requirements
        .iter()
        .filter_map(|requirement| match requirement {
            Requirement::Untestable { name, reason: "" } => {
                Some(RequirementFinding::UntestableWithoutReason {
                    specification: specification.path.clone(),
                    requirement: (*name).to_owned(),
                })
            }
            Requirement::Untestable { .. } | Requirement::Testable(_) => None,
        })
        .collect();
    let testable: Vec<&str> = requirements
        .iter()
        .filter_map(|requirement| match requirement {
            Requirement::Testable(name) => Some(*name),
            Requirement::Untestable { .. } => None,
        })
        .collect();
    if testable.is_empty() {
        return findings;
    }
    let marriage = married_token(&specification.path);
    let partners: Vec<&TextFile> = married_tests
        .iter()
        .filter(|test| Some(test_token(&test.path)) == marriage)
        .collect();
    match partners.as_slice() {
        [] => findings.push(RequirementFinding::NoMarriedTest {
            specification: specification.path.clone(),
        }),
        [test] => findings.extend(
            testable
                .into_iter()
                .filter(|requirement| !test.text.contains(requirement))
                .map(|requirement| RequirementFinding::Unmarried {
                    specification: specification.path.clone(),
                    test: test.path.clone(),
                    requirement: requirement.to_owned(),
                }),
        ),
        several => findings.push(RequirementFinding::SeveralMarriedTests {
            specification: specification.path.clone(),
            tests: several.iter().map(|test| test.path.clone()).collect(),
        }),
    }
    findings
}

fn requirements_in(specification: &str) -> Vec<Requirement<'_>> {
    let mut inside_code_block = false;
    let mut requirements = Vec::new();
    for line in specification.lines() {
        if CODE_FENCES
            .iter()
            .any(|fence| line.trim_start().starts_with(fence))
        {
            inside_code_block = !inside_code_block;
            continue;
        }
        if inside_code_block {
            continue;
        }
        if let Some(heading) = line.strip_prefix(REQUIREMENT_HEADING) {
            requirements.push(requirement_from_heading(heading));
        }
    }
    requirements
}

fn requirement_from_heading(heading: &str) -> Requirement<'_> {
    match heading.split_once(UNTESTABLE_MARK) {
        Some((name, marked)) => Requirement::Untestable {
            name: name.trim(),
            reason: marked
                .split_once(COMMENT_END)
                .map_or(marked, |(reason, _)| reason)
                .trim(),
        },
        None => Requirement::Testable(heading.trim()),
    }
}

fn married_token(specification_path: &str) -> Option<String> {
    let stem = specification_path
        .strip_prefix(SPECIFICATIONS_DIRECTORY)?
        .strip_suffix(SPECIFICATION_SUFFIX)?;
    Some(name_token(stem) + MARRIAGE_WORD)
}

fn test_token(test_path: &str) -> String {
    let file_name = test_path.rsplit('/').next().unwrap_or_default();
    name_token(
        file_name
            .strip_suffix(MARRIED_TEST_EXTENSION)
            .unwrap_or(file_name),
    )
}

fn name_token(name: &str) -> String {
    name.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect()
}
