#![forbid(unsafe_code)]

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use xtask::borrowed_pieces::release_blockers;
use xtask::exact_versions::loose_requirements;
use xtask::layers::{deny_wrapper_findings, layer_findings};
use xtask::lint_tables::{
    MemberManifest, clippy_configurations_outside_the_root, lint_table_findings,
};
use xtask::reference_mentions::mentions;
use xtask::requirements::{TextFile, is_married_test, is_specification, requirement_findings};
use xtask::task_outcome::{TaskError, TaskReport};
use xtask::unsafe_code::{
    UNSAFE_BLOCKS, crate_roots, roots_without_the_promise, unsafe_inventory_findings, unsafe_uses,
};
use xtask::unsafe_reviews::{
    DependencyWithUnsafe, REVIEW_LIST, SOURCE_DIRECTORIES_NOT_BUILT_INTO_DEBAR, registry_packages,
    unsafe_review_findings,
};
use xtask::workspace::Workspace;
use xtask::{autofix, claiming};

const NIGHTLY_TOOLCHAIN_FILE: &str = "rust-toolchain-nightly";
const ROADMAP: &str = "architecture-overview/ROADMAP.md";
const WORKSPACE_MANIFEST: &str = "Cargo.toml";
const DENY_CONFIGURATION: &str = "deny.toml";
const WORKFLOWS: &str = ".github/workflows";
const MIRI_CRATES: [&str; 1] = ["debar-platform"];
const MIRI_FLAGS_FOR_THE_FILESYSTEM_GATE: &str = "-Zmiri-disable-isolation";
const FUZZ_DIRECTORY: &str = "fuzz";
const FUZZ_SECONDS_PER_TARGET: u32 = 60;
const RELEASE_TARGETS: [&str; 2] = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"];

#[derive(Clone, Copy)]
enum Check {
    Format,
    Lints,
    Tests,
    Dependencies,
    LintTables,
    Layers,
    ReferenceMentions,
    Requirements,
    UnsafeCode,
    Workflows,
}

const EVERY_CHANGE: [Check; 10] = [
    Check::Format,
    Check::Lints,
    Check::Tests,
    Check::Dependencies,
    Check::LintTables,
    Check::Layers,
    Check::ReferenceMentions,
    Check::Requirements,
    Check::UnsafeCode,
    Check::Workflows,
];

impl Check {
    fn name(self) -> &'static str {
        match self {
            Self::Format => "format",
            Self::Lints => "lints",
            Self::Tests => "tests",
            Self::Dependencies => "dependencies",
            Self::LintTables => "lint-tables",
            Self::Layers => "layers",
            Self::ReferenceMentions => "reference-mentions",
            Self::Requirements => "requirements",
            Self::UnsafeCode => "unsafe-code",
            Self::Workflows => "workflows",
        }
    }

    fn run(self, root: &Path) -> Result<(), Failure> {
        match self {
            Self::Format => run_command(root, "cargo", &["fmt", "--all", "--check"]),
            Self::Lints => run_command(
                root,
                "cargo",
                &[
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--locked",
                    "--",
                    "-D",
                    "warnings",
                ],
            ),
            Self::Tests => run_command(
                root,
                "cargo",
                &["nextest", "run", "--workspace", "--locked"],
            ),
            Self::Dependencies => check_dependencies(root),
            Self::LintTables => check_lint_tables(root),
            Self::Layers => check_layers(root),
            Self::ReferenceMentions => check_reference_mentions(root),
            Self::Requirements => check_requirements(root),
            Self::UnsafeCode => check_unsafe_code(root),
            Self::Workflows => run_command(root, "zizmor", &[WORKFLOWS]),
        }
    }
}

struct Failure(String);

impl<T: Display> From<T> for Failure {
    fn from(error: T) -> Self {
        Self(error.to_string())
    }
}

type BoardTask = fn(&[String]) -> Result<TaskReport, TaskError>;

const BOARD_TASKS: [(&str, BoardTask); 8] = [
    ("claim", claiming::claim),
    ("check-claim", claiming::check_claim),
    ("classify-work", claiming::classify_work),
    (
        "record-pull-request-size",
        claiming::record_pull_request_size,
    ),
    ("ready-for-review", claiming::ready_for_review),
    ("claim-next", autofix::claim_next),
    ("hand-back", autofix::hand_back),
    ("issue-brief", autofix::issue_brief),
];

const BOARD_TASK_USAGE: &str =
    "board tasks (the issue claim workflow, .claude/skills/claim/SKILL.md):
  claim <issue>... [--branch <branch>]
  check-claim <issue>...
  classify-work <issue> [--theme <x>] [--kind <x>] [--area <x>] [--impact <x>] [--why <sentence>]
  classify-work --options
  classify-work --add-area <name> --area-description <sentence>
  record-pull-request-size
  ready-for-review
  claim-next [<issue> [--include-blocked]] | claim-next --peek
  hand-back <issue> (--body-file <comment.md> | --release-only)
  issue-brief <issue>";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let Some((task, rest)) = arguments.split_first()
        && let Some((_, run)) = BOARD_TASKS.iter().find(|(name, _)| name == task)
    {
        return run_board_task(task, *run, rest);
    }
    let outcome = repository_root().and_then(|root| match arguments.as_slice() {
        [task] if task == "check" => run_every_change_check(&root),
        [task] if task == "miri" => run_miri(&root),
        [task] if task == "fuzz" => run_fuzz_targets(&root, FUZZ_SECONDS_PER_TARGET),
        [task, seconds] if task == "fuzz" => seconds
            .parse()
            .map_err(|_| usage())
            .and_then(|seconds| run_fuzz_targets(&root, seconds)),
        [task] if task == "release-check" => check_release(&root),
        [task] => match EVERY_CHANGE.iter().find(|check| check.name() == task) {
            Some(check) => check.run(&root),
            None => Err(usage()),
        },
        _ => Err(usage()),
    });
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure(reason)) => {
            eprintln!("{reason}");
            ExitCode::FAILURE
        }
    }
}

fn run_board_task(name: &str, task: BoardTask, arguments: &[String]) -> ExitCode {
    match task(arguments) {
        Ok(report) => {
            print!("{}", report.output);
            ExitCode::from(report.exit.code())
        }
        Err(error) => {
            eprintln!("{name}: {error}");
            if let TaskError::Usage(_) = error {
                eprintln!("{BOARD_TASK_USAGE}");
            }
            ExitCode::from(error.code())
        }
    }
}

fn usage() -> Failure {
    let checks: Vec<&str> = EVERY_CHANGE.iter().map(|check| check.name()).collect();
    Failure(format!(
        "usage: cargo xtask <task>\n  check          run every check below\n  {}\n  miri           run the platform crate's tests under Miri\n  fuzz [SECONDS] run every fuzz target for SECONDS each (default {FUZZ_SECONDS_PER_TARGET})\n  release-check  fail while architecture-overview/ROADMAP.md lists a borrowed piece\n{BOARD_TASK_USAGE}",
        checks.join("\n  ")
    ))
}

fn run_every_change_check(root: &Path) -> Result<(), Failure> {
    let failed: Vec<&str> = EVERY_CHANGE
        .iter()
        .filter_map(|check| {
            eprintln!("==> {}", check.name());
            match check.run(root) {
                Ok(()) => None,
                Err(Failure(reason)) => {
                    eprintln!("{reason}");
                    Some(check.name())
                }
            }
        })
        .collect();
    if failed.is_empty() {
        eprintln!("==> every check passed");
        Ok(())
    } else {
        Err(Failure(format!("==> failed: {}", failed.join(", "))))
    }
}

fn run_miri(root: &Path) -> Result<(), Failure> {
    let nightly = read_text(root, NIGHTLY_TOOLCHAIN_FILE)?;
    let toolchain = format!("+{}", nightly.trim());
    let mut arguments = vec![toolchain.as_str(), "miri", "test", "--locked"];
    for crate_name in MIRI_CRATES {
        arguments.extend(["--package", crate_name]);
    }
    run_command_with_environment(
        root,
        "cargo",
        &arguments,
        &[("MIRIFLAGS", MIRI_FLAGS_FOR_THE_FILESYSTEM_GATE)],
    )
}

fn run_fuzz_targets(root: &Path, seconds: u32) -> Result<(), Failure> {
    let nightly = read_text(root, NIGHTLY_TOOLCHAIN_FILE)?;
    let toolchain = format!("+{}", nightly.trim());
    let fuzz = root.join(FUZZ_DIRECTORY);
    run_command(
        &fuzz,
        "cargo",
        &[&toolchain, "metadata", "--locked", "--format-version", "1"],
    )
    .map_err(|Failure(reason)| {
        Failure(format!(
            "{FUZZ_DIRECTORY}/Cargo.lock is out of date: {reason}"
        ))
    })?;
    let listing = command_output(&fuzz, "cargo", &[&toolchain, "fuzz", "list"])?;
    let time_limit = format!("-max_total_time={seconds}");
    let failed: Vec<&str> = listing
        .lines()
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .filter(|target| {
            eprintln!("==> fuzz {target} for {seconds} s");
            run_command(
                &fuzz,
                "cargo",
                &[&toolchain, "fuzz", "run", target, "--", &time_limit],
            )
            .is_err()
        })
        .collect();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(Failure(format!(
            "fuzz targets failed: {}",
            failed.join(", ")
        )))
    }
}

fn check_release(root: &Path) -> Result<(), Failure> {
    release_blockers(&read_text(root, ROADMAP)?)?;
    Ok(())
}

fn check_dependencies(root: &Path) -> Result<(), Failure> {
    let denied = run_command(
        root,
        "cargo",
        &["deny", "--locked", "check", "--allow", "unused-wrapper"],
    );
    let exact = report_findings(&loose_requirements(&workspace(root)?));
    let reviewed = check_unsafe_reviews(root);
    every_failure([denied, exact, reviewed])
}

fn check_unsafe_reviews(root: &Path) -> Result<(), Failure> {
    let findings = unsafe_review_findings(
        &dependencies_with_unsafe(root)?,
        &read_text(root, REVIEW_LIST)?,
    )?;
    report_findings(&findings)
}

fn dependencies_with_unsafe(root: &Path) -> Result<Vec<DependencyWithUnsafe>, Failure> {
    let mut packages = Vec::new();
    for directory in [root.to_path_buf(), root.join(FUZZ_DIRECTORY)] {
        for target in RELEASE_TARGETS {
            let metadata = command_output(
                &directory,
                "cargo",
                &[
                    "metadata",
                    "--format-version",
                    "1",
                    "--locked",
                    "--filter-platform",
                    target,
                ],
            )?;
            packages.extend(registry_packages(&metadata)?);
        }
    }
    packages.sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    packages.dedup();
    let mut found = Vec::new();
    for package in packages {
        let uses = unsafe_uses_under(Path::new(&package.directory), true)?;
        if uses > 0 {
            found.push(DependencyWithUnsafe {
                name: package.name,
                version: package.version,
                uses,
            });
        }
    }
    Ok(found)
}

fn unsafe_uses_under(directory: &Path, is_package_root: bool) -> Result<usize, Failure> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| Failure(format!("cannot list {}: {error}", directory.display())))?;
    let mut uses = 0usize;
    for entry in entries {
        let entry = entry
            .map_err(|error| Failure(format!("cannot list {}: {error}", directory.display())))?;
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|error| Failure(format!("cannot read {}: {error}", path.display())))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if kind.is_dir() {
            if !(is_package_root
                && SOURCE_DIRECTORIES_NOT_BUILT_INTO_DEBAR.contains(&name.as_str()))
            {
                uses = uses.saturating_add(unsafe_uses_under(&path, false)?);
            }
        } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "rs") {
            let bytes = std::fs::read(&path)
                .map_err(|error| Failure(format!("cannot read {}: {error}", path.display())))?;
            uses = uses.saturating_add(unsafe_uses(&String::from_utf8_lossy(&bytes)).len());
        }
    }
    Ok(uses)
}

fn every_failure<const N: usize>(outcomes: [Result<(), Failure>; N]) -> Result<(), Failure> {
    let reasons: Vec<String> = outcomes
        .into_iter()
        .filter_map(Result::err)
        .map(|Failure(reason)| reason)
        .collect();
    if reasons.is_empty() {
        Ok(())
    } else {
        Err(Failure(reasons.join("\n")))
    }
}

fn check_layers(root: &Path) -> Result<(), Failure> {
    let mut findings = layer_findings(&workspace(root)?);
    findings.extend(deny_wrapper_findings(&read_text(
        root,
        DENY_CONFIGURATION,
    )?)?);
    report_findings(&findings)
}

fn check_lint_tables(root: &Path) -> Result<(), Failure> {
    let members = workspace(root)?
        .members
        .into_iter()
        .map(|member| {
            Ok(MemberManifest {
                text: read_file(Path::new(&member.manifest_path))?,
                name: member.name,
            })
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let mut findings = lint_table_findings(&read_text(root, WORKSPACE_MANIFEST)?, &members)?;
    findings.extend(clippy_configurations_outside_the_root(&tracked_paths(
        root,
    )?));
    report_findings(&findings)
}

fn check_reference_mentions(root: &Path) -> Result<(), Failure> {
    let mut found = Vec::new();
    for path in tracked_paths(root)? {
        let content = std::fs::read(root.join(&path))
            .map_err(|error| Failure(format!("cannot read {path}: {error}")))?;
        found.extend(mentions(&path, &content));
    }
    report_findings(&found)
}

fn check_requirements(root: &Path) -> Result<(), Failure> {
    let tracked = tracked_paths(root)?;
    let read_all = |wanted: fn(&str) -> bool| {
        tracked
            .iter()
            .filter(|path| wanted(path))
            .map(|path| {
                Ok(TextFile {
                    text: read_text(root, path)?,
                    path: path.clone(),
                })
            })
            .collect::<Result<Vec<_>, Failure>>()
    };
    let specifications = read_all(is_specification)?;
    let married_tests = read_all(is_married_test)?;
    report_findings(&requirement_findings(&specifications, &married_tests))
}

fn check_unsafe_code(root: &Path) -> Result<(), Failure> {
    let prefix = format!("{}/", root.display());
    let mut roots = crate_roots(&metadata_without_dependencies(root)?, &prefix)?;
    roots.extend(crate_roots(
        &metadata_without_dependencies(&root.join(FUZZ_DIRECTORY))?,
        &prefix,
    )?);
    let roots = roots
        .into_iter()
        .map(|crate_root| {
            let source = TextFile {
                text: read_text(root, &crate_root.path)?,
                path: crate_root.path.clone(),
            };
            Ok((crate_root, source))
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let sources = tracked_paths(root)?
        .into_iter()
        .filter(|path| {
            Path::new(path)
                .extension()
                .is_some_and(|extension| extension == "rs")
        })
        .map(|path| {
            Ok(TextFile {
                text: read_text(root, &path)?,
                path,
            })
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let mut findings = roots_without_the_promise(&roots);
    findings.extend(unsafe_inventory_findings(&sources, &UNSAFE_BLOCKS));
    report_findings(&findings)
}

fn report_findings<T: Display>(findings: &[T]) -> Result<(), Failure> {
    if findings.is_empty() {
        return Ok(());
    }
    let lines: Vec<String> = findings.iter().map(ToString::to_string).collect();
    Err(Failure(lines.join("\n")))
}

fn workspace(root: &Path) -> Result<Workspace, Failure> {
    Ok(Workspace::from_cargo_metadata(
        &metadata_without_dependencies(root)?,
    )?)
}

fn metadata_without_dependencies(directory: &Path) -> Result<String, Failure> {
    command_output(
        directory,
        "cargo",
        &["metadata", "--format-version", "1", "--no-deps", "--locked"],
    )
}

fn tracked_paths(root: &Path) -> Result<Vec<String>, Failure> {
    let listing = command_output(root, "git", &["ls-files", "-z"])?;
    Ok(listing
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect())
}

fn read_text(root: &Path, relative: &str) -> Result<String, Failure> {
    read_file(&root.join(relative))
}

fn read_file(path: &Path) -> Result<String, Failure> {
    std::fs::read_to_string(path)
        .map_err(|error| Failure(format!("cannot read {}: {error}", path.display())))
}

fn run_command(root: &Path, program: &str, arguments: &[&str]) -> Result<(), Failure> {
    run_command_with_environment(root, program, arguments, &[])
}

fn run_command_with_environment(
    root: &Path,
    program: &str,
    arguments: &[&str],
    environment: &[(&str, &str)],
) -> Result<(), Failure> {
    let status = Command::new(program)
        .args(arguments)
        .envs(environment.iter().copied())
        .current_dir(root)
        .status()
        .map_err(|error| Failure(format!("cannot run {program}: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure(format!(
            "`{program} {}` failed: {status}",
            arguments.join(" ")
        )))
    }
}

fn command_output(root: &Path, program: &str, arguments: &[&str]) -> Result<String, Failure> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(root)
        .output()
        .map_err(|error| Failure(format!("cannot run {program}: {error}")))?;
    if !output.status.success() {
        return Err(Failure(format!(
            "`{program} {}` failed: {}\n{}",
            arguments.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    String::from_utf8(output.stdout).map_err(|_| {
        Failure(format!(
            "`{program} {}` printed text that is not UTF-8",
            arguments.join(" ")
        ))
    })
}

fn repository_root() -> Result<PathBuf, Failure> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| Failure("the xtask crate has no parent directory".to_owned()))
}
