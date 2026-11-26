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
use xtask::workspace::Workspace;

const NIGHTLY_TOOLCHAIN_FILE: &str = "rust-toolchain-nightly";
const ROADMAP: &str = "architecture-overview/ROADMAP.md";
const WORKSPACE_MANIFEST: &str = "Cargo.toml";
const DENY_CONFIGURATION: &str = "deny.toml";
const WORKFLOWS: &str = ".github/workflows";
const MIRI_CRATES: [&str; 1] = ["debar-platform"];
const MIRI_FLAGS_FOR_THE_FILESYSTEM_GATE: &str = "-Zmiri-disable-isolation";
const FUZZ_DIRECTORY: &str = "fuzz";
const FUZZ_SECONDS_PER_TARGET: u32 = 60;

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
    Workflows,
}

const EVERY_CHANGE: [Check; 9] = [
    Check::Format,
    Check::Lints,
    Check::Tests,
    Check::Dependencies,
    Check::LintTables,
    Check::Layers,
    Check::ReferenceMentions,
    Check::Requirements,
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

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
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

fn usage() -> Failure {
    let checks: Vec<&str> = EVERY_CHANGE.iter().map(|check| check.name()).collect();
    Failure(format!(
        "usage: cargo xtask <task>\n  check          run every check below\n  {}\n  miri           run the platform crate's tests under Miri\n  fuzz [SECONDS] run every fuzz target for SECONDS each (default {FUZZ_SECONDS_PER_TARGET})\n  release-check  fail while architecture-overview/ROADMAP.md lists a borrowed piece",
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
    every_failure([denied, exact])
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

fn report_findings<T: Display>(findings: &[T]) -> Result<(), Failure> {
    if findings.is_empty() {
        return Ok(());
    }
    let lines: Vec<String> = findings.iter().map(ToString::to_string).collect();
    Err(Failure(lines.join("\n")))
}

fn workspace(root: &Path) -> Result<Workspace, Failure> {
    let metadata = command_output(
        root,
        "cargo",
        &["metadata", "--format-version", "1", "--no-deps", "--locked"],
    )?;
    Ok(Workspace::from_cargo_metadata(&metadata)?)
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
