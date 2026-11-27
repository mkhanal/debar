#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use debar_interfaces::{measure_scan, write_comparison_report};
use debar_matching::UnwantedCategories;
use debar_platform::command_line::arguments;
use debar_platform::threads::ThreadCount;
use debar_scan::{
    DEFAULT_LARGEST_OBJECT_FOR_REGULAR_EXPRESSIONS, Facts, Limits, Matching, ObjectSteps,
    ScanSettings, ScanTime,
};

const DEFAULT_RECURSION_LEVELS: u32 = 17;
const MOST_RECURSION_LEVELS: u32 = 100;

const USAGE: &str = "usage: debar comparison-report --image IMAGE [--every-match] [--heuristic-precedence] [LIMIT] [SCAN OPTION]... [UNWANTED] INPUT REPORT\n\
  Scans INPUT as one top-level object with the compiled IMAGE and writes REPORT in the\n\
  comparison harness's report schema, version 1. It is for comparison runs, not for users.\n\
  The scan stops at its first strong detection unless --every-match is given.\n\
  --heuristic-precedence records a potentially unwanted detection as a strong one.\n\
  UNWANTED is --potentially-unwanted, which also reports potentially unwanted signatures,\n\
  optionally followed by --unwanted-category-containing TEXT or\n\
  --unwanted-category-not-containing TEXT to keep only those whose category does or does not\n\
  contain TEXT. LIMIT is --largest-regular-expression-object BYTES: regular expressions are\n\
  not matched in an object larger than BYTES (default 104857600; 0 matches them in any object).\n\
  SCAN OPTION is --raw-only, which types each object and matches it once against the\n\
  signatures for any kind, with no other pass, no object found inside it and no limit alert,\n\
  or a limit: --max-scan-time MILLISECONDS (default 120000, counted as work done, never on a\n\
  clock), --max-files COUNT, --max-scan-size BYTES, --max-file-size BYTES (0 switches each off),\n\
  --max-recursion LEVELS (0 is the default of 17, at most 100), or --alert-exceeds-max, which\n\
  reports the first limit reached as a potentially unwanted detection.\n\
       debar measure-scan --image IMAGE [--threads COUNT] PATH...\n\
  Scans every regular file under each PATH as a top-level object, COUNT files at once (default\n\
  1), and prints how many bytes were scanned, how many were read and read again, how fast, how\n\
  much of the scan time limit's work they took, and the verdict and detections of every file\n\
  with any, as JSON. It is for measuring throughput, not for users.";

enum Unwanted {
    Off,
    Every,
    Containing(String),
    NotContaining(String),
}

impl Unwanted {
    fn settings(
        &self,
        matching: Matching,
        heuristic_precedence: bool,
        largest_object_for_regular_expressions: Option<u64>,
        scan_limits: ScanLimits,
    ) -> ScanSettings<'_> {
        let (potentially_unwanted, unwanted_categories) = match self {
            Self::Off => (false, UnwantedCategories::Every),
            Self::Every => (true, UnwantedCategories::Every),
            Self::Containing(text) => (true, UnwantedCategories::Containing(text)),
            Self::NotContaining(text) => (true, UnwantedCategories::NotContaining(text)),
        };
        ScanSettings {
            matching,
            heuristic_precedence,
            potentially_unwanted,
            unwanted_categories,
            largest_object_for_regular_expressions,
            limits: scan_limits.limits,
            alert_on_limits: scan_limits.alert_on_limits,
            facts: Facts::NotGathered,
            object_steps: scan_limits.object_steps,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct ScanLimits {
    limits: Limits,
    alert_on_limits: bool,
    object_steps: ObjectSteps,
}

enum Request {
    ComparisonReport {
        image: PathBuf,
        matching: Matching,
        heuristic_precedence: bool,
        largest_object_for_regular_expressions: Option<u64>,
        scan_limits: ScanLimits,
        unwanted: Unwanted,
        input: PathBuf,
        report: PathBuf,
    },
    MeasureScan {
        image: PathBuf,
        threads: ThreadCount,
        inputs: Vec<PathBuf>,
    },
}

fn main() -> ExitCode {
    let arguments = arguments();
    let Some(request) = request_from(&arguments) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let outcome = match request {
        Request::ComparisonReport {
            image,
            matching,
            heuristic_precedence,
            largest_object_for_regular_expressions,
            scan_limits,
            unwanted,
            input,
            report,
        } => write_comparison_report(
            &image,
            &input,
            &report,
            &unwanted.settings(
                matching,
                heuristic_precedence,
                largest_object_for_regular_expressions,
                scan_limits,
            ),
        )
        .map_err(|error| error.to_string()),
        Request::MeasureScan {
            image,
            threads,
            inputs,
        } => measure_scan(&image, threads, &inputs)
            .map(|measurement| println!("{measurement}"))
            .map_err(|error| error.to_string()),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("debar: {error}");
            ExitCode::FAILURE
        }
    }
}

fn request_from(arguments: &[OsString]) -> Option<Request> {
    match arguments {
        [command, flag, image, rest @ .., input, report]
            if command == "comparison-report" && flag == "--image" =>
        {
            let (matching, rest) = matching_from(rest);
            let (heuristic_precedence, rest) = heuristic_precedence_from(rest);
            let (largest_object_for_regular_expressions, rest) = regular_expression_limit(rest)?;
            let (scan_limits, rest) = scan_limits_from(rest)?;
            Some(Request::ComparisonReport {
                image: PathBuf::from(image),
                matching,
                heuristic_precedence,
                largest_object_for_regular_expressions,
                scan_limits,
                unwanted: unwanted_from(rest)?,
                input: PathBuf::from(input),
                report: PathBuf::from(report),
            })
        }
        [command, flag, image, rest @ ..] if command == "measure-scan" && flag == "--image" => {
            let (threads, inputs) = threads_from(rest)?;
            (!inputs.is_empty()).then(|| Request::MeasureScan {
                image: PathBuf::from(image),
                threads,
                inputs: inputs.iter().map(PathBuf::from).collect(),
            })
        }
        _ => None,
    }
}

fn threads_from(options: &[OsString]) -> Option<(ThreadCount, &[OsString])> {
    match options {
        [flag, count, rest @ ..] if flag == "--threads" => {
            Some((ThreadCount::new(count.to_str()?.parse().ok()?)?, rest))
        }
        _ => Some((ThreadCount::ONE, options)),
    }
}

fn matching_from(options: &[OsString]) -> (Matching, &[OsString]) {
    match options {
        [flag, rest @ ..] if flag == "--every-match" => (Matching::EveryMatch, rest),
        _ => (Matching::FirstMatch, options),
    }
}

fn heuristic_precedence_from(options: &[OsString]) -> (bool, &[OsString]) {
    match options {
        [flag, rest @ ..] if flag == "--heuristic-precedence" => (true, rest),
        _ => (false, options),
    }
}

fn regular_expression_limit(options: &[OsString]) -> Option<(Option<u64>, &[OsString])> {
    match options {
        [flag, value, rest @ ..] if flag == "--largest-regular-expression-object" => {
            let bytes: u64 = value.to_str()?.parse().ok()?;
            Some(((bytes != 0).then_some(bytes), rest))
        }
        _ => Some((
            Some(DEFAULT_LARGEST_OBJECT_FOR_REGULAR_EXPRESSIONS),
            options,
        )),
    }
}

fn scan_limits_from(mut options: &[OsString]) -> Option<(ScanLimits, &[OsString])> {
    let mut scan_limits = ScanLimits::default();
    loop {
        match options {
            [flag, rest @ ..] if flag == "--alert-exceeds-max" => {
                scan_limits.alert_on_limits = true;
                options = rest;
            }
            [flag, rest @ ..] if flag == "--raw-only" => {
                scan_limits.object_steps = ObjectSteps::RawOnly;
                options = rest;
            }
            [flag, value, rest @ ..] if flag.to_str()?.starts_with("--max-") => {
                let number: u64 = value.to_str()?.parse().ok()?;
                let limit = (number != 0).then_some(number);
                let limits = &mut scan_limits.limits;
                match flag.to_str()? {
                    "--max-scan-time" => {
                        limits.longest_scan = limit.map(ScanTime::from_milliseconds);
                    }
                    "--max-files" => limits.most_files = limit,
                    "--max-scan-size" => limits.largest_scan = limit,
                    "--max-file-size" => limits.largest_file = limit,
                    "--max-recursion" => {
                        let levels = match u32::try_from(number).ok()? {
                            0 => DEFAULT_RECURSION_LEVELS,
                            levels => levels.min(MOST_RECURSION_LEVELS),
                        };
                        limits.deepest_level = levels.saturating_sub(1);
                    }
                    _ => return None,
                }
                options = rest;
            }
            _ => return Some((scan_limits, options)),
        }
    }
}

fn unwanted_from(options: &[OsString]) -> Option<Unwanted> {
    let text = |value: &OsString| value.to_str().map(str::to_owned);
    match options {
        [] => Some(Unwanted::Off),
        [flag] if flag == "--potentially-unwanted" => Some(Unwanted::Every),
        [flag, filter, value] if flag == "--potentially-unwanted" => {
            if filter == "--unwanted-category-containing" {
                Some(Unwanted::Containing(text(value)?))
            } else if filter == "--unwanted-category-not-containing" {
                Some(Unwanted::NotContaining(text(value)?))
            } else {
                None
            }
        }
        _ => None,
    }
}
