use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use debar_interfaces::{
    DEFAULT_LARGEST_OBJECT_FOR_REGULAR_EXPRESSIONS, ScanSettings, UnwantedCategories, measure_scan,
    write_comparison_report,
};
use debar_platform::command_line::arguments;

const USAGE: &str = "usage: debar comparison-report --image IMAGE [LIMIT] [UNWANTED] INPUT REPORT\n\
  Scans INPUT as one top-level object with the compiled IMAGE and writes REPORT in the\n\
  comparison harness's report schema, version 1. It is for comparison runs, not for users.\n\
  UNWANTED is --potentially-unwanted, which also reports potentially unwanted signatures,\n\
  optionally followed by --unwanted-category-containing TEXT or\n\
  --unwanted-category-not-containing TEXT to keep only those whose category does or does not\n\
  contain TEXT. LIMIT is --largest-regular-expression-object BYTES: regular expressions are\n\
  not matched in an object larger than BYTES (default 104857600; 0 matches them in any object).\n\
       debar measure-scan --image IMAGE PATH...\n\
  Scans every regular file under each PATH as a top-level object and prints how many bytes\n\
  were scanned and how fast, as JSON. It is for measuring throughput, not for users.";

enum Unwanted {
    Off,
    Every,
    Containing(String),
    NotContaining(String),
}

impl Unwanted {
    fn settings(&self, largest_object_for_regular_expressions: Option<u64>) -> ScanSettings<'_> {
        let (potentially_unwanted, unwanted_categories) = match self {
            Self::Off => (false, UnwantedCategories::Every),
            Self::Every => (true, UnwantedCategories::Every),
            Self::Containing(text) => (true, UnwantedCategories::Containing(text)),
            Self::NotContaining(text) => (true, UnwantedCategories::NotContaining(text)),
        };
        ScanSettings {
            potentially_unwanted,
            unwanted_categories,
            largest_object_for_regular_expressions,
        }
    }
}

enum Request {
    ComparisonReport {
        image: PathBuf,
        largest_object_for_regular_expressions: Option<u64>,
        unwanted: Unwanted,
        input: PathBuf,
        report: PathBuf,
    },
    MeasureScan {
        image: PathBuf,
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
            largest_object_for_regular_expressions,
            unwanted,
            input,
            report,
        } => write_comparison_report(
            &image,
            &input,
            &report,
            unwanted.settings(largest_object_for_regular_expressions),
        )
        .map_err(|error| error.to_string()),
        Request::MeasureScan { image, inputs } => measure_scan(&image, &inputs)
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
            let (largest_object_for_regular_expressions, rest) = regular_expression_limit(rest)?;
            Some(Request::ComparisonReport {
                image: PathBuf::from(image),
                largest_object_for_regular_expressions,
                unwanted: unwanted_from(rest)?,
                input: PathBuf::from(input),
                report: PathBuf::from(report),
            })
        }
        [command, flag, image, inputs @ ..]
            if command == "measure-scan" && flag == "--image" && !inputs.is_empty() =>
        {
            Some(Request::MeasureScan {
                image: PathBuf::from(image),
                inputs: inputs.iter().map(PathBuf::from).collect(),
            })
        }
        _ => None,
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
