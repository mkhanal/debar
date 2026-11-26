use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use debar_interfaces::{measure_scan, write_comparison_report};
use debar_platform::command_line::arguments;

const USAGE: &str = "usage: debar comparison-report --image IMAGE INPUT REPORT\n\
  Scans INPUT as one top-level object with the compiled IMAGE and writes REPORT in the\n\
  comparison harness's report schema, version 1. It is for comparison runs, not for users.\n\
       debar measure-scan --image IMAGE PATH...\n\
  Scans every regular file under each PATH as a top-level object and prints how many bytes\n\
  were scanned and how fast, as JSON. It is for measuring throughput, not for users.";

enum Request {
    ComparisonReport {
        image: PathBuf,
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
            input,
            report,
        } => write_comparison_report(&image, &input, &report).map_err(|error| error.to_string()),
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
        [command, flag, image, input, report]
            if command == "comparison-report" && flag == "--image" =>
        {
            Some(Request::ComparisonReport {
                image: PathBuf::from(image),
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
