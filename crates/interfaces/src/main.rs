use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use debar_interfaces::write_comparison_report;
use debar_platform::command_line::arguments;

const USAGE: &str = "usage: debar comparison-report --image IMAGE INPUT REPORT\n\
  Scans INPUT as one top-level object with the compiled IMAGE and writes REPORT in the\n\
  comparison harness's report schema, version 1. It is for comparison runs, not for users.";

fn main() -> ExitCode {
    let arguments = arguments();
    let Some((image, input, report)) = comparison_report_request(&arguments) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match write_comparison_report(&image, &input, &report) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("debar: {error}");
            ExitCode::FAILURE
        }
    }
}

fn comparison_report_request(arguments: &[OsString]) -> Option<(PathBuf, PathBuf, PathBuf)> {
    let [command, flag, image, input, report] = arguments else {
        return None;
    };
    (command == "comparison-report" && flag == "--image").then(|| {
        (
            PathBuf::from(image),
            PathBuf::from(input),
            PathBuf::from(report),
        )
    })
}
