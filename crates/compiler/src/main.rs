use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use debar_clamav_signatures::LineOutcome;
use debar_compiler::compile_to_files;
use debar_platform::command_line::arguments;

const USAGE: &str = "usage: debar-compiler --databases DIRECTORY --image FILE --account FILE\n\
  Compiles every database in DIRECTORY into the image FILE, and writes an account of every\n\
  database line (compiled, left out, or not yet compiled) to the account FILE as JSON.";

struct Request {
    databases: PathBuf,
    image: PathBuf,
    account: PathBuf,
}

fn main() -> ExitCode {
    let Some(request) = request_from(arguments()) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match compile_to_files(&request.databases, &request.image, &request.account) {
        Ok(compilation) => {
            let compiled: usize = compilation
                .account
                .files
                .iter()
                .map(|file| file.count(LineOutcome::Compiled))
                .sum();
            eprintln!(
                "debar-compiler: {compiled} signatures compiled into {} ({} bytes); account in {}",
                request.image.display(),
                compilation.image.len(),
                request.account.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("debar-compiler: {error}");
            ExitCode::FAILURE
        }
    }
}

fn request_from(arguments: Vec<OsString>) -> Option<Request> {
    let mut databases = None;
    let mut image = None;
    let mut account = None;
    let mut arguments = arguments.into_iter();
    while let Some(flag) = arguments.next() {
        let value = PathBuf::from(arguments.next()?);
        let slot = match flag.to_str()? {
            "--databases" => &mut databases,
            "--image" => &mut image,
            "--account" => &mut account,
            _ => return None,
        };
        if slot.replace(value).is_some() {
            return None;
        }
    }
    Some(Request {
        databases: databases?,
        image: image?,
        account: account?,
    })
}
