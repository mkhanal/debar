#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use serde_json::Value;
use sha2::{Digest as _, Sha256};

pub mod largest_file;
pub mod scan_speed;

pub const PINNED_DATABASES: [&str; 3] = ["bytecode.cvd", "daily.cvd", "main.cvd"];

#[derive(Debug)]
pub struct Failure(pub String);

impl<T: std::fmt::Display> From<T> for Failure {
    fn from(error: T) -> Self {
        Self(error.to_string())
    }
}

pub type Outcome<T> = Result<T, Failure>;

#[must_use]
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

#[must_use]
pub fn target_directory() -> PathBuf {
    workspace_root().join("target")
}

pub struct Binaries {
    pub compiler: PathBuf,
    pub debar: PathBuf,
}

pub fn release_binaries() -> Outcome<&'static Binaries> {
    static BUILT: OnceLock<Result<Binaries, String>> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let status = Command::new(option_env!("CARGO").unwrap_or("cargo"))
                .args([
                    "build",
                    "--release",
                    "--locked",
                    "--bin",
                    "debar",
                    "--bin",
                    "debar-compiler",
                ])
                .current_dir(workspace_root())
                .status()
                .map_err(|error| format!("cannot run cargo: {error}"))?;
            if !status.success() {
                return Err(format!(
                    "building Debar's release binaries failed: {status}"
                ));
            }
            let release = target_directory().join("release");
            Ok(Binaries {
                compiler: release.join("debar-compiler"),
                debar: release.join("debar"),
            })
        })
        .as_ref()
        .map_err(|reason| Failure(reason.clone()))
}

pub fn pinned_databases() -> Outcome<PathBuf> {
    let directory = target_directory().join("pinned-databases");
    for database in PINNED_DATABASES {
        if !directory.join(database).is_file() {
            return Err(Failure(format!(
                "{} has no {database}; fetch the pinned databases first with the fetch-pinned-databases script in the signature-format part's crate (see AGENTS.md, Commands)",
                directory.display()
            )));
        }
    }
    Ok(directory)
}

pub fn scratch_directory(name: &str) -> Outcome<PathBuf> {
    let directory = target_directory().join("acceptance").join(name);
    if directory.exists() {
        fs::remove_dir_all(&directory)?;
    }
    fs::create_dir_all(&directory)?;
    Ok(directory)
}

pub struct CompiledImage {
    pub image: PathBuf,
    pub account: Value,
}

pub fn compile(databases: &Path, into: &Path, name: &str) -> Outcome<CompiledImage> {
    let image = into.join(format!("{name}.image"));
    let account = into.join(format!("{name}.account.json"));
    run(Command::new(&release_binaries()?.compiler)
        .arg("--databases")
        .arg(databases)
        .arg("--image")
        .arg(&image)
        .arg("--account")
        .arg(&account))?;
    Ok(CompiledImage {
        image,
        account: serde_json::from_slice(&fs::read(&account)?)?,
    })
}

pub fn official_image() -> Outcome<CompiledImage> {
    static COMPILING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one_at_a_time = COMPILING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let compiler = fs::read(&release_binaries()?.compiler)?;
    let directory = target_directory().join("acceptance").join(format!(
        "official-{}",
        lowercase_hex(Sha256::digest(&compiler).get(..8).unwrap_or_default())
    ));
    let image = directory.join("official.image");
    let account = directory.join("official.account.json");
    if image.is_file() && account.is_file() {
        return Ok(CompiledImage {
            image,
            account: serde_json::from_slice(&fs::read(&account)?)?,
        });
    }
    fs::create_dir_all(&directory)?;
    compile(&pinned_databases()?, &directory, "official")
}

pub fn comparison_report(image: &Path, input: &Path, into: &Path) -> Outcome<Value> {
    let report = into.join("report.jsonl");
    run(Command::new(&release_binaries()?.debar)
        .arg("comparison-report")
        .arg("--image")
        .arg(image)
        .arg(input)
        .arg(&report))?;
    let text = fs::read_to_string(&report)?;
    let first = text
        .lines()
        .next()
        .ok_or_else(|| Failure("the report is empty".to_owned()))?;
    Ok(serde_json::from_str(first)?)
}

pub fn detections(report: &Value) -> Vec<String> {
    report["detections"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

pub fn run(command: &mut Command) -> Outcome<Vec<u8>> {
    let output = command.output()?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(Failure(format!(
            "{command:?} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

#[must_use]
pub fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

pub struct MemoryOnceReady {
    pub private_bytes: u64,
    pub image_resident_bytes: u64,
}

pub fn memory_once_ready(image: &Path, into: &Path) -> Outcome<MemoryOnceReady> {
    let input = into.join("input.fifo");
    run(Command::new("mkfifo").arg(&input))?;
    run(Command::new("dd")
        .arg(format!("if={}", image.display()))
        .arg("iflag=nocache")
        .arg("count=0")
        .arg("status=none"))?;
    let mut child = Command::new(&release_binaries()?.debar)
        .arg("comparison-report")
        .arg("--image")
        .arg(image)
        .arg(&input)
        .arg(into.join("report.jsonl"))
        .stderr(Stdio::piped())
        .spawn()?;
    let mut writer = File::options().write(true).open(&input)?;
    let smaps = fs::read_to_string(format!("/proc/{}/smaps", child.id()))?;
    writer.write_all(b"an object written after the scanner was ready\n")?;
    drop(writer);
    let status = child.wait()?;
    if !status.success() {
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            pipe.read_to_string(&mut stderr)?;
        }
        return Err(Failure(format!("debar failed with {status}: {stderr}")));
    }
    Ok(memory_from_smaps(&smaps, &fs::canonicalize(image)?))
}

fn memory_from_smaps(smaps: &str, image: &Path) -> MemoryOnceReady {
    let image = image.to_string_lossy();
    let mut private_bytes = 0u64;
    let mut image_resident_bytes = 0u64;
    let mut in_image = false;
    let mut anonymous = 0u64;
    let mut private_dirty = 0u64;
    let mut flush = |in_image: bool, anonymous: u64, private_dirty: u64| {
        if !in_image {
            private_bytes = private_bytes.saturating_add(anonymous.max(private_dirty));
        }
    };
    for line in smaps.lines() {
        let mut fields = line.split_whitespace();
        let Some(first) = fields.next() else { continue };
        if first.contains('-') && !first.ends_with(':') {
            flush(in_image, anonymous, private_dirty);
            in_image = line.trim_end().ends_with(&*image);
            anonymous = 0;
            private_dirty = 0;
            continue;
        }
        let kibibytes: u64 = fields
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let bytes = kibibytes.saturating_mul(1024);
        match first {
            "Anonymous:" => anonymous = bytes,
            "Private_Dirty:" => private_dirty = bytes,
            "Rss:" if in_image => image_resident_bytes = image_resident_bytes.saturating_add(bytes),
            _ => {}
        }
    }
    flush(in_image, anonymous, private_dirty);
    MemoryOnceReady {
        private_bytes,
        image_resident_bytes,
    }
}

pub fn instructions_to_scan_one_small_file(image: &Path, into: &Path) -> Outcome<u64> {
    let input = into.join("small.txt");
    fs::write(&input, b"a small clean file to scan\n")?;
    let profile = into.join("callgrind.out");
    run(Command::new("valgrind")
        .arg("--tool=callgrind")
        .arg(format!("--callgrind-out-file={}", profile.display()))
        .arg(&release_binaries()?.debar)
        .arg("comparison-report")
        .arg("--image")
        .arg(image)
        .arg(&input)
        .arg(into.join("report.jsonl")))?;
    let text = fs::read_to_string(&profile)?;
    text.lines()
        .find_map(|line| {
            line.strip_prefix("summary:")
                .or_else(|| line.strip_prefix("totals:"))
        })
        .and_then(|count| count.trim().parse().ok())
        .ok_or_else(|| Failure(format!("{} holds no instruction total", profile.display())))
}

pub struct ContainerMember {
    pub container: String,
    pub member: String,
    pub lines: usize,
    pub contents: Vec<u8>,
}

pub fn members_of_pinned_databases(databases: &Path) -> Outcome<Vec<ContainerMember>> {
    let mut members = Vec::new();
    for container in PINNED_DATABASES {
        let bytes = fs::read(databases.join(container))?;
        let payload = bytes
            .get(512..)
            .ok_or_else(|| Failure(format!("{container} is too short")))?;
        let mut tar = Vec::new();
        flate2::read::GzDecoder::new(payload).read_to_end(&mut tar)?;
        let mut offset = 0usize;
        while let Some(header) = tar.get(offset..offset.saturating_add(512)) {
            if header.iter().all(|byte| *byte == 0) {
                break;
            }
            let name_end = header
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(100)
                .min(100);
            let name =
                String::from_utf8_lossy(header.get(..name_end).unwrap_or_default()).into_owned();
            let size_text: String = header
                .get(124..136)
                .unwrap_or_default()
                .iter()
                .map(|byte| char::from(*byte))
                .filter(char::is_ascii_digit)
                .collect();
            let size = usize::from_str_radix(&size_text, 8)
                .map_err(|error| Failure(format!("{container}: {error}")))?;
            let start = offset.saturating_add(512);
            let contents = tar
                .get(start..start.saturating_add(size))
                .ok_or_else(|| Failure(format!("{container}: {name} is cut short")))?;
            members.push(ContainerMember {
                container: container.to_owned(),
                member: name,
                lines: line_count(contents),
                contents: contents.to_vec(),
            });
            offset = start.saturating_add(size.next_multiple_of(512));
        }
    }
    Ok(members)
}

fn line_count(contents: &[u8]) -> usize {
    let newlines = contents
        .split(|byte| *byte == b'\n')
        .count()
        .saturating_sub(1);
    if contents.last().is_some_and(|byte| *byte != b'\n') {
        newlines.saturating_add(1)
    } else {
        newlines
    }
}

pub fn write_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    fs::write(path, contents)
}

pub fn median_seconds_to_scan_one_small_file(image: &Path, into: &Path) -> Outcome<f64> {
    let input = into.join("small.txt");
    fs::write(&input, b"a small clean file to scan\n")?;
    let results = into.join("hyperfine.json");
    let command = format!(
        "{} comparison-report --image {} {} {}",
        release_binaries()?.debar.display(),
        image.display(),
        input.display(),
        into.join("report.jsonl").display()
    );
    run(Command::new("hyperfine")
        .args([
            "--shell=none",
            "--warmup",
            "5",
            "--runs",
            "50",
            "--style",
            "none",
            "--export-json",
        ])
        .arg(&results)
        .arg(command))?;
    let results: Value = serde_json::from_slice(&fs::read(&results)?)?;
    let mut times: Vec<f64> = results
        .pointer("/results/0/measurements")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|measurement| measurement.pointer("/time_wall_clock/value")?.as_f64())
        .collect();
    times.sort_by(f64::total_cmp);
    times
        .get(times.len() / 2)
        .copied()
        .ok_or_else(|| Failure("hyperfine recorded no runs".to_owned()))
}

pub fn peak_heap_bytes_to_scan(image: &Path, input: &Path, into: &Path) -> Outcome<u64> {
    let profile = into.join("massif.out");
    run(Command::new("valgrind")
        .arg("--tool=massif")
        .arg(format!("--massif-out-file={}", profile.display()))
        .arg(&release_binaries()?.debar)
        .arg("comparison-report")
        .arg("--image")
        .arg(image)
        .arg("--every-match")
        .arg(input)
        .arg(into.join("report.jsonl")))?;
    let text = fs::read_to_string(&profile)?;
    let mut peak = None;
    let mut useful = 0u64;
    for line in text.lines() {
        if let Some(bytes) = line.strip_prefix("mem_heap_B=") {
            useful = bytes.trim().parse()?;
        } else if let Some(bytes) = line.strip_prefix("mem_heap_extra_B=") {
            let total = useful.saturating_add(bytes.trim().parse()?);
            peak = Some(peak.map_or(total, |peak: u64| peak.max(total)));
        }
    }
    peak.ok_or_else(|| Failure(format!("{} holds no heap snapshot", profile.display())))
}

pub fn instructions_to_measure_scan(image: &Path, inputs: &[PathBuf], into: &Path) -> Outcome<u64> {
    let profile = into.join("callgrind.out");
    run(Command::new("valgrind")
        .arg("--tool=callgrind")
        .arg(format!("--callgrind-out-file={}", profile.display()))
        .arg(&release_binaries()?.debar)
        .arg("measure-scan")
        .arg("--image")
        .arg(image)
        .args(inputs))?;
    let text = fs::read_to_string(&profile)?;
    text.lines()
        .find_map(|line| {
            line.strip_prefix("summary:")
                .or_else(|| line.strip_prefix("totals:"))
        })
        .and_then(|count| count.trim().parse().ok())
        .ok_or_else(|| Failure(format!("{} holds no instruction total", profile.display())))
}

pub fn comparison_report_with(
    image: &Path,
    options: &[&str],
    input: &Path,
    into: &Path,
) -> Outcome<Value> {
    let report = into.join("report.jsonl");
    run(Command::new(&release_binaries()?.debar)
        .arg("comparison-report")
        .arg("--image")
        .arg(image)
        .args(options)
        .arg(input)
        .arg(&report))?;
    let text = fs::read_to_string(&report)?;
    let first = text
        .lines()
        .next()
        .ok_or_else(|| Failure("the report is empty".to_owned()))?;
    Ok(serde_json::from_str(first)?)
}
