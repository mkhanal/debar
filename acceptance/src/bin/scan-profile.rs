#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::thread;

use acceptance::scan_speed::{
    BYTES_PER_MEBIBYTE, Calibration, TIMES_THE_REFERENCE_AIMED_FOR, TIMES_THE_REFERENCE_REQUIRED,
    as_float, benchmark_slices,
};
use acceptance::{Failure, Outcome, official_image, release_binaries, run, target_directory};
use serde_json::{Value, json};

struct Stage {
    name: &'static str,
    functions_naming: &'static [&'static str],
}

const STAGES: [Stage; 12] = [
    Stage {
        name: "reading",
        functions_naming: &[
            "ScannedFile>::read_at",
            "std::fs::",
            "std::sys::fs::",
            "filesystem::",
        ],
    },
    Stage {
        name: "typing",
        functions_naming: &["debar_scan::typing::", "type_magic::", "object_kinds::"],
    },
    Stage {
        name: "selecting signatures",
        functions_naming: &[
            "PatternScan>::new",
            "place_positional",
            "selected_groups",
            "placed_starts",
            "selection_filter",
            "executable_layout::",
        ],
    },
    Stage {
        name: "digests",
        functions_naming: &[
            "sha2::",
            "md5::",
            "sha1::",
            "digest::",
            "block_buffer::",
            "ObjectDigests",
        ],
    },
    Stage {
        name: "second pass search",
        functions_naming: &["second_pass_search::"],
    },
    Stage {
        name: "whole-object matching",
        functions_naming: &[
            "regex_automata::",
            "plug_in_matching::",
            "plug_in_subsignatures::",
            "backtracking_search::",
            "backtracking_program::",
            "expression_automata::",
            "byte_values::",
        ],
    },
    Stage {
        name: "hash lookups",
        functions_naming: &["hash_lookup::", "fuse_filter::", "hash_partition::"],
    },
    Stage {
        name: "logical evaluation",
        functions_naming: &[
            "logical_findings",
            "LogicalState>::evaluate",
            "logical_expression::",
        ],
    },
    Stage {
        name: "prefilter",
        functions_naming: &[
            "probe_positions",
            "probe_windows",
            "long_hits",
            "short_hits",
            "probe_everywhere",
            "ArmedParts>::hits",
            "LongAnchorTable>::anchored",
            "AnchorTables>::short_anchored",
            "AnchoredProgram",
            "PatternScan>::probe",
            "PatternScan>::advance",
        ],
    },
    Stage {
        name: "verifying candidates",
        functions_naming: &[
            "verify",
            "verification::",
            "pattern_program::",
            "part_ends::",
            "logical_state::",
            "arm_next_part",
            "anchors_already_probed",
            "insert_in_order",
            "PatternGroup>::",
            "pattern_scan::Candidate",
        ],
    },
    Stage {
        name: "allocating and copying",
        functions_naming: &[
            "malloc",
            "free",
            "memcpy",
            "memmove",
            "memset",
            "realloc",
            "raw_vec",
            "__rust_alloc",
            "__rust_dealloc",
            "_int_",
        ],
    },
    Stage {
        name: "everything else",
        functions_naming: &[""],
    },
];

struct Slice {
    kind: String,
    files: Vec<PathBuf>,
    bytes: u64,
}

type ByStage = [u64; STAGES.len()];

fn main() -> ExitCode {
    match profile() {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure(reason)) => {
            eprintln!("scan-profile: {reason}");
            ExitCode::FAILURE
        }
    }
}

fn profile() -> Outcome<()> {
    let image = match std::env::args_os().nth(1) {
        Some(image) => PathBuf::from(image),
        None => official_image()?.image,
    };
    let debar = match std::env::args_os().nth(2) {
        Some(debar) => PathBuf::from(debar),
        None => release_binaries()?.debar.clone(),
    };
    let directory = target_directory().join("scan-profile");
    if directory.exists() {
        fs::remove_dir_all(&directory)?;
    }
    fs::create_dir_all(directory.join("empty"))?;
    let mut slices = slices(&directory)?;
    slices.push(Slice {
        kind: String::new(),
        files: vec![directory.join("empty")],
        bytes: 0,
    });
    let mut profiled = profile_all(&debar, &image, &directory, &slices)?;
    let starting = profiled.pop().unwrap_or([0; STAGES.len()]);
    slices.pop();
    let report = report(&slices, &profiled, &starting);
    fs::write(
        directory.join("profile.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    print!("{}", table(&report));
    Ok(())
}

fn slices(directory: &Path) -> Outcome<Vec<Slice>> {
    benchmark_slices(&directory.join("slices"))?
        .into_iter()
        .map(|(kind, files)| {
            let bytes = files.iter().try_fold(0u64, |total, file| {
                Ok::<u64, Failure>(total.saturating_add(fs::metadata(file)?.len()))
            })?;
            Ok(Slice { kind, files, bytes })
        })
        .collect()
}

fn profile_all(
    debar: &Path,
    image: &Path,
    directory: &Path,
    slices: &[Slice],
) -> Outcome<Vec<ByStage>> {
    thread::scope(|scope| {
        let running: Vec<_> = slices
            .iter()
            .enumerate()
            .map(|(index, slice)| {
                let output = directory.join(format!("{index}.cachegrind"));
                scope.spawn(move || profile_slice(debar, image, &output, slice))
            })
            .collect();
        running
            .into_iter()
            .map(|profiling| {
                profiling
                    .join()
                    .unwrap_or_else(|_| Err(Failure("a profiling thread failed".to_owned())))
            })
            .collect()
    })
}

fn profile_slice(debar: &Path, image: &Path, output: &Path, slice: &Slice) -> Outcome<ByStage> {
    run(Command::new("valgrind")
        .arg("--tool=cachegrind")
        .arg("--cache-sim=no")
        .arg(format!("--cachegrind-out-file={}", output.display()))
        .arg(debar)
        .arg("measure-scan")
        .arg("--image")
        .arg(image)
        .args(&slice.files))?;
    let text = fs::read_to_string(output)?;
    fs::remove_file(output)?;
    let mut by_stage: ByStage = [0; STAGES.len()];
    let mut stage = STAGES.len();
    for line in text.lines() {
        if let Some(function) = line.strip_prefix("fn=") {
            stage = stage_of(function);
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(line_number), Some(count), None) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if let (Ok(_), Ok(count), Some(slot)) = (
            line_number.parse::<u64>(),
            count.parse::<u64>(),
            by_stage.get_mut(stage),
        ) {
            *slot = slot.saturating_add(count);
        }
    }
    Ok(by_stage)
}

fn stage_of(function: &str) -> usize {
    STAGES
        .iter()
        .position(|stage| {
            stage
                .functions_naming
                .iter()
                .any(|name| function.contains(name))
        })
        .unwrap_or(STAGES.len())
}

fn report(slices: &[Slice], profiled: &[ByStage], starting: &ByStage) -> Value {
    let kinds: Vec<Value> = slices
        .iter()
        .zip(profiled)
        .map(|(slice, by_stage)| {
            let per_byte = |count: u64| as_float(count) / as_float(slice.bytes).max(1.0);
            let scanning: Vec<u64> = by_stage
                .iter()
                .zip(starting)
                .map(|(count, before)| count.saturating_sub(*before))
                .collect();
            let stages: Vec<Value> = STAGES
                .iter()
                .zip(&scanning)
                .map(|(stage, count)| {
                    json!({ "stage": stage.name, "instructions_per_byte": per_byte(*count) })
                })
                .collect();
            let calibration = Calibration::of(&slice.kind);
            let at = |times: f64| {
                calibration.map(|calibration| {
                    calibration.instructions_per_mebibyte_at(times) / BYTES_PER_MEBIBYTE
                })
            };
            json!({
                "kind": slice.kind,
                "bytes": slice.bytes,
                "files": slice.files.len(),
                "instructions_per_byte": per_byte(scanning.iter().sum()),
                "required_instructions_per_byte": at(TIMES_THE_REFERENCE_REQUIRED),
                "aimed_instructions_per_byte": at(TIMES_THE_REFERENCE_AIMED_FOR),
                "stages": stages,
            })
        })
        .collect();
    json!({ "architecture": std::env::consts::ARCH, "kinds": kinds })
}

fn table(report: &Value) -> String {
    let kinds = report["kinds"].as_array().cloned().unwrap_or_default();
    let mut text = format!(
        "Instructions per byte scanned, by stage ({})\n\n{:<24}",
        report["architecture"].as_str().unwrap_or_default(),
        "stage"
    );
    for kind in &kinds {
        let _ = write!(text, "{:>9}", kind["kind"].as_str().unwrap_or_default());
    }
    text.push('\n');
    let names: Vec<String> = kinds
        .first()
        .and_then(|kind| kind["stages"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|stage| stage["stage"].as_str().map(str::to_owned))
        .collect();
    for (row, name) in names.iter().enumerate() {
        let _ = write!(text, "{name:<24}");
        for kind in &kinds {
            let value = kind["stages"]
                .get(row)
                .and_then(|stage| stage["instructions_per_byte"].as_f64());
            let _ = write!(text, "{:>9.1}", value.unwrap_or(0.0));
        }
        text.push('\n');
    }
    for (label, field) in [
        ("scan total", "instructions_per_byte"),
        ("twice the reference", "required_instructions_per_byte"),
        ("fifty times the reference", "aimed_instructions_per_byte"),
    ] {
        let _ = write!(text, "{label:<24}");
        for kind in &kinds {
            let _ = write!(text, "{:>9.1}", kind[field].as_f64().unwrap_or(0.0));
        }
        text.push('\n');
    }
    text
}
