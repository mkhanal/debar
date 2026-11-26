#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::fs;
use std::path::{Path, PathBuf};

use acceptance::{Outcome, instructions_to_measure_scan, official_image, scratch_directory};

const BYTES_PER_MEBIBYTE: f64 = 1_048_576.0;
const NANOSECONDS_PER_SECOND: f64 = 1e9;
const TIMES_THE_REFERENCE: f64 = 2.0;
const X86_64_INSTRUCTIONS_PER_AARCH64_INSTRUCTION: f64 = 1.27;

struct Calibration {
    kind: &'static str,
    reference_mebibytes_per_second: f64,
    instructions_per_nanosecond: f64,
}

const CALIBRATIONS: [Calibration; 7] = [
    Calibration {
        kind: "system",
        reference_mebibytes_per_second: 16.1,
        instructions_per_nanosecond: 14.08,
    },
    Calibration {
        kind: "text",
        reference_mebibytes_per_second: 30.5,
        instructions_per_nanosecond: 14.59,
    },
    Calibration {
        kind: "html",
        reference_mebibytes_per_second: 14.2,
        instructions_per_nanosecond: 15.52,
    },
    Calibration {
        kind: "binary",
        reference_mebibytes_per_second: 26.8,
        instructions_per_nanosecond: 14.27,
    },
    Calibration {
        kind: "pdf",
        reference_mebibytes_per_second: 25.3,
        instructions_per_nanosecond: 13.45,
    },
    Calibration {
        kind: "ole2",
        reference_mebibytes_per_second: 15.9,
        instructions_per_nanosecond: 13.44,
    },
    Calibration {
        kind: "tar",
        reference_mebibytes_per_second: 28.5,
        instructions_per_nanosecond: 14.17,
    },
];

fn instruction_budget_per_mebibyte(calibration: &Calibration) -> f64 {
    let nanoseconds_per_mebibyte =
        NANOSECONDS_PER_SECOND / (TIMES_THE_REFERENCE * calibration.reference_mebibytes_per_second);
    nanoseconds_per_mebibyte
        * calibration.instructions_per_nanosecond
        * instructions_on_this_architecture()
}

fn instructions_on_this_architecture() -> f64 {
    if cfg!(target_arch = "x86_64") {
        X86_64_INSTRUCTIONS_PER_AARCH64_INSTRUCTION
    } else {
        1.0
    }
}

#[test]
fn debar_scans_at_least_twice_as_fast_as_the_reference_scanner() {
    const REQUIREMENT: &str = "Debar Scans At Least Twice As Fast As The Reference Scanner";
    let official = official_image().unwrap();
    let directory = scratch_directory("scan-speed").unwrap();
    let empty = directory.join("empty");
    fs::create_dir(&empty).unwrap();
    let starting = instructions_to_measure_scan(&official.image, &[empty], &directory).unwrap();
    let slices = benchmark_slices(&directory.join("slices")).unwrap();
    let mut failures = Vec::new();
    for (kind, files) in &slices {
        let calibration = CALIBRATIONS
            .iter()
            .find(|calibration| calibration.kind == kind)
            .unwrap();
        let bytes: u64 = files
            .iter()
            .map(|file| fs::metadata(file).unwrap().len())
            .sum();
        let instructions =
            instructions_to_measure_scan(&official.image, files, &directory).unwrap();
        let per_mebibyte =
            instructions.saturating_sub(starting) as f64 * BYTES_PER_MEBIBYTE / bytes as f64;
        let budget = instruction_budget_per_mebibyte(calibration);
        println!(
            "{kind}: {bytes} bytes, {per_mebibyte:.0} instructions per MiB, budget {budget:.0} ({:.0}% of it)",
            100.0 * per_mebibyte / budget
        );
        if per_mebibyte > budget {
            failures.push(format!("{kind}: {per_mebibyte:.0} > {budget:.0}"));
        }
    }
    assert!(failures.is_empty(), "{REQUIREMENT}: {failures:?}");
}

const SLICE_FILE_LENGTHS: [usize; 6] = [1 << 10, 1 << 14, 1 << 16, 1 << 18, 1 << 20, 1 << 21];
const SLICE_FILES_PER_LENGTH: [usize; 6] = [16, 8, 4, 2, 1, 1];
const SYSTEM_FILES: &str = "/usr/bin";
const SYSTEM_SLICE_BYTES: u64 = 4 << 20;

struct SliceRandom(u64);

impl SliceRandom {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound.max(1)).unwrap_or(1)).unwrap_or(0)
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| self.next().to_le_bytes()[0]).collect()
    }
}

fn vocabulary(random: &mut SliceRandom) -> Vec<String> {
    const SYLLABLES: [&str; 24] = [
        "ka", "lo", "mi", "ten", "ar", "su", "pe", "rin", "do", "vel", "qu", "ish", "or", "an",
        "the", "se", "ti", "on", "ex", "um", "bra", "co", "ne", "ly",
    ];
    (0..4000)
        .map(|_| {
            (0..=random.below(3))
                .map(|_| SYLLABLES[random.below(SYLLABLES.len())])
                .collect()
        })
        .collect()
}

fn prose(random: &mut SliceRandom, words: &[String], length: usize) -> Vec<u8> {
    let mut text = Vec::with_capacity(length + 128);
    while text.len() < length {
        for index in 0..6 + random.below(10) {
            if index > 0 {
                text.push(b' ');
            }
            text.extend_from_slice(words[random.below(words.len())].as_bytes());
        }
        text.extend_from_slice(b".\n");
    }
    text.truncate(length);
    text
}

fn slice_file(kind: &str, random: &mut SliceRandom, words: &[String], length: usize) -> Vec<u8> {
    match kind {
        "text" => prose(random, words, length),
        "html" => {
            let mut page =
                b"<!DOCTYPE html>\n<html><head><title>page</title></head>\n<body>\n".to_vec();
            while page.len() < length {
                page.extend_from_slice(b"<p class=\"c\">");
                page.extend(prose(random, words, 200));
                page.extend_from_slice(b"</p>\n<script>var total = 0; for (var i = 0; i < 9; i++) { total += i; }</script>\n");
            }
            page.truncate(length);
            page
        }
        "pdf" => {
            let mut document = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n".to_vec();
            let mut object = 1;
            while document.len() < length {
                let stream = random.bytes(4096);
                document.extend_from_slice(
                    format!(
                        "{object} 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n",
                        stream.len()
                    )
                    .as_bytes(),
                );
                document.extend(stream);
                document.extend_from_slice(b"\nendstream\nendobj\n");
                object += 1;
            }
            document.truncate(length.saturating_sub(6));
            document.extend_from_slice(b"%%EOF\n");
            document
        }
        "ole2" => {
            let mut compound = vec![0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
            compound.resize(512, 0);
            compound.extend(random.bytes(length.saturating_sub(512)));
            compound
        }
        "tar" => {
            let mut archive = Vec::with_capacity(length);
            let mut member = 0;
            while archive.len() + 1024 < length {
                let contents = if member % 2 == 0 {
                    prose(random, words, 8192)
                } else {
                    random.bytes(8192)
                };
                let mut header = [0u8; 512];
                let name = format!("member-{member}.dat");
                header[..name.len()].copy_from_slice(name.as_bytes());
                header[100..107].copy_from_slice(b"0000644");
                header[124..135].copy_from_slice(format!("{:011o}", contents.len()).as_bytes());
                header[257..263].copy_from_slice(b"ustar\0");
                header[263..265].copy_from_slice(b"00");
                header[148..156].copy_from_slice(b"        ");
                let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
                header[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
                archive.extend_from_slice(&header);
                archive.extend(contents);
                member += 1;
            }
            archive.resize(length, 0);
            archive
        }
        _ => random.bytes(length),
    }
}

const GENERATED_SLICES: [&str; 6] = ["text", "html", "binary", "pdf", "ole2", "tar"];

fn benchmark_slices(into: &Path) -> Outcome<Vec<(String, Vec<PathBuf>)>> {
    let mut random = SliceRandom(0x6465_6261_725f_736c);
    let words = vocabulary(&mut random);
    let mut slices = Vec::new();
    for kind in GENERATED_SLICES {
        let directory = into.join(kind);
        fs::create_dir_all(&directory)?;
        let mut files = Vec::new();
        for (length, count) in SLICE_FILE_LENGTHS.iter().zip(SLICE_FILES_PER_LENGTH) {
            for index in 0..count {
                let path = directory.join(format!("{kind}-{length:08}-{index}"));
                fs::write(&path, slice_file(kind, &mut random, &words, *length))?;
                files.push(path);
            }
        }
        slices.push((kind.to_owned(), files));
    }
    let mut system: Vec<PathBuf> = fs::read_dir(SYSTEM_FILES)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .collect();
    system.sort();
    let mut chosen = Vec::new();
    let mut bytes = 0u64;
    for path in system {
        if bytes >= SYSTEM_SLICE_BYTES {
            break;
        }
        bytes += fs::metadata(&path)?.len();
        chosen.push(path);
    }
    slices.push(("system".to_owned(), chosen));
    Ok(slices)
}
