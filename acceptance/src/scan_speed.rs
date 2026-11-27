use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{
    Failure, Outcome, instructions_to_measure_scan, lowercase_hex, release_binaries,
    target_directory, workspace_root,
};

pub const BYTES_PER_MEBIBYTE: f64 = 1_048_576.0;
const NANOSECONDS_PER_SECOND: f64 = 1e9;
pub const TIMES_THE_REFERENCE_REQUIRED: f64 = 2.0;
pub const TIMES_THE_REFERENCE_AIMED_FOR: f64 = 50.0;
const X86_64_INSTRUCTIONS_PER_AARCH64_INSTRUCTION: f64 = 1.27;
pub const BEST_MEASURED_TOLERANCE: f64 = 0.02;
pub const BEST_MEASURED_RECORD: &str = "acceptance/best-scan-speed.json";

pub struct Calibration {
    pub kind: &'static str,
    reference_mebibytes_per_second: f64,
    instructions_per_nanosecond: f64,
}

pub const CALIBRATIONS: [Calibration; 7] = [
    Calibration {
        kind: "system",
        reference_mebibytes_per_second: 13.2,
        instructions_per_nanosecond: 14.08,
    },
    Calibration {
        kind: "text",
        reference_mebibytes_per_second: 14.3,
        instructions_per_nanosecond: 14.59,
    },
    Calibration {
        kind: "html",
        reference_mebibytes_per_second: 9.8,
        instructions_per_nanosecond: 15.52,
    },
    Calibration {
        kind: "binary",
        reference_mebibytes_per_second: 19.1,
        instructions_per_nanosecond: 14.27,
    },
    Calibration {
        kind: "pdf",
        reference_mebibytes_per_second: 0.73,
        instructions_per_nanosecond: 13.45,
    },
    Calibration {
        kind: "ole2",
        reference_mebibytes_per_second: 5.54,
        instructions_per_nanosecond: 13.44,
    },
    Calibration {
        kind: "tar",
        reference_mebibytes_per_second: 30.5,
        instructions_per_nanosecond: 14.17,
    },
];

impl Calibration {
    #[must_use]
    pub fn of(kind: &str) -> Option<&'static Self> {
        CALIBRATIONS
            .iter()
            .find(|calibration| calibration.kind == kind)
    }

    #[must_use]
    pub fn instructions_in(&self, seconds: f64) -> f64 {
        seconds
            * NANOSECONDS_PER_SECOND
            * self.instructions_per_nanosecond
            * instructions_on_this_architecture()
    }

    #[must_use]
    pub fn instructions_per_mebibyte_at(&self, times_the_reference: f64) -> f64 {
        let nanoseconds_per_mebibyte =
            NANOSECONDS_PER_SECOND / (times_the_reference * self.reference_mebibytes_per_second);
        nanoseconds_per_mebibyte
            * self.instructions_per_nanosecond
            * instructions_on_this_architecture()
    }
}

fn instructions_on_this_architecture() -> f64 {
    if cfg!(target_arch = "x86_64") {
        X86_64_INSTRUCTIONS_PER_AARCH64_INSTRUCTION
    } else {
        1.0
    }
}

pub struct KindMeasured {
    pub kind: String,
    pub bytes: u64,
    pub instructions_per_mebibyte: f64,
}

pub fn measured_scan_speed(image: &Path) -> Outcome<Vec<KindMeasured>> {
    static MEASURING: Mutex<()> = Mutex::new(());
    let _one_at_a_time = MEASURING.lock().unwrap_or_else(PoisonError::into_inner);
    let directory = target_directory().join("acceptance").join("scan-speed");
    let record = directory.join(format!(
        "measured-{}.json",
        measurement_key(image, include_bytes!("scan_speed.rs"))?
    ));
    if let Ok(text) = fs::read(&record) {
        return measured_from_json(&serde_json::from_slice(&text)?);
    }
    if directory.exists() {
        fs::remove_dir_all(&directory)?;
    }
    fs::create_dir_all(&directory)?;
    let empty = directory.join("empty");
    fs::create_dir(&empty)?;
    let starting = instructions_to_measure_scan(image, &[empty], &directory)?;
    let mut measured = Vec::new();
    for (kind, files) in benchmark_slices(&directory.join("slices"))? {
        let bytes = files.iter().try_fold(0u64, |total, file| {
            Ok::<u64, Failure>(total.saturating_add(fs::metadata(file)?.len()))
        })?;
        let instructions = instructions_to_measure_scan(image, &files, &directory)?;
        measured.push(KindMeasured {
            kind,
            bytes,
            instructions_per_mebibyte: per_mebibyte(instructions.saturating_sub(starting), bytes),
        });
    }
    fs::write(&record, serde_json::to_vec(&measured_to_json(&measured))?)?;
    Ok(measured)
}

#[must_use]
pub fn per_mebibyte(instructions: u64, bytes: u64) -> f64 {
    as_float(instructions) * BYTES_PER_MEBIBYTE / as_float(bytes).max(1.0)
}

const LOW_HALF: u64 = 0xffff_ffff;
const HALF_SCALE: f64 = 4_294_967_296.0;

#[must_use]
pub fn as_float(count: u64) -> f64 {
    let high = u32::try_from(count >> 32).map_or(0.0, f64::from);
    let low = u32::try_from(count & LOW_HALF).map_or(0.0, f64::from);
    high * HALF_SCALE + low
}

pub(crate) fn measurement_key(image: &Path, measuring_source: &[u8]) -> Outcome<String> {
    let mut hasher = Sha256::new();
    hasher.update(fs::read(&release_binaries()?.debar)?);
    hasher.update(include_bytes!("scan_speed.rs"));
    hasher.update(measuring_source);
    hasher.update(crate::STRING_ROUTINES_FIXED_ON_X86_64);
    hasher.update(image.as_os_str().as_encoded_bytes());
    Ok(lowercase_hex(
        hasher.finalize().get(..8).unwrap_or_default(),
    ))
}

fn measured_to_json(measured: &[KindMeasured]) -> Value {
    Value::Array(
        measured
            .iter()
            .map(|kind| {
                serde_json::json!({
                    "kind": kind.kind,
                    "bytes": kind.bytes,
                    "instructions_per_mebibyte": kind.instructions_per_mebibyte,
                })
            })
            .collect(),
    )
}

fn measured_from_json(value: &Value) -> Outcome<Vec<KindMeasured>> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|kind| {
            Ok(KindMeasured {
                kind: kind["kind"]
                    .as_str()
                    .ok_or_else(|| Failure("a measurement names no kind".to_owned()))?
                    .to_owned(),
                bytes: kind["bytes"]
                    .as_u64()
                    .ok_or_else(|| Failure("a measurement holds no byte count".to_owned()))?,
                instructions_per_mebibyte: kind["instructions_per_mebibyte"]
                    .as_f64()
                    .ok_or_else(|| Failure("a measurement holds no rate".to_owned()))?,
            })
        })
        .collect()
}

#[must_use]
pub const fn this_architecture() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        "aarch64"
    }
}

pub fn best_measured(kind: &str) -> Outcome<u64> {
    best_recorded(BEST_MEASURED_RECORD, kind)
}

pub(crate) fn best_recorded(record: &str, kind: &str) -> Outcome<u64> {
    let path = workspace_root().join(record);
    let record: Value = serde_json::from_slice(&fs::read(&path)?)?;
    record
        .get(this_architecture())
        .and_then(|figures| figures.get(kind))
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            Failure(format!(
                "{} records no best figure for {kind} on {}",
                path.display(),
                this_architecture()
            ))
        })
}

pub(crate) struct SliceRandom(pub(crate) u64);

impl SliceRandom {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0.wrapping_shl(13);
        self.0 ^= self.0.wrapping_shr(7);
        self.0 ^= self.0.wrapping_shl(17);
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        let bound = u64::try_from(bound.max(1)).unwrap_or(1);
        usize::try_from(self.next().checked_rem(bound).unwrap_or(0)).unwrap_or(0)
    }

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes().first().copied().unwrap_or(0)
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| self.byte()).collect()
    }
}

const SYLLABLES: [&str; 24] = [
    "ka", "lo", "mi", "ten", "ar", "su", "pe", "rin", "do", "vel", "qu", "ish", "or", "an", "the",
    "se", "ti", "on", "ex", "um", "bra", "co", "ne", "ly",
];
const VOCABULARY_WORDS: usize = 4000;

pub(crate) fn vocabulary(random: &mut SliceRandom) -> Vec<String> {
    (0..VOCABULARY_WORDS)
        .map(|_| {
            (0..=random.below(3))
                .map(|_| {
                    SYLLABLES
                        .get(random.below(SYLLABLES.len()))
                        .copied()
                        .unwrap_or_default()
                })
                .collect()
        })
        .collect()
}

fn prose(random: &mut SliceRandom, words: &[String], length: usize) -> Vec<u8> {
    let mut text = Vec::with_capacity(length.saturating_add(128));
    while text.len() < length {
        for index in 0..random.below(10).saturating_add(6) {
            if index > 0 {
                text.push(b' ');
            }
            if let Some(word) = words.get(random.below(words.len())) {
                text.extend_from_slice(word.as_bytes());
            }
        }
        text.extend_from_slice(b".\n");
    }
    text.truncate(length);
    text
}

fn web_page(random: &mut SliceRandom, words: &[String], length: usize) -> Vec<u8> {
    let mut page = b"<!DOCTYPE html>\n<html><head><title>page</title></head>\n<body>\n".to_vec();
    while page.len() < length {
        page.extend_from_slice(b"<p class=\"c\">");
        page.extend(prose(random, words, 200));
        page.extend_from_slice(
            b"</p>\n<script>var total = 0; for (var i = 0; i < 9; i++) { total += i; }</script>\n",
        );
    }
    page.truncate(length);
    page
}

const PDF_STREAM_LENGTH: usize = 4096;
const PDF_TRAILER: &[u8] = b"%%EOF\n";

fn pdf_document(random: &mut SliceRandom, length: usize) -> Vec<u8> {
    let mut document = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut object = 1u32;
    while document.len() < length {
        let stream = random.bytes(PDF_STREAM_LENGTH);
        document.extend_from_slice(
            format!(
                "{object} 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n",
                stream.len()
            )
            .as_bytes(),
        );
        document.extend(stream);
        document.extend_from_slice(b"\nendstream\nendobj\n");
        object = object.saturating_add(1);
    }
    document.truncate(length.saturating_sub(PDF_TRAILER.len()));
    document.extend_from_slice(PDF_TRAILER);
    document
}

const OLE2_MAGIC: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const OLE2_HEADER_LENGTH: usize = 512;

fn compound_document(random: &mut SliceRandom, length: usize) -> Vec<u8> {
    let mut compound = OLE2_MAGIC.to_vec();
    compound.resize(OLE2_HEADER_LENGTH, 0);
    compound.extend(random.bytes(length.saturating_sub(OLE2_HEADER_LENGTH)));
    compound
}

const TAR_BLOCK: usize = 512;
const TAR_MEMBER_LENGTH: usize = 8192;

fn tar_archive(random: &mut SliceRandom, words: &[String], length: usize) -> Vec<u8> {
    let mut archive = Vec::with_capacity(length);
    let mut member = 0u32;
    while archive.len().saturating_add(2 * TAR_BLOCK) < length {
        let contents = if member.is_multiple_of(2) {
            prose(random, words, TAR_MEMBER_LENGTH)
        } else {
            random.bytes(TAR_MEMBER_LENGTH)
        };
        archive.extend_from_slice(&tar_header(&format!("member-{member}.dat"), contents.len()));
        archive.extend(contents);
        member = member.saturating_add(1);
    }
    archive.resize(length, 0);
    archive
}

fn tar_header(name: &str, length: usize) -> [u8; TAR_BLOCK] {
    let mut header = [0u8; TAR_BLOCK];
    let mut put = |at: usize, field: &[u8]| {
        if let Some(slot) = header.get_mut(at..at.saturating_add(field.len())) {
            slot.copy_from_slice(field);
        }
    };
    put(0, name.as_bytes());
    put(100, b"0000644");
    put(124, format!("{length:011o}").as_bytes());
    put(257, b"ustar\0");
    put(263, b"00");
    put(148, b"        ");
    let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    if let Some(slot) = header.get_mut(148..155) {
        slot.copy_from_slice(format!("{sum:06o}\0").as_bytes());
    }
    header
}

pub(crate) fn slice_file(
    kind: &str,
    random: &mut SliceRandom,
    words: &[String],
    length: usize,
) -> Vec<u8> {
    match kind {
        "text" => prose(random, words, length),
        "html" => web_page(random, words, length),
        "pdf" => pdf_document(random, length),
        "ole2" => compound_document(random, length),
        "tar" => tar_archive(random, words, length),
        _ => random.bytes(length),
    }
}

const SLICE_FILE_LENGTHS: [usize; 6] = [1 << 10, 1 << 14, 1 << 16, 1 << 18, 1 << 20, 1 << 21];
const SLICE_FILES_PER_LENGTH: [usize; 6] = [16, 8, 4, 2, 1, 1];
pub(crate) const GENERATED_SLICES: [&str; 6] = ["text", "html", "binary", "pdf", "ole2", "tar"];
const SLICE_SEED: u64 = 0x6465_6261_725f_736c;
pub(crate) const SYSTEM_FILES: &str = "/usr/bin";
const SYSTEM_SLICE_BYTES: u64 = 4 << 20;

pub fn benchmark_slices(into: &Path) -> Outcome<Vec<(String, Vec<PathBuf>)>> {
    let mut random = SliceRandom(SLICE_SEED);
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
    slices.push(("system".to_owned(), system_files()?));
    Ok(slices)
}

fn system_files() -> Outcome<Vec<PathBuf>> {
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
        bytes = bytes.saturating_add(fs::metadata(&path)?.len());
        chosen.push(path);
    }
    Ok(chosen)
}
