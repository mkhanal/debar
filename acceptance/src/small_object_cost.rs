use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::scan_speed::{
    GENERATED_SLICES, SYSTEM_FILES, SliceRandom, best_recorded, measurement_key, slice_file,
    vocabulary,
};
use crate::{Failure, Outcome, instructions_to_measure_scan, target_directory};

pub const BEST_SMALL_OBJECT_RECORD: &str = "acceptance/best-small-object-cost.json";
pub const SMALL_OBJECT_LENGTH: usize = 1 << 10;
pub const LARGEST_SMALL_SYSTEM_FILE: u64 = 16 << 10;
const SMALL_OBJECTS_PER_KIND: usize = 64;
const SMALL_OBJECT_SEED: u64 = 0x736d_616c_6c5f_6f62;

pub struct SmallObjectKind {
    pub kind: &'static str,
    reference_seconds_per_object: f64,
}

pub const SMALL_OBJECT_KINDS: [SmallObjectKind; 7] = [
    SmallObjectKind {
        kind: "system",
        reference_seconds_per_object: 0.002_513_8,
    },
    SmallObjectKind {
        kind: "text",
        reference_seconds_per_object: 0.001_587_6,
    },
    SmallObjectKind {
        kind: "html",
        reference_seconds_per_object: 0.002_126_0,
    },
    SmallObjectKind {
        kind: "binary",
        reference_seconds_per_object: 0.002_085_7,
    },
    SmallObjectKind {
        kind: "pdf",
        reference_seconds_per_object: 0.001_894_8,
    },
    SmallObjectKind {
        kind: "ole2",
        reference_seconds_per_object: 0.004_479_1,
    },
    SmallObjectKind {
        kind: "tar",
        reference_seconds_per_object: 0.003_034_8,
    },
];

impl SmallObjectKind {
    #[must_use]
    pub fn of(kind: &str) -> Option<&'static Self> {
        SMALL_OBJECT_KINDS.iter().find(|small| small.kind == kind)
    }

    #[must_use]
    pub fn reference_seconds_per_object(&self) -> f64 {
        self.reference_seconds_per_object
    }
}

pub struct SmallObjectsMeasured {
    pub kind: String,
    pub objects: u64,
    pub instructions_per_object: f64,
}

pub fn small_object_slices(into: &Path) -> Outcome<Vec<(String, Vec<PathBuf>)>> {
    let mut random = SliceRandom(SMALL_OBJECT_SEED);
    let words = vocabulary(&mut random);
    let mut slices = vec![("system".to_owned(), small_system_files()?)];
    for kind in GENERATED_SLICES {
        let directory = into.join(kind);
        fs::create_dir_all(&directory)?;
        let mut files = Vec::with_capacity(SMALL_OBJECTS_PER_KIND);
        for index in 0..SMALL_OBJECTS_PER_KIND {
            let path = directory.join(format!("{kind}-small-{index:03}"));
            fs::write(
                &path,
                slice_file(kind, &mut random, &words, SMALL_OBJECT_LENGTH),
            )?;
            files.push(path);
        }
        slices.push((kind.to_owned(), files));
    }
    Ok(slices)
}

fn small_system_files() -> Outcome<Vec<PathBuf>> {
    let mut small = Vec::new();
    for entry in fs::read_dir(SYSTEM_FILES)? {
        let entry = entry?;
        let length = entry.metadata()?.len();
        if entry.file_type()?.is_file() && length > 0 && length <= LARGEST_SMALL_SYSTEM_FILE {
            small.push(entry.path());
        }
    }
    small.sort();
    Ok(small)
}

pub fn measured_small_object_cost(image: &Path) -> Outcome<Vec<SmallObjectsMeasured>> {
    let directory = target_directory()
        .join("acceptance")
        .join("small-object-cost");
    let record = directory.join(format!(
        "measured-{}.json",
        measurement_key(image, include_bytes!("small_object_cost.rs"))?
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
    for (kind, files) in small_object_slices(&directory.join("slices"))? {
        let objects = u64::try_from(files.len())?;
        let instructions = instructions_to_measure_scan(image, &files, &directory)?;
        measured.push(SmallObjectsMeasured {
            kind,
            objects,
            instructions_per_object: per_object(instructions.saturating_sub(starting), objects),
        });
    }
    fs::write(&record, serde_json::to_vec(&measured_to_json(&measured))?)?;
    Ok(measured)
}

#[must_use]
pub fn per_object(instructions: u64, objects: u64) -> f64 {
    crate::scan_speed::as_float(instructions) / crate::scan_speed::as_float(objects).max(1.0)
}

pub fn best_small_object_cost(kind: &str) -> Outcome<u64> {
    best_recorded(BEST_SMALL_OBJECT_RECORD, kind)
}

fn measured_to_json(measured: &[SmallObjectsMeasured]) -> Value {
    Value::Array(
        measured
            .iter()
            .map(|kind| {
                serde_json::json!({
                    "kind": kind.kind,
                    "objects": kind.objects,
                    "instructions_per_object": kind.instructions_per_object,
                })
            })
            .collect(),
    )
}

fn measured_from_json(value: &Value) -> Outcome<Vec<SmallObjectsMeasured>> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|kind| {
            Ok(SmallObjectsMeasured {
                kind: kind["kind"]
                    .as_str()
                    .ok_or_else(|| Failure("a measurement names no kind".to_owned()))?
                    .to_owned(),
                objects: kind["objects"]
                    .as_u64()
                    .ok_or_else(|| Failure("a measurement holds no object count".to_owned()))?,
                instructions_per_object: kind["instructions_per_object"]
                    .as_f64()
                    .ok_or_else(|| Failure("a measurement holds no cost".to_owned()))?,
            })
        })
        .collect()
}
