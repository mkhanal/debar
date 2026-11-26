# Roadmap

The pieces Debar is built from, their order, and what exists today. Each piece gets its own design, requirements and build, and ends with something measured or compared.

## What exists today

- The governing documents in this repository.
- The study folder for the first signature format, with its reference scanner and databases pinned and a first set of notes.
- The toolchain image (`toolchain.Dockerfile`) and `./in-toolchain`, which runs any command in it, locally as in CI.
- A Cargo workspace on Rust 1.100.0 with the `xtask` crate and slices 1 to 4 of pieces 3 and 4: hash signatures, extended signatures of every target, file typing and logical signatures, end to end:
  - `debar-platform`: `MappedFile` (the only `unsafe`), the filesystem gate's directory listing, reads and atomic writes, reading a scanned file, the command line, and a stopwatch.
  - `debar-image`: the format-neutral model for hash and pattern signatures and the image: header, section directory and checksums, front-coded names, one hash table per purpose, category and algorithm with its size directory and a binary fuse filter probed in place, one pattern section per signature group holding a hashed four-byte anchor filter, a two-byte filter, anchor tables, placed signatures (from the start, before the end, or at an entry point, a section or version information in an executable) and verification programs, Debar's own `ObjectKind`, an object-kinds section mapping each kind to its signature groups and its typing data, a type-magic table, a logical-signature section per group (postfix expressions, count ceilings, conditions), the categories of potentially unwanted signatures and a filter per set of selected groups, all read in place.
  - `debar-clamav-signatures`, the first signature-format part: containers, hash files, ignore lists, extended signature files of every target with every offset form, logical signature files with their target description, expression and modifiers, and the file-type database, with an account of every line of every database file. It writes each target's group, the reference's window overlap per group (counting logical-signature parts it does not yet compile), the reference's memory of nine part ends, and for a hash key listed more than once only the name the reference reports.
  - `debar-compiler`, which compiles a folder of databases into an image and an account report.
  - `debar-matching`: which digests an object needs, whole-file and section lookups, false-positive trust, and a streaming pattern scan (`feed` and `finish`) over the groups an object kind selects, with look-back, executable placements resolved against an `ExecutableLayout` asked for only for executables, type-recognition outcomes, and detections ordered as the reference reports them; logical signatures counted, gated on their rarest subsignatures with a second pass for the armed ones, and evaluated with their conditions; potentially unwanted detections filtered by setting and category.
  - `debar-scan`, the scan core so far: typing an object from its first bytes (magic, text detection, type recognition, the wide-text retry) and re-typing it from what a full scan recognised.
  - `debar-interfaces` with `debar comparison-report`, which writes the comparison harness's report for one top-level object: its type, and its pattern, hash and logical detections from the groups its kind selects; and `debar measure-scan`, which measures throughput.
  - `acceptance`, outside the product, whose tests prove the requirements in `specs/` by running Debar's commands as a user would.
  - `fuzz/`, a cargo-fuzz workspace with a target for every part parser (the file-type database with typing among them), for opening and reading a damaged image, for the pattern scan with executable layouts, and for logical lines, expressions and evaluation.
- The comparison with the reference scanner on every push and pull request (`.github/workflows/comparison.yml`), through the harness's reusable workflow: its fixtures, an input built from every buildable extended signature of targets 0 (plus 6,000 inputs across a 128 KiB boundary), 3, 4 and 7, and from every buildable logical signature of the same targets, judged by the harness's ratchets for Debar.
- `cargo xtask check`, run on every push and pull request on amd64 and arm64: formatting, lints (including the gates), tests, dependencies (exact versions, licences, sources, advisories, and bans that keep outside resources in the platform crate and layers in order), the lint tables that confine `unsafe` to the platform crate, the layer table, mentions of a reference scanner, requirements married to tests, and the workflows. Miri runs on the platform crate on every change.
- `cargo xtask release-check`, which fails while "Borrowed pieces" lists anything.
- Requirements in `specs/` for hash, pattern and logical detection, file typing, the accounting of the pinned databases, an image identical across runs and architectures, readiness within 50 ms, private memory within 64 MiB and at least twice the reference's throughput, each passing on every change. On the pinned databases: 3,212,354 hash signatures, 105,901 pattern signatures, 321,093 logical signatures (1,303 waiting for slice 5) and 256 file-type lines compiled into a 465 MB image in 14.5 s; start, readiness and a small scan in 3,335,557 instructions; 64 KiB of the image resident and 160 KiB private memory once ready; 2.6 to 4 times the reference's single-threaded throughput on every corpus kind.

## The pieces, in order

| # | Piece | It is done when |
| --- | --- | --- |
| 1 | **Foundation** | The reference is pinned, the study notes hold an inventory of everything the reference scanner does, and the workspace builds, lints and tests an empty crate with every check below in place |
| 2 | **Comparison harness** | One command runs the reference scanner and Debar on the same input and reports any difference in what each extracted and what each detected, failing only on differences not already known. It can build a matching input from a signature, proved against the reference scanner. Until Debar can scan, its side is proved against a stand-in |
| 3 | **Signature compiler** | Every database file of the format compiles into an image, every signature in the pinned databases is accounted for in it, and the start-time and memory budgets are requirements whose tests pass on every change |
| 4 | **Matching engine** | Given raw bytes, it reports the same signatures the reference scanner does, and the scan-speed budget is a requirement whose test passes on every change |
| 5 | **Scan core** | A file of a kind needing no format module is scanned end to end with the reference scanner's limits and verdicts, within every budget |
| 6 | **Format modules** | Each module matches the reference scanner on its own inputs in the harness, within every budget, and records the facts native mode reports as findings. Built one at a time, the most common formats first |
| 7 | **Signature programs** | Signatures that are programs run and produce the reference scanner's detections |
| 8 | **Updater and live update** | Published databases are fetched, verified and compiled, and a running scanner switches image with no scan lost and within the memory budget |
| 9 | **Interfaces** | Native mode is complete, with its findings, refusals, whole-file reach and confinement, and compatibility mode passes for every command, protocol message and configuration option of the scanner being replaced |

Pieces 1 and 2 come first whatever else changes: every later piece is checked against the notes and the harness.

## Borrowed pieces

A build that is not a release may link a reference scanner's code to measure progress before Debar's own piece exists (Constitution §13). Each is listed here, with the piece that replaces it. No release is cut while this list has an entry.

- None.

## Evidence for the same detections

No test can cover every possible file, so Constitution §1 rests on three kinds of evidence together:

- **Each pattern signature** is checked with a matching input built from the signature itself.
- **Each hash signature** is checked by lookup.
- **Large collections of real files**, clean and malicious, are run through the reference scanner and Debar, and compared object by object.

## Candidates under consideration

Ideas for inside the layers. None is decided; each is settled in the design of its piece and recorded in [DECISIONS.md](./DECISIONS.md).

- **Signatures as a compiled program.** The compiler sees every signature at once and groups them by the facts they require, so the engine selects the applicable set from an object's facts before matching any bytes.
- **Work on demand.** A fact is computed only when a live signature asks for it.
- **Streaming with fixed memory per scan.** Content flows through matching as it is produced, with no temporary files, except where a signature needs random access.
- **Hashes behind a small in-memory filter.** The full table stays on disk and is touched only when the filter says a hash may be present.
- **Signature programs compiled ahead of time**, when the image is built.
- **The image laid out by hand and read in place** with `zerocopy`, with no validation pass at start.
- **Our own matcher**: a literal prefilter laid out in the image as a double-array automaton, then verification of wildcards and gaps. `daachorse` and `aho-corasick` are the measured starting points.
- **Hand-written readers** for scanned formats over the input gate, so a damaged file is handled as the reference scanner handles it.
- **A binary fuse filter** in the image in front of the hash tables.
- **An interpreter for signature programs**, with their bytecode checked and lowered when the image is built.
- **A fixed thread pool** for the daemon, with blocking I/O through the gates, instead of an async runtime.
- **mimalloc and an arena per scan**, kept only if they measure better.
- **Compile once, map everywhere.** The updater is the only thing that compiles; every scanner process maps the same image.

## Checks to build

Rules that are written down but not yet enforced by a machine. Each is removed from this list when it runs on every change.

- Every format module is fuzzed (Constitution §8). `cargo xtask fuzz` runs every fuzz target for 30 seconds on every change; ClusterFuzzLite, with longer runs weekly, arrives with the first format module.
- Audits of every dependency with cargo-vet. The tool is in the toolchain image; the audit set is started with the first dependency linked into a release.
- Mutation testing with cargo-mutants and coverage with cargo-llvm-cov, weekly. Both tools are in the toolchain image.
- Resource budgets (Constitution §12) gated on allocation counts and proportional set size. Start time and throughput are gated on instruction counts and memory on private and resident bytes read from `/proc`.
- No release while "Borrowed pieces" has an entry (Constitution §13): `cargo xtask release-check` exists and runs in the release workflow, which comes with the first release.
