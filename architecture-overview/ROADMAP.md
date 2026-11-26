# Roadmap

The pieces Debar is built from, their order, and what exists today. Each piece gets its own design, requirements and build, and ends with something measured or compared.

## What exists today

- The governing documents in this repository.
- The study folder for the first signature format, with its reference scanner and databases pinned and a first set of notes.
- No Rust code, no build, and none of the checks listed under "Checks to build".

## The pieces, in order

| # | Piece | It is done when |
| --- | --- | --- |
| 1 | **Foundation** | The reference is pinned, the study notes hold an inventory of everything the reference scanner does, and the workspace builds, lints and tests an empty crate with every check below in place |
| 2 | **Comparison harness** | One command runs the reference scanner and Debar on the same input and reports any difference in what each extracted and what each detected. It can build a matching input from a signature |
| 3 | **Signature compiler** | Every database file of the format compiles into an image, and every signature in the pinned databases is accounted for in it |
| 4 | **Matching engine** | Given raw bytes, it reports the same signatures the reference scanner does, and start time and memory on the pinned databases are measured against the baseline |
| 5 | **Scan core** | A file of a kind needing no format module is scanned end to end with the reference scanner's limits and verdicts |
| 6 | **Format modules** | Each module matches the reference scanner on its own inputs in the harness. Built one at a time, the most common formats first |
| 7 | **Signature programs** | Signatures that are programs run and produce the reference scanner's detections |
| 8 | **Updater and live update** | Published databases are fetched, verified and compiled, and a running scanner switches image with no scan lost |
| 9 | **Interfaces** | Native mode is complete, and compatibility mode passes for every command, protocol message and configuration option of the scanner being replaced |

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
- **Compile once, map everywhere.** The updater is the only thing that compiles; every scanner process maps the same image.

## Checks to build

Rules that are written down but not yet enforced by a machine. Each is built in piece 1 and removed from this list when it runs on every change.

- Formatting, lints and the test suite, on every change.
- Exact dependency versions and allowed licences (`CODING-GUIDELINES.md`, "Depend with care").
- The gates: no file, memory map, socket, clock or random number outside the platform layer (Constitution §9).
- `unsafe` only in the platform layer.
- Layers depend downward only (Constitution §10).
- No committed file mentions a reference scanner beyond its supported signature format and its compatibility surface (Constitution §4).
- Every requirement is married to a test (`/lazyspec-validate`).
- No release while "Borrowed pieces" has an entry (Constitution §13).
