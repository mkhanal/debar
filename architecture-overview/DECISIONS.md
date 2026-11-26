# Decisions

What was decided, when, and why. Newest last. A decision that is later changed gets a new entry that names the one it replaces; the old entry stays.

Reasoning that depends on a reference scanner's internals is kept in that format's study folder, not here (Constitution §4).

### 2026-11-26 — Debar is a new product in its own repository

**Decision.** Debar is its own scanner with its own design and its own repository. It is not a fork of any existing scanner.

**Why.** The aims (drop-in, much smaller footprint, near-instant start) need a different data model from the ground up, and a new product is free to support more than one signature format.

### 2026-11-26 — Written in Rust, from scratch, every part

**Decision.** Every part is written in Rust, including the unpackers, parsers and the runtime for signatures that are programs.

**Why.** Memory safety on hostile input, and one codebase an agent can hold and change. Reusing another scanner's parsers permanently was considered and rejected: it would keep that scanner's resource behaviour and its class of memory defects.

### 2026-11-26 — Only what a signature can observe must match

**Decision.** Debar matches the reference scanner wherever a signature can observe the difference, and is free everywhere else (Constitution §2).

**Why.** Signatures are tested against their reference scanner's output, so that output is the specification. Faults a signature cannot see are not worth reproducing.

### 2026-11-26 — Architecture is free to differ

**Decision.** Debar does not follow any reference scanner's internal structure. The layers are in [ARCHITECTURE.md](./ARCHITECTURE.md).

**Why.** The footprint and start-time aims come from the design, mainly from compiling signatures into an image that is mapped instead of loaded.

### 2026-11-26 — One engine with a native mode and a compatibility mode

**Decision.** The native interface is the core. Compatibility with another scanner's commands, protocol, parameters and configuration is a part translated onto it (Constitution §11). Scanning a file streamed over HTTP belongs to native mode.

**Why.** One engine to prove and maintain, and a compatibility part can be added for another scanner without touching the engine.

### 2026-11-26 — First release is Linux on amd64 and arm64

**Decision.** The first release covers the daemon, its client, the one-shot scanner, the updater and the signature tool, on Linux. The rest is in `DEFERRED.md`.

**Why.** It matches how the scanner is deployed today. Linux-only techniques stay in the platform layer so other systems remain possible.

### 2026-11-26 — Build it whole; borrowed code only in builds that are not releases

**Decision.** Debar is built piece by piece and proved by comparison until it covers everything. An intermediate build may link reference scanner code to measure resource gains early; a release contains none (Constitution §13).

**Why.** Early measurements are worth having, and a release that still depends on borrowed code would not be the product.

### 2026-11-26 — GPL version 2 only

**Decision.** Debar is licensed under the GNU General Public License version 2 only.

**Why.** It is the licence the people switching already accept, and a hosted service is unaffected by it. A more permissive licence is deferred until there is legal advice.

### 2026-11-26 — Debar's code is its own, and study material is private

**Decision.** No code is copied or translated from a reference scanner (Constitution §3). Its source, databases and every note about how it works inside live in the git-ignored `study/` folder (Constitution §4). Committed files name a reference scanner only to say Debar supports its signature format and to state the surface Debar is compatible with.

**Why.** Debar is not a copy of another scanner and must not read as one if it is opened up. Keeping the engine free of any one format also lets more formats be added.

Compatibility is not copying: it is stated as the surface a user sees (commands, parameters, protocol messages, configuration options, output) and never as the code behind it.

**Replaces** the earlier working assumption, never recorded here, that code could be ported directly from the reference scanner.

### 2026-11-26 — Requirements are kept with lazyspec

**Decision.** Requirements live in `specs/*.lazyspec.md`, each married to a test that repeats its words (Constitution §7).

**Why.** A requirement that nothing proves drifts from the code. One area for the whole repository until the layers exist as crates.

### 2026-11-27 — Mozilla Public License 2.0, the same terms for everyone

**Decision.** Debar is licensed under the Mozilla Public License 2.0. No one, its authors included, holds rights others lack, and no part of Debar is closed. Contributions are signed off under the Developer Certificate of Origin instead of a contributor licence agreement (Constitution §14).

**Why.** The owner will release Debar as real open source and compete on the hosted service, support and a compiled image feed: may the best service survive. Anyone, a company included, may use, host, sell and ship Debar and link it as a library from their own program without asking. Changes to Debar's own files come back when a changed Debar is shipped. Corporate licence policies generally accept the MPL, where the AGPL is often refused on its name alone. Contributors give their work on the same terms as everyone else, which is the promise that Debar can never be closed. Debar is written from scratch, so no other code fixes its licence, and loading signature databases as data does not bind it.

**Considered.**

- GPL version 2 only: anyone may host a changed Debar without sharing, and linking it binds the linking program.
- AGPL version 3, alone or with a linking exception and commercial licences: makes hosted competitors share changes, but its name deters companies, and the exception would need custom legal text.
- EUPL 1.2: covers network use and allows linking, but is little known to corporate policies.
- PolyForm Shield or the Elastic License 2.0: forbid competing or hosted resale without permission, and are not open source.
- Open core, with closed paid add-ons: not open source as a whole, and deters contributors.

**Replaces** "GPL version 2 only" of 2026-11-26.

### 2026-11-27 — Databases come from our own mirror

**Decision.** Debar's updater fetches databases from a mirror Debar's operators run, never from the format publisher's own servers. The mirror is filled with the publisher's supported mirroring tool.

**Why.** A publisher may rate-limit or block clients it does not recognise. A mirror filled the supported way keeps Debar's supply within the publisher's rules, and lets a hosted service compile once and hand images to every scanner. The reasoning that names the publisher is in the format's study folder.

### 2026-11-27 — The toolkit

**Decision.**

- **Build.** One Cargo workspace, one crate per layer, each crate created when its piece starts. Rust 1.100.0 is pinned in `rust-toolchain.toml`; one dated nightly is pinned beside it for fuzzing, Miri and sanitizers only.
- **Environment.** One container image, pinned by digest, built in CI and published to GitHub's container registry. CI and developer machines run the same image; on macOS it runs in a Linux virtual machine. Linux-only code, checks and measurements run in it.
- **Checks.** Every check is an `xtask` command, so the same command runs locally and in CI, and the CI workflows stay thin.
- **Lints.** clippy pedantic, and denied in the workspace lint table: `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `as_conversions`, `string_slice`, `todo`, `unreachable` and `undocumented_unsafe_blocks`. `unsafe_code` is forbidden in every crate but the platform crate.
- **Gates and layers.** clippy's `disallowed_methods` and `disallowed_types` keep files, sockets, memory maps, the clock and randomness inside the platform crate (Constitution §9). cargo-deny `bans` with `wrappers` allow only the platform crate to depend on crates that reach those resources, and allow each layer's crate only as a dependency of the layers above it (Constitution §10). An `xtask` check over `cargo metadata` stands in wherever `wrappers` cannot express a rule.
- **Supply chain.** Exact versions and `--locked`; cargo-deny for licences, sources, advisories and bans; Cargo's minimum publish age of 14 days; cargo-vet for audits.
- **Tests.** cargo-nextest; proptest; cargo-fuzz with `arbitrary` for every format module; Miri on the platform crate; cargo-mutants and longer fuzzing weekly; cargo-llvm-cov for coverage.
- **Measurement.** Budgets (Constitution §12) are gated on instruction counts from gungraun, allocation counts, and proportional set size read from `/proc`, which counts a shared image fairly. Start time is measured with hyperfine. Wall-clock figures are recorded and never gate a change.
- **CI.** GitHub Actions on standard amd64 and arm64 runners. Actions are pinned to commit SHAs, each job gets only the token permissions it needs, `pull_request_target` is never used, and workflows are linted with zizmor. ClusterFuzzLite fuzzes each change; Debar applies to OSS-Fuzz once it has format modules.

**Why.** The aims are footprint and start time, so the budgets must be measured the same way on every run. Shared runners make time noisy, hence instruction and allocation counts. Hostile input is met by the compiler and lints, not by review. Every choice is one an agent arriving cold already knows, or reads as ordinary Rust. Standard runners are free for a public repository.

**Considered.** Buck2 and Bazel (a second build graph for little gain); Nix (most hermetic, hard for agents to read); `just` and `cargo-make` (a second language for every command); dylint and cargo-pup (nightly-bound or young); criterion (wall time, noisy in CI).

**Not yet verified,** checked when each is set up: whether clippy reads a separate `clippy.toml` per crate, whether rust-lld is the default linker on arm64 Linux, and whether `wrappers` expresses every layer rule.

### 2026-11-27 — The comparison harness is public, in its own repository

**Decision.** The harness that runs a reference scanner beside Debar lives in its own public repository, one per signature format. Debar's CI calls it as a reusable workflow pinned to a commit, against the change under test. It runs the reference scanner from its pinned image as a black box, through its public interfaces, and compares what a user or signature could observe. The databases come from that pinned image, never from the publisher's servers. How a reference scanner works inside stays in the private study folder.

**Why.** Comparison on every change, on free public runners, without the reference scanner's name or image entering this repository (Constitution §4) or any format entering the engine's repository (Constitution §11). The harness's own design is settled with piece 2.

### 2026-11-27 — The toolkit, as set up

**Decision.** The toolkit of the entry above is in place, with these settled while setting it up:

- **The image** is published by the `toolchain-image` workflow to `ghcr.io/mkhanal/debar-toolchain`, built natively on each architecture, and run by the digest committed in `toolchain-image`. `./in-toolchain` runs any command in it, locally and in CI.
- **The gates' exemption** for the platform crate is in its own lint table, not a `clippy.toml` beside it. The workspace forbids `unsafe_code`, `disallowed_methods` and `disallowed_types`, so no crate can allow them with an attribute; only the platform crate and `xtask` keep their own lint table, and `cargo xtask lint-tables` checks that each equals the workspace's but for its exemptions.
- **`missing_errors_doc` and `missing_panics_doc` are allowed.** Both are in clippy pedantic and demand doc comments, which the no-comments rule forbids.
- **The layer table** is `xtask/src/layers.rs`. It names each layer's crate (`debar-interfaces`, `debar-scan`, `debar-formats`, `debar-matching`, `debar-image`, `debar-platform`) and the tools beside the layers (`debar-compiler`, `debar-updater`), so every crate is placed before it is used.
- **A married test** for `specs/<stem>.lazyspec.md` is `<crate>/tests/<stem>_lazyspec.rs`, holding each requirement's text word for word.

**Why.** Each of these is the smallest arrangement that makes the rule a machine check rather than a review comment.

**What setting up found,** answering the three items the entry above left unverified:

- **Clippy reads a separate `clippy.toml` per crate.** It takes the nearest one to the crate and does not merge it with the root's, so a crate with its own file silently drops every gate. `cargo xtask lint-tables` therefore rejects any `clippy.toml` but the root's.
- **rust-lld is the default linker on amd64 Linux but not on arm64 Linux.** With Rust 1.100.0, `cargo rustc -- --print link-args` shows `-fuse-ld=lld` on `x86_64-unknown-linux-gnu` and the system linker through `cc` on `aarch64-unknown-linux-gnu`.
- **cargo-deny's `wrappers` expresses every rule between crates that exist and are named in `deny.toml`,** for normal, build and dev dependencies between workspace crates alike. It cannot reject a crate missing from the table, which `cargo xtask layers` does, and it does not know the table, so `cargo xtask layers` also checks that `deny.toml`'s wrappers match it.

### 2026-11-27 — Speed and footprint are hard, tested budgets

**Decision.** Start time, scan speed and memory are requirements with budgets, tested on every change (Constitution §12). The budgets, on the pinned databases and default settings, against the reference scanner measured on the same machine:

- **Ready to scan within 50 ms** with every official database loaded, from a compiled image. The reference takes about 5.8 s.
- **At most 64 MiB of private memory** once ready, the image itself being a shared, file-backed mapping. The reference peaks at about 972 MiB.
- **At least twice the reference scanner's throughput** on the standard benchmark corpus.
- **No growth past the memory budget while switching to a new image.** The reference builds a second engine beside the first.

Each becomes a requirement in `specs/` with its married test in the piece that first makes it measurable: start time and memory with the signature compiler (piece 3), throughput with the matching engine (piece 4), the switch with the updater (piece 8). CI gates on instruction counts, allocation counts and proportional and private memory, calibrated against these figures; wall-clock figures are checked as medians on the same runner class.

**Why.** The owner set speed and load speed as hard requirements. A budget nothing enforces erodes one reasonable change at a time. The numbers turn "near-instant" and "much smaller" into something a test can fail.

**Not yet settled.** The reference's throughput on the standard corpus is being measured; the corpus is defined in the study folder. A budget that proves unreachable is changed only by a person's decision, recorded here with the measurement.

### 2026-11-27 — Native mode screens, as well as scans

**Decision.** Native mode reports findings beside the malware verdict (macros, scripts and programs, encrypted content, PDF scripts and launch actions, links to outside content, content that disagrees with the file's name); refuses archive bombs, nesting too deep, expansion past a limit and scans over their time budget with a finding naming the limit; scans parts other scanners can miss, such as ZIP64 entries and files attached inside a PDF; and runs confined, with no network and no programs started, keeping nothing after answering, with back-pressure for a saturated scanner and refusal of a stalled sender. Compatibility mode does none of this beyond what the scanner it replaces does.

**Why.** A caller deciding whether to accept a file needs to know what it holds, not only whether it is known malware. Debar's format modules produce these facts while parsing, and facts are computed only when asked for, so the findings cost nothing when unused. One process then replaces a scanner plus a separate screening service in front of it. Extra detections in compatibility mode would be differences a signature can observe (Constitution §2), so they stay in native mode. Which file types to accept remains the caller's rule.

**Consequence.** Format modules (piece 6) record these facts; native mode (piece 9) reports them.

### 2026-11-27 — The comparison harness, designed

**Decision.** Piece 2 is built in its own public repository for the first signature format, under MPL 2.0, from these parts:

- **An observer for the reference scanner.** A small program linked to the pinned reference scanner's library through its public interface. It scans one input with every detection reported, and writes one record per object the scanner reaches: its depth, its parent, its type, its size, a hash of its bytes, and the detections raised on it. It runs in an image built from the pinned reference, published by the harness's own CI.
- **A report schema** both sides write: JSON lines, one object per line, versioned in the harness repository. Debar writes the same schema from a command of its own when it can scan (piece 4 onwards); until then the harness proves its Debar side against a stand-in.
- **A comparer** that lines up the two reports object by object and names each difference: an object one side reached and the other did not, a type, size or content hash that differs, a detection one side raised and the other did not.
- **An input builder** that turns each pattern signature into bytes it must match, and checks each built input against the reference scanner itself, so the builder is proved before it judges Debar. Hash signatures are checked by lookup instead.
- **A ratchet.** The harness keeps the list of differences already known. A run fails on any difference not on the list, and the list only shrinks as pieces land. Debar's CI calls the harness as a reusable workflow pinned to a commit.

**Why.** Object-by-object records show where two scanners part, not only that their verdicts differ, which is what every later piece needs to be checked against. Proving the input builder against the reference first means a failure always points at Debar. The ratchet lets the harness run on every change from the start, while most detections are still to be built, without hiding a regression among known gaps.

**Not yet settled.** Inputs that need a built executable around them (entry-point and section offsets) and logical signatures with conditions the builder cannot yet satisfy are reported as not built, counted, and taken up as the format modules arrive.

### 2026-11-27 — The image and the matching engine, designed

**Decision.** Pieces 3 and 4 are designed together, because the image's layout exists to serve the matcher.

- **Who holds what.** `debar-image` holds the engine's own, format-neutral signature model, every section's layout with its builder and its lookups, and the validated view over a mapped image. `debar-matching` holds per-scan state: streaming, candidate verification, logical evaluation and outcomes (a detection, a type found, a rescan request, a program trigger, do-not-cache). Each signature format is a part beside the compiler that may use only `debar-image`; it turns its databases into the model and an account of every line. The compiler holds no format knowledge. The platform crate maps the file; nothing else touches `mmap`.
- **The image.** One immutable file per database set, little-endian records with no alignment needs, sections on 4 KiB boundaries ordered from what start needs to what only a detection reads, a checksum on the header and on each section. Start reads only the header and its small tables; the updater verifies every section before publishing. Every access is bounds-checked, so a damaged image can give wrong answers but never undefined behaviour. The same databases compile to a byte-identical image on every platform.
- **Hashes.** One sorted table per purpose and algorithm, a directory of sizes that also decides which digests an object needs, and a binary fuse filter of our own that is probed in place.
- **Patterns.** Signatures are grouped by the kind of object they apply to; a table in the image maps Debar's object kinds to groups, so the engine never learns a format's type numbers. Each pattern is indexed by its rarest fixed bytes in a hashed four-byte filter per group, sized for the cache; patterns tied to a known offset skip the filter. Matching is one continuous stream with a look-back, verified by one of three program shapes. Logical signatures are parsed into trees when the image is built and evaluated after the walk; the lever for executable throughput is gating each logical signature on one rare part and counting the rest in a bounded second pass.
- **Regular expressions.** A linear-time engine whose compiled forms live in the image.
- **Order of work.** Hashes end to end first, which makes the start and memory budgets measurable on most of the data; then fixed patterns, all object kinds, logical signatures (where the throughput budget is written), regular expressions and the remaining subsignatures, the carried tables, and tuning.

**Why.** Everything the scanner needs at start is a page or two of a shared, file-backed mapping, so start is bounded by opening one file and private memory holds only per-scan state. Grouping by object kind keeps a document scan from touching the executable signatures that are most of the data. A filter with one independent memory read per byte is cheaper than walking a large automaton held in memory.

**Considered.** Matching owning the lookup code while the compiler owns construction (two crates agreeing byte for byte); the format part inside the compiler (a format inside a layer-side tool); a double-array automaton or an off-the-shelf multi-pattern crate as the main filter (kept as measured baselines: neither can be read in place); hashes without a filter (every miss touches the large table).

**Budget definition.** Private memory is counted as anonymous plus privately dirtied memory, excluding the image mapping, because the kernel reports a file page mapped by one process as private even though it is shared and reclaimable.

**Not yet settled,** measured as the slices land: start cost and image size; the reference scanner's windowing and detection order; per-scan state under hostile input times threads; whether a regex engine that never gives up may stand where the reference's gives up after a step limit (a difference for a person to decide, recorded in the study folder). The full design, with figures and the reference-specific reasoning, is kept in the study folder.

### 2026-11-27 — Hash signatures end to end, as built

**Decision.** Slice 1 of the image and the matching engine is in place, with these settled where the design left them open:

- **The first signature-format part** is `debar-clamav-signatures`, in `crates/clamav-signatures/`. The layer table gains a placement for signature-format parts: a part may use only `debar-image`, and only `debar-compiler` may use a part. The reference-mentions check treats a part's crate and path names as a statement that Debar supports its format, so `Cargo.toml`, `deny.toml` and the layer table may name it.
- **Requirements are proved from outside.** The `acceptance` crate sits outside the product, like `xtask`, and is exempt from the gates. Its tests build the release binaries and run `debar-compiler` and `debar` as a user would. They run one at a time.
- **The pinned databases for tests and CI** come from the comparison harness's published image, never from the publisher. The image's digest and each file's SHA-256 are committed beside the part, with the script that copies them out. CI runs that script on the runner before `cargo xtask check`.
- **cargo-deny bans only crates that something may use.** A crate nothing may depend on, such as `debar-interfaces`, cannot be banned with an empty wrapper list, because cargo-deny then bans the workspace member itself. `cargo xtask layers` still rejects any dependency on it. `cpufeatures`, which asks the kernel only which processor features exist, may depend on `libc`.
- **Miri** runs the platform crate's tests with isolation off, so the filesystem gate is checked. Miri cannot map a file, so the mapping tests are ignored there. The one `unsafe` call, the mapping itself, is covered by the native tests.
- **The start budget's gate** is the instruction count, under callgrind, of starting, becoming ready and scanning one small file. It must be at most 50,000,000, which is the 50 ms budget at one instruction per nanosecond. That rate is well below what the runners sustain, which leaves room for system calls and page faults the count does not see. The gate also requires at most 512 KiB of the image resident once ready.
- **The memory budget's gate** reads `/proc/<pid>/smaps` while Debar waits to read its input from a named pipe, that is, once ready. For each mapping other than the image, it counts the larger of `Anonymous` and `Private_Dirty`, since the two overlap.
- **A duplicated hash key reports the entry loaded last.** The reference's choice depends on its own sort; the difference is recorded in the study folder for a person to decide.
- **A malformed hash line fails the compile**, as it fails the reference's load. Every line ends with one outcome: compiled, outside the functionality level, ignored, a comment, not a signature, or not yet compiled.
- **The image** keeps its accounting totals in the compiler's account report, not in its header. Its size directory samples every 64th size instead of indexing the top 16 bits, because most sizes are small. The fuse filter's parameters are computed in integers.
- **`debar comparison-report`** writes the harness's report for one top-level object. It is named for comparison runs and is not native mode's interface.
- **The toolchain image** carries `g++`, which libFuzzer needs.

**Why.** Each is the smallest arrangement that lets the slice's requirements run on every change, deterministically, without naming the reference scanner outside the paths allowed to.

**Measured** on the pinned databases, in the toolchain image on an Apple Silicon Mac (aarch64 Linux VM, 12 cores):

| Figure | Value |
| --- | --- |
| Hash signatures compiled | 3,213,878, with 7 removed by an ignore list |
| Compile time | 5.4 s median of 5 (`hyperfine`), 700 MiB peak resident |
| Image | 90 MB: names 20.1 MB, section hash entries 53.4 MB, whole-file hash entries 10.8 MB, filters 3.6 MB, size directories 2.0 MB |
| Start, readiness and one small scan | 420,212 instructions; 2.1 ms wall-clock median of 300 (`hyperfine -N`), recorded and not gated |
| Once ready | 64 KiB of the image resident, 140 KiB private |
| Hash lookups, need and lookup without the digest | about 2.0 million whole-file and 2.9 million section lookups per second |

**Not yet settled.** Calling the comparison harness's reusable workflow from CI: that workflow file would name the reference scanner, so it needs a place in the reference-mentions allow-list first.

### 2026-11-27 — Generic extended signatures end to end, as built

**Decision.** Slice 2 of the image and the matching engine is in place, with these settled where the design left them open:

- **The pattern model** is format-neutral: masked bytes, one byte from a set, gaps, choices of strings, a string of a width equal to none of a set, tests of the bytes before and after a match, and a placement (anywhere, from the start, before the end, each with a shift). The part reads the format's text into it and decides which file types, offsets and quirks apply; the engine knows none of them.
- **A pattern is split only at unbounded gaps.** Each piece is one verification program, checked over sets of positions, so bounded gaps up to 1 MiB stay inside it. Pieces chain: each must start at or after the earliest end of a valid chain through the one before. Nested alternatives are expanded into strings when the image is built, at most 4,096.
- **One pattern section per signature group**, holding its parts in one section: a four-byte anchor filter of 32 bits per distinct anchor (128 KiB for the generic group), its bucketed anchor table, a two-byte filter and table for pieces with no four-byte run, a list of pieces with no anchor, the placed signatures, the signatures and the programs. Anchors are chosen by rarity from a table of byte costs measured on the benchmark corpus.
- **The scan is one stream.** The object's length is given up front, so end-relative placements resolve before the first byte. Candidates are verified first in, first out by anchor position, so chains and the order of detections do not depend on how the object is cut into chunks.
- **Each signature is reported at most once per object**, in the reference's order: by report window, then a rank the part writes (bodies of plain bytes first), then position. The windows' length and overlap are image data written by the part. Without every-match, the scan stops once the window of the first strong detection is complete.
- **A malformed extended line fails the compile**, as it fails the reference's load. The account gains outcomes for a target the format does not load, an offset that never reports, and an offset that needs executable facts.
- **Property tests use a small deterministic generator of their own.** proptest would bring `rand` into the workspace, which the bans keep inside the platform crate.
- **The comparison workflow** is `.github/workflows/comparison.yml`, the one workflow allowed to name the reference scanner, because it names the harness it calls. The harness gained a ratchet per scanner under test, rules covering a kind of difference on every input, a difference for a detection reported a different number of times, and a mode that scans an input built from every buildable signature of a target type.

**Why.** Each keeps the format in the part and the engine format-neutral (Constitution §11), keeps the scan's memory bounded by the image rather than the input (§8), and makes the result independent of chunking and scheduling (§16).

**Measured** on the pinned databases, in the toolchain image on an Apple Silicon Mac (aarch64 Linux VM):

| Figure | Value |
| --- | --- |
| Pattern signatures compiled | 34,049: 34,007 generic `.ndb` lines and 42 `.ndu` lines |
| Image | 98 MB, of which the pattern section is 7.9 MB; compile 5.6 s |
| Start, readiness and one small scan | 887,355 instructions; 2.4 ms wall-clock median, recorded and not gated |
| Once ready | 64 KiB of the image resident, 124 KiB private |
| Generic pattern scan, the two benchmark tars as raw objects | 138 MiB/s, against about 68 MiB/s for the reference's raw scan with the same 34,019 lines loaded (study folder) |
| Comparison, 40,001 built inputs | Every input detected under the signature it was built for, by both scanners; the remaining differences are in the harness's ratchet for Debar |

**Not yet settled.** How many times a signature is reported, and through which passes and normalised views, which come with the scan core and format modules; the window overlap, which the reference takes from a signature not compiled yet; and the reference's windowing quirks, each recorded in the study folder for a person to decide. The throughput budget is written with logical signatures (slice 4).

### 2026-11-27 — Every extended-signature target and file typing, as built

**Decision.** Slice 3 of the image and the matching engine is in place, with these settled where the design left them open:

- **Object kinds are Debar's own.** `ObjectKind` in `debar-image` lists every kind of object the signature format can name. The part maps the format's type names onto it and writes an object-kinds section: for each kind, its name in the format, its signature groups in the order they run (its target's group, then the generic group), its rank when a type is recognised, how a full scan matches its own bytes (not at all, as itself, or as another kind) and which kinds it re-types when a full scan finds it, and whether it is an executable. The engine runs what the table lists and knows no target number (Constitution §11).
- **One pattern section per group.** Each target compiles into its own group; type recognition is a group of its own whose outcome is a type found at an offset, never a detection.
- **Executable placements** (entry point, section start, last section, whole section, version information, and end-relative placements in an executable) are resolved per object, in 32-bit arithmetic modulo 2^32 as the reference resolves them, against an `ExecutableLayout` the caller supplies. It is asked for only when the object's kind is an executable; without one, those placements and every end-relative placement in that scan match nothing, as when the reference cannot parse the header. They are tested with synthetic layouts until the executable format modules (piece 6) parse real ones.
- **Typing** is the scan core's first job, in a new `debar-scan` crate: magic from the first bytes, then text, wide text or binary data from bytes the part lists as never in text, then type recognition over the first bytes with the ranks the part writes, then the wide-text retry. After a full scan, a recognised kind re-types the object where the part says it does. `debar comparison-report` uses it to type the top-level object, skip the raw scan and hash lookup for kinds whose own bytes are never matched, and report the kind's name. The scan core's recursion is not built.
- **Parts are split where the reference splits them**, at every `*` and every gap the format does not rewrite into wildcards, and each part remembers its first end and its latest eight, overwritten in turn: the reference's memory, which can lose a match when a part recurs. A program no longer holds a bounded gap between parts.
- **The window overlap is the reference's longest pattern part per group**, counted from every body it loads, logical subsignatures included though they are not compiled yet. That reproduces the reference's 8,000 bytes for the generic group and every target group's value.
- **A hash key listed more than once** is stored once, under the name the reference reports, which the part computes from the reference's documented ordering of a size bucket and its lookup; the other lines are accounted as shadowed. The rule was checked against the study folder's model of it on 400 keys.
- **Not reproduced, reproduced if observed:** a right-edge class passing at every window end, a variable body accepted past a window end, a lone bracket byte lost at a window start, bodies equal but for bracket distances checked once, a part occurrence in a window overlap recorded twice, and the exchange of a part's first and found ends. None can change a detection on the pinned databases as far as the study folder shows; each is recorded there. A crash of the reference (a leading negated class, `SL+n` with no sections) is never reproduced.
- **Not yet built, recorded as gaps:** the second wide-text retry (its conversion is not studied), the tar and archive refinements of typing, and the reference's built-in type table, used only when no file-type database is loaded.

**Why.** Each keeps the format in the part, makes the result independent of how the object is cut into chunks (Constitution §16), and reproduces what a signature can observe (Constitution §2) wherever the pinned databases can observe it.

**Measured** on the pinned databases, in the toolchain image on an Apple Silicon Mac (aarch64 Linux VM):

| Figure | Value |
| --- | --- |
| Compiled | 3,212,354 hash signatures (1,524 shadowed), 105,901 pattern signatures in 12 target groups, 256 file-type lines (189 magic, 67 recognition) |
| Image | 123 MB, of which the PE group is 20.9 MB and the generic group 8.4 MB; compile 7.8 s |
| Start, readiness and one small scan | 1,278,024 instructions; 1.9 ms wall-clock median, recorded and not gated |
| Once ready | 64 KiB of the image resident, 128 KiB private |
| Generic pattern scan, the two benchmark tars as raw objects | 98 MiB/s, against 133 MiB/s before parts were split where the reference splits them and about 68 MiB/s for the reference |
| Comparison | Inputs built for targets 0 (40,001, with the boundary inputs) and 4 (1,064): every one detected by both scanners under its signature. Targets 3 (3,958) and 7 (1,565): detected by the reference only, through normalisation not built yet, judged by their own ratchets. The top-level type agrees on every input and fixture, which closes the rule for untyped objects; no other known difference changed |

**Not yet settled.** Recovering the throughput the reference's part split costs (anchoring a bounded part from its predecessor instead of the filter is the first candidate), with the throughput budget in slice 4.

### 2026-11-27 — Logical signatures and the throughput budget, as built

**Decision.** Slice 4 of the image and the matching engine is in place, with these settled where the design left them open:

- **Every logical line is read as the reference loads it,** check by check in the reference's order: what fails the whole compile, what is skipped and why, the expression without operator precedence (lenient leaves, rejected modifiers on a single group), the target description block, and content subsignatures with their offsets and the `i`, `w`, `f` and `a` modifiers. A line holding a regular-expression, byte-comparison, image fuzzy hash or macro subsignature is accounted as not yet compiled (slice 5); an unknown attribute or type name is accounted as not loaded. The prefilter load rule the study found also applies to extended bodies. Expressions nest at most 256 deep, where the reference has no limit; nothing official nests deeper than 3.
- **The image holds a logical section per group:** postfix expressions, a count ceiling per subsignature (counts saturate there, deciding as exact counts do), the conditions, and the signatures that would hold with no match (none officially). Subsignatures compile into the group's pattern section. A section names the category of every potentially unwanted signature, filtered at scan time by a "category contains" or "does not contain" setting that the compatibility part will fill from the scanner's options. The section directory may now span more than one page.
- **Gated matching.** Each signature is gated on the cheapest set of its subsignatures whose absence makes the expression false; only those enter the main filter. After the main pass, if a gate fired for a signature with subsignatures left out, the object is matched a second time with an automaton built for the armed signatures alone (`aho-corasick`, MIT, the design's named baseline; a DFA up to 1,024 programs, a contiguous NFA up to 8,192, the full stored tables above that). Results equal a single full pass; a property test against a naive evaluator proves it.
- **Counting** follows the study: a single-part subsignature counts each distinct start; a subsignature in parts counts each completion. Counts are kept as a set of starts bounded by the ceiling, so the order a second pass finds them in does not matter.
- **Throughput levers** besides gating: a filter precomputed in the image for each set of groups an object kind selects, probed once per position before any group's own filter; later parts with only a two-byte anchor searched only once their predecessor matched; case-insensitive anchors in their own filter; a subsignature skipped once its count is saturated.
- **Per-scan state (A8)** is bounded by the image: at most 4.8 MiB per scan for the largest kind (Windows executables), of which 1.4 MiB is the second pass's automaton (`cargo run --release -p debar-matching --example logical_state_bound -- IMAGE`).
- **The throughput budget** is a requirement (`specs/scan-speed.lazyspec.md`). Its gate counts instructions per MiB on fixed generated slices of each corpus kind and on system files from the toolchain image, against a budget per kind: the instructions Debar would execute at twice the reference's single-threaded wall-clock rate, at the instructions per nanosecond Debar measured on that kind of the standard corpus (13.4 to 15.5 on the measuring machine). Those rates were measured on aarch64; on x86_64 the same scans execute 1.26 to 1.29 times the instructions (text, binary, PDF, OLE2 and tar slices, measured on the CI runners), so the budget there is scaled by 1.27. The reference was measured with every parser, normaliser and signature program Debar lacks switched off (study folder, `measure-raw-scan.sh`).
- **Image residency once ready is measured from a cold page cache.** The image is mapped with random access advised over the whole of it before its header is read, so starting reads only the header and directory pages. A warm cache, as left by compiling the image just before, lets the kernel map whole large folios on the first touch (2 MiB on the arm64 runner), which depends on the kernel, not on what Debar reads; the gate therefore drops the image from the page cache before starting.
- **`debar measure-scan`** reports scanning throughput over files, for measurement; **`debar comparison-report`** takes `--potentially-unwanted` with an optional category filter.
- **Not built, recorded as gaps in the harness's ratchets:** `HandlerType` re-scans (reported to the caller as a rescan request; the scan core is piece 5), icon groups (piece 6), the reference's second matching pass over binary data and normalised text (pieces 5 and 6).

**Why.** Each keeps the format in the part (Constitution §11), reproduces what a signature can observe (§2), and bounds memory by the image rather than the input (§8).

**Measured** on the pinned databases, in the toolchain image on an Apple Silicon Mac (aarch64 Linux VM):

| Figure | Value |
| --- | --- |
| Logical lines | 321,093 compiled, 1,303 not yet compiled (slice 5), 7 ignored, of 322,403; 1,511,984 content subsignatures |
| Image | 465 MB (the PE pattern section 278 MB); compile 14.5 s |
| Start, readiness and one small scan | 3,335,557 instructions; 2.0 ms wall-clock median; 8 KiB of the image resident from a cold cache, 148 KiB private once ready |
| Throughput, Debar against the reference (MiB/s, one thread) | system files 53.6 / 16.1; text 89.9 / 30.5; binary 93.5 / 26.8; PDF 65.8 / 25.3; OLE2 62.9 / 15.9; tar 73.9 / 28.5; gzip 89 / 32.4; tar.gz 90 / 30.9; ZIP 74 / 2.0; OOXML 75 / 2.0; HTML not matched raw / 14.2 |
| Comparison | Inputs built from logical signatures: target 0, 749 of 750 detected (the other needs a regular expression); target 4, 5 of 5; targets 3 and 7 only through normalisation, judged by their own ratchets. Extended inputs of target 0 now all 40,001 detected |

### 2026-11-27 — Regular expressions, byte comparisons, image hashes and container signatures, as built

**Decision.** Slice 5 of the image and the matching engine is in place, with these settled where the design left them open:

- **Regular expressions run in `regex-automata`** (`=0.4.18`, MIT or Apache-2.0, with `regex-syntax` `=0.8.11`), on bytes with Unicode off and leftmost-first matching, in linear time. The supervisor chose it to make progress; **the owner has not decided the engine**, and the choice is recorded as open in the study folder together with the alternatives.
- **The part translates each pattern itself** into the engine's syntax tree, with the signature format's semantics written into the tree: ASCII-only classes and case folding, `.` short of a newline, the end of the subject also before a final newline, and the `U` flag swapping greed. A pattern needing a backreference, lookaround, an atomic group, a possessive quantifier, recursion, a conditional or a control verb is accounted as needing a backtracking engine and not loaded; on the pinned databases that is 56 lines (62 subsignatures). A pattern the format would refuse fails the compile.
- **The image holds a section per group** of regular expressions (trigger, placement, flags, the stored pattern, and forward and reverse dense automata read in place when they fit in 256 KiB together), byte comparisons and a sorted table of image fuzzy hashes, and one section of container signatures with an automaton for each entry name, in the order they are tested. Automata start on 8-byte boundaries; where a mapping is not aligned, they are copied before use.
- **Matching after the walk.** A scan whose groups hold any of these asks for the whole object once the passes are done (`ScanEnd::WholeObjectNeeded`), then, per group, applies byte comparisons, then image hashes, then regular expressions in load order, each counted as the format counts it, before evaluating. A signature holding one of these keeps every content subsignature in the main pass, so the second pass never depends on them.
- **The regular-expression size limit** is a setting (`largest_object_for_regular_expressions`); `debar comparison-report` defaults it to the format's 104,857,600 bytes and takes `--largest-regular-expression-object`.
- **The image fuzzy hash is a fact the caller supplies** (`PatternRequest::image_fuzzy_hash`); computing it is piece 6. **Container signatures are matched against entry facts the caller supplies** (`container_entry_detections`); parsing archives is piece 6. Both are tested with synthetic facts.
- **Not kept across scans:** compiled patterns that are not in the image are compiled again in each scan that needs them (45 on the pinned databases). A bounded cache comes with the daemon if measurement asks for it.

**Why.** A linear engine bounds the time any input can take (Constitution §8) and its automata can be shared from the image rather than built per process; translating the patterns in the part keeps the format out of the engine (§11).

**Measured** on the pinned databases, in the toolchain image on an Apple Silicon Mac (aarch64 Linux VM):

| Figure | Value |
| --- | --- |
| Logical lines | 322,340 compiled, 56 needing a backtracking engine, 7 ignored, none not yet compiled; 1,161 regular expressions (1,114 with automata in the image, 21 MB), 1 byte comparison, 109 image fuzzy hashes |
| Container signatures | 133 compiled, 2 ignored; section 1.2 MB |
| Image | 488 MB; compile 15.6 s (`hyperfine`, 3 runs) |
| Start, readiness and one small scan | 4,053,061 instructions; 8 KiB of the image resident from a cold cache, 184 KiB private once ready |
| Throughput, share of the budget (twice the reference) | text 77 %, binary 67 %, PDF 86 %, OLE2 55 %, tar 70 %, system files 54 % |
| Comparison | The 27 acceptance cases for regular expressions and byte comparisons gave the same detections in both scanners |
