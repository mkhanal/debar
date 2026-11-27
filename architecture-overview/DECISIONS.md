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

### 2026-11-27 — Every pinned database file compiled, verified containers and a backtracking matcher, as built

**Decision.** Slice 6 of the image and the matching engine is in place, with these settled where the design left them open:

- **A backtracking matcher of Debar's own** runs the regular expressions the linear engine cannot express (backreferences, named or numbered; lookahead and lookbehind; atomic groups; possessive quantifiers; a `$` followed by what can match the final newline). The supervisor chose it; the owner has not reviewed it. The part's translator now builds one format-neutral tree (`ExpressionTree`, in `debar-image`); a tree with a linear form still goes to `regex-automata` exactly as before, and any other is compiled into a program section of fixed-width instructions read in place. A lookbehind must have a longest match (each length in its range is tried, ending at the current position); a repeated group that matched nothing stops repeating after that pass; a backreference to a group that took no part fails.
- **Its bounds** (Constitution §8): 100,000 steps from one start position (each choice pushed, and each retry of a repeated byte), 2,000 open choices, 65,536 backtracking entries and an instruction allowance per step; exhausting any is "no match" for that search, as the reference treats its own limits. The counting is Debar's own: where exactly PCRE2 gives up is not reproduced, and the difference stays recorded in the study folder. Nesting of lookaround and atomic groups is capped at 32 and programs at 65,536 instructions when the image is built. The bounds are a parameter (`BacktrackingBounds`), smaller in the fuzz target.
- **A construct Debar does not support** (recursion, conditionals, `\K`, `\G`, `\R`, verbs, callouts, Unicode properties, quantified assertions) leaves its line "not yet compiled"; none occurs in the pinned databases. The account no longer has a "needs a backtracking engine" outcome.
- **Containers are verified in the part**, in the reference's order: for a `.cvd`, its detached `<name>-<version>.cvd.sign` if it is among the files, then the header's MD5 and signature; for `.cvd` and `.cld`, the signed `.info` index; for every container, each member's size and SHA-256. `.cud`, the unsigned container, now compiles, its members unofficial and unsigned. Every database records how it was verified (`Provenance`). Synthetic containers in the part's tests are unsigned, since no signing key is held; the signed path is proved on the pinned databases.
- **The detached signature is trusted by its root**: the chain inside the signature must reach a certificate whose SHA-256 is that of the root the reference ships as its trust anchor, each certificate's signature checked by its issuer's key. **Certificate validity dates are not checked against the clock**, so whether a database loads never depends on the time (Constitution §16); the reference refuses outside the certificates' validity and so differs there, which a signature cannot observe. A first line `#clamsign` with no version, which makes the reference abort, is treated as "cannot verify". A trust-anchor directory option comes with the compatibility interface.
- **Cryptography**: `cms` `=0.2.3`, `x509-cert` `=0.2.5`, `der` `=0.7.10`, `const-oid` `=0.9.6`, `base64ct` `=1.8.3` parse the signatures, all Apache-2.0 or MIT. The RSA arithmetic is `num-bigint` `=0.4.8` (MIT or Apache-2.0) with Debar's own PKCS#1 v1.5 padding check, **because the `rsa` crate depends on `rand_core`, which the dependency bans keep to the platform layer** (Constitution §9).
- **Engine switches** are evaluated when the image is compiled, in load order, from each module's default; the image records a set of Debar's own engine features (91, in Debar's words), never the format's module words. A switch read before a file decides whether that file loads: certificate rules need the certificate switch, URL rules the phishing engine, programs any program engine.
- **Carried sections** (cold, decoded on demand by the piece that uses them): certificate rules in the reference's lookup order, newest first, with the serial comparison the reference stores (a blank serial stops it for every later line of the file) and duplicates shadowed; icon signatures with their two group name tables; URL rules with their kind, list, verdict and, for expressions, the stored text and a search automaton. Whether an expression rule loads, or loads but can never match, follows the study's description of the reference's fixed-tail rule, modelled in the part (a trailing unquantified group is expanded branch by branch).
- **Signature programs** are parsed and checked with the reference's load-time and preparation checks into a format-neutral program section; inputs the reference leaves undefined are refused. A program's trigger compiles as an ordinary logical signature whose outcome is `RunProgram` or `HookTriggered`; matching reports these as program triggers, never as detections, until piece 7 runs them. Programs outside a signed container are kept with that provenance: the image is a superset and the unsigned-program setting applies where programs run.
- **Image layout version 6.** Logical signature records carry their outcome.
- The acceptance helper compiles the official image once per test process, since parallel compiles exceeded the memory of the build machine.

**Why.** Every line of the pinned databases now has a compiled outcome (piece 3), each format detail stays in the part (Constitution §11), verification keeps a changed database out (§1), and the matcher's bounds keep hostile input finite (§8).

**Measured** on the pinned databases, in the toolchain image on an Apple Silicon Mac (aarch64 Linux VM):

| Figure | Value |
| --- | --- |
| Account | 3,647,104 compiled, 3,251 outside the functionality level, 1,528 shadowed, 1,168 not signatures, 22 ignored, 6 comments, none not yet compiled |
| Regular expressions | 1,223, of which 62 as backtracking programs; all 56 lines that held them compile |
| Carried files | 30 certificate rules, 222 icon signatures, 448 URL rules, 21 switch lines (none applies; 86 of 91 features on), 82 programs (80 with a trigger), 3 outside the level |
| Containers | main, daily and bytecode each verified by its detached signature |
| Image | 496 MB; compile 20.3 s (`hyperfine`, 3 runs), 2.1 GiB peak |
| Start, readiness and one small scan | 4,108,274 instructions; 2.8 ms wall-clock median; 8 KiB of the image resident from a cold cache, 168 KiB private once ready |
| Throughput, share of the budget (twice the reference) | text 77 %, binary 67 %, PDF 86 %, OLE2 55 %, tar 70 %, system files 55 % |

### 2026-11-27 — Aim for fifty times the reference's speed, and never lose speed once gained

**Decision.** Twice the reference scanner's throughput stays the hard floor in `specs/`. Above it, the target is fifty times the reference on every kind of file in the standard corpus, single-threaded and at equal concurrency for the daemon. Each corpus kind's instruction budget is a ratchet: it is set to the best measured figure plus a small tolerance, so a change that slows Debar fails even while it is still above twice the reference. A budget only tightens; loosening one is a person's decision, recorded with the measurement that forced it.

**Why.** The owner set fifty times as the aim: the reference is not a fast baseline. A floor alone would let speed already won drain away one reasonable change at a time.

**Consequence.** Performance is a standing track, not a final slice: each stage is profiled, work no signature can observe is skipped, and the larger levers (a SIMD prefilter behind a safe platform primitive, cheaper verification, cheaper digests, parallel scanning of independent objects) are measured against every corpus kind. Progress against fifty times is reported with every change that moves it.

### 2026-11-27 — The scan core, designed

**Decision.** Piece 5 builds the scan core in `debar-scan` to this shape:

- **Layers.** One scan owns a stack of layers, at most the recursion limit deep. Each layer keeps ordered evidence (strong, potentially unwanted, weak), its kind and how it changed, its facts, lazily computed digests, and whether it is trusted or must not be cached. A popped layer's evidence merges into its parent; a trusted layer contributes nothing. Whether an alert is strong or potentially unwanted is decided when the image is built, so the engine never reads a signature's name.
- **Steps per object,** in a fixed order with fixed hook points: too small, count against the limits, type, cache, format modules that run before the object's own bytes, the object's own matching, logical outcomes in evaluation order (detections, rescans as another kind, program triggers), embedded objects, extra passes for the kind, modules that run after, finish. A strong alert ends the scan unless every match is asked for; false-positive trust is checked on every alert, for the layer and every layer above it.
- **Format modules are pulled, one part at a time.** The scan core asks a module for its next part and scans it completely before asking again, so limits, cut points and first-match stops fall where the reference's order puts them. Modules never call each other and never decide what is scanned next.
- **Input.** Scanned content is read only by positional reads through the input gate, which bounds and counts every read and treats a file that changes during the scan as a failure, never a silent truncation. A bounded page pool sits in front of it. Scanned files are never memory-mapped, because a file truncated while mapped would kill the process. Extracted content is a window onto its parent, bytes a module produced, or a producer that can decode again.
- **Limits** go through one ledger per scan, counting as the reference counts. The scan time limit is a deterministic work budget, converted from the configured time by a fixed constant, so a verdict never depends on the machine's speed (Constitution §16). A daemon may add an optional wall-clock watchdog, off by default, whose firing is reported as an error, never as a verdict.
- **The clean cache** lives in the daemon only, is bounded, and is keyed on the content's full hash, its length, the image, the settings that change detections and the object's ancestry. A hit charges the object's recorded use to the limits, so a cache can never change a verdict. It is on by default in the daemon, and can be switched off.
- **Reports.** A scan always returns a report: the verdict, the reported detections in the reference's order, whether the scan completed and why not, every limit that was reached, and the facts gathered when findings are asked for. Compatibility mode renders it as the reference does; native mode reports every limit and failure as a finding.
- **Concurrency.** Independent files are scanned in parallel; each scan is single-threaded and owns its state, and only the image and the verdict-neutral cache are shared. A scan's memory is bounded at 32 MiB; the daemon reserves that bound for each scan it admits, which gives native mode its back-pressure.
- **Streamed input** larger than the in-memory threshold is spilled to an unlinked temporary file through the filesystem gate, the only temporary file Debar makes, gone when it is closed.

**Why.** Every rule above is one a signature can observe, kept, or one it cannot, made deterministic. Pulling parts one at a time is the only order that reproduces where the reference cuts a scan short.

**Consequence.** The scan logic that grew inside the interfaces layer for the harness moves into `debar-scan`, and the input gate is rebuilt to bound its reads, before anything else. Text moves to piece 6, because it is matched through the script normaliser, the first format module. Matching reads such objects through the input gate as "Whole-object matching reads through pages" below records. The full design, with the reference-specific reasoning, is in the study folder.

### 2026-11-27 — The throughput ratchet, the scan profile and a cheaper prefilter, as built

**Decision.** The first piece of the performance track is in place, with these settled:

- **The ratchet.** `acceptance/best-scan-speed.json` records, per architecture and corpus kind, the best instructions per MiB measured as the twice-the-reference requirement counts them. A second requirement in `specs/scan-speed.lazyspec.md` fails a change that scans more than 2 % above a record, and fails one that scans more than 2 % below it until the record is lowered to the new figure, printed in the failure; so a record only tightens, and raising one is a visible edit for a person to decide. The two requirements share one measurement, cached under a key of the binary, the image and the slice generator, since the counts are deterministic.
- **The tolerance is 2 %.** Instruction counts repeat exactly for one binary and input; 2 % absorbs differences between machines of one architecture (a runner against a local virtual machine) and small unrelated changes, and is still well inside any gain worth recording. The x86_64 records were measured under amd64 emulation (OrbStack on Apple Silicon, valgrind in the toolchain image); CI's figures replace them if they differ by more than the tolerance.
- **The profile.** `cargo run --release -p acceptance --bin scan-profile [IMAGE [DEBAR]]` generates the same slices as the requirement, runs cachegrind without cache simulation on each kind and on an empty run, groups each function's own instructions into stages by a table of name rules in the tool, subtracts the empty run per stage and prints instructions per byte per stage and kind beside the twice and fifty times targets (also written as `target/scan-profile/profile.json`). Stage entry functions are marked never to be inlined so their bodies keep their names. Callgrind's toggles and entry dumps were tried first and rejected: its call tracking on the aarch64 binary missed returns and most entries (4 of about 64 entries dumped). Limits: code inlined into a function counts where it is inlined; the type-recognition scan inside typing counts as prefilter and verification.
- **The lever: the prefilter**, the largest stage on every kind (86 to 93 instructions per byte). The per-position tests now run in a loop with no calls, which looks for the next position the precomputed selection filter (four-byte and two-byte) or the armed-part filter admits, and only there does the per-group work; the armed-part filter holds every case variant of each anchor, so no position is lowered to test it; the two-byte filters are fixed-size arrays with no bounds check. The hits, and their order, are those of the previous loops. 31 instructions per position, from 81.
- **No SIMD yet.** The test is a hashed bitset load per position, which vector units without gathers do not speed up; whether baseline intrinsics are safe to call on Rust 1.100 (A13) is still open.

**Why.** The owner's aim of fifty times the reference needs every stage measured and speed once gained kept (the decision before this one); the prefilter was the largest stage everywhere.

**Measured** on the pinned databases, in the toolchain image on an Apple Silicon Mac (aarch64 Linux VM), on the requirement's slices. No detection changed: Debar's report was byte-identical before and after on the harness's 48,354 built inputs and fixtures, the slices and the system files, and every acceptance test passes.

| Instructions per byte, before → after | text | binary | PDF | OLE2 | tar | system |
| --- | --- | --- | --- | --- | --- | --- |
| Prefilter | 87.9 → 32.8 | 86.4 → 31.2 | 88.7 → 33.7 | 92.6 → 34.3 | 86.4 → 31.3 | 92.8 → 38.0 |
| Digests (MD5 and SHA-256, in software) | 40.0 | 40.0 | 40.0 | 40.0 | 40.0 | 40.0 |
| Second pass search | 0 | 0 | 39.8 | 44.4 | 1.4 | 39.7 |
| Verifying candidates | 31.4 | 29.4 | 29.0 | 26.5 | 22.7 | 39.1 |
| Allocating and copying | 9.3 | 7.8 | 11.4 | 9.6 | 8.7 | 12.6 |
| Selecting signatures | 5.6 | 5.6 | 5.5 | 6.2 | 5.5 | 1.7 |
| Scan total | 176.2 → 122.5 | 171.1 → 117.1 | 218.8 → 165.2 | 221.6 → 164.5 | 166.7 → 112.7 | 228.4 → 175.6 |
| Share of the budget (twice the reference) | 77 % → 53 % | 67 % → 46 % | 86 % → 65 % | 55 % → 41 % | 70 % → 47 % | 55 % → 42 % |
| Times the reference, single-threaded | 2.6 → 3.7 | 3.0 → 4.4 | 2.3 → 3.1 | 3.6 → 4.9 | 2.9 → 4.2 | 3.6 → 4.8 |
| Fifty times the reference would be | 9.1 | 10.2 | 10.1 | 16.1 | 9.5 | 16.7 |
| Wall-clock on the standard corpus, MiB/s, median of 3, before → after (recorded, not gated; a shared machine) | 61 → 76 | 65 → 104 | 21.0 → 21.1 | 23 → 29 | 34 → 46 | 45 → 58 |

On x86_64 (emulated) the same slices run 1.33 times the aarch64 instructions on text and binary and 1.27 to 1.35 on PDF, OLE2 and tar; system files differ by architecture. The real PDF corpus did not speed up: its time goes to stages the slices barely exercise, which the profile should be pointed at next.

**Next levers, by the profile:** the digests (40 per byte on every kind: SHA-256 in hardware behind a safe primitive, A13), the second pass search (about 40 per byte where it runs: the armed anchors through the same call-free filter instead of an automaton built per scan), verification (23 to 39), and the copy of every chunk into the retained buffer.

### 2026-11-27 — The scan core's first slice: the top-level object

**Decision.** Build steps 0 and 1 of the scan core are built to the agreed design, with these choices at this scale:

- **The input gate** is `debar_platform::input::ScannedFile`: the length is fixed when the file is opened, every read is positional, bounded by that length and counted against an allowance, and a read that ends early is `ChangedWhileScanned`. The allowance is eight times the scan-size limit, so a scan may read each byte it counts a fixed number of times; with the limit off there is none. A file that is not a regular file (a pipe) is read once and held in memory up to 16 MiB, until streamed input is designed with piece 9. No page pool yet: the top-level object is read sequentially, pass by pass, in 128 KiB chunks, and the whole-object digests are taken on the first pass when it reads to the end.
- **An object that needs its regular expressions, byte comparisons or image fuzzy hash matched** is handed to matching as `ObjectBytes`, which reads it as the entry "Whole-object matching reads through pages" below says.
- **The layer stack** always holds the top level, so there is always a current layer; nested layers are pushed by the next slice. Weak indicators are dropped until the clean cache needs them.
- **False-positive trust** needs its own digest need (`whole_object_trust_digest_need` in matching), since a database may list false positives without any hash signature.
- **A first-match scan stops at the first strong alert that survives trust**; matching stops the pass at the same window boundary, and the scan core skips the hashes, the logical outcomes and the re-typing after it, as the reference does.
- **Reports within one window are ordered by where the match starts**, not by Debar's anchor, which can lie anywhere in the body. This is what first-match makes observable: a body that is a later part of a longer one is reported after it.
- **The top-level `MaxFileSize` case** reports nothing found and records the limit; the alert for an exceeded limit arrives with the limit alerts in the next slice.
- **`comparison-report` stops at the first strong detection by default**, as the reference does; `--every-match` and `--heuristic-precedence` select the other settings. An incomplete scan fails the command, since the harness's report cannot say so. `measure-scan` scans with the default settings.

**Why.** Each is the smallest form of the agreed design that the top-level object needs, and leaves the stack, the ledger and the report shaped for children, modules, the work budget and the cache.

**Consequence.** The comparison runs without every match as well as with it. Without it the reference and Debar disagree on which name to report on 74 of the 40,001 target-0 built inputs, where two plain bodies start at the same byte, recorded in the harness's first-match ratchet until the reference's order for them is known.

### 2026-11-27 — The scan core's passes per kind

**Decision.** Build step 2 of the scan core is built, with these choices:

- **The image says which kinds are matched again, and as what.** Each kind in the object-kinds section may name a kind its own bytes are matched again as, after its own pass; the part names other data for binary data, compiled Python and AI models. The engine knows no kind by name for this (Constitution §11).
- **The extra pass is chosen by the kind typed from the first bytes**, not by a kind the object's own pass re-types it to, as in the reference.
- **Every pass is a full pass:** patterns of the named kind's groups, then whole-object hashes, then logical outcomes, each alert checked for trust and able to end a first-match scan. The extra pass recognises no types. Digests are taken once per object and reused by each pass that needs them.
- **Each signature is reported at most once per pass**, so a generic signature or a listed hash on binary data is reported twice under every match, as the reference reports it.
- **Kinds whose own bytes are never matched** (HTML typed from its first bytes, ignored kinds) are neither matched nor hash-checked; both rules are now requirements.
- **Not built:** the reference's mail-target pass over text that its own pass re-types to mail, which comes with the mail parser and the script normaliser in piece 6, and runs after the normaliser there.

**Why.** Each reproduces how many times, and as which kind, the reference matches an object's own bytes, which a signature observes through its report count and through signatures for other data (Constitution §2).

**Consequence: two throughput records are raised**, because the reference does the same work. The slices for binary data and tar hold files typed as binary data (every 1 KiB tar slice file is cut short of a full archive), which now get their second full pass; on small files that is the whole matching cost again. Instructions per MiB, aarch64: binary 96,193,508 → 98,252,603, tar 97,169,301 → 104,644,572; x86_64, scaled from CI's calibrated records by the aarch64 ratio since emulation counts fewer instructions than CI: binary 140,131,592 → 143,131,215, tar 141,218,852 → 152,082,872 (CI's figure replaces these if it differs by more than the tolerance). Every kind stays within twice the reference. Taking the second pass's generic-group results from the first instead of matching them again is a matching change for the performance track.

**Measured** in the toolchain image on an Apple Silicon Mac, with the harness's 40,001 built target-0 inputs and its fixtures, with and without every match: no new difference; 75 lines of `debar-known-differences.jsonl` (a generic signature reported twice by the reference and once by Debar on binary data) no longer occur.

### 2026-11-27 — Work is tracked as claimed GitHub issues, as in the owner's other product

**Decision.** At the owner's request, Debar tracks work the way the owner's other product does, with the same semantics, so several agents can work in parallel without taking the same work:

- **Issues and the board.** Work is GitHub issues of type Task, Bug or Feature, in this repository and the comparison harness's, on one project, "Debar" (https://github.com/users/mkhanal/projects/2), linked to both. Its Status is Open, In Progress, In Review or Done; the board sets Open when an item is added and Done when it closes or its pull request merges. Its fields are Branch, Lines changed, Files changed, Why it matters, and the single-select Theme, Kind, Area and Impact, whose options and definitions are Debar's own, held on the board and chosen by `.claude/skills/claim/work-classification.md`. An issue states the problem or outcome, its evidence and how we will know it is met, never the solution.
- **Claims.** An issue is held by the branch in its Branch field while that branch exists on GitHub, or by an open pull request that closes it; one branch may hold many issues, and an issue one branch at a time. Claiming publishes the branch, records it with the status from the branch's pull request, makes the claimant the only assignee, then reads the board again and reports `lost` if a simultaneous claim overwrote it. An unattended run claims by creating `autofix/<n>` on GitHub, which only one run can create. A hand-back labels the issue `agent-blocked`, keeps pushed work on `autofix/<n>-draft` and returns it to Open. The `assign-issue-creator` workflow assigns every new issue to whoever opened it.
- **Skills** `work`, `explore`, `fix`, `build`, `claim`, `pr`, `autofix`, `autofix-schedule`, `worktree` and `work-status`, catalogued in `.claude/README.md`. Debar's lanes replace the other product's: design agreed and recorded here, requirements through `/lazyspec`, tests first, the `signature-expert` for anything about a reference scanner, `cargo xtask check` and the comparison.
- **The scripts are `xtask` tasks in Rust**: `claim`, `check-claim`, `classify-work`, `record-pull-request-size`, `ready-for-review`, `claim-next`, `hand-back` and `issue-brief`, with the claim, queue, board-item, size, classification and brief rules as pure functions tested in `xtask/tests/`, and every GitHub call made through `gh` with the caller's `GH_TOKEN`. They run in the toolchain image like everything else, so the image now carries `gh` (Debian's 2.46.0). Steps that are a few `gh` or `git` commands (`worktree`, `work-status`, scheduling with launchd, cron or T3 Code) are instructions in their skill. The host-side runner a schedule starts, which creates worktrees and starts agent processes outside the image, is a short POSIX shell script, `.claude/skills/autofix/run-unattended`, like `in-toolchain`.

**Where Debar differs, on purpose.**

- **A push to `main` may land claimed work** without a pull request, when whoever directs the work asks for it (AGENTS.md, "Handing work to an agent"): the commit carries the `Closes` lines and the branch is deleted after the push.
- **`needs-decision`** labels an issue that waits on a person's decision; unattended runs pass it over like `agent-blocked`. The other product has no such label; its product labels are not copied.
- **The board does not add issues by itself.** A user-owned project's auto-add workflow cannot be configured through the API, so issues are created with `--project Debar`, and a claim or classification adds any issue that is missing. The other built-in workflows were copied with the board.
- **No local cache** of the board's fields and item ids: each task reads them from GitHub, a few calls more for the same answers.
- **No diagram evidence gate** in `ready-for-review` and no screenshot rules in `pr`: Debar has no diagrams directory or screens; its evidence is text.
- **The T3 Code schedule loops in its own conversation** rather than through a runner script, since `t3` runs on the host; launchd and cron run `run-unattended`.
- **Lockfiles** left out of a pull request's size are `Cargo.lock` files.

**Why.** Parallel agents in separate worktrees need one place that says who holds what, checked and changed atomically enough that two never start the same work; the owner chose the workflow already proven on the other product.

**Consequence.** AGENTS.md: work starts by claiming its issue, and hands in through the `pr` skill. Harness issues are claimed on the board by hand until the harness repository has the tasks.

### 2026-11-27 — A filtered second pass and cheaper verification, as built

**Decision.** The second step of the performance track, with these settled:

- **The second pass searches through a filter, not an automaton.** The armed signatures' anchors (at most 8,192 programs, as before; above that the image's stored second-pass tables) are put, per scan, into a 65,536-bit filter of their first two bytes (every case variant for case-insensitive anchors) and a table hashed on those two bytes, case-folded. The search tests eight positions per branch against the filter, and only where one may hold looks the position up in the table and compares the whole anchor as one word. The hits, and their order at each position (exact anchors before case-insensitive ones, two-byte before four-byte, then the order the signatures were armed in), are those the automaton gave. `aho-corasick` is no longer a dependency of Debar's own code. The search state is at most 296 KiB per scan, from 1.4 MiB, so the largest per-scan logical state is 3.7 MiB (Windows executables), from 4.8 MiB.
- **A candidate is ruled out by its anchor first.** A candidate with one possible start whose anchor sits at a fixed distance in its program is dropped when the object's bytes there are not the anchor, before its signature record or program is read. This is what most placed candidates are: the signatures tied to an offset are verified on every object, and on a small text file they are about 3,600.
- **A run is matched only where its first exact byte occurs.** For a run of bytes tried at a range of starts, the starts are found by searching for the first byte the run fixes exactly, eight bytes to a word in safe code, or by testing the first byte where none is fixed (`memchr` measured within 0.6 instructions per byte of this, and is not used: its unsafe code has no recorded review, Constitution §18); a candidate stops at its earliest match, which is all it needs.
- **The x86_64 records come from CI's runners, not from emulation.** Instruction counts under amd64 emulation on Apple Silicon ran 2 to 4 % below those of CI's ubuntu-24.04 x86_64 runners on the same binary, more than the tolerance, so the records measured under emulation failed CI. This is a calibration, not a loosening: each x86_64 record is CI's figure for the code before this step, scaled by this step's speed-up as measured under emulation, and is replaced by CI's own figure if that differs by more than the tolerance. The aarch64 records stay measured locally, which CI's arm64 runners confirm.
- **The set of starts holds its first range inline**, so a candidate with one range of starts, nearly all of them, allocates nothing.

**Why.** The profile of the first step put the second pass search (about 40 per byte where logical signatures arm it) and verification (23 to 39) next after the prefilter; the digests are being reorganised with the scan core and were left alone.

**Measured** on the pinned databases, in the toolchain image on an Apple Silicon Mac (aarch64 Linux VM), on the requirement's slices. No detection changed: Debar's report was byte-identical before and after on the harness's 46,844 built inputs and fixtures, with and without potentially unwanted signatures, on the slices, the toolchain's system files and the standard corpus (6,387 files), and every acceptance test passes.

| Instructions per byte, before → after | text | binary | PDF | OLE2 | tar | system |
| --- | --- | --- | --- | --- | --- | --- |
| Second pass search | 0 | 0 | 39.8 → 7.0 | 44.4 → 7.1 | 1.4 → 0 | 39.7 → 12.3 |
| Verifying candidates | 31.4 → 11.0 | 29.4 → 8.6 | 29.0 → 12.6 | 26.5 → 8.5 | 22.7 → 9.9 | 39.1 → 25.9 |
| Allocating and copying | 9.3 → 3.2 | 7.8 → 2.6 | 11.4 → 4.2 | 9.6 → 3.1 | 8.7 → 3.0 | 12.6 → 5.4 |
| Prefilter (unchanged) | 32.8 | 31.2 | 33.7 | 34.3 | 31.3 | 38.0 |
| Digests (unchanged) | 40.0 | 40.0 | 40.0 | 40.0 | 40.0 | 40.0 |
| Selecting signatures (unchanged) | 5.6 | 5.6 | 5.5 | 6.2 | 5.5 | 1.7 |
| Scan total | 122.5 → 95.4 | 117.1 → 90.7 | 165.2 → 108.2 | 164.5 → 102.1 | 112.7 → 92.4 | 175.6 → 127.2 |
| Share of the budget (twice the reference) | 53 % → 42 % | 46 % → 36 % | 65 % → 43 % | 41 % → 26 % | 47 % → 39 % | 42 % → 30 % |
| Times the reference, single-threaded | 3.7 → 4.7 | 4.4 → 5.5 | 3.1 → 4.7 | 4.9 → 7.8 | 4.2 → 5.1 | 4.8 → 6.6 |
| Fifty times the reference would be | 9.1 | 10.2 | 10.1 | 16.1 | 9.5 | 16.7 |
| Wall-clock on the standard corpus, MiB/s, median of 3, before → after (recorded, not gated; a shared machine) | 70 → 106 | 107 → 125 | 53 → 62 | 68 → 97 | 88 → 92 | 25 → 41 |

The stage rows were profiled before this change met the scan core's first slice and with `memchr` in place of the safe byte search; the shares, the multiples and the records are measured on the code as committed, which runs within 1 % of those totals (HTML 2.3 per byte).

A 1 KiB text object costs 2.4 M instructions beyond the scan's start, from 5.0 M. The HTML slice, not matched raw, falls from 4.3 to 2.0 per byte.

**Why the real PDF corpus did not speed up.** Profiled with cachegrind over its 396 PDFs (104 MiB): 209 instructions per byte before this step, 167 after, against 108 on the PDF slice. The difference is whole-object matching, 54.6 per byte on real PDFs and 3.0 on the slice, nearly all of it Debar's backtracking matcher (51 per byte: the machine 22.3, the search loop 16.8, reading each instruction from the image 12.1). One logical signature does it, `Pdf.Exploit.CVE_2019_5067-7054139-0`: its regular expression holds a back-reference, so no linear engine can run it, and its trigger is `/Parent` and `/Kids`, which every real PDF holds and the generated slice does not. So the expression is searched over the whole of every PDF.

**Next levers, by the profile:** the digests (40 per byte on every kind); the prefilter (31 to 38); on real PDFs, a necessary condition checked in linear time before the backtracker (the expression with each back-reference widened to the language of its group, compiled when the image is built: if it finds nothing, the backtracker cannot match either, and a search it gives up counts as no match too), and reading each backtracking program once instead of per instruction; on system files, the cost per anchored candidate (25.9 per byte, mostly the lookups `verify` does before it reaches the bytes); and placing the signatures tied to offsets on every object (about 0.9 M of a small object's 2.4 M instructions), which could be sorted when the image is built.

### 2026-11-27 — Memory safety, as enforced

**Decision.** Constitution §18 is held by these checks, each of which fails a change that breaks it:

- **The promise in every root.** Every crate root outside the platform library, its integration tests, examples, binaries, build scripts and every fuzz target included, begins with `#![forbid(unsafe_code)]`, as well as inheriting `unsafe_code = "forbid"` from the workspace lint table. `cargo xtask unsafe-code` reads every target from `cargo metadata`, for the workspace and for `fuzz/`, and fails on a root without it, so a new crate or test cannot omit it.
- **The inventory.** `UNSAFE_BLOCKS` in `xtask/src/unsafe_code.rs` lists each file allowed unsafe code and how many blocks it holds: `crates/platform/src/mapped_file.rs` (the mapping) and `crates/platform/src/effective_user.rs` (`geteuid`), one each. `cargo xtask unsafe-code` counts `unsafe` blocks in every tracked Rust file, ignoring comments and strings, and fails on a block in an unlisted file, a count that differs, or any unsafe function, implementation, trait, extern block or attribute anywhere, so the platform layer's interface stays safe and every unsafe operation is a block.
- **One operation per block, each stated.** The workspace and the three crates with their own lint tables deny `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`, `unnecessary_safety_comment` and `unsafe_op_in_unsafe_fn`. Miri runs the platform crate's tests on every change; it cannot run file-backed mappings, and runs `geteuid`. No outside data reaches either block: the mapping's bytes reach the image reader, which is fuzzed (`image_open`, `image_sections`).
- **Shared memory only in a form others cannot change.** `MappedFile::open` maps only an `UnchangeableFile`: a regular file with no write permission for anyone, owned by the user Debar runs as or by the administrator. Anything else is refused with an error naming the file, before a byte is mapped. The compiler publishes its image through `publish_read_only_file`, which creates the partial file with mode `0444` and moves it into place. Cost: one `fstat` and one `geteuid` at start, no memory. Requirements in `specs/signature-databases.lazyspec.md`.
- **Dependencies' unsafe code.** `cargo xtask dependencies` scans the source of every registry package in the resolved graph of the workspace and of `fuzz/`, for both release targets, and fails while one with unsafe code has no review in `unsafe-reviews.toml` at its exact version, or a review names a package that no longer needs one. Each review says what the unsafe code does, whether the product or only the tools reach it, and what was read.

**Why.** Each clause becomes a check a change cannot pass by accident. The unsafe-code counter is a few dozen lines of xtask reusing one lexer for Debar's files and its dependencies', where cargo-geiger would add a tool for one number. The review list is ours rather than cargo-vet's: cargo-vet records audits against broad criteria and would begin by exempting every crate, which records nothing about unsafe code; the list records exactly the review §18 asks for, and a version bump voids it. cargo-vet stays in the toolchain for wider audits.

**Considered, for the mapped image.** A private copy of the image (sound everywhere, but about 90 MB of private memory and of reading at every start, against budgets of 64 MiB and 50 ms); reading through a gate that copies out of the mapping (every lookup and filter probe would copy, and truncation still raises `SIGBUS`); a sealed memfd (immutable, but each process would copy the file into it, unless a long-lived process hands it out); file leases (they notify, they do not prevent); fs-verity (the kernel refuses every write and truncation, even the administrator's, at no private-memory cost, but needs a filesystem and kernel with it enabled, which neither the CI runners' nor the development machines' filesystems have been shown to be). Permissions and ownership were chosen because they hold on every filesystem today at no cost.

**Not yet closed.** The administrator, the owning user after making the file writable, and writers outside the local kernel's permission checks (network and userspace filesystems) can still change or shorten a mapped image. The `// SAFETY:` line on the mapping says so. Issue #26 holds the problem for the owner.

### 2026-11-27 — Parity is the verdict and the set of detections, not their order

**Decision.** For the same file, databases and settings, Debar gives the reference scanner's verdict; asked for every detection, the same set of names; asked for one, a name the reference reports for that file when asked for every detection, of the same class (Constitution §1). The order detections are found in, and how often one repeats, are not part of the result. Native mode offers every detection on request.

**Why.** The owner set parity as: the input is what is scanned, the output is what is wrong with it. Order never changes a verdict: whichever strong detection comes first, the file is infected and potentially unwanted findings are held back the same way. It only changes which genuine name is shown when a file matches several signatures. Reproducing the reference's order needed its load-order hashing and, for some ties, its memory addresses, which cannot be computed at all.

**Replaces** the requirement of the same name in single-detection mode implied by the earlier wording of Constitution §1, and the plan to replay the reference's anchor order in the compiler.

### 2026-11-27 — People choose their signature sources

**Decision.** A signature source is one publisher's signatures in a supported format, carrying where it is fetched from, how it is verified, the terms it may be used under and how often it changes. Each deployment chooses its sources by configuration. The updater fetches and verifies each source by its own rules; the compiler builds every chosen source into one image; every detection names the source it came from. Sources come in three steps after the first release (ROADMAP pieces 10 to 12): third-party sets in the first format, a second format with its own reference scanner, and hash and indicator feeds.

**Why.** The owner wants other publicly available signatures usable on top of the first format's official databases, and each deployment to decide what it trusts. The engine already knows no format (Constitution §11), so a source is configuration plus, for a new format, a new part.

**Consequence.** Parity (Constitution §1) holds per format against that format's reference scanner loading the same chosen sources. A source's terms are checked before it is used: some public sets allow free use but forbid redistribution, which bears on a hosted service distributing compiled images. Replaces the deferred item "More signature formats".

### 2026-11-27 — Whole-object matching reads through pages

**Decision.** Matching after the walk takes the object as `ObjectBytes` (the trait now lives in the platform layer's input gate, beside `ScannedFile`) instead of one in-memory slice, so a file up to the file-size limit is scanned to its end:

- **An object of at most 4 MiB is read whole** into memory and matched as before, by `regex-automata`'s own search.
- **A larger one is read through a pool of 32 pages of 128 KiB** (4 MiB), most recently used kept, owned by that one call and freed after it. Regular expressions in the image run their forward automaton over the pages and their reverse automaton back from the match end, with the same start, look-behind and end-of-input rules as `regex-automata`'s search, skipping bytes an accelerated state stays on. One compiled from its text at scan time runs as `regex-automata`'s lazy automaton the same way, with its cache never given up. The backtracking matcher reads its subject through the same pages, and a byte comparison reads its bytes from the input gate.
- **A read that fails part-way ends the scan `Incomplete`** with the input error (`PatternScanError::Input`, reported by the scan core as `ScanFailure::Input`); none is taken as the end of the object.
- **Every page read is counted against the scan's read allowance**, so each regular expression searching a large object to its end reads it once more. At eight times the scan-size limit, a 100 MiB file allows about thirty such searches before the scan ends `Incomplete`; none of the pinned databases' expressions came near it on the files measured.

**Measured.** A 100 MiB file whose six expressions (four in the image, one compiled from its text, one backtracking) are matched to its last byte: peak heap 4.13 MiB above a run that scans nothing (`valgrind --tool=massif`), 0.47 s to scan on an arm64 Mac in the toolchain image (`debar measure-scan`, 214 MiB/s), and the reference's set of detections. The streamed searches cost about 7 instructions a byte for an automaton in the image and 20 for one compiled at scan time. The scan-speed slices are at most 2 MiB, so they take the held path and their figures do not move.

**Why.** Memory mapping a scanned file was rejected (truncation raises SIGBUS), and holding the object whole costs its size in private memory. Pages keep a scan within its 32 MiB bound at any object size, and the held path keeps the measured speed of every object the benchmark corpus holds.

**Consequence.** The 16 MiB cap and `ScanFailure::TooLargeToHoldWhole` are gone, which answers open item A6 of the matcher design. Two requirements now hold this: "A File Up To The File-Size Limit Is Scanned To Its End" and "Scanning One File Holds At Most 32 MiB Of Memory".

### 2026-11-27 — SHA-256 in hardware, through the maintained digest crates

**Decision.** The digest crates move to `md-5` 0.11.0, `sha1` 0.11.0 and `sha2` 0.11.1, whose SHA-256 and SHA-1 run on the CPU's SHA instructions on arm64 as well as on x86_64, chosen at run time. No code of Debar's own changes; the unsafe code of each new or changed crate (`block-buffer` 0.12.1, `cpufeatures` 0.3.1, `hybrid-array` 0.4.15 and the three hashes) is reviewed in `unsafe-reviews.toml`.

- **The maintained crate, not our own.** On arm64, `sha2` 0.10 kept its hardware backend behind its `asm` feature, which also replaces the x86_64 SHA-NI path with `sha2-asm`'s software assembly and adds a C build; a platform-layer primitive of our own would be new unsafe code for what a reviewed crate already does. 0.11.1 is preferred to 0.11.2 (two days old), which changes only RISC-V and SHA-512 backends Debar does not use.
- **Every digest computed today is needed.** The whole-object need rule (an entry at the object's exact size, or of any size) asks for MD5 and SHA-256 on every object, because the pinned databases hold entries of any size for both: 11 MD5 and 2 SHA-256, all whole-file detection (`awk -F: '$2=="*"{print FILENAME, length($1)}'` over the unpacked `.hdb`, `.hsb`, `.hdu`, `.hsu`, `.fp` and `.sfp` files). No trust entry needs a digest at the sizes measured, and SHA-1 is not computed. So no digest can be skipped without changing what a signature observes.
- **MD5 is now the digest cost.** In software it is 9.6 instructions per byte (`md-5` 0.10.6 and 0.11.0 alike, 16 MiB under cachegrind), as much as the whole fifty-times budget on text (9.1), binary (10.2), PDF (10.1) and tar (9.5). No CPU Debar targets has MD5 instructions, and a stream's steps depend on each other, so vectors do not help.
- **x86_64 is unchanged where it is measured.** Valgrind does not run SHA-NI, so the scan profile and the ratchet on x86_64 still count software SHA-256: about 1 % fewer instructions under amd64 emulation, inside the tolerance, so the x86_64 records stay. On x86_64 hardware SHA-NI was already used before this change.

**Measured** on the pinned databases, in the toolchain image on an Apple Silicon Mac (aarch64 Linux VM). No detection changed: Debar's report (detections, verdict, type and the object's SHA-256) was byte-identical before and after on every eighth of the harness's 40,063 built inputs, sorted by path, and its fixtures (5,009 inputs), with and without every match, and every acceptance test passes.

| Instructions per byte, before → after | text | binary | PDF | OLE2 | tar | system |
| --- | --- | --- | --- | --- | --- | --- |
| Digests (MD5 and SHA-256) | 40.0 → 11.2 | 40.0 → 11.2 | 40.0 → 11.2 | 40.0 → 11.2 | 40.0 → 11.2 | 40.0 → 11.2 |
| Scan total | 96.0 → 67.5 | 93.2 → 64.8 | 108.4 → 80.0 | 102.4 → 73.9 | 99.2 → 70.9 | 126.3 → 98.0 |
| Share of the budget (twice the reference) | 42 % → 30 % | 37 % → 26 % | 43 % → 32 % | 25 % → 18 % | 42 % → 30 % | 30 % → 24 % |
| Times the reference, single-threaded | 4.8 → 6.8 | 5.4 → 7.8 | 4.7 → 6.3 | 7.9 → 10.9 | 4.8 → 6.7 | 6.6 → 8.5 |
| Fifty times the reference would be | 9.1 | 10.2 | 10.1 | 16.1 | 9.5 | 16.7 |
| Wall-clock on the standard corpus, MiB/s, median of 3, before → after (recorded, not gated; a shared machine) | 76 → 125 | 85 → 117 | 43 → 51 | 79 → 103 | 71 → 110 | 56 → 67 |

Other stages are unchanged within 0.5 per byte. Under amd64 emulation the digest stage goes from 63.5 to 62.1 per byte.

**Next levers, by the profile:** the prefilter (32 to 38 per byte), verification (9 to 25), and MD5 (9.6 on every object), which puts fifty times out of reach on text, binary, PDF and tar while the need rule asks for it on every object.

### 2026-11-27 — Embedded objects, re-typed objects and their limits, as built

**Decision.** Build step 3 of the scan core is built, with these choices:

- **Logical outcomes are one ordered sequence.** Matching returns detections, rescans as another kind and program triggers as `LogicalEvent`s in evaluation order; the scan core handles each in turn, so a rescan's child is scanned at its signature's place and a first-match abort inside it ends the evaluation.
- **Type matches are reported at every offset in an object's own pass.** There a type-recognition pattern is not marked done after its first match, so every offset it matches is a `TypeFound`. Typing from the first bytes weighs every offset too, as decided below ("Typing from the first bytes weighs every mark it finds").
- **The image says what a kind found at an offset does.** Each kind in the object-kinds section may be recorded at an offset and then either do nothing yet, re-type the object in place, or be scanned as an embedded object of a named kind, starting a fixed number of bytes before the match, each with a host condition (any, only in, not in). The typing rules carry how many offsets are recorded per object. The part writes these from its tables, dropping the action of a kind whose engine feature is switched off; the engine knows no kind by name for this (Constitution §11).
- **The walk** takes the recorded offsets in Debar's order (by offset), skips offset 0 and any offset not beyond the last one taken, and marks each taken offset as soon as it is taken. An embedded object is a window from there to the end of its parent, scanned with the given kind, no typing and no type recognition of its own. A re-typed object (a handler-type rescan) is a window over the same bytes, scanned with recognition on, and not rescanned again. A rescan refused at its push ends that pass's logical outcomes and loses the walk and the found-type re-type, as in the reference.
- **Layers** are pushed for every child, after the child is admitted against the limits and the recursion limit, and counted again when scanned; ids are given at the push, so a child refused before it has none. A popped layer's evidence merges into its parent unless trusted. `ObjectContext` holds the ancestors' current kinds and whether the layer is re-typed.
- **Limits.** The recursion limit is `Limits::deepest_level`; every refusal records a `LimitEvent`, marks the layers from the current one up not to be cached (`FinishedObject::cacheable`), and, when `alert_on_limits` is set, raises the first limit of the scan as a potentially unwanted alert whose name the image gives (a new engine-alerts section, written by the part).
- **`comparison-report`** takes the reference's limit options (`--max-files`, `--max-scan-size`, `--max-file-size`, `--max-recursion`, `--alert-exceeds-max`), writes one record for each object that was typed, and attributes a detection on an untyped layer to its nearest typed ancestor.
- **Not built, recorded:** children that need a format module's header check (ZIP, CAB and ARJ self-extracting archives, executables found in executables, ZIP or OLE2 files) and the MBR check before re-typing are only recorded and taken, so they move nothing; the reference's walk order is its recording order (unsorted, multi-part bodies recorded at their last part with earlier starts, window-overlap duplicates), Debar's is by offset; an executable marker in an executable, ZIP or OLE2 host is not counted towards the offset cap; under every match the reference drops a 128 KiB window's found type when an Aho-Corasick body matched in it, which Debar does not reproduce.

**Why.** Each rule is the reference's, read and measured in the study folder ("The embedded-object walk exactly"), and each changes which objects a signature sees.

### 2026-11-27 — The pass as other data reuses the groups the object's own pass matched, as built

**Decision.** Binary data, compiled Python and AI models no longer match the generic group a second time when their own bytes are matched again as other data:

- **Matching returns what each group it matched found** (`PatternOutcomes::matched_groups`): per group, its pattern detections with the end of each match, and its logical outcomes evaluated on their own. `PatternScan::reusing` takes them: a group of the new selection that the earlier pass matched is not matched again, its detections are re-ordered by the new selection's report windows and group order, and its logical outcomes take its place in the evaluation order, so the outcomes are those of matching every group again. Only the groups not matched before read the object; with none, the object is not read again.
- **A group is reused only when matching it again must give the same outcomes:** the earlier pass ran to its end (no strong match stopped it without every match), found no type in that group, was for an object of the same length, the same every-match setting and image fuzzy hash, and neither pass resolves executable offsets. Otherwise the group is matched again, as before.
- **The image has a selection filter for the groups a kind is matched again with beyond its own** (target 14 for binary data), so the remaining groups are prefiltered when a database has signatures for them. The pinned databases have none, so for them the pass as other data matches nothing again and keeps only its hash lookups and its alerts.

**Why.** The reference's pass as other data matches the generic group over the same bytes, settings and conditions as the object's own pass, so the generic group's outcomes are the same in both; matching it twice cost the binary and tar slices the whole matching cost again on small files (issue #30).

**Measured** on the pinned databases, in the toolchain image on an Apple Silicon Mac (aarch64 Linux VM). No detection changed: Debar's reports were byte-identical before and after, with and without every match, on 6,000 of the harness's built inputs drawn with seed 30 and its fixtures, and on 4,000 of those inputs prefixed with 20 bytes that type them as binary data (3,952 with detections); every acceptance test passes.

| Instructions per MiB, aarch64, before → after | binary | tar |
| --- | --- | --- |
| Scan total | 67,846,531 → 65,848,605 | 74,235,278 → 66,965,267 |
| Selecting signatures, per byte | 6.1 → 5.6 | 8.2 → 5.5 |
| Verifying candidates, per byte | 9.7 → 9.2 | 12.1 → 9.9 |
| Prefilter, per byte | 31.9 → 31.2 | 31.9 → 31.3 |

Both are back to where they were before the pass as other data was added, less the hardware SHA-256 gain since (binary 65.8 M, tar 66.8 M). The other kinds move by under 1 %. The x86_64 records are lowered by the same share of what the pass as other data had added there, 97 % (binary 143,131,215 → 140,220,715, tar 152,082,872 → 141,517,172), not measured natively; CI's figures replace them if they differ by more than the tolerance.

### 2026-11-27 — The format-module interface, as built

**Decision.** Build step 4 of the scan core is built, with these choices:

- **The interface is its own layer's crate, `debar-formats`,** below the scan core (Constitution §10), so a module depends on it and never on the scan core. It holds `FormatModule` (the kinds it claims, its stage, `open`, and an optional `header_check`), `PartSource` (pulled with `next`), `ModuleOutput` (a part, a container entry or a fact), `Part` with its bytes (a window of the object, bytes produced in memory, or a regenerable producer behind `ObjectBytes`) and its role (a child, typed from its bytes unless a kind is given, or a normalised view matched as a kind), `ModuleContext`, `ModuleError` (input or damage), `Fact`, `Limit` and `Object`. `BUILT_IN_MODULES` lists the modules `scan` uses; adding a format adds a module there and changes nothing in the scan core. `scan_with_modules` takes another list, for tests.
- **`Object` is a shared, cheaply cloned window** (`Rc`) onto the top-level bytes, produced bytes or a producer, so a layer, a module and its producers can all hold the bytes they read without borrowing from the scan core's stack. Layers hold `Object`s in place of the borrowed window.
- **The steps.** For each object: its kind's modules of the before-own-bytes stage, its own bytes, the extra pass, then the after-own-bytes stage. A re-type in the walk or after it runs the new kind's before-own-bytes modules at that point. The scan core asks for one output at a time and scans a part completely before asking again; a strong first-match alert anywhere ends the module and the scan.
- **Limits stay the scan core's.** A part is admitted at its push and counted when scanned, like any child. `ModuleContext::admit` lets a module check before it extracts; a refusal there is recorded by the scan core as the module returns. The context tells the module how its last part ended (scanned, trusted or refused for which limit), because what follows differs by format: ZIP goes on after a member refused for size and stops at its own file count, TAR stops at any refusal, HTML stops its views at the first that does not succeed.
- **Views** are pushed (a level, the limits checked) and never counted; only an empty view is skipped. They get a full pass of their kind with no type recognition: patterns, whole-object hashes, false-positive trust and logical outcomes, so a handler type can re-scan from one. They are invisible to container conditions and to the object observer.
- **A container entry** is tested against the container signatures on the container's layer as the module yields it, before its part.
- **Header checks.** When a found-at-an-offset kind is scanned as a kind whose module has a header check, the check decides: a failure makes no object, a length makes the object that long (zero meaning the rest, a length past the end cut to it) and moves the walk's last-taken offset to its last byte, so archives inside it are not taken.
- **Damage** ends that module's parts and becomes the fact `BrokenStructure` on the object; what its earlier parts found is kept and the steps go on. A read error from the input gate ends the scan `Incomplete`.
- **Facts** are format-neutral (macros, scripts, executable content, encryption, document actions, external links, a kind that disagrees with the name, expansion, overlapping parts, broken structure, unsupported variants), recorded per object, each at most once, and reported only when `ScanSettings::facts` asks.
- **Memory.** Produced bytes held across the stack are bounded at 16 MiB per scan (`MOST_PRODUCED_BYTES_HELD`); the context gives a module the room left, and a module over it must give a regenerable producer instead; producing more is a scan failure, a defect of the module. Views, entries and facts, which no limit counts, are bounded at 100,000 per scan, beyond which the scan fails; each limit is recorded once per object. These bounds are Debar's, invisible to a signature.
- **Proof** is a test-only container, `crates/scan/tests/modules/test_container.rs`, used by the requirements in `specs/container-parts.lazyspec.md` and by the fuzz target `scan_core`, which drives it from arbitrary input under limits drawn from the input and asserts no object deeper than the limit, no more objects than the file-count limit, and no allocation past 32 MiB above the heap held before the scan (the `cap` allocator, tests and fuzzing only).

**Measured.** A container nested three deep, each level decoding to a 24 MiB part, scanned with every part read to its end: 727,808 bytes of peak heap above what was held before the scan (`cargo test -p debar-scan --test container_parts_lazyspec`, debug build, toolchain image on an Apple Silicon Mac). The fuzz target ran 237,782 inputs in 300 s without a finding.

**Why.** Pulling one output at a time is what lets limits, cut points and first-match stops fall where the reference's order puts them; everything a module would need the scan core for is either an output it yields or a question the context answers, so a module needs nothing above its layer.

**Not built, recorded:** no real format module exists yet; the offset a re-type at an offset hands its parser (ISO 9660 and UDF) and the MBR check before re-typing; the ZIP header check's own container-signature test (no pinned container signature names a kind a self-extracting host can have); `Decrypted` inherited by children; native mode's wider reach (ZIP64, PDF attachments), which comes with the module that needs it.

### 2026-11-27 — The scan time limit as a work budget, as built

**Decision.** The scan time limit (`Limits::longest_scan`, `comparison-report --max-scan-time MILLISECONDS`, default 120,000, 0 switches it off) is built as the agreed design says, with these choices:

- **The unit of work is one byte-equivalent,** charged where the scan does work in proportion to its input: each 128 KiB chunk fed to a pattern pass (every pass: own bytes, the second pass, the pass as other data, views), charged before the chunk is matched, so the cut falls at a chunk boundary as the reference's falls at a window; each byte a regular expression's automaton searches in whole-object matching; and each instruction a backtracking expression executes, checked inside the search, so no expression runs past the budget. Admissions and counts check the budget (first, as the reference checks its clock first) but charge nothing; logical evaluation and byte comparisons charge nothing, since the image bounds them per object and the limits bound the objects. Format modules charge through the bytes of the parts they hand over; a module's own decoding is charged when the first real module needs it (piece 6).
- **Matching meters, the scan core owns the budget.** `debar_matching::WorkMeter` is charged by the scan core for the chunks it feeds and lent to `PatternScan::match_whole_object_within`, which returns `WholeObjectEnd::OutOfWork` when it runs out; `PatternScan::cut_short` gives the detections found before a cut. `match_whole_object` and every other entry keep their meaning, unmetered.
- **When the budget is spent** the whole scan stops: the body detections already found in the pass are kept, the object's hash and logical signatures are not evaluated, the limit is recorded, the layers above are marked not to be cached, and the alert `ScanTimeLimitExceeded` (named `Heuristics.Limits.Exceeded.MaxScanTime` by the signature-format part) is raised only under `alert_on_limits` and only if no limit alerted before. The scan completes with its verdict. This is what the study measured the reference doing on a timeout.
- **The conversion constant is 31,590 units per millisecond,** written into the code. Calibrated once: Debar's work on the standard corpus's system files (`debar measure-scan`, which now prints `work_units`: 666,858,070 for the 2,424 files) over the reference's median single-threaded scan time of the same files (21.11 s, study knowledge "Baseline: scan speed"). The system files are the part where both scanners scan nearly the same content; on kinds the reference scans more slowly (PDF, archives), Debar's budget is relatively larger, so Debar never stops a scan the reference, on the measured machine, would finish. At the default the budget is 3.79 × 10⁹ units, above the 1.12 × 10⁹ a scan of 400 MiB of such content takes, so it does not bind within the other limits' defaults.
- **The harness is unchanged.** Its inputs are far below the default budget.

**Measured.** Instructions per MiB on the ratchet's slices, aarch64, before → after: text 70,714,192 → 70,821,706 (+0.15 %), HTML 2,304,975 → 2,321,845 (+0.73 %), binary +0.06 %, PDF +0.15 %, OLE2 +0.11 %, tar −0.02 %, system −0.04 %; all within the 2 % tolerance, records unchanged.

**Not built, recorded:** the daemon's optional wall-clock watchdog (piece 9); bytecode timeouts (piece 7). How the reference's clean cache treats an object its time limit cut short is a difference for a person to weigh with the other time-limit differences (study notes); Debar never caches a layer above a limit.

### 2026-11-27 — Typing from the first bytes weighs every mark it finds

**Decision.** Typing a text or binary object from its first 1,024 bytes weighs every place a type pattern completes, in scan order, as the reference does; correctness comes first, since the type decides which signatures run (Constitution §1). Decided by the supervisor; built with these choices:

- **Two scans only when order can matter.** The first-bytes recognition scan still takes each pattern's first match (`GroupSelection::TypeRecognitionOnly`). Only when one of the kinds found always replaces (`RecognitionRank::always_replaces`) does typing scan the same bytes again with every offset weighed (`GroupSelection::TypeRecognitionAtEveryOffset`). Without such a kind the winner's priority only rises, so a repeated mark can never win and the first matches give the reference's answer.
- **A pattern in parts that gives the type starts again.** In the every-offset scan, matching keeps the running winner by the image's ranks (`RecognitionRank::replaces`, which the scan core's winner rule uses too) and forgets a multi-part pattern's remembered parts when its completion replaces the type, so it counts again only from a new first part; a completion that does not replace keeps them. This is the reference's rule (study notes, file-typing "Step 7 exactly", cases d25 to d38).
- **Test.** `Every Mark In A File's First Bytes Is Weighed In The Order It Is Found` (specs/file-typing.lazyspec.md) runs the cases the reference was run on through the official image. The case where an excluded self-extracting kind masks an XDP mark (d29) is left out: Debar's walk then re-types the object as XDP in place, and which type the comparison records for that object is a question about the walk, not about typing.

**Measured.** Instructions per MiB on the ratchet's slices, aarch64, before → after: HTML 2,321,846 → 2,330,339 (+0.37 %), text, binary, PDF, OLE2, tar and system within ±0.02 %; all within the 2 % tolerance, records unchanged. x86_64 not measured natively; the same code path runs, so a similar change is expected and CI's ratchet checks it.

### 2026-11-27 — Small objects pay for what they hold, not for every signature tied to an offset, as built

**Decision.** The cost of starting to scan an object is measured on small objects and kept as a ratchet, and the setup that cost every object the same whatever it held is gone:

- **Signatures tied to an offset are found by their anchor.** A signature placed a fixed distance from the start, whose first part has an anchor at a fixed displacement, is no longer listed for placement on every object: the image holds it in a table sorted by where its anchor must lie and by the anchor's bytes and case. Placement waits for the object's first bytes, looks up each anchor position the object reaches, and places only the signatures whose anchor is there (and every one whose anchor lies beyond the bytes fed so far, as before). The others are placed as before. A dropped candidate is one the verifier would have ruled out by its anchor with no other effect; the queue stays ordered by anchor, so whether a first-match scan stops is decided as before. The layout version is 7.
- **A program with no context before it** takes its starts as they are, instead of adding them one at a time.
- **An expression record is read only when it may run**: its trigger flags and signature are tested on the stored entry first.
- **A regular expression's reverse automaton is read only when the forward one finds a match end**, and **each automaton in the image is validated once per opened image** (`Image::validated_automaton`), not on every object: validating the 44 KiB automaton of one PDF signature's expression cost 156,000 instructions on every PDF.
- **A candidate's full program is read only after its header has passed** the anchor, already-detected, chain, category and armed checks.
- **The measure.** `scan-profile` prints a second table, instructions per small object by stage, over 64 generated objects of 1 KiB of each kind and the toolchain image's system files of at most 16 KiB (`acceptance/src/small_object_cost.rs`), against twice and fifty times the reference's measured time per object. The requirement "Debar Never Spends More On A Small Object Than Its Best Measured Cost" ratchets it as the per-kind records do, in `acceptance/best-small-object-cost.json`.
- **The reference's time per small object** is measured in the study folder ("Raw scan per small object" in the scan-speed baseline): about 1.6 to 4.5 ms per object, nearly all of it the same for every object. The calibration keeps the least of three passes, the strictest target.

**Why.** Real corpora are mostly small files (the system part of the standard corpus is 2,424 files in 237 MiB), and per-byte gains did not reach them (issue #6): a 1 KiB text object cost 2.4 M instructions, 0.9 M of them placing about 3,300 signatures tied to offsets that nearly never matched.

**Measured** on the pinned databases, in the toolchain image on an Apple Silicon Mac (aarch64 Linux VM). No detection changed: Debar's reports were byte-identical before and after, with and without every match, on 6,000 of the harness's built inputs drawn with seed 6 and its fixtures, and on the scan-speed slices, the small objects and every file of the toolchain's `/usr/bin` (897 files); every acceptance test passes.

| Instructions per small object, aarch64, before → after | system | text | html | binary | PDF | OLE2 | tar |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Selecting signatures | 656,531 → 17,768 | 703,468 → 17,307 | 7,959 → 3,115 | 703,878 → 17,712 | 690,766 → 19,377 | 783,391 → 17,202 | 706,092 → 20,658 |
| Verifying candidates | 1,450,706 → 663,217 | 1,045,798 → 189,453 | 200,130 → 69,943 | 991,897 → 135,631 | 830,000 → 175,166 | 872,284 → 151,799 | 1,121,832 → 264,996 |
| Whole-object matching | 137,655 → 16,645 | 123,636 → 10,379 | 0 | 123,815 → 10,563 | 296,898 → 18,612 | 136,181 → 16,141 | 127,040 → 13,783 |
| Scan total | 3,240,538 → 1,376,584 | 2,465,726 → 415,760 | 282,978 → 146,116 | 2,393,291 → 348,144 | 2,426,728 → 454,220 | 2,434,745 → 402,209 | 2,550,239 → 511,190 |
| Fifty times the reference would be | 707,886 | 463,262 | 659,910 | 595,259 | 509,701 | 1,203,982 | 860,062 |
| Times the reference, single-threaded | 10.9 → 25.7 | 9.4 → 55.7 | 117 → 226 | 12.4 → 85.5 | 10.5 → 56.1 | 24.7 → 150 | 16.9 → 84.1 |

| Instructions per MiB, aarch64, before → after | text | html | binary | PDF | OLE2 | tar | system |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Scan total | 70,821,706 → 53,698,648 | 2,321,845 → 1,193,916 | 65,848,605 → 48,836,262 | 83,798,351 → 67,215,375 | 77,436,709 → 60,578,340 | 66,965,267 → 51,310,692 | 102,720,088 → 96,818,316 |

The ratchet's figures are callgrind's (the requirement's count) and the table's cachegrind's (the profile's); they agree within 1 %. The x86_64 records are not measured natively: each per-MiB record is the previous one scaled by this change's speed-up under amd64 emulation (text 140.3 M → 118.1 M per MiB emulated), and each small-object record is the emulated figure scaled by its kind's ratio of the previous record to the emulated figure before this change (1.026 to 1.046; HTML 0.989), since emulation counts about 4 % fewer instructions than CI's runners. CI's figures replace them if they differ by more than the tolerance.

**Not yet at fifty times: small system files** (shell scripts in the toolchain image, 4.7 KiB on average), at 26 times. Their cost is matching what they hold, not setup: real script text arms about 750 candidates an object, so verification (663,000) and the prefilter (368,000) dominate. That is the per-candidate verification lever already named for system files. On text the five mail-typing patterns, searched from every newline of the first 1,024 bytes in each of three passes, are the largest single item left (about 100,000 an object).

### 2026-11-27 — Independent files scanned in parallel, as built

**Decision.** Independent files are scanned on several threads at once, as the scan core's design says (each scan single-threaded and owning its state, only the image shared), with these choices:

- **Threads are an outside resource behind a platform gate.** `debar_platform::threads::each_in_parallel(items, ThreadCount, work)` runs `work` on each item on a fixed number of scoped threads (each with an 8 MiB stack, as the main thread has), every thread taking the next item from one atomic counter, and returns the results in the items' order, whatever order they finish in. One thread, or one item, runs on the calling thread with no thread started, so single-threaded figures and instruction counts are unchanged. Starting a thread or reading the machine's core count anywhere else is refused by `clippy.toml` (§9). It is plain `std` (`thread::scope`, `AtomicUsize`): no crate and no `unsafe`.
- **Nothing a scan shares can change its verdict.** The image is read-only; settings are shared by reference; each worker opens its own file through the input gate and runs its own scan. There is no clean cache yet; when it comes it must stay verdict-neutral (study design, §5). The requirement "Every File Gets The Same Verdict And Detections However Many Files Are Scanned At Once" (`specs/scan-verdicts.lazyspec.md`) proves it through `debar measure-scan` at 1, 2, 4, 8 and 16 threads against `comparison-report` of each file.
- **`debar measure-scan --threads COUNT`** (default 1) scans COUNT files at once, prints `threads`, and lists the verdict and detections of every file with any, in file order. A scan that cannot finish is reported for the first such file in file order, after every scan has ended. `comparison-report` scans one file and is unchanged: parallelism inside one file is out of scope.
- **Left to piece 9:** the daemon's and one-shot scanner's pools, which will use the same gate but must admit work as it arrives rather than over a known list, reserving the 32 MiB bound per admitted scan for back-pressure, and choosing the thread count (the machine's cores, read through the gate, are the obvious default; for a person to set).

**Measured** in the toolchain image on the Apple M2 Max of the reference's baseline (12 CPUs visible), the official image, `debar measure-scan` with the page cache warm, best of three to eight passes; peak memory sampled every 10 ms from `/proc/<pid>/status` (`VmRSS`; anonymous `RssAnon`). **The machine was busy**: other agents' builds held the host's load average between 18 and 58 throughout, and a second round taken at the higher load gave a third to two thirds of these rates; treat them as lower bounds.

| Threads | System files (237.1 MiB, 2,424 files) | Documents, seven kinds (683.2 MiB, 2,773 files) | Peak `VmRSS` / anonymous, system files |
| --- | --- | --- | --- |
| 1 | 73.1 MiB/s | 65.7 MiB/s | 26.8 / 6.3 MiB |
| 2 | 149.6 (2.0×) | 164.4 (2.5×) | 32.7 / 12.1 MiB |
| 4 | 211.7 (2.9×) | 300.7 (4.6×) | 43.1 / 22.7 MiB |
| 10 | 264.5 (3.6×) | 454.1 (6.9×) | 64.5 / 47.1 MiB |
| 12 | 282.5 (3.9×) | 259.9 | 69.2 / 53.7 MiB |

- **Memory** grows by about 4.5 MiB of anonymous memory per thread (documents: 7.0 MiB at one thread, 65.4 MiB at twelve), far inside the 32 MiB bound per scan; the image is shared. The reference's daemon held 1,104 to 1,225 MiB scanning the same parts.
- **The system files stop scaling at the largest file**: one 53.4 MiB file takes 0.73 s at the one-thread rate, which caps the part at about 325 MiB/s however many threads run. Scanning the largest files first, or parallelism inside one file, is what would lift it.
- **Documents** are the binary, gzip, OLE2, PDF, tar, tar.gz and text folders. ZIP and OOXML are left out because a 16 MiB file of either cannot finish (#38), and HTML because Debar does not match it raw yet. The twelve-thread figure fell below ten threads on every pass, as the other containers took the cores.
- **Against the reference's daemon at equal concurrency** (ten scanning threads, study knowledge "Baseline: scan speed"): system files 264.5 against 56.1 to 58.3 MiB/s, 4.5 to 4.7 times; single-threaded the same part is 73.1 against 10.2 to 11.7, 6.2 to 7.2 times. Debar's lead shrinks at ten threads because of the largest-file cap above, which the reference's slower rate never reaches. The reference's documents figure (12.7 to 13.2 MiB/s) covers all ten kinds and the unpacking Debar does not do yet, so it is not compared.

**Why.** The aim of fifty times the reference is judged single-threaded and at equal concurrency (the decision "Aim for fifty times…"); a single core could not meet the second half at all.
