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
