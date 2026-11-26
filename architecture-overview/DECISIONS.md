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
