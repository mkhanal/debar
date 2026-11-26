# Debar — instructions for every coding agent

The shared contract, whichever agent runs. What Debar is and aims for: [PRODUCT.md](./PRODUCT.md).

**All code follows [CODING-GUIDELINES.md](./CODING-GUIDELINES.md) and the hard requirements in [CONSTITUTION.md](./CONSTITUTION.md).** Claude Code loads both with this file through `CLAUDE.md`; any other agent reads both in full before its first change.

## Where things are

Each kind of thing has one home. Look there, and put new material there.

| What | Where |
| --- | --- |
| What Debar is and promises | `PRODUCT.md` |
| Hard requirements | `CONSTITUTION.md` |
| How to write the code | `CODING-GUIDELINES.md` |
| Layers and what each may use | `architecture-overview/ARCHITECTURE.md` |
| The pieces, their order and what exists so far | `architecture-overview/ROADMAP.md` |
| Decisions and why they were made | `architecture-overview/DECISIONS.md` |
| Where requirements live | `lazyspec.md` |
| Work set aside for later | `DEFERRED.md` |
| Everything about a reference scanner | `study/<format>/`, never committed |

## The study folder

`study/` holds what Debar has learned from each signature format's reference scanner: its source and databases at the pinned version, notes on how it behaves, measurements and comparisons. It is git-ignored here and private (Constitution §4). It is a repository of its own, `mkhanal/debar-study`.

- It exists only in the main checkout. From a linked worktree, reach it at `"$(git rev-parse --path-format=absolute --git-common-dir)/../study"`.
- Start at `study/README.md`. It lists the formats and the rules for an entry.
- If the folder is missing, clone it into the main checkout with `git clone https://github.com/mkhanal/debar-study.git study`, then run the fetch script its README names. If you cannot, stop and ask. Do not rebuild its notes from memory.

## Read before you touch

| Before you… | Read |
| --- | --- |
| say or assume anything about how a reference scanner behaves | That format's notes in `study/`. If the answer is not there, ask the `signature-expert` agent, which reads the reference and writes the answer down. Never answer from memory (Constitution §5) |
| write code that parses, unpacks or normalises scanned content | Constitution §2, §8 and §9, and that format's notes in `study/` on what a signature observes there |
| add a crate or raise a dependency's version | "Depend with care" in `CODING-GUIDELINES.md` |
| open a file, map memory, open a socket or read the clock | Constitution §9. Ask the platform layer for it |
| write a committed file that mentions a reference scanner | Constitution §4. A committed file may name its signature format as supported and the surface Debar is compatible with (commands, parameters, protocol messages, configuration options, output). How it works inside goes in `study/` |
| start a piece of work | `architecture-overview/ROADMAP.md` for where it sits, and `architecture-overview/DECISIONS.md` for what is already settled |

## Terminology

Use these words in code, specifications and documents, and no second word for the same thing.

- **Signature format**: one family of signature databases and the rules for reading them.
- **Reference scanner**: the program a signature format was written for, at its pinned version.
- **Database**: a signature file as its publisher ships it.
- **Image**: Debar's compiled form of all loaded databases, mapped into memory instead of parsed at start.
- **Object**: a file being scanned, or anything extracted from one.
- **Fact**: something computed about an object that a signature can test, such as its type, a hash, its size or its normalised text.
- **Observable**: able to change whether some signature matches. Constitution §2 turns on this word.
- **Detection**: one signature matching one object, reported by the signature's name.
- **Verdict**: what a scan reports for the file as a whole.
- **Layer**: a level of the architecture. Never used for nesting inside a scanned file; that is an object's depth.
- **Part**: a signature format or a compatibility interface, plugged into the engine (Constitution §11).
- **Compatibility mode**, **native mode**: the two interfaces described in `PRODUCT.md`.

## How work proceeds

- One piece at a time, in the order in `architecture-overview/ROADMAP.md`.
- A piece starts with its design agreed with a person and recorded in `architecture-overview/DECISIONS.md`.
- Requirements are written through `/lazyspec`, each married to its test. Before finishing any task, run `/lazyspec-validate`.
- Tests come before the code they prove.
- Anything learned about a reference scanner on the way is written into `study/` before the task ends.

## Commits and pull requests

- The message says what changed and why. That is where the journey lives (Constitution §17).
- A commit, pull request, issue or comment never says a tool or an AI wrote, generated or committed it: no `Co-Authored-By` naming one, no "Generated with" line, and no tool as author or committer. The person who directs the work is its author.
- Every commit is signed off (`git commit -s`) under the Developer Certificate of Origin (Constitution §14).
- Study material is never committed to this repository (Constitution §4). Changes to the notes are committed in the study repository.

## Commands

Everything builds and runs inside the toolchain image, on CI and on a developer machine alike; nothing needs Rust installed on the host. `./in-toolchain` runs any command in that image with the repository at `/work` and Cargo's caches in named Docker volumes. It needs Docker (on macOS, a Linux virtual machine such as OrbStack or Docker Desktop).

| To… | Run |
| --- | --- |
| run every check a change must pass | `./in-toolchain cargo xtask check` |
| run one of them | `./in-toolchain cargo xtask <check>`, where `<check>` is `format`, `lints`, `tests`, `dependencies`, `lint-tables`, `layers`, `reference-mentions`, `requirements` or `workflows` |
| run the platform crate's tests under Miri | `./in-toolchain cargo xtask miri` |
| check that a release may be cut | `./in-toolchain cargo xtask release-check` |
| format the code | `./in-toolchain cargo fmt --all` |
| open a shell in the image | `./in-toolchain` |

What each check enforces:

- **format**, **lints**, **tests**: `cargo fmt --check`, `cargo clippy` with warnings denied, `cargo nextest run`. The lints include the gates (Constitution §9): `clippy.toml` disallows files, sockets, processes, the environment, the clock, memory maps and randomness, and only the platform crate allows them.
- **dependencies**: `cargo deny check` against `deny.toml` (licences from "Depend with care", crates.io as the only source, advisories, and bans that let only the platform crate depend on crates that reach outside the process), and every dependency naming one exact `=` version. Cargo refuses any version published less than 14 days ago (`.cargo/config.toml`).
- **lint-tables**: every crate inherits `[workspace.lints]`, which forbids `unsafe_code` and the gate lints; only the exemptions in `xtask/src/lint_tables.rs` (the platform crate, and `xtask` for the gates) keep their own table, equal to the workspace's but for those lints. One `clippy.toml`, at the root.
- **layers**: every crate is placed in the layer table in `xtask/src/layers.rs`, depends only on what that table allows (Constitution §10), and `deny.toml` bans each layer crate with exactly the dependents the table allows.
- **reference-mentions**: no tracked file names a reference scanner outside the paths listed in `xtask/src/reference_mentions.rs` (Constitution §4).
- **requirements**: every requirement in `specs/*.lazyspec.md` appears word for word in its one married test file, `<crate>/tests/<stem>_lazyspec.rs`, with the specification's stem joined by underscores. Put the requirement's text in the test, for example as the string a test asserts it proves.
- **workflows**: `zizmor` over `.github/workflows`.

CI (`.github/workflows/checks.yml`) runs `./in-toolchain cargo xtask check` on amd64 and arm64 and `cargo xtask miri` for every push and pull request, so a change that passes locally passes there.

**The image.** `toolchain.Dockerfile` defines it; `toolchain-image` holds the published image's digest, which `./in-toolchain` runs. To change the image, edit the Dockerfile (or `rust-toolchain-nightly`, the one nightly used for Miri, fuzzing and sanitizers), try it locally with `docker build -f toolchain.Dockerfile -t debar-toolchain:local .` and `DEBAR_TOOLCHAIN_IMAGE=debar-toolchain:local ./in-toolchain cargo xtask check`, then push: the `toolchain-image` workflow builds both architectures, publishes them to `ghcr.io/mkhanal/debar-toolchain`, and prints the line to commit to `toolchain-image`. Keep the Rust version in the Dockerfile's base image and in `rust-toolchain.toml` the same.
