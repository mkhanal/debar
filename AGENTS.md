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
- A commit, pull request, issue or comment never credits a tool or an AI as author or co-author.
- Study material is never committed to this repository (Constitution §4). Changes to the notes are committed in the study repository.

## Commands

The repository holds no Rust code yet. Build, lint and test commands are added here with the first crate.
