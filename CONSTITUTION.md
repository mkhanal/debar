# Debar Constitution

Numbered hard requirements. They bind all code, specifications, study notes and releases.

## 1. Same Signatures, Same Detections

For each supported signature format, Debar loads every database file unchanged. For the same file, databases and settings it reports every detection the format's reference scanner reports, under the same signature name. The reference scanner is the program the signatures were written for, at the one version pinned in that format's study folder.

## 2. Match What A Signature Can Observe

Signatures were written and tested against what their reference scanner hands to matching: extracted content, normalised text, hashes, file types, container facts and offsets. Debar produces the same, even where the reference's behaviour looks wrong.

Everything a signature cannot observe is Debar's to do better: failures, memory use, speed, error handling and internal structure.

A difference in what a signature can observe is a defect, unless a person has decided to keep it and it is recorded in that format's study folder with the evidence that no detection depends on it.

## 3. Debar's Code Is Its Own

Debar is written to its own design. No code is copied or translated from another scanner's source. A reference scanner is studied to learn what a signature observes, and run to compare results; neither puts its code into Debar. The one exception is the temporary linking §13 allows in a build that is not a release.

## 4. Study Material Stays Out Of The Repository

Everything taken from or written about a reference scanner's code and inner workings lives in the git-ignored `study/` folder: its source, its databases, notes on how it works inside, measurements of it and comparisons with it.

Committed files name a reference scanner for two things only: to say Debar supports its signature format, and to state the surface Debar is compatible with, meaning the commands, parameters, protocol messages, configuration options and output a user of that scanner sees. Compatibility is with that surface, never with the code behind it.

## 5. Knowledge Is Written Down With Its Evidence

What is known about a reference scanner lives in its study folder. Each claim cites the reference file and line it was read from, or the command that measured it. A claim from memory is not knowledge. Work that learns something new writes it there before it ends. The rules for an entry are in `study/README.md`.

## 6. One Pinned Reference Per Format

Every claim about a reference scanner and every comparison with it names the one pinned version. Moving the pin is a change of its own: it repeats the comparisons and re-checks every citation.

## 7. Requirements Are Married To Tests

What Debar promises is written as requirements, each proved by a test that repeats its words. The rule is the Specifications section at the end of this document; where requirements live is [lazyspec.md](./lazyspec.md).

## 8. Every Scanned Byte Is Hostile

No input causes a panic, an unbounded allocation, unbounded recursion or a loop without a bound. A size, count, offset or depth read from input is checked against the remaining limit before it is used. Every format module is fuzzed.

## 9. One Gate For Each Outside Resource

Each resource outside the process is reached through one place in the platform layer:

- **Scanned content** through the input gate, which bounds every read and counts it against the scan limits.
- **The filesystem** (databases, the compiled image, configuration, temporary space) through the filesystem gate.
- **The network** through the network gate.
- **Time and randomness** through their gates, so nothing else is non-deterministic.

No other code opens a file, maps memory, opens a socket, reads the clock or draws a random number.

## 10. Layers Depend Downward Only

The layers are named in [architecture-overview/ARCHITECTURE.md](./architecture-overview/ARCHITECTURE.md). A layer uses the layers below it through their public interface. It never reaches upward, and never into another layer's internals.

## 11. Signature Formats And Interfaces Are Parts

The engine knows nothing of any one signature format or any one scanner's interface. A signature format is a part that turns its database files into the engine's own compiled form. A compatibility interface is a part that translates one scanner's commands, protocol, parameters and configuration onto Debar's native interface, and holds no scanning logic. Adding a format or an interface adds a part and changes no layer beneath it.

## 12. Speed And Footprint Are Budgeted And Tested

Start time, scan speed and memory are hard requirements, not aims. Each has a budget, written as a requirement and proved by a test that runs on every change from the piece that first makes it measurable. A change that exceeds a budget fails, like any other failing test.

- A budget is measured the same way on every run: on counts that do not depend on a shared machine's load, calibrated against the wall-clock and memory figures the budget promises.
- A budget is only raised by a person's decision, recorded with the measurement that forced it.
- Any other statement about start time, memory or speed comes with a measurement anyone can repeat.

## 13. No Borrowed Code In A Release

A build that is not a release may link a reference scanner's code to measure progress before Debar's own piece exists. Every borrowed piece is listed in [architecture-overview/ROADMAP.md](./architecture-overview/ROADMAP.md), and no release is cut while that list has an entry.

## 14. Open Source, The Same Terms For Everyone

Debar is licensed under the Mozilla Public License 2.0, and only under it. No one holds rights over Debar that others lack, and no part of it is offered under closed terms.

- Every contribution is made under the same licence and signed off under the Developer Certificate of Origin.
- Everything linked into a released program carries a licence that keeps Debar usable by any program that links it; the list is in [CODING-GUIDELINES.md](./CODING-GUIDELINES.md). A tool used only to build, test or measure Debar is not linked into it and needs only to permit that use.

## 15. Fail Loud

An error travels to the layer that can report it. None is swallowed, replaced by a default, or logged and forgotten. What a caller is told when a scan cannot finish is a written requirement, never the side effect of an ignored error.

## 16. Same Input, Same Verdict

The same file, databases and settings give the same result on every run and every supported platform. Time, randomness and thread scheduling never change a verdict.

## 17. State, Not Journey

Code, tests, specifications and names say what the system is now, not how it got here.

- **Forbidden in identifiers and file names:** phase and version markers (`v2`, `new_`, `old_`, `legacy_`), issue or pull-request numbers, and words such as `temp`, `fix` or `refactored`.
- **Required:** a file named for what it holds, a test named for the behaviour it proves, and the old name gone when something is renamed.
- **The journey lives in** commit messages, pull-request descriptions, `architecture-overview/DECISIONS.md` and `architecture-overview/ROADMAP.md`.

<!-- lazyspec:begin -->
## Specifications

Requirements live in `*.lazyspec.md`. Read `lazyspec.md` first if there is
one: which files count, and what a requirement in each area is for. A
requirement is a `## ` heading, and its text is its name.

**It is married to a test repeating that text word for word, in the one
file naming the specification and `lazyspec`.** Join them the way this
repository joins words in test names; some languages cannot take a dot:

```
billing.lazyspec.md        ## Refunds Never Exceed What Was Captured
billing.lazyspec.test.ts   describe('Refunds Never Exceed What Was Captured', ..)
test_billing_lazyspec.py   """Refunds Never Exceed What Was Captured"""
billing_lazyspec_test.go   t.Run("Refunds Never Exceed What Was Captured", ..)
```

Most tests marry nothing, and should not: unit and integration tests sit
below the requirements. One specification, one test file - split one that
grows too large and split its tests with it. Where tests already exist,
write the married file anyway: names in an ordinary suite were not
written to be requirements. The old tests stay, marrying nothing.
Untestable? Mark it `## Name <!-- no-test: why -->`.

**Specifications are locked unless you are in `/lazyspec`.** Run
`/lazyspec` to change one, with its tests in the same edit, never beside
unrelated work, and say that you did.

**Write each requirement as soon as you know it** - before the code,
during it, or after. Then leave it alone.

**Before finishing any task, check and report both.** `/lazyspec-validate`
does it for you.

- Every heading you touched is married. Say which are not.
- If you changed what the software does, say whether a requirement
  covers it yet. "Not yet" is fair while experimenting, not in a pull
  request.
<!-- lazyspec:end -->
