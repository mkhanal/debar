# Coding Guidelines

The reader of this code is usually an agent arriving cold, with one task and a limited view. It must be able to tell what a piece of code is for from the code itself, change it without breaking something it never saw, and know the change is right.

Every guideline here serves that reader or one of the product's aims in [PRODUCT.md](./PRODUCT.md). Each says which. A guideline that serves neither is deleted, not followed.

Hard requirements are in [CONSTITUTION.md](./CONSTITUTION.md); this file is how to write code that meets them.

## Show the intention

This comes first. When it conflicts with brevity, habit or cleverness, intention wins.

- **A name states the purpose, in the domain's words.** `remaining_scan_budget`, not `n` or `limit2`. A reader should not need the body to know what a function is for, or the caller to know what a value means.
- **One word per concept, everywhere.** The vocabulary is in [AGENTS.md](./AGENTS.md#terminology). A second word for the same thing makes a reader look for a difference that is not there.
- **A function does the one thing its name says.** If the honest name needs "and", it is two functions.
- **The top of a module tells its story.** Its entry function reads as the steps of the job, in order, each step a well-named call. Detail sits below, in the order it is used.
- **Give each meaning its own type.** An offset into the file and an offset into a buffer are different types, as are a declared size and a measured one. Mixing two is then a compile error instead of a bug found on a hostile file.
- **A closed set of cases is an enum, matched without a catch-all arm.** Adding a case then makes the compiler list every place that must decide what to do with it.
- **Make the invalid unrepresentable.** Check input once, at the boundary, into a type that can only hold valid values. Code past the boundary never checks again and never wonders whether it should.
- **A function that can fail says how, in its type.** Errors are enum variants named for what went wrong, carrying what the reader of the message needs to act.
- **Absence is `Option`, never a sentinel or a default.** A default hides the question of what a missing value means.
- **No comments.** A comment is a second statement of intent that nothing checks, and an agent cannot tell which of the two is true. Rename or restructure until the code says it. The why belongs in the commit message. Two exceptions: a `// SAFETY:` line on an `unsafe` block, because the facts it relies on cannot be written as code, and tool directives.

Where code deliberately matches something that looks wrong (Constitution §2), the name says what it does and the test that pins it names the behaviour. The explanation is in the study notes.

## Keep it small

Less code is less to read, less to break and less to keep in view. This serves the reader and the footprint aim alike.

- **Solve the problem in front of you.** No option, parameter, trait or generic until a second real use exists.
- **A module has one purpose you can state in a phrase**, and is short enough to read whole alongside its tests. When it is not, split it by purpose.
- **Everything is private until something else needs it.** A crate's public interface is its contract; keep it small enough to read in one sitting.
- **Plain control flow.** A function where a function will do, not a macro. A concrete type where there is one implementation, not a trait.
- **A table where the behaviour is a table.** File types, configuration options and protocol commands are data; write them as data and let one piece of code walk it.
- **A file is named for what it holds.** No `utils`, `helpers`, `common` or `misc`, and no `mod.rs`: a reader choosing which file to open has only the names to go on.
- **Named constants for values with meaning.** A limit, a type code or a protocol word appears once, under a name.

## Keep the structure

The layers and what each may use are in [architecture-overview/ARCHITECTURE.md](./architecture-overview/ARCHITECTURE.md). They exist so that a change to one layer can be made and checked without reading the others.

- A layer uses the layers below it, through their public interface only (Constitution §10).
- Files, memory maps, sockets, the clock and random numbers are reached only through the platform layer's gates (Constitution §9). Code that needs one asks for it as a parameter, which also shows the reader what it touches.
- A format module never calls another format module. It turns one object into its parts and facts; the scan core decides what happens to those.
- Nothing above a signature-format part or a compatibility part knows which format or which scanner it serves (Constitution §11).

## Survive hostile input

Every scanned byte is hostile (Constitution §8). These are how that is met in Rust, not style.

- A value read from input never reaches an index, a slice bound, an allocation size, a loop count or arithmetic unchecked. Use checked arithmetic and the fallible accessors, and return the error.
- No `unwrap`, `expect` or `panic!` outside tests. A state that truly cannot happen is made unrepresentable instead.
- `unsafe` appears only in the platform layer.
- Each format module has a fuzz target from the day it is written.

## Be fast where it is measured

The footprint and start-time aims are met by design in a few places, not by tuning everywhere.

- Where a requirement states a budget, meet it and keep the measurement beside the code as a test.
- Everywhere else, the clearest code wins.
- An optimisation arrives with the measurement that justifies it, and the tests of the plain version still pass.

## Depend with care

- **Use a maintained crate before writing our own**, unless it cannot produce what the reference scanner produces from a damaged file, or it breaks a resource budget. Record the reason in `architecture-overview/DECISIONS.md` when we write our own.
- **Every dependency names one exact version** (`=1.2.3`), the lockfile is committed, and builds run `--locked`. The toolchain is pinned the same way. A dependency then changes only when someone changes it in review.
- **Licences compatible with GPL version 2 only:** MIT, BSD, ISC, Zlib and Unicode, and a crate offered under a choice that includes one of them. A crate under the Apache License 2.0 alone is not on this list; adding one needs a person's decision, recorded.

## Test what is promised

- **Write the failing test first**, for the behaviour, then the least code that passes it.
- **Test through the public interface, and name the test for the behaviour.** A test that knows the internals breaks when they are improved.
- **Three kinds of test, each with its own job.** A requirement test proves a promise and repeats its words (Constitution §7). A comparison test puts the same input through the reference scanner and Debar. Everything else, unit, property and fuzz tests, is free to write, change and delete.
- **Deterministic.** No sleeps, no network, no dependence on the clock or on ordering.
- **Never weaken a requirement or a comparison to make a test pass.** Fix the code.
