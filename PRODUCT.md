# Debar

Debar is a file scanner that finds malware using existing signature databases. Someone already running the scanner those signatures were written for can switch to Debar and keep their databases, commands, configuration and integrations.

It is its own program, written in Rust to its own design.

## Supported signature formats

- ClamAV signature databases.

A signature format is a part that plugs into the engine. Others can be added beside the first.

## Signature sources

A **signature source** is one publisher's signatures in a supported format, with where they are fetched from, how they are verified, the terms they may be used under, and how often they change. Each deployment chooses its sources: the format's official databases, publicly available third-party sets in the same format, and later sets in other formats. Debar compiles every chosen source into one image, and every detection says which source it came from.

Choosing sources is part of the roadmap, not the first release.

## Compatible interfaces

- ClamAV's: the parameters of its commands, its daemon's socket protocol, and its configuration files.

A compatible interface is also a part. It covers what a user of that scanner sees, not the code behind it.

## Aims

1. **A drop-in replacement.** For each supported format, Debar works with every signature and handles every case the format's own scanner handles.
2. **A much smaller footprint.** It uses far less memory and other system resources than that scanner.
3. **Near-instant start.** It is ready to scan almost as soon as it starts.
4. **Faster scanning.** It scans the same files far faster than that scanner: at least twice as fast on every kind of file, aiming for fifty times.

The second, third and fourth aims are budgets every change is tested against (Constitution §12), not hopes.

## What drop-in means

- **The same signatures.** Every database file of a supported format loads unchanged.
- **An updater.** It fetches the format's published databases, verifies them and applies incremental updates.
- **Live updates.** New signatures take effect while scans continue, with no downtime.
- **The same detections.** Whatever the format's own scanner flags, Debar flags, under the same signature name.
- **The same interface, in compatibility mode.** The commands, parameters, network protocol and configuration files a user of that scanner already relies on work unchanged, under Debar's program names.

## Two modes

- **Compatibility mode** behaves at its interface as the scanner being replaced does, for people switching.
- **Native mode** offers the same functions through Debar's own contract, free to be clearer and faster. Scanning a file streamed over HTTP is part of it.

Native mode also tells a caller what a file holds, not only whether it is known malware:

- **Findings beside the verdict.** Macros, scripts and programs, encrypted content, PDF scripts and launch actions, links to outside content, and content that disagrees with the file's name, each reported as a finding. They come from facts Debar's parsers produce anyway, and cost nothing when not asked for. Which files to accept stays the caller's rule.
- **Hostile files answered plainly.** Archive bombs, nesting too deep, expansion past a limit and scans over their time budget are refused with a finding naming what was exceeded, and never exhaust the scanner.
- **The whole file reached.** Parts other scanners can miss, such as entries stored in ZIP64 form and files attached inside a PDF, are scanned too. Compatibility mode does not do this, so its detections stay those of the scanner being replaced.
- **A confined scanner.** Scanning runs where it cannot reach the network or start programs, keeps nothing after answering, asks a caller to retry when saturated, refuses a sender that stalls, and continues the caller's trace.

Both are faces of one engine.

## Where Debar differs on purpose

Whatever a signature cannot observe is Debar's to do better: memory held, time taken, limits enforced, and files that make other scanners fail. Whatever a signature can observe matches the scanner the signature was written for, because that is what the signature was tested against. The rule is Constitution §2.

## First release

Linux on amd64 and arm64: the daemon, its client, the one-shot scanner, the updater and the signature tool.

Later initiatives are listed in [DEFERRED.md](./DEFERRED.md).

## Licence

Mozilla Public License 2.0. The text is in [COPYING](./COPYING).

Anyone, a company included, may use, run, host, sell and ship Debar, and call it as a library from their own program, without asking anyone. Their own program keeps its own licence. Whoever ships a changed Debar shares the changes to Debar's own files under the same licence. Everyone gets the same terms, its authors included.
