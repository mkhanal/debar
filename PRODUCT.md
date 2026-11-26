# Debar

Debar is a file scanner that finds malware using existing signature databases. Someone already running the scanner those signatures were written for can switch to Debar and keep their databases, commands, configuration and integrations.

It is its own program, written in Rust to its own design.

## Supported signature formats

- ClamAV signature databases.

A signature format is a part that plugs into the engine. Others can be added beside the first.

## Compatible interfaces

- ClamAV's: the parameters of its commands, its daemon's socket protocol, and its configuration files.

A compatible interface is also a part. It covers what a user of that scanner sees, not the code behind it.

## Aims

1. **A drop-in replacement.** For each supported format, Debar works with every signature and handles every case the format's own scanner handles.
2. **A much smaller footprint.** It uses far less memory and other system resources than that scanner.
3. **Near-instant start.** It is ready to scan almost as soon as it starts.

## What drop-in means

- **The same signatures.** Every database file of a supported format loads unchanged.
- **An updater.** It fetches the format's published databases, verifies them and applies incremental updates.
- **Live updates.** New signatures take effect while scans continue, with no downtime.
- **The same detections.** Whatever the format's own scanner flags, Debar flags, under the same signature name.
- **The same interface, in compatibility mode.** The commands, parameters, network protocol and configuration files a user of that scanner already relies on work unchanged, under Debar's program names.

## Two modes

- **Compatibility mode** behaves at its interface as the scanner being replaced does, for people switching.
- **Native mode** offers the same functions through Debar's own contract, free to be clearer and faster. Scanning a file streamed over HTTP is part of it.

Both are faces of one engine.

## Where Debar differs on purpose

Whatever a signature cannot observe is Debar's to do better: memory held, time taken, limits enforced, and files that make other scanners fail. Whatever a signature can observe matches the scanner the signature was written for, because that is what the signature was tested against. The rule is Constitution §2.

## First release

Linux on amd64 and arm64: the daemon, its client, the one-shot scanner, the updater and the signature tool.

Later initiatives are listed in [DEFERRED.md](./DEFERRED.md).

## Licence

Mozilla Public License 2.0. The text is in [COPYING](./COPYING).

Anyone, a company included, may use, run, host, sell and ship Debar, and call it as a library from their own program, without asking anyone. Their own program keeps its own licence. Whoever ships a changed Debar shares the changes to Debar's own files under the same licence. Everyone gets the same terms, its authors included.
