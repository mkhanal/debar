# Architecture

Debar is built in layers. A layer uses only the layers below it, through their public interface (Constitution §10). This lets one layer be changed and checked without reading the others.

## The layers

From the top down:

| Layer | Its one job | It never |
| --- | --- | --- |
| **Interfaces** | Take a request from a person or a program and return a result. Native: the commands, the daemon and scanning over HTTP. Compatibility: one part for each scanner whose interface Debar accepts | Decides anything about a scan |
| **Scan core** | Scan one object under given settings: find its type, ask format modules for its parts and facts, apply the limits, descend into parts, and gather detections into a verdict | Reads a format or matches a byte itself |
| **Format modules** | Turn one object of one kind into its parts and its facts: unpack an archive, parse a document, normalise text, run a signature's program | Calls another format module, or decides what is scanned next |
| **Matching engine** | Given an object's bytes and facts, report which signatures in the image match | Knows where the bytes came from |
| **Image** | The compiled form of all loaded databases, read in place from a memory map | Parses a database at scan time |
| **Platform** | The gates to everything outside the process: scanned content, the filesystem, memory maps, the network, the clock and randomness (Constitution §9) | Holds any scanning logic |

## Beside the layers

Two tools produce the image. They use the image layer and the platform layer, and nothing above.

- **Signature compiler.** Reads database files and writes an image. Each signature format is a part of it (Constitution §11): the part reads its own files and emits the engine's own compiled form.
- **Updater.** Fetches and verifies a format's published databases, runs the compiler, and publishes the new image for running scanners to switch to.

## The two paths

- **Update path.** Updater → signature compiler → a new image on disk. This is the only place a database is parsed.
- **Scan path.** Interface → scan core → format modules and matching engine → image. A scanner starts by mapping the current image, and switches to a newer one between scans without stopping.

## What is not settled here

This document fixes the layers and the direction of dependency. The inside of each layer is designed when its piece of work starts, agreed with a person and recorded in [DECISIONS.md](./DECISIONS.md). How layers map to crates is decided with the first crate. The candidates under consideration are in [ROADMAP.md](./ROADMAP.md).
