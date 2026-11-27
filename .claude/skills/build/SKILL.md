---
name: build
description: "Debar: net-new behaviour or a roadmap piece. Agreed design in DECISIONS, requirement through /lazyspec, failing test first, the least code that passes, the full check and the comparison. TRIGGER on /build or a request to add, implement, support or measure something that does not exist yet."
argument-hint: '[--unattended] <what to build> | <issue number>'
---

# Build

## 1. Claim

Run the `claim` skill: find or create the issue (its body says the outcome wanted, the evidence that it is missing, and how we will know it is met; never the solution) and claim it. A held issue stops here.

## 2. The design is agreed

Read `architecture-overview/ROADMAP.md` for where the work sits and `architecture-overview/DECISIONS.md` for what is settled. A new piece, or a choice the decisions do not settle that a person would want to make (a new layer, crate or dependency, a difference a signature can observe, a budget), needs a person's agreement recorded in DECISIONS first: stop and ask (unattended: hand back). Choices inside a settled design are yours; record the ones a later reader needs.

## 3. What the reference does

When the behaviour depends on a reference scanner, read that format's notes in `study/`, and ask the `signature-expert` agent for anything missing. Whatever is learned is written into `study/` before the task ends.

## 4. Requirement and failing test

A promise Debar makes is written as a requirement through `/lazyspec`, married to its test (Constitution §7). Every other test is written first, through the public interface, named for the behaviour. A new format module gets its fuzz target the day it is written.

## 5. Green, measured, checked

The least code that passes. Where a budget applies, the measurement sits beside the code as a test; an optimisation arrives with the measurement that justifies it. Then `./in-toolchain cargo xtask check`, the comparison where a signature can observe the change, and `/lazyspec-validate`.

## 6. Hand in

The `pr` skill. Decisions you took alone go under **What needs a decision**, and the settled ones into DECISIONS.
