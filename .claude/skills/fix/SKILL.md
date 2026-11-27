---
name: fix
description: "Debar: a defect in existing behaviour (a wrong or missing detection, a harness difference, a crash on hostile input, a budget or ratchet missed). Claim, reproduce with a failing test, name the root cause, fix it there, check. TRIGGER on /fix or a report that something is broken, wrong or slower."
argument-hint: '[--unattended] <what is broken> | <issue number>'
---

# Fix

## 1. Claim

Run the `claim` skill: find or create the issue (its body says the problem, the evidence and how we will know it is fixed) and claim it. A held issue stops here.

## 2. Reproduce

Write the failing test first, through the crate's public interface, named for the behaviour that should hold. Where the defect is a difference from the reference, the reproduction is the harness case or a built input, and what the reference does comes from `study/` or the `signature-expert` agent, never from memory. A crash on hostile input gets a fuzz case as well (Constitution §8).

## 3. Root cause

Name where the bad value or state first appears, and why. Fix it there, never where it shows. Three hypotheses tried and failed, or no cause you can name: stop and ask (unattended: hand back).

Never: retry, sleep, widen a match arm, add a fallback default, swallow an error (Constitution §15), skip or loosen a test, weaken a requirement or comparison, or special-case the reported input. Never raise a throughput record or loosen a budget; that is a person's decision recorded in DECISIONS.

## 4. Green and check

The least code that passes the test; then `./in-toolchain cargo xtask check`. When the fix changes what a signature can observe, run the comparison and say what moved. A requirement the fix makes true is written through `/lazyspec`, and `/lazyspec-validate` passes.

## 5. Hand in

The `pr` skill. Its body carries a **Root cause** section after **What changes**.
