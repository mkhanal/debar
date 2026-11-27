# Work classification

Every issue and pull request on the "Debar" board carries a Theme, Kind, Area, Impact and one sentence on why it matters. The options and what each one means live on the board, nowhere else. Read them before choosing:

```bash
./in-toolchain cargo xtask classify-work --options
```

Pick the one option that fits best; `classify-work` refuses a value that is not an option.

**Classify the issue.** A pull request that closes no issue is classified itself.

## Theme: when two fit

Judge by who benefits. Apply these in order:

1. Anything that changes which detections Debar reports, under which name, for the same file, databases and settings, is Detection parity, even when it was found through a crash or a slow scan.
2. A fix takes the theme of the capability that broke. It is Robustness only when Debar itself failed on its input: a crash, a hang, an unbounded allocation or recursion, a swallowed error, or a verdict that changed between runs or platforms.
3. A change whose purpose is a measured budget (start time, memory, image size, throughput, the fifty-times aim) is Speed & footprint, as long as no detection changes; one that changes a detection is Detection parity first.
4. What can reach Debar or what Debar can reach (the platform gates, confinement, verified database containers) is Security. Pinning that keeps untrusted code out is Security; pinning so everyone runs the same tool is Delivery & enablement.
5. What a user of the reference scanner's commands, protocol, configuration and output sees is Compatibility; what only native mode offers is Native capability.
6. What lets someone running Debar install, configure, update or observe it is Operability.
7. Work whose only beneficiaries are the team (the toolchain, CI, the checks, the harness, the study tooling, the agent workflow) is Delivery & enablement.
8. A specification, document or cleanup change takes the theme of what it is about; its Kind is Maintenance.

## Impact

High is one of the few changes in a release worth naming to a user or an operator: it changes what they can do, rely on or measure. Most work is Normal. Judge against these:

| High | Normal |
| --- | --- |
| A signature format's databases load and detect end to end | A renamed type or a moved module |
| A budget is met that was not, or the fifty-times aim moves for a corpus kind | A small speed-up inside the budget |
| A compatibility interface passes for a whole command or protocol | A CI, tooling or dependency switch |
| | A fix to something not yet released |

## Why it matters

One plain sentence in outcome language: who gets what. No implementation terms.

> A mail server switching to Debar keeps every detection it had, at a fiftieth of the time.

## Area

Pick the Area of the concern the work serves, not the folder the code sits in: a typing gap that loses detections in executables is Scan core if the scan core types objects, Format modules if a module must produce the fact. Infrastructure that serves one Area takes that Area; shared infrastructure is Engineering platform. A dependency or toolchain upgrade is Engineering platform even when it touches one crate.

An Area is a part of Debar a user or contributor would name. When the work creates a new one (a new signature-format part, compatibility interface or layer) and no Area fits, add one, then classify:

```bash
./in-toolchain cargo xtask classify-work --add-area "<name>" --area-description "<one sentence on what the part covers>"
```

Never add an Area for an internal sub-part of an existing one; a name that already exists, in any case, is refused.
