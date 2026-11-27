# Debar: agent tooling

The catalogue of this repository's skills, agents and board tasks. The shared contract every agent reads is [`AGENTS.md`](../AGENTS.md); this file only lists what exists and where.

`/skills` lists everything, this repository's skills mixed with plugins and built-ins. **Ours are the ones whose description begins with `Debar:`**; they are the only ones that know this repository's constitution, checks and board.

## Skills: type `/<name>`

| Skill | What it does |
| --- | --- |
| `/work <anything>` | Front door: classifies the task (understand, fix, build, decide) and routes it to its lane |
| `/explore <area>` | Read-only investigation of the code, roadmap, decisions and study notes; routes any change to a lane |
| `/fix <what is broken>` | A defect: claim, failing test, named root cause, fix at the cause, full check, hand in |
| `/build <what>` | Net-new behaviour inside an agreed design: claim, requirement through `/lazyspec`, failing test, code, full check and comparison, hand in |
| `/claim <the work \| issue>` | Find or create the issue (problem, evidence, done when; never the solution) and claim it before changing anything; stops when someone else holds it |
| `/pr [draft \| ready \| land \| <n>]` | Hand in the branch's claimed work: a pull request that closes its issues and moves them to In Review when ready, or a push to `main` that closes them |
| `/autofix [--unattended] [<issue>]` | Take the next Open issue on the board (or a named one) and deliver it through its lane as a pull request, or hand it back on the issue with questions, labelled `agent-blocked`; never merges |
| `/autofix-schedule [nightly \| every <n> hours \| HH:MM \| remove] [<n> issues]` | Set up, change or remove this machine's schedule of unattended `/autofix` runs, through T3 Code or launchd/cron |
| `/worktree <name>` | A new worktree beside the main checkout, on its own branch from the latest `main` |
| `/work-status` | Snapshot of your in-flight worktrees, branches, held issues, pull requests and conversations |
| `/lazyspec`, `/lazyspec-validate` | Change a requirement with its married test; check every requirement is still married (plugin skills, named in `AGENTS.md`) |

## Agents

| Agent | Role |
| --- | --- |
| `signature-expert` | Answers how a reference scanner behaves from `study/`, and writes down what it learns there with its evidence. Writes no product code |

## Board tasks: `./in-toolchain cargo xtask <task>`

They need `GH_TOKEN` exported (`export GH_TOKEN="$(gh auth token)"`, with the `project` scope), and `gh` in the toolchain image.

| Task | Used by |
| --- | --- |
| `claim <issue>... [--branch <b>]` | `claim`, `pr` |
| `classify-work <issue> [--theme …] [--kind …] [--area …] [--impact …] [--why …]`, `--options`, `--add-area` | `claim`, `pr` |
| `record-pull-request-size`, `ready-for-review` | `pr` |
| `claim-next [<issue> [--include-blocked]]`, `claim-next --peek` | `autofix`, `run-unattended` |
| `check-claim <issue>...`, `issue-brief <issue>`, `hand-back <issue> (--body-file <f> \| --release-only)` | `autofix` |

`.claude/skills/autofix/run-unattended` is the host-side runner a launchd or cron schedule starts.

## The board

The "Debar" project, https://github.com/users/mkhanal/projects/2, linked to this repository and to the comparison harness's.

- **Status**: Open (not yet claimed), In Progress (held by the branch in **Branch** or an open pull request), In Review (pull request ready), Done (merged or closed). The board's workflows set Open when an item is added and Done when it closes or its pull request merges.
- **Classification**: Theme, Kind, Area, Impact and Why it matters, chosen by [`skills/claim/work-classification.md`](./skills/claim/work-classification.md); **Lines changed** and **Files changed** for pull requests.
- **Issue types**: Task, Bug, Feature. **Labels** the workflow reads: `agent-blocked` (an agent handed it back), `needs-decision` (a person must decide first); scheduled runs pass both over.
- **Adding issues**: a user-owned project cannot be set to add a repository's issues by itself from the API, so create issues with `--project Debar` (the `claim` skill does); a claim or classification adds any issue that is missing. The `assign-issue-creator` workflow assigns every new issue to whoever opened it.
- Harness issues live in the harness repository and on the same board, under the same rules. Its checkout has no `xtask`: claim a harness issue by checking on the board that no live branch or open pull request holds it, then setting its Branch and Status (In Progress) there and assigning yourself.
