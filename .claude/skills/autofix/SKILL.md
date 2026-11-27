---
name: autofix
description: "Debar: take the next Open issue on the board (or a named one) and deliver it through the full lane (fix or build, the full check, an independent root-cause review, a pull request); a scheduled run (--unattended) hands back to a person on the issue what needs one. TRIGGER on /autofix, a request to pick up an issue from the board, or a scheduled run working the board."
argument-hint: "[--unattended] [<issue number>]"
---

# Autofix

Every issue in **Open** on the board is ready for an agent. One run takes one issue and either opens a pull request for a person to review and merge, or hands the issue back with what it found and the questions a person must answer. Nothing is merged by a run.

Board tasks run in the toolchain image with your GitHub token: `export GH_TOKEN="$(gh auth token)"` (it needs the `project` scope).

## Two modes

|                         | Unattended                                                                | Attended                                                                   |
| ----------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Started by              | a scheduled task, always with `--unattended`                              | a person in the conversation, without it                                   |
| Takes                   | the next Open issue, or the one named, never one labelled `agent-blocked` | the issue the person names, `agent-blocked` included, or the next Open one |
| A question for a person | a hand-back on the issue ([unattended.md](./unattended.md))               | asked in the conversation, as the lane asks it                             |

`--unattended` is what makes a run unattended: a scheduled task's prompt is `/autofix --unattended`, and a run without it never hands back on its own. Unattended runs follow [unattended.md](./unattended.md) throughout; read it before Step 1. Attended runs follow the lane's own stop conditions, and use unattended.md's **Never a band-aid** and **The claim stays yours** too.

A hand-back puts the issue back in **Open** with the `agent-blocked` label, its findings and questions in a comment. Scheduled runs pass it over until a person removes the label; every later run, scheduled or attended, reads that comment and the answers under it first. An issue labelled `needs-decision` is never picked up unattended until the decision is recorded and the label removed; it counts as a hand-back.

## 0. A worktree of its own

Run in a linked worktree made for this run, never the main checkout or a worktree with someone's work in it. When `AUTOFIX_RUN` is set, `run-unattended` started the run and has already made the worktree: go to Step 1. Otherwise make one (`worktree` skill) and check that the tree is clean (`git status --porcelain` prints nothing).

## 1. Take the next issue

```bash
./in-toolchain cargo xtask claim-next
```

It reads the board once, with each issue's status, branch, labels and linked pull requests, and chooses from that listing: the **Open** issues, newest first, leaving out those labelled `agent-blocked` and those with an open pull request from another branch, plus any issue still marked as held by a branch that no longer exists (a run that died; the live branches come from one `git ls-remote`). It then re-reads the chosen issue's board item (open, unlabelled, held by no branch or pull request) just before claiming, because another run or a person may have taken it since the board was read; an issue that fails the re-read is passed over for the next one. It claims the issue by creating its branch, `autofix/<n>`, on GitHub. Every run names an issue's branch the same way and GitHub creates a branch once, so two runs, on one machine or several, never both hold an issue; the loser passes the issue over as `branch taken`. Once the branch exists, it records the claim on the board (In Progress, with the branch) in one update, reads the item once more and gives the issue up (`lost`) if another branch or pull request now holds it, and assigns the issue to the person running it. The branch starts from `autofix/<n>-draft` when an earlier hand-back kept work there (the draft is then deleted, its commits now on the branch), and from the default branch otherwise. It switches the worktree to the branch. When claiming fails part-way, it deletes the branch and releases the board item again before exiting 1.

| Exit | Meaning                                                                                                | Do                               |
| ---- | ------------------------------------------------------------------------------------------------------ | -------------------------------- |
| 0    | `claimed`: the issue, its branch, and the draft it resumes from, if any                                | Step 2                           |
| 4    | `queue empty`: every Open issue was passed over (`passedOver` says why)                                | Report and end the run           |
| 1    | it failed (the GitHub API, a dirty tree, a leftover local `autofix/<n>` branch), with the claim undone | Report the error and end the run |

With an issue number as the argument, pass it on (`claim-next <issue>`): the queue is narrowed to that issue, with the same checks and lock, and exit 4 means it is not claimable (not Open, or held). An attended run adds `--include-blocked`, so a person can take up an issue an agent handed back; an unattended run never does. When an attended run claims an `agent-blocked` issue, remove the label once the person has answered its questions (`gh issue edit <n> --remove-label agent-blocked`).

## 2. Understand it

Get everything about the issue in one call:

```bash
./in-toolchain cargo xtask issue-brief <issue>
```

It prints the title, labels, the number of sub-issues, any pull requests closing it, the commits already on the branch (from a resumed draft), the description and every comment in order, including a person's answers to an earlier hand-back. Read further only what the brief points to: the requirement in `specs/`, the decision in DECISIONS, the study note, the code. Classify the issue by the `claim` skill's [work-classification.md](../claim/work-classification.md) rules.

Decide the lane, as `/work` does: a defect in existing behaviour goes to `fix`; net-new behaviour inside an agreed design goes to `build`. Anything else needs a person: unattended, hand back (unattended.md, **Hand back when**); attended, ask. Investigating is cheap; changing code is not. When the issue needs a person, settle that now, before writing code.

## 3. Deliver it

Run the lane's skill (`fix` or `build`), in unattended mode when the run is, from its first phase, with the claim already made. It keeps every phase: the failing test, the named root cause, green, and `./in-toolchain cargo xtask check`.

Run `./in-toolchain cargo xtask check-claim <issue>` before the first commit and before every push (unattended.md, **The claim stays yours**).

## 4. Independent review

Once the check passes, dispatch one review subagent on the largest model. It gets the issue (body and comments), the diff against the default branch, and the repository's rules (AGENTS.md, CODING-GUIDELINES.md, CONSTITUTION.md); never the run's own reasoning or root-cause write-up, so its reading is not anchored on the implementer's. Ask it:

1. Where does the bad value or state first appear, and does the diff change it there? Or does the diff only change where it shows?
2. Does the diff do any of unattended.md's **Never a band-aid** list?
3. Does the test fail without the change and pass with it, for the reason the issue describes?
4. Does the diff change anything a signature can observe that the issue does not ask for (Constitution §2)?
5. Is anything the issue asks for left undone, or anything done that it does not ask for?

Every finding is fixed in one round, then the same questions go to a fresh review subagent (mid-size model). If findings remain after that round, hand back with them in the comment (attended: put them to the person).

## 5. Gate and open the pull request

1. `./in-toolchain cargo xtask check`, waited on until it reports (unattended.md, **The turn is the run**). A failure is fixed at its cause (Step 3 again) or, when the environment is at fault, the issue is released (unattended.md).
2. `./in-toolchain cargo xtask check-claim <issue>`.
3. The `pr` skill: a draft pull request, a **Root cause** section after **What changes**, and every decision the run made alone under **What needs a decision**. Then `./in-toolchain cargo xtask ready-for-review`.

## 6. Report

End the run with one of the following, then stop, with nothing it waits on still running. One run takes one issue.

- the pull request, its head commit and its checks;
- the hand-back: the issue and its questions;
- `queue empty`;
- the failure, and what a person must fix before the next run.

## Scheduling

Each developer chooses when their machine runs: `/autofix-schedule` sets it up through T3 Code or the operating system's scheduler (launchd, cron), with whichever agent CLI they use. Every trigger runs this skill with `--unattended`, once per issue, each time in a new worktree and its own conversation, up to a limit per run (4 by default). Runs on any number of machines and schedules share the board safely: Step 1's live check and branch lock keep them off each other's issues.
