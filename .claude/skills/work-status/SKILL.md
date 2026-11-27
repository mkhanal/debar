---
name: work-status
description: "Debar: snapshot of in-flight work (worktrees, branches, the issues they hold, pull requests, conversations) with active / stale / abandoned / completed status. TRIGGER on what am I working on, what to pick back up, or /work-status."
argument-hint: '[--recent | --all] [--mark-abandoned <branch> | --mark-complete <branch> | --unmark <branch>]'
---

# Work status

Join four sources per worktree and branch, then classify each item.

## 1. Gather

From any checkout:

```bash
main_checkout="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")"
git -C "$main_checkout" fetch --quiet --prune origin
git -C "$main_checkout" worktree list --porcelain
gh pr list --author @me --state all --limit 50 --json number,title,state,isDraft,headRefName,updatedAt,statusCheckRollup
gh project item-list 2 --owner mkhanal --format json --limit 1000 \
  | jq '[.items[] | select(.branch != null) | {issue: .content.number, title: .content.title, status, branch}]'
```

For each worktree: `git -C <path> status --porcelain` (dirty or clean), `git -C <path> rev-list --left-right --count origin/main...HEAD` (behind and ahead), `git -C <path> log -1 --format=%cr` (last commit), and whether the branch is merged (`git -C <path> merge-base --is-ancestor HEAD origin/main`). The conversation for a worktree is the newest `~/.claude/projects/<the worktree path with / replaced by ->/*.jsonl`: its modification time and its first user prompt as the summary.

## 2. Classify

- **COMPLETED** when its pull request is merged, its branch is fully in `origin/main`, or both the worktree and the remote branch are gone; or when it is marked complete.
- **ABANDONED** when it is marked abandoned.
- **OPEN** otherwise, tagged by the newest of its commit, its conversation and its pull request: `active` (2 days or less), `stale` (3 to 7), `likely-abandoned` (more than 7).

Marks live in `<git common dir>/work-status-marks.json`, never committed: `{"<branch>": "abandoned" | "complete"}`. `--mark-abandoned`, `--mark-complete` and `--unmark` edit that file.

## 3. Report

By default show OPEN items only; `--recent` adds COMPLETED from the last 7 days; `--all` shows everything. One row per item: branch, worktree, the issues it holds and their board status, pull request and checks, dirty/ahead/behind, freshness, the conversation's summary, and how to resume it (`cd <worktree> && claude --continue`).

When the question is interpretive ("what should I resume next?", "which pull requests merged that I forgot?"), reason over what you gathered and answer it; do not paste the raw output.
