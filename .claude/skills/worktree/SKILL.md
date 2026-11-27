---
name: worktree
description: "Debar: create a new git worktree for claimed work, on its own branch from the latest main, with one command. TRIGGER when work needs its own checkout or branch, when the user asks for a worktree, or when you are about to run `git worktree add`."
argument-hint: '<name> [--branch <branch>]'
---

# Worktree

From any checkout of Debar:

```bash
main_checkout="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")"
git -C "$main_checkout" fetch --quiet origin
git -C "$main_checkout" worktree add -b <branch> "$main_checkout-worktrees/<name>" origin/main
```

The branch defaults to `chore/<name>`; name it `<type>/<issue>-<what>` for claimed work (`fix/41-archive-depth`). Worktrees sit beside the main checkout, in `<main checkout>-worktrees/`, never inside another checkout.

Nothing else needs setting up: `./in-toolchain` mounts the worktree and the shared git directory, and Cargo's caches are shared Docker volumes (the worktree's own `target/` builds on first use). The study folder exists only in the main checkout; reach it at `"$main_checkout/study"` (AGENTS.md, "The study folder").

Then claim the issue from the new worktree (`/claim`); its branch holds it.

Removing one when its work has landed: `git -C "$main_checkout" worktree remove <path>`, then delete the branch locally and on GitHub; deleting the branch releases any issue it still held.
