---
name: pr
description: "Debar: hand in the branch's claimed work, as a pull request or a push to main, closing its issues and moving them to In Review when ready. TRIGGER on every pull-request action (opening one, changing its title or body, marking it ready, merging it) and on landing claimed work on main, however the request is worded, or on /pr."
argument-hint: '[draft | ready | land | <pull request number to update>]'
---

# Pull request

A pull request delivers the issues its branch holds, and tells its reviewers what changed, how it was proven, and what they must decide, no more. Every pull-request action runs through this skill, each step in order, however the request is worded. Work from the branch's own worktree; never open, edit or push to a pull request on someone else's branch without their say-so.

Work handed to an agent by whoever directs it may instead land on `main` directly (AGENTS.md, "Handing work to an agent"): steps 1 to 3 hold all the same, and step 5 says how.

## 1. Check the claim

List the issues this branch holds:

```bash
gh project item-list 2 --owner mkhanal --format json --limit 1000 \
  | jq --arg b "$(git branch --show-current)" '[.items[] | select(.branch == $b) | .content.number]'
```

None: the work was never claimed; run the `claim` skill first. Then re-claim every issue the work will close, which also proves no one else holds them and sets their board status from the pull request (In Progress while there is none or it is a draft, In Review once it is ready):

```bash
./in-toolchain cargo xtask claim <issue>...
```

Exit 3: stop and report the holder (`claim` skill, step 4). Never close an issue another branch holds.

### Every issue the merge delivers

The board counts on a merge into `main` closing every issue whose work it carries. GitHub closes an issue only from a `Closes #<n>` line in a pull request merged into the default branch, or in a commit pushed to it, so name every such issue:

- **Issues the work also resolves.** Search open issues and open pull requests for the outcomes this work delivers (`claim` skill, step 1). An open issue it resolves gets its `Closes` line. When another open pull request holds that issue, this one supersedes it: if that pull request is yours, close it with a comment naming this one, then claim the issue; if it is someone else's, ask them first.
- **Stacked pull requests.** A pull request based on another one's branch closes nothing when it merges into that branch. After the parent merges, retarget the child to `main` (`gh pr edit <child> --base main`) and merge it there. When the child's work lands through the parent instead, the parent carries the child's `Closes` lines, and the child is closed with a comment naming the parent.
- **Work already in `main`.** A pull request whose head is already in `main` (`git merge-base --is-ancestor <head> origin/main`) is closed with a comment naming the pull request or commit that delivered it, and any issue it still holds is closed the same way.

Then classify each of those issues for the board, choosing from the options `classify-work --options` lists by the rules in [work-classification.md](../claim/work-classification.md): set **Impact** and one sentence on **why it matters** to the people it serves, and re-check that the Theme, Kind and Area chosen at the claim still fit what the work became; pass any that changed:

```bash
./in-toolchain cargo xtask classify-work <issue> --impact "<impact>" --why "<one sentence>" \
  [--theme "<theme>"] [--kind "<kind>"] [--area "<area>"]
```

## 2. Check the work

The lane's gate has passed (`work` skill). For every change, `./in-toolchain cargo xtask check` passes, once, before the push. Requirements touched are married (`/lazyspec-validate`), and anything learned about a reference scanner is written into `study/`. A red check on your own branch is work to do, not a footnote.

## 3. Write the title and body

**Title**: the outcome it delivers, in domain words (`Scan nested archives to the depth the settings allow`), not the implementation.

**Body**: written for the reviewer arriving cold, sized to the change: a one-line fix gets a few lines. In this order, leaving out any part with nothing to say:

1. `Closes #<n>` for every issue from step 1, one per line; `Stacked on #<n>` when the base is another pull request's branch.
2. **What changes**: the behaviour before and after, from the user's or operator's side. A table for facts that compare, such as a measurement before and after.
3. **What needs a decision**: anything a person must approve or answer: a design not yet recorded in DECISIONS, a difference a signature can observe kept on purpose (Constitution §2), a budget loosened, a dependency added, a requirement changed. Each self-contained, with the recommendation.
4. **Verified**: the checks run and their result (`cargo xtask check` passes; the harness count; the measurement with its command), and what was not verified, said plainly.

Never in the body: the history of how the work went, a file-by-file list the diff already shows, a "Generated with" line or any other attribution to a tool or AI, credentials, or anything about a reference scanner's inner workings (Constitution §4: that belongs in `study/`).

## 4. Evidence

Debar has no screens. Evidence is text: the command and its output, a measurement table, a harness count. Paste text as text, never as an image.

## 5. Open it, or land it

```bash
git push -u origin HEAD
gh pr create --base main --title "<outcome>" --body-file <body.md> [--draft] [--reviewer <handle>]
```

- `--draft` while work continues; the issues stay **In Progress**.
- Then record the pull request's size on its board item (lines changed, additions plus deletions, and files changed, lockfiles left out):

  ```bash
  ./in-toolchain cargo xtask record-pull-request-size
  ```

When it is ready for review, from the branch:

```bash
./in-toolchain cargo xtask ready-for-review
```

It marks the branch's pull request ready, records its size on the board, and re-claims every issue the branch holds, which moves them to **In Review**; exit 3 means another branch took one of them (`claim` skill, step 4). An issue the branch claims later, while the pull request is ready, goes straight to In Review. `gh pr ready <n> --undo` and a re-claim move them back to In Progress. Merging closes the issues and the board moves them to **Done**.

**Landing on `main` without a pull request**, when whoever directs the work asked for it: the commit message carries the `Closes #<n>` lines, and its body says what step 3 says. Rebase on `origin/main`, run the full check, push to `main`, then delete the claiming branch on GitHub (`git push origin --delete <branch>`). The push closes the issues and the board moves them to Done. Then stop: whoever directs the work watches CI.

## 6. Update it

Rewrite the body to describe the pull request as it now stands, not an appended changelog:

```bash
gh pr view <n> --json body --jq .body > body.md
test -s body.md   # an empty fetch must never be written back
gh pr edit <n> --body-file body.md
```

When the branch claims another issue, add its `Closes` line and classify it (step 1). After pushing more commits, record the size again, and re-check each closed issue's Impact, why it matters, Theme, Kind and Area against what the pull request now does.

## 7. Merge it

Only when the person asked for the merge; an unattended run never merges. Before merging:

- the pull request is ready, not a draft, and its base is the default branch (a stacked one is retargeted first, step 1);
- the body as it now stands meets step 3; fix any gap through step 6;
- step 2 holds for the head commit, and CI passed on it;
- the size is recorded.

Then merge only the head you checked:

```bash
gh pr merge <n> --merge --match-head-commit <head SHA>
```
