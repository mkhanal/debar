---
name: claim
description: "Debar: find or create the GitHub issue for the work and claim it, so no two people or agents work on the same thing. TRIGGER before any task that edits the repository, or on /claim."
argument-hint: '<the work, in a sentence> | <issue number>'
---

# Claim

Every change starts from a GitHub issue that this work holds and nobody else does. An issue is held by the branch recorded in its **Branch** field on the board (the "Debar" project, https://github.com/users/mkhanal/projects/2, shown **In Progress**), or by an open pull request that closes it. It holds until that branch is deleted or the pull request is merged or closed.

One branch may hold any number of issues: related work goes together in one branch and one worktree, or is spread over several, whichever fits. The only rule is that an issue is held by one branch at a time.

An issue's creator is assigned when it is opened, and whoever claims it becomes its only assignee. Assignment never holds an issue: anyone may claim an assigned issue that no branch or pull request holds.

The board has four statuses: **Open** (not yet claimed), **In Progress**, **In Review** and **Done**. Anyone, person or agent, may create an issue. There is no priority field and no grooming: whoever picks an issue up scopes it, so work on what adds value now; an old issue nobody picks up is simply not needed.

The board tasks run in the toolchain image with your GitHub token, which needs the `project` scope (`gh auth refresh -s project`). Export it once per shell:

```bash
export GH_TOKEN="$(gh auth token)"
```

## 1. Find the issue

Skip to step 3 when given an issue number.

A new issue is the last resort. The same need filed twice splits the work and its history, so first rule out that the need is already somewhere.

**The current work first.** List the issues this branch already holds, read each one's body, and reread the task in hand:

```bash
gh project item-list 2 --owner mkhanal --format json --limit 1000 \
  | jq --arg b "$(git branch --show-current)" '[.items[] | select(.branch == $b) | .content.url]'
```

If the need is part of that work (a case, a symptom or a step of what the branch already delivers), it needs no issue. When it widens what "done" means, add it to that issue's done-when (`gh issue edit <n> --body-file`) or comment on it.

**Then everyone else's.** Search open issues, open pull requests and recently closed issues in both repositories on the board (`mkhanal/debar`, and for harness work the comparison harness's repository, the one `.github/workflows/comparison.yml` calls; pass `--repo` to `gh`) with two or three phrasings of the outcome, in domain words, and read each candidate's body, not just its title:

```bash
gh issue list --state open --search "<words>" --limit 20 --json number,title,url,assignees
gh pr list --state open --search "<words>" --limit 20 --json number,title,url,headRefName,author
gh issue list --state closed --search "<words>" --limit 10 --json number,title,url,closedAt
```

| What the search finds | Do |
| --- | --- |
| An issue asking for the same outcome, whatever its wording | Claim it (step 3) |
| A larger issue this need is one part of | Claim the larger issue, or comment the case on it; never split off a part that cannot be delivered alone |
| An issue covering part of the need | Claim it, and create an issue (step 2) only for the remainder, linking it |
| An open pull request doing the work, or an issue another branch holds | Stop: it is held (step 4). A finding that belongs to that work goes as a comment on it, not as a new issue |
| A recently closed issue for it | Check whether the work is done before starting again; reopen it if it regressed |
| Several symptoms with one cause | One issue for the cause, the symptoms listed in it |
| Nothing covering any part of it | Step 2 |

This applies equally to what you find while working: a bug, a gap, debt. File it only once neither the current work nor an existing issue covers it. Once filed, claim it for this branch (step 3) if this branch will do it; otherwise leave it unclaimed in Open, free for anyone.

## 2. Create the issue

**An issue states the problem or the outcome wanted, its evidence, and how we will know it is met. It never prescribes the solution.** Solutions come up while building and are decided then, recorded in `architecture-overview/DECISIONS.md` or the pull request. "Digests cost about 40 instructions per byte on every kind of file, more than the whole fifty-times budget allows", not "use hardware SHA-256".

Title it with the value it adds or the problem it removes, in domain language. The body has three parts, in this order, and names the related issues the search turned up:

1. **Problem** (or **Outcome**): who needs it and what is wrong or missing now.
2. **Evidence**: the measurement, harness count, requirement or study note that shows it, with where it came from.
3. **Done when**: how anyone can check it is met: a requirement passes, a measurement moves, a harness count changes, a question is answered and recorded.

An issue that needs a person's decision says the question, the evidence and the options only as context, and is labelled `needs-decision`.

```bash
gh issue create --title "<outcome or problem>" --body-file <body.md> --type <Task|Bug|Feature> --project Debar
```

Use **Bug** for something that should have worked and did not, **Feature** for something Debar or its tooling could not do before, **Task** for anything else. `--project Debar` puts it on the board, where it starts **Open** (the board does not add issues by itself; see `.claude/README.md`). An issue made without it is added the first time it is claimed or classified.

Classify it as soon as it exists (see [Classify what you claimed](#classify-what-you-claimed)), whether or not you claim it, so unclaimed work shows its Theme, Kind and Area too.

No epics, sub-issue hierarchies or pre-planned backlog: an issue is created when work is claimed or when a problem is found, never to plan future work.

## 3. Claim it

From the branch you will work on (any name; not the default branch):

```bash
./in-toolchain cargo xtask claim <issue> [<issue>...]
```

`--branch <name>` claims for another branch instead of the current one. Claim more issues on the same branch whenever related work joins it.

| Exit | Outcome | Do |
| --- | --- | --- |
| 0 | every issue `claimed`: the branch is on GitHub (created at its base on the default branch if it was local only), recorded on each issue's board item, In Progress (In Review if the branch's pull request is ready for review), and you are the only assignee | Work |
| 3 | `not claimed` (an issue is held or closed: nothing was claimed) or `lost` (a claim made at the same moment overwrote yours on those issues) | Step 4 for those issues |
| 1 | the claim could not be made (e.g. the token lacks the `project` scope, or `GH_TOKEN` is not exported) | Stop and report the error; never work unclaimed |

The board's own workflows give every issue added to it the status **Open**, and **Done** when it closes.

### Classify what you claimed

Once claimed, record on the board what kind of value each claimed issue adds, so anyone can see where the work goes without reading it. Read the options and their definitions from the board, and choose by the rules in [work-classification.md](./work-classification.md):

```bash
./in-toolchain cargo xtask classify-work --options
./in-toolchain cargo xtask classify-work <issue> --theme "<theme>" --kind "<kind>" --area "<area>"
```

An Area is a part of Debar a user or contributor would name. When the work creates a new one (a new signature-format part, a new compatibility interface, a new layer) and no Area fits, add it first with `classify-work --add-area "<name>" --area-description "<one sentence>"`. Never add one for an internal sub-part of an existing Area.

Only the fields given are written; run it again with a different value to change one. A value that is not one of the board's options is refused with the list of options (exit 1): pick one of those, never a new one. A field missing from the board also fails with its name: report it, the board needs the field. Impact and why the work matters are set when the work is handed in (`pr` skill).

## 4. Held: stop

Report the holder from the output: branch, pull request, author, last update. Never push to, rebase, or take over another claim's branch or pull request; that needs the holder's say-so. Offer the user the choices that fit: pick other work, contribute on the holder's pull request once they agree, or split a genuinely separate outcome into its own issue.

## 5. Carry the claim through

- The pull request body, or the message of the commit that lands the work on `main`, says `Closes #<issue>` for every issue the branch holds (`Closes <owner>/<repository>#<n>` for an issue in the harness's repository).
- When the pull request is ready for review, `./in-toolchain cargo xtask ready-for-review` marks it ready, records its size on the board and re-claims the branch's issues, which moves them to In Review (a claim always sets the status from the branch's pull request).
- Merging the pull request, or pushing the closing commit to `main`, closes the issue and the board moves it to Done. Then delete the branch on GitHub.
- Abandoning the work: delete the branch (and close the pull request); that releases every issue it held.
