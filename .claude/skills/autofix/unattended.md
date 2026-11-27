# Unattended mode

How a lane (`fix`, `build`, and the `work` router in front of them) runs when no person is there to answer: started with `--unattended` in its arguments, which a scheduled `autofix` run always passes on. A run a person started in a conversation is never unattended. Everything in the lane still applies (the claim, the failing test, the root cause, `./in-toolchain cargo xtask check`, the `pr` skill); this file changes only what happens when the lane would ask a person something.

## No one to ask

Never ask in chat and never wait. Every point where the lane would stop for a person ends one of two ways:

- **Decide and go on**, when the answer follows from the issue, the requirements, DECISIONS, the study notes, the code and the way nearby code already does it. Record the decision under **What needs a decision** in the pull request, with the reason, so the reviewer can overturn it.
- **Hand back**, when it does not: a person's direction is needed, or the change is too risky to make alone. You judge which; when unsure, hand back.

## The turn is the run

The scheduler takes the end of the conversation's turn as the end of the run: it checks the worktree and moves to the next issue at once, and nothing wakes the conversation in time to finish. So never end the turn while a command the run waits on (the full check, a test run, a push) is still running, and never end it with a promise to continue. Run the command in the foreground; when it outlasts the tool's foreground limit, start it in the background and keep the turn waiting on it until it reports, then act on the result in the same turn.

## Hand back when

Each of these needs a person, so it is a hand-back, never a guess:

- **The design is not agreed.** No decision in DECISIONS covers it, or the issue can be read more than one way, or it would add a layer, a crate or a dependency.
- **A difference a signature can observe** would be kept on purpose, or the reference's behaviour is not in `study/` and the `signature-expert` agent cannot settle it (Constitution §2, §5).
- **A budget or a ratchet** would be loosened, or a requirement or comparison weakened.
- **A change to `CONSTITUTION.md`, `PRODUCT.md`, a requirement's wording, the toolchain image, CI, branch protection or secrets.**
- **A destructive or irreversible operation**, or anything outside this repository and its study folder.
- **The root cause cannot be named**, or three hypotheses have failed (`fix`, step 3).
- **The issue is bigger than one pull request**, or is a goal with sub-issues.
- **The issue looks done, duplicated or no longer wanted.** Say why, and let the person close it.
- **The independent review still finds a symptom fix** after one round of changes (`autofix`).

## How to hand back

Write the comment for a person arriving cold, then run:

```bash
./in-toolchain cargo xtask hand-back <issue> --body-file <comment.md>
```

It keeps the run's pushed commits on `autofix/<issue>-draft` (named in the comment; the next run on the issue starts from it), labels the issue `agent-blocked`, posts the comment, deletes `autofix/<issue>` and clears the claim, so the issue is back in **Open**. Push partial work first when it would help the person decide; the task refuses while the local branch has unpushed commits, so nothing is lost by accident. Run again after a failure part-way: it does not repeat a comment already posted (it reads the comments only when the issue already carries the label). Exit 3 means `autofix/<issue>` no longer holds the issue (a person or pull request took it): stop, and do not comment.

The comment:

1. **Found**: what the investigation established, with file and line references and the failing test when there is one.
2. **Why this needs a person**: which of the reasons above, in one or two sentences.
3. **Questions**: numbered, as many as needed, each answerable without reading the others, each with options and the one you recommend and why.
4. **To resume**: what you will do once each question is answered.

A person answers in the comments and removes the label, which puts the issue back in the queue. The next run reads every comment, its own included, before starting.

## Never a band-aid

The lane's rules hold with no reviewer present, so they are checked, not trusted:

- Fix the source of the bad value, never where it shows. The pull request has a **Root cause** section: where the bad value or state first appears, and why. If you cannot write it, hand back.
- Never retry, sleep, widen a match arm, add a fallback default, swallow an error, add an `allow` for a lint, skip or loosen a test, raise a throughput record, or special-case the reported input to make a test pass.
- Never edit an existing test's expectation unless it encodes the bug itself. Say so in the pull request when you do.
- `./in-toolchain cargo xtask check` passes. A failure you did not cause is reported in the pull request, never worked around. When the local environment cannot run the check (Docker down, the pinned databases not fetched), the issue is not at fault: release it with `./in-toolchain cargo xtask hand-back <issue> --release-only` (no comment or label; pushed work is kept on the draft), stop the run and report the failure.

## Never unattended

Merge; push to `main`; push to, rebase or comment on a branch or pull request you did not create in this run; edit a requirement, `CONSTITUTION.md` or `PRODUCT.md`; force-push; skip hooks; change CI, the toolchain image, branch protection or secrets; create releases or tags; write a commit, pull request or comment that credits a tool or AI.

## The claim stays yours

`claim-next` re-reads the issue's board item just before claiming it, and claims it by creating its branch, which GitHub creates for one run only; a run that finds the branch already made passes the issue over. It reads the item again after recording the claim, and gives the issue up when another branch or pull request holds it. A person can still claim the issue on another branch or open a pull request for it while the run works. Before the first commit, before every push and before opening the pull request, run:

```bash
./in-toolchain cargo xtask check-claim <issue>
```

Exit 3 means the claim was lost. Stop at once, push nothing and do not comment. Switch off the branch and delete it locally and, when no pull request is open from it, on GitHub (`git push origin --delete autofix/<issue>`).

## A run that stopped part-way

A run killed mid-way (machine asleep, session ended, GitHub unreachable) leaves its issue held by `autofix/<issue>`. When that branch is gone, the next `claim-next` puts the issue back in the queue by itself. While it is still there, a person releases it from any checkout once they know no run is using it:

```bash
./in-toolchain cargo xtask hand-back <issue> --release-only
```

It keeps the branch's pushed commits on the draft, deletes the branch and sets the issue back to **Open**.
