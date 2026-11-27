---
name: work
description: "Debar: entry point for any task. Classifies it (understand / fix / build / decide) and dispatches to the right lane. TRIGGER on /work or a task handed over without a workflow named."
argument-hint: '<any task or question>'
---

# Work router

The default front door. Hand it anything; it works out which lane the task belongs to and runs that lane's discipline. You never have to remember whether something is an `/explore`, a `/fix` or a `/build`.

This skill holds **no workflow logic of its own**: it classifies and delegates to the lane skills, each of which owns its discipline.

## Classify the request

Read the task and pick the lane. When the signal is mixed, prefer **explore first**: understanding is cheap and read-only.

| Signal in the request | Lane | Delegate to |
| --- | --- | --- |
| "how does … / where is … / why does …", scoping, "understand …": no change implied yet | **Understand** | the `explore` skill |
| How a reference scanner behaves, or whether a difference is one a signature can observe | **Understand** | the `signature-expert` agent, which answers from `study/` and writes down what it learns (Constitution §5). Never answer from memory |
| "broken / failing / wrong / slower / regressed / a detection is missing": a defect in existing behaviour, a harness difference, a budget missed | **Fix** | the `fix` skill |
| "add / build / implement / support / measure …": behaviour or a piece of the roadmap that does not exist yet | **Build** | the `build` skill |
| A choice only a person can make: a design not yet agreed, a difference kept on purpose, a budget loosened | **Decide** | stop and ask; the issue is labelled `needs-decision` and the answer goes into `architecture-overview/DECISIONS.md` |
| Large or ambiguous ("make archives better", "speed up PDFs") | **Understand first** | `explore`, then route its recommendation into the right lane |

## Rules of the router

1. **Don't pre-implement.** Classify, announce the lane ("Routing to /fix: this is a harness difference in …"), then invoke that skill and follow it exactly.
2. **Pure questions never trigger edits.** Anything that reads as "understand X" goes to `explore` and stays read-only until a change is confirmed.
3. **Build starts from an agreed design.** A piece of work starts with its design agreed with a person and recorded in `architecture-overview/DECISIONS.md` (AGENTS.md, "How work proceeds"). `/work` never makes that agreement itself; without it, Build stops and asks.
4. **Claim before any lane that changes the repository.** Fix and Build run the `claim` skill first (find or create the issue, then claim it); a held issue stops the task there. Understand never claims.
5. **Finish through the `pr` skill.** A lane that changed the repository hands its work in there, as a pull request or a push to `main`.
6. **Inherit every stop condition** of the lane you delegate to. The router adds none and removes none.
7. **Sizable work runs supervised.** You stay the supervisor and hand work to agents sized and briefed per AGENTS.md "Handing work to an agent"; small work you do inline.
8. **One classification question, max.** If you genuinely cannot tell the lanes apart, ask once, then proceed.
9. **Unattended runs ask no one.** With `--unattended` (a scheduled `autofix` run), the lane runs in unattended mode ([unattended.md](../autofix/unattended.md)): a question that would go to a person becomes a hand-back on the issue.
