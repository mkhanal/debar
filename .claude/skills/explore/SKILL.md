---
name: explore
description: "Debar: read-only investigation. Maps an area of the code, the roadmap, the decisions and the study notes, answers the question, and routes any change it implies to a lane. Makes no edits. TRIGGER on /explore or a question about how Debar works."
argument-hint: '<area or question>'
---

# Explore

Answer the question from what is written and measured, and change nothing.

1. **Where it sits.** Read `architecture-overview/ROADMAP.md` for the piece, `architecture-overview/DECISIONS.md` for what is settled, and `architecture-overview/ARCHITECTURE.md` for the layer and what it may use.
2. **What exists.** Read the crate's public interface, its tests and its requirements in `specs/`. Run its tests or a measurement when the answer depends on behaviour (`./in-toolchain cargo nextest run -p <crate>`, `scan-profile`, `measure-scan`: AGENTS.md "Commands").
3. **What the reference does.** Read that format's notes in `study/`. When the answer is not there, ask the `signature-expert` agent; never answer from memory.
4. **Answer** with file and line references, the command and output behind each claim, and what is not known.
5. **Route.** When the answer implies a change, name the lane (`fix`, `build`, or a person's decision) and the issue it belongs to (`claim` skill, step 1). Do not claim or edit.
