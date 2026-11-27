---
name: autofix-schedule
description: "Debar: set up, change or remove this machine's schedule of unattended /autofix runs (nightly, every few hours), through T3 Code or the operating system's scheduler (launchd, cron), with whichever agent CLI the developer uses. TRIGGER on /autofix-schedule, or a request to schedule, change or stop autofix runs."
argument-hint: "[nightly | every <n> hours | HH:MM | remove] [<n> issues]"
---

# Autofix schedule

Each developer decides when their own machine works the board: nightly, every few hours, or not at all. Every run is the same whatever starts it: it works up to a set number of Open issues (4 by default), one after another, each in a fresh worktree and its own agent conversation running `/autofix --unattended`, ending in a pull request or a hand-back. It stops early when no Open issue is waiting. Only the trigger differs. Runs on different machines and schedules share the board safely, because the lock and the hand-backs live on GitHub (`autofix` skill, Step 1).

## 1. Settle the choices

Take them from the arguments, or ask once, recommending the first option:

| Choice  | Options                                                                                                                                   |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| When    | nightly at 02:00 (recommended), another time of day, or every N hours                                                                     |
| Issues  | at most 4 per run (recommended), or another number                                                                                        |
| Trigger | T3 Code's scheduled tasks when this session runs in T3 Code; otherwise the operating system's scheduler (launchd on macOS, cron on Linux) |
| Agent   | for the operating-system trigger, the CLI that runs the agent, with its non-interactive flags                                             |

Before scheduling, the machine must already be able to do a run:

- the main checkout is on a commit that has the `autofix` skill;
- `gh auth status` passes with the `project` scope;
- Docker is running, since every board task and check runs through `./in-toolchain`.

A machine that sleeps at the scheduled time skips that run. launchd runs it on wake; cron does not.

## 2a. T3 Code

Create a scheduled task with T3's `schedule_task` tool, from a conversation in the main checkout:

- **Schedule**: the chosen time.
- **New conversation for every run** (`bindToCurrentThread: false`), so runs do not pile up in one conversation's context.
- **Title**: `autofix`.
- **Prompt**: the T3 conversation only launches the runs, so its own context stays small:

  > Rename this conversation to `autofix <today's date> <HH:MM>`. In the main checkout, with `GH_TOKEN` set from `gh auth token`, repeat up to 4 times: run `./in-toolchain cargo xtask claim-next --peek`; when it exits 4, stop. Otherwise start `t3 thread start <main checkout> "Run the autofix skill, .claude/skills/autofix/SKILL.md, with the argument --unattended." --title "autofix <date> <HH:MM>" --worktree origin/main --branch autofix-run/<UTC time> --wait --json` and wait for it. When it returns, read its worktree with `t3 thread show --json --messages 0 <thread id>`; if that worktree's `autofix/*` branch has commits not on GitHub, keep the worktree, say so and stop; otherwise remove the worktree and its run branch. Stop too when the conversation failed or stopped to wait for an answer. Reply with each conversation's link and outcome.

Each issue then runs as its own T3 Code conversation in its own T3 worktree, which the `autofix` skill's Step 0 accepts as made for the run. `--provider <id> --model <slug>` on `t3 thread start` choose another agent; it needs T3 Code's runtime mode to be full access, since no one is there to approve tool use.

To change or stop the schedule later, list the scheduled tasks and update or delete that one.

## 2b. launchd or cron

The command is the agent CLI with its non-interactive flags, running `/autofix --unattended` with no one to approve tool use. Check `<agent> --help` for the flags, and never guess them. For Claude Code:

```bash
claude -p "/autofix --unattended" -n "{run}" --permission-mode bypassPermissions
```

`.claude/skills/autofix/run-unattended` starts the agent once per issue and replaces every `{run}` in the command with that issue's run name, `autofix <date> <HH:MM>`. Each is a new agent process, so each is a new conversation. Another agent reads the same skill: name `.claude/skills/autofix/SKILL.md` and the `--unattended` argument in its prompt.

The runner:

- runs at most one run per machine at a time (`<git common dir>/autofix-runs/running.pid`);
- for each issue, up to the limit: checks the board for a waiting Open issue (`claim-next --peek`) and stops when there is none; makes a worktree beside the main checkout (`<checkout>-autofix/<time>`) and runs the agent in it with `AUTOFIX_RUN` set; removes the worktree afterwards. It keeps the worktree, says so and stops the run when the agent left unpushed commits (pushed work is resumed from its branch), and stops when the agent fails.

The log of every run is in `<git common dir>/autofix-runs/`. To try it once by hand:

```bash
.claude/skills/autofix/run-unattended --issues 1 -- claude -p "/autofix --unattended" -n "{run}" --permission-mode bypassPermissions
```

**macOS (launchd).** Write `~/Library/LaunchAgents/dev.debar.autofix.<main checkout path with every non-alphanumeric run replaced by ->.plist`, then load it with `launchctl bootout gui/$(id -u)/<label>` (ignore "not found") and `launchctl bootstrap gui/$(id -u) <plist>`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.debar.autofix.<name></string>
  <key>ProgramArguments</key>
  <array>
    <string><main checkout>/.claude/skills/autofix/run-unattended</string>
    <string>--issues</string><string>4</string>
    <string>--</string>
    <string>claude</string><string>-p</string><string>/autofix --unattended</string>
    <string>-n</string><string>{run}</string>
    <string>--permission-mode</string><string>bypassPermissions</string>
  </array>
  <key>WorkingDirectory</key><string><main checkout></string>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string><the PATH that finds git, gh, docker and the agent></string></dict>
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>2</integer><key>Minute</key><integer>0</integer></dict>
  <key>StandardOutPath</key><string><git common dir>/autofix-runs/scheduler.log</string>
  <key>StandardErrorPath</key><string><git common dir>/autofix-runs/scheduler.log</string>
</dict>
</plist>
```

Every N hours instead of a time of day: replace `StartCalendarInterval` with `<key>StartInterval</key><integer><N × 3600></integer>`. Escape `&`, `<` and `>` in every string. To remove it: `launchctl bootout gui/$(id -u)/<label>` and delete the plist.

**Linux (cron).** One line per checkout, marked so it can be replaced or removed: `crontab -l` (empty when there is none), drop any line ending in `# debar-autofix:<main checkout>`, append the new one, and write it back with `crontab -`:

```
0 2 * * * cd '<main checkout>' && PATH='<path>' '<main checkout>/.claude/skills/autofix/run-unattended' --issues 4 -- claude -p '/autofix --unattended' -n '{run}' --permission-mode bypassPermissions >> '<git common dir>/autofix-runs/scheduler.log' 2>&1 # debar-autofix:<main checkout>
```

Every N hours: `0 */N * * *`. To remove it, drop the marked line and write the crontab back.

## 3. Report

Report the schedule, the issue limit, the trigger, the agent command (or T3 Code's provider and model) and where the run logs are. Then report how to change or remove the schedule: `/autofix-schedule <new choice>` or `/autofix-schedule remove`.
