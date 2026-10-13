# Weekly security sweep

`sweep.py` points AI agents at the codebase as attackers, has a second agent
try to knock down each finding, and gives you a report plus GitHub issue
drafts. It doesn't schedule itself; run it from your calendar reminder.

```bash
make security-sweep                      # or: tools/security-sweep/sweep.py run
```

A full run takes a few hours. While it runs, keep the laptop plugged in with
the lid open. The script holds a systemd sleep inhibitor, but closing the lid
can still suspend the machine. If a run is interrupted, finish it with
`sweep.py run --resume <run dir>`. Agents that already finished are not re-run.

**Usage limits.** Kimi's plan has a 5-hour usage window. A single hunter plus
two verifiers used up the remaining window in testing, so expect Kimi to run
out partway through most runs. When either CLI reports a spent window, the
script stops starting tasks on it for the rest of the run. Pending
verifications fall back to the other model, and skipped hunters show as failed
in the report. Once the window resets, `--resume` runs only those skipped
hunters. Where Claude counts against a subscription, the same applies to it.
The report's "cost" is Claude's API-equivalent figure.

## What it does

1. **Snapshot.** Exports `master` (or `--ref`) with `git archive` into a
   read-only directory with no `.git`. The agents never see your working
   tree, so uncommitted changes aren't swept.
2. **Hunt.** One agent per attacker goal in `goals.toml`, per agent CLI
   (Claude and Kimi by default, so 18 hunters). Goals are attacker outcomes
   such as "recover the seed", "defeat the PIN limit" or "get a signature for
   something the screen didn't show". They aren't one goal per invariant
   because real breaks combine weaknesses across invariants: #855 (one
   dumped SE → PIN → seed) slipped past reviews that checked each invariant's
   wording in isolation. Hunters get the commits since the last sweep as a
   hint about where to look first.
3. **Verify.** Each finding of MEDIUM or above goes to a verifier whose job is
   to refute it. The verifier is the *other* model where possible: Kimi checks
   Claude's findings and Claude checks Kimi's. The verifier also checks the
   finding against every GitHub issue, open and closed, and against the
   owner-accepted risks in CLAUDE.md. A match with a closed issue is reported
   as a regression.
4. **Merge.** One agent groups the surviving findings by root cause and writes
   one issue draft per group.
5. **Report and log.** Shows a desktop notification at the end. Everything
   is kept under `~/pq1-security-sweeps/`:

   ```
   history.md                    one row per sweep: date, commit, new findings,
                                 re-found issues, failed agents, cost, report link
   <date>-<commit>/
     report.md                   the readable result
     sweep.log                   timestamped log of the run (resumes and filings append)
     issues/*.md                 one GitHub issue draft per new finding
     summary.json  findings.json hunt/  verify/   structured results
     raw/                        every agent's full output
     meta.json  context/         what was swept and the issue list it was checked against
   ```

**Nothing is filed automatically.** Read the report, then:

```bash
tools/security-sweep/sweep.py file ~/pq1-security-sweeps/<run>   # asks before filing
```

That command files each draft as `[sweep] <title>` with the labels `finding`
and `priority:<severity>`. It records what it filed, so running it twice
doesn't create duplicates.

## Reading the report

- **New findings:** verified CONFIRMED or PLAUSIBLE, and not already tracked.
  PLAUSIBLE means one step needs silicon to settle. These are the only items
  that need your attention.
- **Re-found known issues:** already on GitHub. While #855 is open, expect the
  `seed-extraction` and `pin-bypass` hunters to find it again each week. It
  serves as a canary: if a hunter stops finding a known open bug, that hunter
  has become less effective.
- **Refuted or accepted:** each with the verifier's reason, so you can
  overrule one.
- **Hunter coverage** and **What held:** what each hunter checked and found
  sound. A goal with no findings and a long "held" list was swept properly. A
  failed hunter means that goal was not covered this week.

Exit codes: `0` no new findings · `1` new findings · `2` no new findings, but
some agents failed (coverage incomplete) · `130` interrupted.

## Options worth knowing

```
--backends claude        only Claude (faster; loses the cross-model check)
--goals seed-extraction pin-bypass
--claude-model opus      default: your claude CLI default
--claude-effort high     low|medium|high|xhigh|max
--jobs 4                 agents running at once
--hunt-timeout 60        minutes per hunter; --verify-timeout 30
--min-verify-severity MEDIUM
--budget-usd 15          spending cap per Claude agent
--dry-run                write every prompt to <run>/prompts/ and stop
```

## Safety model

The agents read untrusted content: the whole repo, including vendored code
and docs. They are confined as follows:

- **Claude** runs with `--permission-mode dontAsk` and only read tools
  (`Read`, `Grep`, `Glob`, plus `ls`/`grep`/`wc`/`head`/`tail`/`xxd`). It has
  no MCP servers (`--strict-mcp-config`, so no Gmail or Drive), no web access
  and no subagents. Without `dontAsk`, a global `defaultMode: auto` would let
  it run any shell command it chose.
- **Kimi** runs every tool call without asking in `-p` mode, edits included.
  It is confined by the environment instead: the snapshot is `chmod a-w` and
  has no `.git`, and `gh` runs with an empty config, so it is logged out.
  Kimi can still reach the network and write outside the snapshot. If that's
  unacceptable, use `--backends claude`.

## Changing the goals

Edit `goals.toml`. Keep `start` to entry points, not a list of known bugs:
AGENTS.md asks reviewers to derive threats from the source in fresh
contexts. The prompts are in `prompts/`. Placeholders are `${name}`, filled in
by `sweep.py`.
