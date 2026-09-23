---
name: pq1-conformance
description: Check that the PQ1 wallet UI (the 428x142 NV3007 hardware-wallet screens) still obeys its design rules — in the Python design system (pq1/, screens/, flows/) AND in a firmware port of it (C / C++ / Rust / MicroPython). Runs the deterministic checker (python3 -m tools.check — the verdict law, the entrance law, named-curves-only, timing tokens, flow grammar, doc-vs-code, golden frames) and walks a port through the spec (handoff/spec/*.json, scripts/port_diff.py). Trigger this skill whenever the user wants to - check conformance or consistency, ask "did I break a design rule", run the checker, verify a port or firmware matches the spec, diff a tokens.h / constants file against motion.json, review a ported screen, animation, transition or button handler against the catalog, check timings or easings after an edit, add a rule to the checker, baseline a known exception, update the golden frames, or says "teach the checker X" / "the checker got Y wrong".
---

# PQ1 conformance

The PQ1 look is a small set of laws — how a verdict arrives, which curves exist, what the two
buttons do, how a flow is shaped. This skill keeps them true in two places:

- **Mode A — the Python repo** (`pq1/`, `screens/`, `flows/` are present): run the deterministic
  checker after any edit.
- **Mode B — a port** (firmware source is present): verify it against the machine-readable spec and
  the catalog. The Python is the reference; **`spec/*.json` is the ground truth** (it is dumped from
  the running Python), then the catalog pages, then `pq1/DESIGN.md` prose.

Both may apply (a port living next to the Python). Do Mode A first: a port checked against a
broken reference proves nothing.

---

## Mode A — check the design system

```
python3 -m tools.check                 # every rule; exit 1 on anything not in baseline.toml   (≈ 5 s)
python3 -m tools.check --rule V-TIN    # one rule
python3 -m tools.check --golden        # + sampled rendered frames vs golden.json              (≈ 5 s)
python3 -m tools.check --golden full   # + every 14 fps frame of every library screen          (≈ 20 s)
python3 -m tools.handoff --check       # is handoff/ still true to the code?                   (≈ 2 s)
```

Reading the output: `ok` the rule holds · `ok (n known)` it holds apart from `n` accepted
exceptions listed in `tools/check/baseline.toml` · `FAIL` a **new** violation — shown with
`file::Class.func:line`, the offending expression, and what the law wants · `info` noted, never
fails · `STALE` a baseline row whose exception no longer exists (someone fixed it — delete the row).

When a rule fails:

1. **Fix the code.** The message names the law; `pq1/DESIGN.md` and the catalog page explain it.
2. Re-run. If the change was visual and intended, look at the render, then `--update-golden`.
3. Only when the owner decides to accept the debt: `python3 -m tools.check --propose` prints the
   `[[known]]` block — paste it into `tools/check/baseline.toml` **with a reason**. Never baseline
   to make a failure go away on your own initiative; never loosen a rule to pass.

After a design-system change that was meant: rebuild the handoff (`python3 -m tools.handoff`) so
the spec and the catalog the firmware developer reads move with it.

### The rules

| id | law it enforces | how |
|---|---|---|
| V-BASE | every `screens/verdict/*` animation subclasses `VerdictAnim` | live |
| V-ENTRANCE | the entrance (fade + 0.97→1 rise, ease-out, within `ARRIVE_MS`) is *called* via `self.entrance(u)`, never re-derived with `motion.arrive` | ast |
| V-TIN | a verdict's `T_IN` never exceeds `ARRIVE_MS`; a mechanism lengthens `T_WAIT` | live, per preset |
| V-SUM | `t_resolve == T_HOLD + T_IN + T_WAIT + T_TEXT` | live |
| V-HOLD | every resolving screen rests `RESULT_HOLD_MS` after `t_resolve` | live |
| V-LAWCOPY | the law's phase numbers are inherited, not re-declared; one handoff span | ast |
| V-PHASEVAR | *(info)* per-verdict `T_HOLD` / `T_WAIT` that differ from the default | live |
| M-EASE | no hand-rolled power curve — `(1 - x) ** n` belongs in `pq1/motion.py` | ast |
| M-DIVLIT | no bare timing divisor (`e / 350`) — name the span | ast |
| M-ACCENT | no one-shot phase under `VERDICT_ACCENT_MIN_MS` (two panel frames) | live |
| M-UNUSED | every public name in `pq1/motion.py` is consumed somewhere | ast |
| M-FPS | *(info)* the panel frame rate is a named constant | live |
| L-CONTRACT | a `screens/` module: `ANIM` == module name, `SPEC`, registered | live |
| L-LOOP | a looping film (`StatusAnim.loops`) wraps pixel-exact by whole `loop_ms` turns; `film_time` is the identity at zero wraps; a live film is `inf` until answered, then latches `t_resolve + wraps × loop_ms` and still rests `RESULT_HOLD_MS` | render |
| F-IMPORT | every flow module imports (a flow that raises does not exist at runtime) | live |
| F-ICON | every `icon` a flow or library screen names is in `components.GLYPHS` — the Ethereum fallback is deliberate, so this stops it ever answering a *typo*; `letter:X` (an unknown chain's initial) is a namespace, legal by shape | live |
| F-CHAIN | a chain screen names its network with `chain=<id>`, never a hand-written chain `icon=` — one id derives the mark, the colour and the caption, so the art and the words cannot name different networks | live |
| F-NORM | every flow builds for every ending; `--early` works exactly when a Confirm? exists | live |
| F-DEFEND | a flow with `ENDS` names its `DEFAULT_END` | live |
| F-STATE | every ending's state is a `colors.STATE` key | live |
| F-ENDVOCAB | `ENDS` keys come from one vocabulary (`rules.END_VOCAB`) | live |
| F-ENDPAIR | endings follow the grammar: done = qubit + check · failing = resolve + X (qubit + X only when the flow names the film — a failure after dispatch) · led by a film = arrive · or a library verdict | live |
| F-CONFIRM | Confirm? sits at `CONFIRM_INDEX` of every segment with `CONFIRM_MIN_DETAILS`+ details, nowhere else | live |
| F-RETURN | the walk returns to the ask: the screen before an ending is a hero that commits | live |
| X-VALIDATE | unknown names raise — no silent fallback | live probe |
| D-CLAIMS | every `` `NAME` (number) `` in `pq1/DESIGN.md` equals the live value | regex |
| S-FRESH | `handoff/spec` matches the live code | live |
| S-SKILLCOPY | `handoff/skill/` is a byte-identical copy of this folder | hash |
| G-GOLDEN | *(opt-in)* rendered frames match `golden.json`; skips on another Pillow / FreeType | render |

**Add a rule** — a function in `tools/check/rules.py` returning `V(where, key, msg)` rows, decorated
`@rule(id, severity, title, method)`; add its row to the table above; run it alone with `--rule`.
`where` is a stable address (`file.py::Class.func`, `flow:<name>`, `anim:<key>`) — never a line
number, or edits above it orphan the baseline. If the new rule hits existing debt, `--propose` and
paste the blocks **with reasons**.

### baseline.toml etiquette

One `[[known]]` block per accepted exception: `rule`, `where`, `key` (the three that must match),
`audit` (the finding id in `handoff/REPORT.md` it belongs to) and `reason`. The checker never writes
this file. When the owner fixes an exception the row goes `STALE` — delete it; that is the ratchet:
the count only goes down. `--strict` (for CI) fails on stale rows too.

---

## Mode B — review a port

Ground truth, in order: `spec/*.json` → `catalog/` pages → `source/pq1/DESIGN.md`. The GIFs in
`previews/` are illustrations: never measure timing off a GIF (GIF delays are centiseconds — they
play ~2 % fast).

```
python3 scripts/port_diff.py path/to/tokens.h [more files] [--spec handoff/spec] [--all] [--strict]
```

`MISMATCH` and `DEMO` exit 1. `MISSING` means the port does not define a device token by name — it
may be inlined: find it by hand. `EXTRA` is a timing-looking constant the spec does not know — a
behaviour invented in the port; it should exist in `pq1/` first.

Then walk this checklist, screen by screen. Report each row as MATCH / MISMATCH / MISSING /
UNVERIFIABLE with `file:line` on both sides.

| # | verify in the port | against |
|---|---|---|
| 1 | **Constants** — every timing token, no demo tokens | `port_diff.py`; zero MISMATCH, zero DEMO |
| 2 | **Time is milliseconds.** Animations are pure functions of elapsed ms; nothing counts frames; springs step on real `dt` | `catalog/transitions/spring-morph.md`, `spec/motion.json` `springs.*.per_panel_frame` (the travel the port must reproduce at each 14 fps frame) |
| 3 | **Verdict law** per screen *and per preset*: hold → arrive → wait → caption, `t_resolve`, the 2450 rest | `spec/anims.json` (`phases`, `t_resolve`, `duration`), `catalog/transitions/verdict-law.md` |
| 4 | **Entrance law**: alpha and scale 0.97→1 both ease-out, inside `ARRIVE_MS`, one shared function, never an overshoot | `spec/motion.json` `easings.arrive` / `ease_out` (33 samples each — compare the port's curve numerically) |
| 5 | **Curves**: every easing in the port is one of `spec/motion.json` `easings`; the only overshoot is `back_out` in the status flash | each library page's Timeline table |
| 6 | **Gesture thresholds**, including the boundary: a press of *exactly* `TAP_MAX_MS` is a tap (`<=`); the hold fires at `HOLD_COMMIT_MS` from press-DOWN; snap-back is ease-out over `HOLD_SNAPBACK_MS` | `spec/gestures.json` `tokens`, `catalog/actions/` |
| 7 | **State machine**: replay each scripted session and compare screen ids, states and armed sets | `spec/traces.json`; `spec/gestures.json` `truth_table` for every context × gesture |
| 8 | **Input rules**: left regresses / right progresses; the ask is the hub; decline armed on every navigable screen; sign only where `commit`; endings ignore input; a press during a transit retargets, never drops | `catalog/actions/`, `catalog/transitions/reversal.md` |
| 9 | **Flow shape**: Confirm? is the 6th screen of a segment with 7+ details; endings follow the grammar | `spec/flows.json`, `spec/screens.schema.json` `flow_shape` |
| 10 | **Transits**: token-less screens fade to black and drop the next handoff; the handoff crossfade runs under the hold phase; text-in delay | `catalog/transitions/` |
| 11 | **Nothing demo-only was ported**: dwell timers, auto-advance, the demo-performed hold, the KIOSK spring pace, bench keys | every page tagged DEMO-ONLY / BENCH-ONLY in `catalog/INDEX.md` |
| 12 | **Data stays data**: amounts, symbols, addresses, hashes are per-transaction values — never constants; an unknown token's gradient is hashed from its address | `catalog/components/token-disc.md`, `catalog/components/detail-text.md` |
| 13 | **The loading loop**: a film starts at dispatch, repeats the steady orbit in whole turns (`spec/motion.json` `qubit_timeline.loop` / `loop_ms`) until the host answers, latches its outcome at the spiral — no later than `t6` of the last turn; the spiral + flash tail and the rest are fixed; a finished ending freezes | `catalog/transitions/loading-loop.md`, `spec/anims.json` `loops`, `spec/traces.json` "host answers" traces |

A port may legitimately differ in *how* it draws (no supersampling, RGB565, a different font
rasteriser). It may not differ in *when*, *how long*, *which curve*, or *what a button does*.

---

## Improving this skill

- **This file is the skill.** Edit `.claude/skills/pq1-conformance/SKILL.md` directly — plain
  markdown, versioned with the repo. The rules are plain Python in `tools/check/rules.py`; the port
  helper is `scripts/port_diff.py`. Under `handoff/skill/` this folder is a **generated copy** — edit
  the source here and rebuild (`python3 -m tools.handoff`); once installed in another project
  (`cp -R handoff/skill/pq1-conformance <project>/.claude/skills/`) the copy is theirs to grow.
- When the user says "teach the checker …" / "the checker got … wrong", or a review misses something
  it should have caught: **fold the lesson in now.** A new law → a rule function + a row in *The
  rules*. A new thing to verify in a port → a row in the Mode B checklist. A new source pattern
  `port_diff.py` could not read → a regex in its `PATTERNS`. The tables are the extension points —
  grow rows, not prose.
- Preserve when editing: frontmatter stays exactly `name` + `description` (the description's trigger
  list is what routes requests here); **point, don't duplicate** — this file is a checklist while
  `pq1/DESIGN.md`, the code and `handoff/spec/*.json` stay the authority.
- After editing: run `python3 -m tools.check`, `python3 -m tools.check --list` and
  `python3 scripts/port_diff.py --help` — every command in this file must work verbatim.
