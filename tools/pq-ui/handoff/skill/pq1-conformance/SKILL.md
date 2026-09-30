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
| V-BOX | a verdict *sign* inks its LARGEST dimension to `layout.VERDICT_BOX` — measured on the resting frame, never read back off the screen's own constant; a disc ending (`firmware_verified`, `headshake`) is held to the disc instead, and the PIN pill, LAST ATTEMPT and the open padlock are not signs | live, measured |
| V-CENTRE | a sign and every registered mark sit *on* the circle: the ink's luminance-weighted centroid within 1.5 px of (its own cx, `CIRCLE_CY`) — bbox-centring is not enough for an asymmetric shape; letters are text, centred by the font's metrics | live, measured |
| V-MARKBAND | *(warn)* a new mark lands in the band the registered set spans — extent 39–60 % of the visible disc, ink 4.5–12.5 % of its area; a chain's brand logo, full-bleed art and the off-disc signs (plus, minus, exclamation) are exempt | live, measured |
| M-EASE | no hand-rolled power curve — `(1 - x) ** n` belongs in `pq1/motion.py` | ast |
| M-ROLE | an entrance is `ease_out` — a bare `ease()` result never becomes an alpha | ast |
| M-DIVLIT | no bare timing divisor (`e / 350`) — name the span | ast |
| M-ACCENT | no one-shot phase under `VERDICT_ACCENT_MIN_MS` (two panel frames) | live |
| M-UNUSED | every public name in `pq1/motion.py` is consumed somewhere | ast |
| M-FPS | *(info)* the panel frame rate is a named constant | live |
| L-CONTRACT | a `screens/` module: `ANIM` == module name, `SPEC`, registered | live |
| L-LOOP | a looping film (`StatusAnim.loops`) wraps pixel-exact by whole `loop_ms` turns; `film_time` is the identity at zero wraps; a live film is `inf` until answered, then latches `t_resolve + wraps × loop_ms` and still rests `RESULT_HOLD_MS` | render |
| F-IMPORT | every flow module imports (a flow that raises does not exist at runtime) | live |
| F-ICON | every `icon` a flow or library screen names is in `components.GLYPHS` — the Ethereum fallback is deliberate, so this stops it ever answering a *typo*; `letter:X` (an unknown chain's initial) is a namespace, legal by shape | live |
| F-CHAIN | a chain screen names its network with `chain=<id>`, never a hand-written chain `icon=` — one id derives the mark, the colour and the caption, so the art and the words cannot name different networks | live |
| F-ELLIPSIS | no ellipsis in a value the signer must verify — a hash **pages**, it never shortens. Exactly two shortenings are sanctioned (DESIGN.md § Text rules): the blind-call `DATA HASH` fingerprint and a resolved recipient under its SemiBold name. Three ASCII periods are never a shortening | live |
| F-MARKCONTRAST | a mark reads on its own disc: WCAG 3:1 between the resolved mark colour (`colors.mark_color`, or the colour the screen pins) and the fill it knocks out of, on every flow screen and every library `SPEC` / preset — logo art has no knock-out colour and is skipped | live |
| F-ASSET | every glyph registered through `components.register_logo` found its file, and every `TOKEN_LOGOS` stem resolves to registered art — the `?` monogram is unreachable at build time | live |
| I-ARMED | a live hold says which button is down: driven through the real `FlowDriver`, a left hold and a right hold must render DIFFERENT frames on a commit screen, a decline hold must change the chevron row on a detail (where it is the only armed hold), and nothing may be drawn inside `TAP_MAX_MS` — a tap still looks like a tap | live |
| T-WIDTH | every detail line MEASURES inside `TEXT_REGION_W` in the face it will be drawn in — a character count is not a width (at 22, `D` x21 is 327.6 px and `l` x21 is 132.2); a value screen measures against `TEXT_REGION_FULL_W` | live |
| T-FIT | *(info)* detail screens whose typed `size` sits below the largest tier that measures — a typed size is the author's pin, reported never failed | live |
| C-RAMP | the mono ramp (the recognized-token look) is reached only by an explicit `palette` int — `placeholder_index` hashes strings over the 13 ramps below it, so no unrecognized token renders as ether | live |
| C-INK | an ink tint is a `pq1/colors.py` token — no bare factor typed into `colors.scale(WHITE, …)` in `pq1/` or `screens/`. A runtime alpha is not a tint: the canvas takes the screen's alpha as its own argument | ast |
| C-CONTRAST | the colour system's legibility floors, measured in WCAG relative luminance: every placeholder ramp's fill stop ≥ `colors.PLACEHOLDER_MIN_CONTRAST` (4.5) against WHITE (it carries the white ring and mark), every named ink tier ≥ 4.5 against the black panel, and every mark ≥ 3:1 against its disc once the hold film has risen over it. Chain brand colours are F-MARKCONTRAST's 3:1, not this | live |
| A-FLOOR | a visibility guard reads a named floor — `colors.ALPHA_FLOOR` (the panel's first visible alpha), `FILM_FLOOR` for a black film over drawn ink, `motion.LEVEL_EPS` for a hold fill level; no bare small number compared against an alpha-named operand in `pq1/` or `screens/` | ast |
| T-TOKEN | a type size or tracking is a `pq1/typography.py` token — no bare `size=` / `ls=` number and no typed `*_SIZE` / `*_LS` constant in `pq1/` or `screens/` (typography.py itself excepted; flows type `size=` by design — that is T-FIT's business) | ast |
| F-NORM | every flow builds for every ending; `--early` works exactly when a Confirm? exists — a bench flow (no `ENDS`) is exempt from the pairing, having nothing to commit to | live |
| F-DEFEND | a flow with `ENDS` names its `DEFAULT_END` | live |
| F-STATE | every ending's state is a `colors.STATE` key | live |
| F-ENDVOCAB | `ENDS` keys come from one vocabulary (`rules.END_VOCAB`) | live |
| F-ENDPAIR | endings follow the grammar: done = qubit + check · failing = resolve + X (qubit + X only when the flow names the film — a failure after dispatch) · led by a film = arrive · or a library verdict | live |
| F-CONFIRM | Confirm? sits at `CONFIRM_INDEX` of every segment with `CONFIRM_MIN_DETAILS`+ details, nowhere else | live |
| F-RETURN | the walk returns to the ask: the screen before an ending is a hero that commits | live |
| G-CONFIRM | the Confirm? screen is composed like the chain screen: `CONFIRM_TEXT_X` / `CONFIRM_CIRCLE_X` equal `layout.chain_compose("Confirm?", SIZE_XL)` | live |
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
python3 scripts/port_diff.py path/to/ui_colors.h --colors    # the same, for spec/colors.json
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
| 8 | **Input rules**: left regresses / right progresses; the ask is the hub (right enters; left on an idle screen goes back one screen or does nothing, never forward, `layout.back_target`; both chevrons stay); a hold never fades a chevron — both stay through sign, decline and the PIN cancel (I-ARMED); decline armed on every navigable screen; sign only where `commit`; endings ignore input; a press during a transit retargets, never drops | `catalog/actions/`, `catalog/transitions/reversal.md` |
| 9 | **Flow shape**: Confirm? is the 6th screen of a segment with 7+ details; endings follow the grammar | `spec/flows.json`, `spec/screens.schema.json` `flow_shape` |
| 10 | **Transits**: token-less screens fade to black and drop the next handoff; the handoff crossfade runs under the hold phase; text-in delay | `catalog/transitions/` |
| 11 | **Nothing demo-only was ported**: dwell timers, auto-advance, the demo-performed hold, the KIOSK spring pace, bench keys | every page tagged DEMO-ONLY / BENCH-ONLY in `catalog/INDEX.md` |
| 12 | **Colour**: every base and state colour, every ramp stop, the pinned chain discs and marks, the ink tints and the hold film. A ramp stop that differs changes what the user checks on a signing screen. The mono ramp is reachable only by an explicit pin — a hashed symbol / address never lands there | `port_diff.py --colors`; `spec/colors.json` (`tokens`, `hash_rule`), `catalog/components/token-disc.md` |
| 13 | **Data stays data**: amounts, symbols, addresses, hashes are per-transaction values — never constants; an unknown token's gradient is hashed from its address | `catalog/components/token-disc.md`, `catalog/components/detail-text.md` |
| 14 | **The loading loop**: a film starts at dispatch, repeats the steady orbit in whole turns (`spec/motion.json` `qubit_timeline.loop` / `loop_ms`) until the host answers, latches its outcome at the spiral — no later than `t6` of the last turn; the spiral + flash tail and the rest are fixed; a finished ending freezes | `catalog/transitions/loading-loop.md`, `spec/anims.json` `loops`, `spec/traces.json` "host answers" traces |

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
