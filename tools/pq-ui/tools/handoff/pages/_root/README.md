# PQ1 wallet UI — handoff

Everything needed to port the PQ1 hardware-wallet UI (428 × 142 NV3007 panel, two buttons) to the
device **without losing the design or its rules**. {{counts}}.

This folder is **generated from the running Python** (`python3 -m tools.handoff`): every duration,
frame count and `file:line` in it was read from the code at build time. If a page and the code ever
disagree, the code wins — run `python3 -m tools.handoff --check`.

## Start here (one minute)

| you want | open |
|---|---|
| the rules that must survive the port, on one page | [`CLAUDE.md`](CLAUDE.md) — your Claude loads it automatically |
| every screen type, component, button action and transition, one page each, with a preview | [`catalog/INDEX.md`](catalog/INDEX.md) |
| the numbers as data: tokens, easing samples, per-screen phase tables, the gesture truth table, replayable input traces, every flow | [`spec/`](spec/) |
| to see it move | [`previews/`](previews/) — GIFs re-rendered at the panel's {{val:tools.handoff.introspect.PANEL_FPS}} fps from the code (illustrations: never measure timing off a GIF) |
| to check your port against the spec | [`skill/pq1-conformance/`](skill/pq1-conformance/SKILL.md) |
| **which rules are real** — what to implement, what to ignore, what is deliberate | [`RULES.md`](RULES.md) |
| what the consistency audit found, and what is still open | [`REPORT.md`](REPORT.md) |
| the Python itself | `source/` in the zip · the repo root otherwise (`pq1/` design system, `screens/` library, `flows/` the flows, `tools/panel/` the NV3007 driver) |

Paths such as `pq1/motion.py:326` are relative to the **source root**: the repo root, or `source/`
inside the zip.

## How to read a catalog page

Each page has the same parts: what it is → when it appears (which live flows use it) → its spec
(the screen dict) → geometry → a **motion table** → what the buttons do (rows of the executed truth
table) → a preview → do / don't. The motion table is the contract:

| phase | ms | {{lit:frames @14 fps}} | easing | token | defined at |
|---|---:|---:|---|---|---|
| what happens | how long | the same, in panel frames | the `pq1/motion.py` curve | the constant that owns the number | where to read it |

Every page carries a tag: **PORT** (implement it) · **DEMO-ONLY** / **BENCH-ONLY** (exists for the GIF
loop or the laptop bench player — do not port) · **SPEC-ONLY** (specified, not rendered by the Python yet).

## The specs

| file | holds |
|---|---|
| `spec/motion.json` | every timing / geometry token (`value`, `unit`, `frames_14`, `scope: device\|demo`, `source`), every easing (its Python source + 33 samples), sampled envelopes (hold fill, page flip, chevron hint, confirm band, busy pulse), both spring profiles sampled per panel frame, the verdict law, the qubit timeline, the explosion tables |
| `spec/anims.json` | every library screen × preset and the three core status animations: phases per preset, `t_resolve`, `duration`, result hold, what it rests on, whether it can lead, which curves it calls, the spec a flow splices in |
| `spec/screens.schema.json` | the screen dict: every field, defaults per kind, enums, the validation errors the design system raises, layout tokens, the Confirm? rule |
| `spec/gestures.json` | the input tokens and the **truth table** — every context × gesture, produced by executing the reference driver |
| `spec/traces.json` | scripted two-button sessions and the screens / states / armed sets they must produce — replay them against the port |
| `spec/flows.json` | all flows, screen by screen, with their endings |
| `spec/build.json` | a hash of the sources this folder was built from |

## Use the checker skill

```
cp -R skill/pq1-conformance <your-project>/.claude/skills/        # Claude Code finds it there
python3 skill/pq1-conformance/scripts/port_diff.py path/to/ui_tokens.h --spec spec
```

Then ask your Claude to *"check the port against the PQ1 spec"* — the skill walks the constants, the
verdict and entrance laws, the curves, the gesture thresholds, the state machine (via the traces),
the flow shape and the do-not-port list. In the zip the skill is also pre-installed at
`.claude/skills/pq1-conformance/`.

## Running the Python

```
cd source            # (or the repo root)
pip install -r requirements.txt          # Pillow only
python3 -m flows send_token --end all    # render a flow: every ending
python3 -m screens --list                # the library screens
python3 -m tools.check                   # the design rules, as a checker
python3 tools/panel/play_flow.py send_token --fps 14     # drive it on the NV3007 with the keyboard
```
