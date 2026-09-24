## What it is

A laptop keyboard standing in for the two buttons. `tools/panel/play_flow.py` builds a `FlowDriver` over a flow, feeds it key edges, and streams the live-rendered frames to a physical NV3007 over the USB-SPI bridge — so the grammar can be felt on real glass before firmware exists.

It exists to answer "does this feel right", not to be ported. Production firmware reads real buttons and will never run this file or `pq1/driver.py`.

## The keys

| key | gesture | what it does |
|---|---|---|
| `→` / `d` | right tap | forward one screen; into the details from an ask; on a PIN row: digit +1 |
| `←` / `a` | left tap | back one screen; into the details from an ask; on a PIN row: digit −1 |
| `space` / `e` | both buttons | **PIN row only**: ENTER the digit; the 8th checks the PIN |
| `D`, or `d` `d` quickly | right double press | **PIN row only**: NEXT, the cursor forward over entered digits |
| `A`, or `a` `a` quickly | left double press | **PIN row only**: BACK, the cursor to the previous digit |
| `s` / `enter`, held | right hold | sign, on armed screens — [hold right](hold-right-sign.md) |
| `x` / `backspace`, held | left hold | decline; on a PIN row, cancel — [hold left](hold-left-decline.md) |
| `y` / `n` | — | **the host, not a button**: answers a looping film — `y` the work succeeded (the check), `n` it failed (the X, on a flow that authors a failure film; elsewhere a notice). The film finishes its current turn and spirals in ({{loc:pq1.driver.FlowDriver.answer}}). On the device the signing core answers — [loading loop](../transitions/loading-loop.md) |
| `r` | — | jump back to the first screen; it works at any time, and is meant for after an ending |
| `q` / Ctrl-C | — | quit |

The player's own `KEYMAP` string is copied verbatim into `spec/gestures.json` (`bench_keymap_BENCH_ONLY`), so the authority for this table cannot drift from the file.

## Where the keyboard is not the device

Five differences to keep in mind while reading the panel:

- **A tap key has no duration.** `d` calls `press` and `release` with the same clock value, so it is always inside {{tok:pq1.motion.TAP_MAX_MS}}. Real buttons can be held a little too long and become a hold.
- **A hold is inferred from key repeat.** Holding `s` produces a stream of repeats; the player treats a gap in that stream as the release — a long gap before the first repeat (the OS's delay-until-repeat, `--initial-gap`) and a short one after (`--repeat-gap`). A release is therefore seen **late**, by up to that gap. Let go just before the fill completes and the bench may commit anyway. Real buttons have exact edges; port from the edges.
- **`--instant-holds` is not a gesture.** With key repeat off, one press calls `FlowDriver.hold` and fires the whole gesture at once ({{loc:pq1.driver.FlowDriver.hold}}). The fill still appears full for the commit, because `Sim.hold_commit` back-dates a press by {{tok:pq1.motion.HOLD_COMMIT_MS}} when there was none ({{loc:pq1.flow.Sim.hold_commit}}).
- **`space` is not "both buttons".** It calls `FlowDriver.enter`, which does nothing off an entry ({{loc:pq1.driver.FlowDriver.enter}}). Pressing `a` and `d` together *does* reach the real grammar — and outside an entry that is two taps, not a chord. See [unbound gestures](unbound-gestures.md). `D` / `A` are the same kind of shortcut for the double press.
- **`y` / `n` are the host answering.** There is no such button; the port wires the signing core's result to the same `answer`. `--ready MS` is a scripted host that answers "succeeded" MS after the film starts ({{loc:pq1.driver.FlowDriver.auto_answer}}).
- **`r` has no hardware equivalent.** `FlowDriver.restart` snaps back to the first screen and drops the built animations so an entry starts empty ({{loc:pq1.driver.FlowDriver.restart}}). The device has no restart gesture.

## What the bench gets right

- The **NAV** spring profile ({{val:pq1.motion.NAV}}) — `FlowDriver`'s default, the hardware pace, not the demo loop's KIOSK.
- No auto-advance: every dwell is pinned to infinity, so nothing moves without a key — see [demo auto-advance](demo-auto-advance.md).
- Real timing: the fill rises from the real press edge, drains on a real release, and commits only at completion.
- The panel rate: the player targets {{val:tools.handoff.introspect.PANEL_FPS}} fps, the NV3007's own rate.

Not simulated: the press-feedback chevron nudge ([press feedback](../components/press-feedback.md)).

## Reading the status line

Every frame the player rewrites one line: the screen's index and id, its page when it has more than one, its kind, the driver's state (`navigating` / `resolving` / `finished`; on a looping film the kind field reads `waiting (y ok / n fail)` until the answer, then `answered → check` / `x`), and the list of gestures armed right now — `<-tap`, `tap->`, `hold-R sign`, `hold-L decline`, and on a PIN row `tap-L −`, `tap-R +`, `both enter`, `2x-L back`, `2x-R next`, `hold-L cancel`. On an entry the kind field carries the digits typed so far. While a hold is live the line appends the fill percentage; the player adds the measured frame rate at the end. It is the fastest way to see what the grammar thinks is armed ({{loc:pq1.driver.FlowDriver.status_line}}).

## Running it

It needs a real terminal (raw keyboard input — it refuses a pipe) and a Python with `pyusb` on the panel bridge, not the system `python3`. The flow's endings are chosen at launch: `--end` for the signing ending, `--decline-end` for the failing one, defaulting as `flows.playable` does ({{loc:flows.playable}}).

```
.venv/bin/python tools/panel/play_flow.py safe/add_owner
.venv/bin/python tools/panel/play_flow.py pin/unlock            # type the PIN yourself
.venv/bin/python tools/panel/play_flow.py safe/clear_sign --end declined --instant-holds
```

## Do / Don't

- **Do** use it to check a port's *feel* against the reference, one screen at a time.
- **Don't** port any of this file: no keymap, no key-repeat hold synthesis, no restart key, no status line.
- **Don't** treat a late release or an instant hold on the bench as the specified behaviour. The contract is `pq1/DESIGN.md` § Input and the timings in `spec/motion.json`.

{{partial:port-notes}}
