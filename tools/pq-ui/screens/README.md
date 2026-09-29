# screens — the PQ1 screen library

Reusable screens and animations, one module per screen, grouped by
category. Everything renders through the [pq1](../pq1/README.md) design
system (Aileron type scale, `colors.STATE` palette, the 214/72 circle
grid, baseline-128 captions) and registers its animation into
`pq1.status.ANIMS`, so any flow can splice any library screen as a
status-kind screen dict.

## Catalog

| screen | category | what it shows | presets / params |
|---|---|---|---|
| `firmware_verified` | verdict | white disc + black check | — |
| `shield` | verdict | the backup shield arrives with its mark and nods yes (check: one decaying dip, ±5 px over 700 ms) or shakes its head no (x: one decaying wiggle, ±6 px over 420 ms) | `backup_ok`, `no_match`; `--text` |
| `wipe` | verdict | warning triangle + brush | `wallet_wiped` (pulse), `wallet_wiped_anim` (sweep), `wallet_wiped_explosion` (sweep led by the major explosion: red qubits flying in from both sides, "WIPING…" / "DO NOT POWER OFF" alternating until the blast, the sign 700 ms after the boom); `--treatment` |
| `tamper` | verdict | warning triangle + exclamation, centred | — |
| `padlock` | verdict | padlock locking / unlocking | `lock`, `unlock`; `--dir` |
| `factory_signing` | verdict | the factory-blue gear arrives spinning and coasts to a tooth-aligned stop (1 turn over 1.8 s), its teeth motion-blurred over one panel frame so the fast launch never aliases backwards at 14 fps | — |
| `rng_failed` | verdict | the red die at rest, then thrown: a short three-axis tumble (half a turn / three quarters / a quarter, 1.5 s) decelerating onto the 1-2-3 corner, lightly motion-blurred over a third of a panel frame so the launch never strobes at 14 fps | — |
| `last_attempt` | verdict | the attempt counter at rest, then reeling down to 1 beside the heart, which pumps | `--attempts` (1-9, default 8) |
| `sig_error` | verdict | detail-grid error notice, variable detail text | `--lines`, `--label`, `--side`, `--size` |
| `headshake` | verdict | the X ring (the unbranded DECLINED sign) arrives and shakes its head once: no | `canceled`, `wrong_seed_phrase`; `--text` |
| `pin_mismatch` | verdict | the PIN pill fills, turns red and is shaken off | `wrong_pin` (the entry's first miss); `--text` |
| `duress_differ` | verdict | the PIN pill is scanned and the duress rule refuses it | — |
| `explosion` | fx | qubit split → clump → blast; can lead another screen (a verdict, or an ending arriving — `busy` rides the orbit, a spec naming an icon hands the flow token off into the split) | `major_explosion`, `minor_explosion`; `--severity`, `--enter left\|right\|sides`, colour flags; `--revs N` (whole orbit turns before the spiral, `loading.REVS` 3 — the film's minimum: it loops on the bench until the host answers; `--ready MS` renders that); spec `busy_until` (`"spiral"` / `"boom"`) |
| `pin_entering` | pin | the eight-ring PIN input, typed with the two buttons (tap ±1, both buttons ENTER the digit — the 8th checks the PIN directly (a 200 ms beat), no hold —, double press NEXT / BACK over entered digits, hold left cancels; the hints pulse 3 s on / 3 s off; no hint and no PIN ENTERED swap on a submit); the demo dials `typed` and, with `exit="submit"`, submits on the 8th digit and fades the row out so the verdict its digits earn (`miss` / `match`) plays in the same screen | `--pin`, `--typed`, `--exit rest\|submit`; spec `miss=` / `match=` (screen dicts), `labels=` |
| `pin_differ` | pin | duress-PIN mismatch error (the plain-screen twin of `duress_differ`) | — |
| `unknown_token` | idle | a solid token drifting on the idle sweep, its ramp trailing (the default demo) | `--ramp 0-13`, `--symbol`, `--address` |
| `batch_sign` | idle | drifting teal token + pager | `--tx`, `--total` |
| `hold_to_confirm` | confirm | the system hold fill (the disc filling up) → confirm / cancel; honours the spec's token + `resting` branding | `hold_confirm_success`, `hold_confirm_cancel`; `--ending`, `--family safe` (pair with `-o`) |

## Rendering

Run from the repo root. Output defaults to `renders/screens/<name>.gif`
under the invoked name (`-o` writes anywhere else).

```bash
python3 -m screens --list                   # this catalog
python3 -m screens                          # default demo: unknown_token, random ramp
python3 -m screens padlock --dir unlock     # -> renders/screens/padlock.gif
python3 -m screens verdict/padlock          # category-qualified, same screen (-> verdict_padlock.gif)
python3 -m screens unlock                   # a preset -> renders/screens/unlock.gif
python3 -m screens explosion --severity minor --ring '#FF4B42'
python3 -m screens explosion --enter left   # the circle slides in from the left first
python3 -m screens explosion --enter sides  # two qubits fly in from both edges onto the orbit
python3 -m screens wallet_wiped_explosion   # explosion lead -> WALLET WIPED sweep
python3 -m screens sig_error --lines "Sig not unlocked &" "Sig verify FAIL"
python3 -m screens pin_entering --pin 19580324 --fps 14 --frames renders/screens/pin_entering_frames
python3 -m screens hold_to_confirm --ending cancel --at 2600 --scale 3
```

Common flags (`pq1.render`): `-o/--out`, `--fps` (30 preview, 14 = panel
rate), `--at MS` (single PNG), `--frames DIR`, `--scale N`, `--loops N`.
Name frame folders `*_frames` — git ignores them. To loop one on the panel:
`.venv/bin/python tools/panel/play_frames.py renders/screens/<name>_frames --fps 14`.

## Splicing screens into a flow

```python
# flows/unlock_batch.py
import screens   # registers every library anim into pq1.status.ANIMS

SCREENS = [
    screens.spec("pin_entering", pin="24031958"),
    screens.spec("batch_sign", tx=1, total=5),
    screens.spec("padlock", preset="unlock"),      # green, "UNLOCKED"
]
ENDS = {"locked": screens.spec("padlock", preset="lock")}
```

`screens.spec(name, **over)` returns a flow-ready dict: `kind="status"`,
the module's `anim`, `handoff=True` (the flow's token crossfades into the
screen instead of popping), `token` pinned solid (the unknown-token
gradient never leaks into a spliced screen) and an explicit `result`.
`python -m flows unlock_batch` then drives it like any flow.

### Leading a screen with a film

A status screen may open on a film that ends on an empty canvas — the
`lead` field (`pq1.status.LedAnim`). The lead plays first; the screen's
own animation starts when the lead resolves, the lead's tail (the
explosion's late rings) fading underneath; durations add, so the flow
dwells for the whole sequence; `lead_gap` (ms) holds the screen back
further; a looping lead (the film waiting for the host's answer) carries the led
screen with it — `t_start` follows the lead's `t_resolve`. The explosion's `enter="left"` / `"right"` slides its circle in
from that side on the flows' KIOSK spring; `enter="sides"` flies two
qubits in from both edges straight onto the orbit, their speed only
falling onto the orbit's:

```python
screens.spec("wipe", preset="wallet_wiped_explosion")
# == screens.spec("wipe", treatment="sweep", lead_gap=700,
#                 lead=dict(anim="explosion", severity="major", enter="sides",
#                           busy=["WIPING…", "DO NOT POWER OFF"], busy_until="boom",
#                           revs=5,                        # two extra orbit turns
#                           body=RED, trail=RED, clump_from=RED, clump_to=RED,
#                           ring=RED))                     # pq1.colors
```

Never write the film and the verdict as two status screens — two dwells
with a black transit between them. A film that rests on a look (the qubit
film) cannot lead: `anim_for` raises.

### A PIN entry in a flow

One try is ONE screen: the entry, then the verdict its digits earn,
playing after the row fades out (the `miss` / `match` tails — never the
entry and its verdict as two status screens). `flows/pin/attempt()` builds
it; the ladder is the screen list, one attempt per try:

```python
# flows/pin/unlock.py
from flows.pin import PIN, attempt, last_attempt, locked, wrong_pin

BODY = [attempt(wrong_pin(), id="TRY 1"),          # miss 1: WRONG PIN
        attempt(last_attempt(2), id="TRY 2")]      # miss 2: the counter reels 2 -> 1
ENDS = {"unlocked": attempt(locked(), typed=PIN, id="TRY 3"),   # a match: UNLOCKED
        "locked": attempt(locked(), id="TRY 3")}                # miss 3: LOCKED
```

`typed` is what the demo dials on that try (a miss is `00000001`); the
attempt's `state` follows it, so `--end all` sorts the GIFs into
`success/` and `cancel/`. On the bench the digits are typed live — the
8th ENTER checks the PIN, no hold — and the driver plays the verdict the typed digits earn, moving on to the next
attempt after a miss (`tools/panel/play_flow.py pin/unlock`). A PIN gate
inside another flow is `attempt(wrong_pin(), match=None)` ahead of the
ending: a match continues to the next screen, a miss retries on the next
attempt in the list. Leaving an entry or a verdict, `Sim` fades the
screen to black and draws no token disc over the transit
(`StatusAnim.rests_on_token`, DESIGN.md § Verdict screens).

## Module protocol

A screen is ONE file in a category folder:

```python
ANIM = "padlock"                # registered anim name == module name
SPEC = dict(direction="lock", state="failed", bottom="LOCKED")
PRESETS = {"lock": {...}, "unlock": {...}}          # old names -> overrides
def add_args(ap): ...           # optional CLI flags
def spec_from_args(a): ...      # flags actually passed -> spec overrides
class Padlock(VerdictAnim): ... # or StatusAnim for non-verdicts
status.register(ANIM, Padlock)
```

Discovery is automatic (`pkgutil` over the category folders). Verdict
anatomy, timing law and rules: `pq1/DESIGN.md` § Verdict screens.
Stateful screens (batch_sign) may also define
`build(args, preset_overrides)` to own the render loop.

MicroPython device screens (seed words, check word) are not part of the
library — they live in `reference/device/` as references for the firmware.
