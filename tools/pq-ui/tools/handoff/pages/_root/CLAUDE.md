# PQ1 — rules for a Claude porting this UI to firmware

You are helping port the PQ1 hardware-wallet UI to the real device. The design is finished and
approved; your job is a faithful port. **Working in the PQ-UI Python repo itself? This file is not
for you — edit `tools/handoff/`, never `handoff/`.**

**Ground truth, in order:** `spec/*.json` (dumped from the running Python) → `catalog/` pages →
`source/pq1/DESIGN.md` prose → the Python source. GIFs are illustrations — never measure timing off
one. Before calling any screen done, run the `pq1-conformance` skill (`skill/pq1-conformance/`).

## Non-negotiable

1. **Time is milliseconds.** Every animation is a pure function of elapsed ms; the panel samples it
   at {{val:tools.handoff.introspect.PANEL_FPS}} fps. Never count frames. Springs step on the real `dt`.
2. **No accent under two panel frames.** A one-shot phase shorter than {{tok:pq1.motion.VERDICT_ACCENT_MIN_MS}}
   may never reach the glass.
3. **The entrance law.** A verdict icon fades in and rises from {{val:pq1.motion.ARRIVE_FROM}} to 1, both on
   `ease_out`, inside {{tok:pq1.motion.ARRIVE_MS}} — never longer, never an overshoot, one shared function
   ({{loc:pq1.verdict.VerdictAnim.entrance}}). A mechanism (a turn, a tumble) plays on the *arrived* icon.
4. **The verdict law.** hold {{val:pq1.verdict.VerdictAnim.T_HOLD}} → arrive {{val:pq1.verdict.VerdictAnim.T_IN}} →
   wait {{val:pq1.verdict.VerdictAnim.T_WAIT}} → caption {{val:pq1.verdict.VerdictAnim.T_TEXT}} (ease-out), then every
   ending rests {{tok:pq1.status.RESULT_HOLD_MS}}. Per-screen and per-preset values: `spec/anims.json`.
5. **Named curves only.** Use the curves in `spec/motion.json` → `easings` (source + samples). Navigation
   springs are critically damped (damping 1.0): no bounce. The one sanctioned overshoot is `back_out`, in the
   status flash only. `motion.pop` is unused — do not port it as an entrance.
6. **The device uses the NAV spring** (response 0.40, {{loc:pq1.motion.NAV}}). KIOSK is the demo loop's pace.
7. **Tap** = released within {{tok:pq1.motion.TAP_MAX_MS}} (inclusive); it fires on **release**.
8. **Hold** = the fill stays empty until {{val:pq1.motion.TAP_MAX_MS}}, then rises **linearly** to full at
   {{tok:pq1.motion.HOLD_COMMIT_MS}} from press-**down**; the action fires only at completion. An early
   release drains it over {{tok:pq1.motion.HOLD_SNAPBACK_MS}} on `ease_out` and does nothing. The first live hold wins.
9. **Left regresses, right progresses — never flipped.** The ask is the hub: either tap enters the
   details. Decline (hold left) is armed on every navigable screen; sign (hold right) only where the
   screen commits (the ask, Confirm?). Endings accept no input.
10. **A press is never dropped.** Input during a transit retargets the springs from the live pose.
    Nothing moves without a press: dwell timers and auto-advance are demo-only.
11. **PIN entry**: tap = ±1 on the dial; both buttons within {{tok:pq1.motion.CHORD_MS}} = ENTER; a second
    press within {{tok:pq1.motion.DOUBLE_TAP_MS}} = BACK / NEXT over entered digits (only where the cursor can
    move — a dial is never taken away); the 8th ENTER checks the PIN at once, no hold; hold left cancels;
    hold right is unbound.
12. **Token-less transit.** Leaving a screen that owns its canvas (a verdict, the PIN row) fades to black —
    a fade, never a cut — no token rides the transit, and the next screen's handoff is dropped.
13. **A lead film and its screen are one screen** (film → gap of black → the look arrives). Never split them.
14. **Busy captions breathe** on a {{tok:pq1.motion.BUSY_PULSE_MS}} cycle, whole cycles, and only once the
    qubits are on the orbit. A steady caption means "do something", a breathing one means "wait".
15. **Endings**: success plays the qubit film and lands a check; a cancel does no work, so it resolves in
    place with an X; a failure the host reports after dispatch names the film and it collides into the X;
    an ending led by a film arrives. Unbranded flows stroke the disc in the state colour;
    branded families (SAFE, CoWSwap, firmware) fill it.
16. **Flow shape**: a segment with {{val:pq1.layout.CONFIRM_MIN_DETAILS}} or more details takes Confirm? as its
    6th screen — inserted by the design system, never by hand. The walk returns to the ask before an ending.
17. **Geometry is fixed**: {{val:pq1.layout.W}} × {{val:pq1.layout.H}} on black; the disc is r {{val:pq1.layout.CIRCLE_R}}
    at y {{val:pq1.layout.CIRCLE_CY}} and never resizes; all band text sits on baseline y {{val:pq1.layout.BASELINE_Y}}.
18. **Data stays data.** Amounts, symbols, addresses, hashes are per-transaction values — never constants,
    never re-cased. An unknown token wears the gradient hashed from its **address**; the gradient is
    reserved for unrecognised tokens. Icon art is procedural (traced paths), never a recoloured bitmap.
19. **Unknown names fail loudly — except the icon.** An unknown `anim`, `state` or `result` raises; never
    invent one. (All three are enforced: see `spec/screens.schema.json` → `enums_enforced`.)
20. **The Ethereum mark is the deliberate fallback for an icon.** A screen that names no `icon` takes
    the schema default `"eth"` ({{loc:pq1.layout.normalize_screens}}), and an icon name the registry
    does not hold draws that same mark ({{loc:pq1.components.glyph}}). **This is a design
    decision, not a gap** — the device is an Ethereum wallet and the ether mark is the honest answer for
    art it cannot resolve; `screens/idle/batch_sign.py` documents it as the intended look. Port it as it
    is. Do **not** raise, and do not substitute a `?`.
    **The one narrowing: a CHAIN does not take the ether mark.** A chain id the registry does not
    hold resolves to `letter:<X>` and the disc draws that initial ({{loc:pq1.components.glyph}} —
    the `letter:` namespace is matched by shape, never a registry entry). Drawing Ethereum's mark
    would name a *different network*, which is the one case where the fallback would state
    something false rather than merely generic. The disc is still never empty.
21. **But a name the registry DOES hold must never degrade.** Resolve every brand mark eagerly at
    startup. In the Python the family marks (`safe`, `cowswap`) register when their flow package is
    imported, so `{"icon": "safe"}` can draw the Ethereum mark if that import has not happened — and the
    substitute ignores `icon_color`. A correct name silently becoming another brand's logo is a bug, and
    the one part of this area you must not reproduce.
22. **A loading film is open-ended.** Start it when the work is dispatched; repeat the steady orbit
    ({{val:qubit:t_orbit}}–{{val:qubit:t5}}) in whole turns of {{tok:qubit:loop_ms}} until the host answers; then finish the
    current turn, spiral in and latch the outcome — no later than {{val:qubit:t6}} of the last turn. The spiral + flash
    tail and the {{tok:pq1.status.RESULT_HOLD_MS}} rest are fixed; the busy caption runs unwrapped; a finished ending
    freezes forever. `spec/anims.json` `loops` says which films may; `L-LOOP` proves the wrap pixel-exact.

## Do not port

Everything tagged **DEMO-ONLY** or **BENCH-ONLY** in `catalog/INDEX.md`, and every token with
`"scope": "demo"` in `spec/motion.json`: `HERO_DWELL`, `DETAIL_DWELL`, `STATUS_DWELL`, `CONFIRM_DWELL`,
`PAGE_SWAP_MS`, `KIOSK`, `FADE_MS`, `MOVE_MS`; the demo-performed hold; the bench key map.

## When the spec is silent

Do not invent motion. Find the nearest catalog page, copy its grammar, and raise the gap so it is
decided once — in `pq1/` — and regenerated here. Known open inconsistencies are listed in `REPORT.md`:
port the behaviour the Python has today unless `REPORT.md` says a fix is planned.
