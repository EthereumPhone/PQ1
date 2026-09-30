## What it is

The rest at the end of every ending. However long a screen took to get there — a film, a verdict, a cancel that does no work at all — once it has resolved it stands still for the **same** span before anything else may happen. One constant, {{tok:pq1.status.RESULT_HOLD_MS}}, and one rule:

    duration = t_landed + RESULT_HOLD_MS        t_landed = t_resolve + landing_ms

That is `StatusAnim.duration` ({{loc:pq1.status.StatusAnim.duration}}), inherited by every film and every verdict. The hold counts from the moment the result is **fully visible**: on a verdict that is `t_resolve` itself (`landing_ms` 0 — the caption has already landed), on a film it is {{tok:pq1.status.RESULT_LANDING_MS}} later, once the result glyph and its caption have faded in. A screen sets `t_resolve` (and a film its `landing_ms`); it never sets its own rest. Three kinds of screen override `duration` instead, and each has a reason: a [led screen](lead-film.md) defers to its main (so the rest is still counted once, at the end), an entry's length depends on what was typed into it and on the verdict tail that follows (the rest lives inside that tail), and an idle screen never resolves at all — it loops. A **live** loading film ([loading loop](loading-loop.md)) reports `t_resolve` and `duration` as infinity until the work answers; the moment it does both are finite again and the rule holds unchanged, the hold counted from the latched resolve.

## What `t_resolve` means

Two slightly different things, which matters when you port the hold:

- On a **verdict** ([the verdict law](verdict-law.md)) everything has already landed at `t_resolve` — icon, mechanism and caption. The hold is completely static.
- On a **film** ([qubit](../screen-types/status-qubit.md), [resolve](../screen-types/status-resolve.md)) `t_resolve` is when the *result begins*: the flash is done and the glyph starts. The result glyph fades in, and the caption a beat behind it, and the hold counts from when both have **landed** — `t_landed` = `t_resolve` + {{tok:pq1.status.RESULT_LANDING_MS}} ({{loc:pq1.status.StatusAnim.t_landed}}): the glyph over {{tok:pq1.motion.RESULT_FADE_MS}} on `ease_out`, the caption {{tok:pq1.motion.RESULT_LAG_MS}} behind it on the same fade (`loading.qubit_pose`, `ResolveStatus.draw`). On the device that instant is the stock `t7` plus wraps × {{val:qubit:loop_ms}}, read from the property ({{loc:pq1.status.QubitStatus.t_resolve}}), never from a constant.

Either way the hold is measured from `t_resolve`, never from the last thing that moved.

## The spans

| screen | resolves at | landed at | rests | ends |
|---|---:|---:|---:|---:|
| [cancel resolve](../screen-types/status-resolve.md) — no film | {{val:anim:core/resolve:t_resolve}} | {{val:anim:core/resolve:t_landed}} | {{val:pq1.status.RESULT_HOLD_MS}} | {{val:anim:core/resolve:duration}} |
| [qubit film](../screen-types/status-qubit.md) | {{val:anim:core/qubit:t_resolve}} | {{val:anim:core/qubit:t_landed}} | {{val:pq1.status.RESULT_HOLD_MS}} | {{val:anim:core/qubit:duration}} |
| [arrive](../screen-types/status-arrive.md), after a lead | {{val:anim:core/arrive:t_resolve}} | {{val:anim:core/arrive:t_landed}} | {{val:pq1.status.RESULT_HOLD_MS}} | {{val:anim:core/arrive:duration}} |
| a plain verdict — firmware verified | {{val:anim:verdict/firmware_verified:t_resolve}} | {{val:anim:verdict/firmware_verified:t_landed}} | {{val:pq1.status.RESULT_HOLD_MS}} | {{val:anim:verdict/firmware_verified:duration}} |
| the longest — WALLET WIPED with its [lead film](lead-film.md) | {{val:anim:verdict/wipe@wallet_wiped_explosion:t_resolve}} | {{val:anim:verdict/wipe@wallet_wiped_explosion:t_resolve}} | {{val:pq1.status.RESULT_HOLD_MS}} | {{val:anim:verdict/wipe@wallet_wiped_explosion:duration}} |

A led screen rests **once**, at the very end — never after the lead as well.

## Motion

{{motion-head}}
{{row:the screen's own animation | - | — | ends at its `t_resolve`, which every animation defines for itself}}
{{row:a film's result lands — glyph, then caption | pq1.status.RESULT_LANDING_MS | ease_out | `RESULT_LAG_MS` + `RESULT_FADE_MS`; zero on a verdict}}
{{row:the result hold | pq1.status.RESULT_HOLD_MS | hold | nothing moves: the resting look or the icon and its caption simply stand}}
{{row:the demo's status dwell, for comparison | pq1.motion.STATUS_DWELL | — | the legacy constant — the qubit film's resolve plus the hold. `pq1/status.py` asserts they still agree}}

{{tok:pq1.motion.STATUS_DWELL}} is a **demo token**: the device never waits on it. The animation's own `duration` is the only span to port.

## Leaving an ending

| context | what happens when the hold ends |
|---|---|
| the button grammar ({{loc:pq1.driver.FlowDriver.frame}}) | the state turns `finished` and the **resting frame freezes**. The flow does not walk on by itself — this is the device behaviour. A live film that was never answered never finishes: it loops; there is no timeout in this design |
| a mid-batch ending | the exception: the player moves on to the next segment's first screen. The reference calls this its own advance ({{loc:pq1.driver.FlowDriver.frame}}) — decide deliberately whether the device steps between a batch's transactions without a press |
| a [PIN entry](../actions/entry-outcome.md) | the outcome routes ({{loc:pq1.driver.FlowDriver._after_entry}}) — a miss opens the next attempt, or rests on its verdict when none is left; a match continues to the first screen that is not an entry, or rests; a cancel returns to the last navigable screen before the row, or — when there is none, as in both PIN flows — opens a fresh round in place |
| the demo loop | the screen's dwell IS its `duration`, so the Sim advances to the next screen by itself. **Do not port** ([demo auto-advance](../actions/demo-auto-advance.md)) |

Leaving a verdict, an entry or any ending that shows a result is a [fade to black](tokenless-fade.md), not a morph.

## Input

None, from the ending's first frame to the last: every press is refused while the state is not `navigating` ({{loc:pq1.driver.FlowDriver.press}}). The hold is not a window to skip — there is no skip gesture ([unbound gestures](../actions/unbound-gestures.md)).

## Do / Don't

- **Do** keep one constant for it. The conformance checker's `V-HOLD` fails any resolving screen whose rest differs.
- **Do** measure it from `t_resolve`, so a longer mechanism pushes the end of the screen out rather than eating the rest.
- **Don't** count the hold from the wall clock or the stock film length: on a film that looped it starts at the LATCHED `t_resolve`.
- **Don't** shorten it for a "quick" ending. A cancel resolves in {{tok:anim:core/resolve:t_resolve}} and then rests exactly as long as the film does — that symmetry is the point.
- **Don't** port `burst.HOLD_END` ({{loc:pq1.procedural.burst.HOLD_END}}): it records the original explosion's post-boom rest and nothing reads it.
- **Don't** apply the rule to a screen that never resolves: the idle screens loop, and the [PIN row](../library/pin-pin-entering.md) is an entry whose own duration is the typed row plus whichever verdict tail follows — the hold lives inside that tail (a baselined exception, A-03).

{{partial:port-notes}}
