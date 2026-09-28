## What it is

The contract that lets a film wait. A loading film is a scripted depiction of work whose real length the device does not know: in the demo it is one fixed script; on the device it **starts when the work is dispatched**, the steady orbit **repeats in whole turns** while the answer is outstanding, and the answer chooses the landing — the check, or the X. Nothing in the drawing changed to allow this: the orbit was already pixel-periodic, and every frame before the spiral's end was already identical for success and failure. What changed is what the film is *told*, and when.

Two films loop: the [qubit film](../screen-types/status-qubit.md) and the [explosion](../library/fx-explosion.md), including when the explosion leads ([led](../screen-types/status-led.md) screens loop while their lead does). `StatusAnim.loops` ({{loc:pq1.status.StatusAnim.loops}}) says so, and `spec/anims.json` carries `loops`, `loop` and `loop_ms` per animation.

## The three regions

| region | from | to | on the device |
|---|---|---|---|
| the fixed prefix — seed, split, join | 0 | {{val:qubit:t_orbit}} | plays once |
| **the loop** — the steady orbit, `QubitCfg.loop` | {{val:qubit:t_orbit}} | {{val:qubit:t5}} | repeats, whole turns of {{tok:qubit:loop_ms}}, until the host answers |
| the fixed tail — spiral, flash, result, rest | {{val:qubit:t5}} | {{val:anim:core/qubit:duration}} | plays once, after the last whole turn |

The loop region is exactly the [busy caption](../components/busy-caption.md)'s window — the only part of a film over which the device may claim to be working. On the explosion's side entrance the region starts where the pair lands on the orbit ({{loc:pq1.procedural.burst.t_arrive}}), later than the stock join.

## Motion

{{motion-head}}
{{row:the loop unit — one orbit turn | qubit:loop_ms | linear | constant angular speed, so frame(t) equals frame(t + one turn) byte for byte across the whole region; the checker's `L-LOOP` proves it on every build}}
{{row:the loop region at the stock turns | qubit:t5 - qubit:t_orbit | linear | {{val:pq1.loading.REVS}} turns (`revs` — the film's MINIMUM); {{val:pq1.loading.REVS_LONG}} where a loading must endure (the firmware reboot, the wipe)}}
{{row:the answer arrives: the current turn completes | - | — | `wraps_for` ({{loc:pq1.loading.wraps_for}}) counts the whole turns past the stock orbit; an answer inside the fixed prefix adds none, so a signing that finishes early still plays the stock film}}
{{row:the spiral — the LATCH | qubit:T_SPIRAL | linear | the outcome is taken here ({{loc:pq1.status.StatusAnim.resolve}}); its end, {{val:qubit:t6}} of the last turn, is the first outcome-dependent frame — an answer that arrives later is refused: the film has committed}}
{{row:the flash and the result | qubit:T_FLASH | back_out + linear | unchanged — see [the qubit film](../screen-types/status-qubit.md)}}
{{row:resolved | anim:core/qubit:t_resolve | — | at the stock turns; plus wraps × {{val:qubit:loop_ms}} on the device — `t_resolve` is a property ({{loc:pq1.status.QubitStatus.t_resolve}}), infinite while a live film is unanswered}}
{{row:result hold | pq1.status.RESULT_HOLD_MS | hold | fixed; counted from the latched resolve — [result hold](result-hold.md)}}

`film_time` ({{loc:pq1.loading.film_time}}) maps real time to pose time: the identity with no wraps (so every existing render is byte-identical), a whole-turn step back inside the loop otherwise. The busy caption is **not** mapped: it breathes on the unwrapped clock, whole cycles fitted to the film's stock window and continuing at that period while the loop runs, then fades out over {{tok:pq1.status.BUSY_FADE_MS}} when the spiral starts ({{loc:pq1.status.StatusAnim.draw_busy}}).

## Who answers

| where | who | how |
|---|---|---|
| the device | the signing core / host | `answer(ok)` ({{loc:pq1.driver.FlowDriver.answer}}) — the film finishes its turn and spirals into the check (`ok`) or the X |
| the bench | you | `y` / `n` in the panel player ([bench keys](../actions/bench-keys.md)); the driver marks every looping ending `live` |
| a render | the spec | `ready` (the ms at which the work answers): `python3 -m flows send --end failed --ready 7000` — the same knob on `python3 -m screens explosion --ready 9000` |

A **failure after dispatch** is an ending that names the film — `anim="qubit", result="x", state="failed"` (`send`'s TRANSACTION FAILED, `anim:core/qubit-fail` in the spec). The bench's `n` restyles the running film with that ending's landing (result, state, colour, caption) — the token, the icon and the busy caption stay the film's. A user **decline** never plays a film: [the resolve](../screen-types/status-resolve.md). A film built for a demo (no `live`, no `ready`) is the stock script: it needs no answer and freezes on its resting frame like every ending.

## Preview

{{preview}}

## Do / Don't

- **Do** start the film at dispatch — never after the work is done.
- **Do** lengthen only in whole turns, at build time (`revs`) or at run time (the wrap). Never slow the spin or stretch the split, the spiral or the flash.
- **Do** latch at the spiral. If the answer comes during the spiral or later, the film is already committed: show the next ending, never rewind.
- **Don't** wrap the caption's clock. The pose wraps; the breath does not.
- **Don't** add a timeout. An unanswered film loops; the device decides when it is done.
- A port that cannot loop holds the last orbit frame; it never restarts the film.

{{partial:port-notes}}
