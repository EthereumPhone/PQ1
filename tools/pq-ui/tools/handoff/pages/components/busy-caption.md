## What it is

The line in the bottom band **while a status screen is still working** — `SIGNING…`, `RECONNECTING…`, `WIPING…`. Same type, same slot and same drawing as the resolved [caption](caption.md); what differs is that it lives inside a window and breathes.

Two dresses, chosen by the animation, never by the flow:

| dress | when | how it moves |
|---|---|---|
| **breathing** — `StatusAnim.busy_pulse` true | a loading film (the qubit film, the explosion) | fades in and out, slowly, for as long as the loading runs |
| **steady** | a gesture, not a loading — `HOLD TO CONFIRM` | fades in once, holds, fades out once |

The rule behind it: a caption over a loading animation pulses; a caption that instructs a gesture stands still.

## When it appears

Only on a `status` screen whose animation declares a busy window (`t_busy`) **and** whose spec carries `busy`. Everything else about it is computed, not authored: the flow gives the words, the animation gives the window.

- the qubit film ({{loc:pq1.status.QubitStatus}}) — the window opens once the two qubits are on the orbit and closes when they spiral in
- the explosion ({{loc:screens.fx.explosion.Explosion}}) — the same orbit window, or, with `busy_until="boom"`, held through the spiral and the clump and closed one {{tok:pq1.status.BUSY_FADE_MS}} before the blast launches
- `hold_to_confirm` ({{loc:screens.confirm.hold_to_confirm.HoldToConfirm}}) — steady, from frame 0 to the commit (its cancel ending closes the window at the early release instead)
- the **cancel resolve has no window** ({{loc:pq1.status.ResolveStatus}}): its `t_busy` is `None`, so a `busy` on a cancel ending is silently ignored. A cancellation did no work — there is nothing to caption.
- the PIN row is not this: it pins `t_busy` to `None` and draws `ENTER PIN` / `PIN ENTERED` itself, one swap per typed row — see [PIN row](pin-row.md).

## Spec

| key | form | meaning |
|---|---|---|
| `status.busy` | `"SIGNING…"`, or a list of lines | the caption shown inside the animation's loading window; optional, film only — the cancel resolve has no window |

That row is written out here instead of generated: the parser folds the closing paragraph of `pq1/layout.py`'s schema docstring into this key. The docstring is the contract.

`busy` is one string, or a list of strings that take turns (`["WIPING…", "DO NOT POWER OFF"]`).

## Geometry

Identical to the resolved [caption](caption.md): question caps, size {{val:pq1.typography.SIZE_QUESTION}}, tracking {{val:pq1.typography.LS_QUESTION}} px, centred on x {{val:pq1.layout.CENTER_X}}, baseline y {{val:pq1.layout.BASELINE_Y}}, white. It is the same call ({{loc:pq1.components.caption}}).

The busy line and the resolved line never overlap: every window closes before its screen resolves.

## Motion

One function owns all of it: `StatusAnim.draw_busy` ({{loc:pq1.status.StatusAnim.draw_busy}}), with the breath in `motion.busy_pulse` ({{loc:pq1.motion.busy_pulse}}). The clock is ms since the screen started.

{{motion-head}}
{{row:dark while the token splits and sweeps out | qubit:t2 + qubit:T_SPLIT + qubit:T_JOIN | hold | the qubit film's window opens only once both qubits are ON the orbit — never over the split}}
{{row:the qubit film's window: it breathes until the spiral begins | qubit:t5 - qubit:t2 - qubit:T_SPLIT - qubit:T_JOIN | raised cosine | this window fits exactly one breath}}
{{row:nominal breath | pq1.motion.BUSY_PULSE_MS | raised cosine | the window is cut into the NEAREST whole number of these, at least one, so the real period is a little longer or shorter and the line always starts and ends dark}}
{{row:steady dress: fade in from the window's start | pq1.status.BUSY_FADE_MS | ease_out | }}
{{row:steady dress: fade out, beginning AT the window's end | pq1.status.BUSY_FADE_MS | ease_out | so a steady line outlives its window by one fade}}
{{row:a list of lines: each line holds | pq1.status.BUSY_SWAP_MS | — | the window plus one fade is cut into equal slots, one line per slot; more lines than whole slots and the slots shrink to fit them all}}
{{row:on the device, while the film loops | - | raised cosine | the pose wraps, the breath does not: the period fitted to the STOCK window carries on unwrapped for as long as the loop runs (a list gains slots on the same grid), then fades out over BUSY_FADE_MS as the spiral starts — [loading loop](../transitions/loading-loop.md)}}

The breath is a raised cosine — `0.5 − 0.5·cos(2πu)` over the cycle's unit progress: dark at the start, full in the middle, dark at the end. Fitting whole cycles into the window is what makes it land dark exactly when the loading stops; do not free-run a sine against a wall clock. When the film loops the caption keeps that period on the unwrapped clock and is faded out over {{tok:pq1.status.BUSY_FADE_MS}} (ease-out) the moment the spiral starts, so a wrap never jumps the caption.

**A list takes turns, it does not scroll.** The number of slots is the larger of the line count and the whole number of `BUSY_SWAP_MS` that fit, and slot `k` shows line `k mod count` — so the two-line WALLET WIPED film gets three slots and shows `WIPING…` again at the end. On a breathing film each slot is one breath; on a steady caption each line fades out before the next fades in, like the [confirm band](confirm-band.md).

Windows are computed from the film, so they are not round numbers: the explosion's opens when its bodies arrive, which on a two-sided entrance lands on a fractional millisecond. Compute them the same way in the port instead of writing constants down.

## Preview

No clip of its own. It plays in [status — the qubit film](../screen-types/status-qubit.md), and held to the boom in the firmware ending of [status — led by a film](../screen-types/status-led.md).

## Do / Don't

- **Do** start the breath only when the circles are already going round.
- **Do** run the breath on the unwrapped clock when the film loops; never wrap it with the pose.
- **Do** fit whole cycles to the window, so the line fades to black on its own instead of being cut off.
- **Do** keep the words as data — a firmware version, a warning — and keep them short enough for one line.
- **Don't** pulse an instruction. `HOLD TO CONFIRM` is a gesture caption: steady, one fade each way.
- **Don't** caption a cancel ending. There is no film and no window.
- **Don't** let a busy line and the resolved line share a frame.

{{partial:port-notes}}
