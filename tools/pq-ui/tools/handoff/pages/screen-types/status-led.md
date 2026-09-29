## What it is

One status screen made of **two** animations played in a row: a **lead** film that ends on an empty canvas, an optional **gap** of black, then the screen's own animation — the **main**. The lead shows the work (the explosion: the token loads, clumps and blows apart). The main states the result: [arrive](status-arrive.md) for an ending, or a verdict icon such as WALLET WIPED.

Any `status` screen whose spec carries `lead` becomes one. `status.anim_for` ({{loc:pq1.status.anim_for}}) builds both animations and wraps them in `LedAnim` ({{loc:pq1.status.LedAnim}}). It is still **one** screen: one entry in the flow, one dwell, no input from the first frame of the lead to the end of the result hold.

## When it appears

Where the work is destructive or long enough to deserve its own film. Today: both firmware endings (`flows/firmware/__init__.py`) — `UPDATED` after the major explosion, `DECLINED` after the minor one — and the library preset `wallet_wiped_explosion` ([verdict / wipe](../library/verdict-wipe.md)). The firmware `DECLINED` is the one cancel in the live flows that plays a film (`send`'s FAILED is the other film ending on a failure — the [qubit film](status-qubit.md) into the X, a failure after dispatch rather than a cancel); every other cancel either resolves in place ([the resolve](status-resolve.md), the default) or ends on a verdict (`unlock_batch` → LOCKED). {{used-in}}

## Spec

The screen's own keys describe the **main**:

{{fields:anim,resting,status.bottom}}

Three more keys describe the lead. They are not in the `pq1/layout.py` schema; the `pq1/status.py` docstring documents them:

| key | form | meaning |
|---|---|---|
| `lead` | `dict(anim="explosion", severity="major", …)` | a full status spec of its own, played first. It carries the film's knobs — `severity`, `enter`, `revs`, `busy`, `busy_until`, colours — see [fx / explosion](../library/fx-explosion.md) |
| `lead_gap` | ms, default 0 | extra black between the lead resolving and the main starting |
| `handoff` | `True` | the flow's resting token crossfades out **under the lead**, from the screen's first frame — never after it |

{{example}}

**Only a film that ends on an empty canvas can lead.** Such a film sets `t_tail`; today that is the explosion alone. A lead that rests on a look (the qubit film, a verdict) raises a `ValueError` when the screen is built. A lead spec is standalone: it inherits nothing from the screen around it. The firmware family therefore repeats the flow's `icon` and `token` inside the lead, so the token's mark and edge stroke hand off into the split exactly as in the [qubit film](status-qubit.md). The main, by contrast, is the screen's own spec with `lead` removed — it keeps `resting`, `result`, `state` and `bottom`. Both are built with `handoff` off: only `LedAnim` draws the token handoff, once.

## How the two clocks fit

`LedAnim` has one clock, `t`, from the screen's time 0.

| moment | value | what draws |
|---|---|---|
| 0 | | the lead, on `t` |
| the lead resolves | `lead.t_resolve` — the boom lands, the first ring is done | the lead's **tail**: late rings still fading |
| the main starts | `t_start` = `lead.t_resolve` + `lead_gap` | the main, on its own clock `t − t_start`, drawn **over** the tail |
| the tail ends | `lead.t_resolve` + `lead.t_tail` | the lead stops drawing |
| resolved | `t_start` + `main.t_resolve` | |
| the screen ends | `t_start` + `main.duration` | |

What rests on the canvas, the screen's name and whether it is interactive are all the **main's**. So a led `arrive` leaves a token disc; a led verdict owns its canvas ([token-less transit](../transitions/tokenless-fade.md)).

## Motion

The firmware `UPDATED` ending — a major explosion on a longer orbit (`flows.firmware.LOAD_REVS` = {{val:flows.firmware.LOAD_REVS}} turns), no gap, then `arrive`:

{{motion-head}}
{{row:the lead film, to the boom | anim:fx/explosion:t_resolve - qubit:T_SPIN + flows.firmware.LOAD_REVS * qubit:rev_ms | — | the stock major film with its steady orbit swapped for the longer one; phase by phase on [fx / explosion](../library/fx-explosion.md)}}
{{row:the lead's tail, under the main | anim:fx/explosion:t_tail | — | ring stagger × (rings − 1): {{val:burst:MAJOR.rings}} rings launched {{val:burst:MAJOR.stagger_ms}} ms apart. The minor pop has {{val:burst:MINOR.rings}} rings, so its tail is {{val:anim:fx/explosion@minor_explosion:t_tail}} ms}}
{{row:the main's black hold | pq1.status.ArriveStatus.T_HOLD | hold | the tail fades through it. A major tail is LONGER than this hold: with no gap its last faint ring overlaps the start of the entrance}}
{{row:flow-token handoff, when `handoff` is set | pq1.status.LedAnim.HANDOFF_MS | ease_out | runs from the screen's time 0, under the lead}}
{{row:the main, to its resolve | anim:core/arrive:t_resolve | ease_out + arrive | see [arrive](status-arrive.md)}}
{{row:result hold | pq1.status.RESULT_HOLD_MS | hold | once, after the main}}
{{row:whole screen | anim:fx/explosion:t_resolve - qubit:T_SPIN + flows.firmware.LOAD_REVS * qubit:rev_ms + anim:core/arrive:duration | — | durations add}}

WALLET WIPED is the other reference: its lead enters from both sides, its preset sets a `lead_gap` so the sign waits for the blast to clear, and the whole screen resolves at {{tok:anim:verdict/wipe@wallet_wiped_explosion:t_resolve}} and ends at {{tok:anim:verdict/wipe@wallet_wiped_explosion:duration}}. See [lead film, tail and gap](../transitions/lead-film.md) and [side entrance](../transitions/side-entrance.md).

The lead's `busy` caption breathes like the film's ([busy caption](../components/busy-caption.md)). With `busy_until="boom"` it stays up through the spiral and the clump and is gone as the blast launches. The turns above are the minimum: on the device the lead loops while the reboot is outstanding and the led screen's start moves with it ([loading loop](../transitions/loading-loop.md)).

## Input

None, for the whole sequence ([unbound gestures](../actions/unbound-gestures.md)).

## Preview

{{preview}}

## Do / Don't

- **Do** keep it one screen with one clock. Never split the film and its result into two status screens: two dwells, and a black transit between them.
- **Do** draw the main over the lead's tail; do not wait for the tail unless `lead_gap` says so.
- **Do** lengthen the loading with whole turns (`revs`), at the same spin speed — and let the loop add turns beyond that while the work is outstanding.
- **Don't** let a film that rests on a look lead. Refuse it at build time, as the reference does.
- **Don't** port the demo's dwell: the Sim waits for the summed `duration` and then advances by itself. The driver freezes the finished ending on its resting frame.

{{partial:port-notes}}
