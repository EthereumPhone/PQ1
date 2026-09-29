## What it is

Everything the renderer does **by itself** so a GIF can be made without a finger: it waits out a dwell on each screen, moves on, and — where the next screen is an ending — performs the hold gesture for you. None of it belongs on the device.

`pq1.flow.Sim` is the demo loop ({{loc:pq1.flow.Sim.draw}}). `pq1.driver.FlowDriver` is the device-shaped walk of the same screens, and its first act is to switch all of this off.

## How the driver switches it off

`FlowDriver.__init__` deep-copies the screen list and pins **every** screen's `dwell` to infinity before the `Sim` is built ({{loc:pq1.driver.FlowDriver}}). `Sim.draw` then never reaches its advance branch, never starts a demo hold, and never turns a page on the clock. Nothing moves without a press — exactly as on hardware.

It also swaps the spring pace: the `Sim` defaults to the KIOSK profile ({{val:pq1.motion.KIOSK}}), the driver asks for NAV ({{val:pq1.motion.NAV}}). **The device uses NAV.** Every transition in the GIFs is a little slower than the real thing.

## The dwells — do not port any of them

Each is how long a settled screen stays before the loop moves on. A screen may override with its own `dwell`; otherwise:

{{motion-head}}
{{row:a hero | pq1.motion.HERO_DWELL | — | one full [idle sweep](../components/idle-sweep.md)}}
{{row:a detail or a value, per page | pq1.motion.DETAIL_DWELL | — | multiplied by the screen's page count}}
{{row:a Confirm? | pq1.motion.CONFIRM_DWELL | — | two [band](../components/confirm-band.md) messages, so both are read}}
{{row:a status screen | pq1.motion.STATUS_DWELL | — | the token names the qubit film's duration; the code actually reads each screen's own animation duration, so a shorter ending dwells less; a film rendered with `ready` dwells its wrapped duration}}
{{row:a paged screen's page turn | pq1.motion.PAGE_SWAP_MS | — | the flip starts one fade early so the outgoing page lands on the slot boundary — [tap on a paged screen](tap-page.md)}}

Where the loop goes next is the screen's `next` field, default the following screen, wrapping to the first ({{loc:pq1.flow.Sim._resolve_next}}) — that wrap is what makes a GIF loop.

## The demo-performed hold

A cut into an ending would be a lie: on the device an ending is only ever reached through a hold. So the loop performs the hold itself, inside the dwell it already had.

- **Which side** comes from `Sim._demo_hold_side` ({{loc:pq1.flow.Sim._demo_hold_side}}), resolved once per screen at construction: nothing when this screen is itself a status, nothing unless the screen the loop advances to (the resolved `next`, not necessarily the following index) is a status; **left** ([decline](hold-left-decline.md)) when that ending's `state` is not `done`; **right** ([sign](hold-right-sign.md)) when it resolves done *and* this screen has `commit`. A done ending behind a screen that does not commit keeps a plain cut — the hold is never faked where it is not armed.
- **When**: the press is back-dated to `dwell − HOLD_COMMIT_MS`, so the fill is exactly full at the moment the dwell expires and the leg begins. Dwell lengths — and therefore GIF durations — are unchanged by it.
- In practice that is the returning ask of every flow, and the Confirm? in an `--early` render.

{{motion-head}}
{{row:the screen rests, nothing drawn | pq1.motion.HERO_DWELL - pq1.motion.HOLD_COMMIT_MS | — | on a hero; the press edge is planted at the end of this}}
{{row:still nothing: the fake press is inside the tap window | pq1.motion.TAP_MAX_MS | hold | the fill's appearance is what says "this became a hold"}}
{{row:the fill rises to full | pq1.motion.HOLD_COMMIT_MS - pq1.motion.TAP_MAX_MS | linear | the same [hold flood](../components/hold-flood.md) a real press draws}}
{{row:the leg to the ending, fill fading with it | - | spring KIOSK | NAV on the device — [hold commit fade](../transitions/hold-commit-fade.md)}}

## The one advance the driver keeps

A [batch](../screen-types/batch-segment.md) ending mid-run — SIGNED 1 OF 3 — is **not** the end of the walk. When a finished ending is the screen before another segment's first screen, `FlowDriver.frame` moves on to that segment by itself ({{loc:pq1.driver.FlowDriver.frame}}); any other finished ending freezes on its resting frame and waits.

Executed on `batch/transfers`: sign transaction 1, SIGNED 1 plays, and the walk lands on BATCH 2 on its own, with no press.

Port that one. `pq1/DESIGN.md` § Input states it as the grammar — "the mid-batch ending plays through into the next segment" — so it is device behaviour, not a demo convenience; the code's own comment at that line calls it "the demo's own advance", which is the misleading half. Confirm the wording with the designer, but build the advance.

## Do / Don't

- **Don't** implement a dwell timer, an auto-advance, or a screen that leaves by itself — outside the batch case above.
- **Don't** ship the KIOSK spring profile. Use NAV.
- **Don't** turn a page on a clock.
- **Don't** copy the demo hold's shape as a "confirming" animation: what it draws is exactly what a real press draws, and a real press is the only thing that should draw it.
- **Do** read the GIFs and previews in this catalog as *pictures of screens*, and this section as the reason their timing is not the device's.
- **Do** keep the `next` field in mind when reading a flow module: it is the demo's route through the screens, not a device transition.

{{partial:port-notes}}
