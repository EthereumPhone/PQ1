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
- **When**: the press is back-dated to `dwell − HOLD_COMMIT_MS`, and the hold fires on `motion.hold_full` — the same test the driver uses — so the leg begins on the first frame the fill is drawn full, a hair before the dwell expires. Dwell lengths — and therefore GIF durations — are unchanged by it.
- In practice that is the returning ask of every flow, and the Confirm? in an `--early` render.

{{motion-head}}
{{row:the screen rests, nothing drawn | pq1.motion.HERO_DWELL - pq1.motion.HOLD_COMMIT_MS | — | on a hero; the press edge is planted at the end of this}}
{{row:still nothing: the fake press is inside the tap window | pq1.motion.TAP_MAX_MS | hold | the fill's appearance is what says "this became a hold"}}
{{row:the fill rises to full | pq1.motion.HOLD_COMMIT_MS - pq1.motion.TAP_MAX_MS | linear | the same [hold flood](../components/hold-flood.md) a real press draws}}
{{row:the leg to the ending, fill fading with it | - | spring KIOSK | NAV on the device — [hold commit fade](../transitions/hold-commit-fade.md)}}

## The two advances the driver keeps

Almost every finished ending freezes on its resting frame and waits for a press. There are exactly **two** exceptions, and both are device behaviour, not demo convenience. Port both, and generalise neither.

**1. A mid-batch ending.** A [batch](../screen-types/batch-segment.md) ending mid-run — SIGNED 1 OF 3 — is **not** the end of the walk. When a finished ending is the screen before another segment's first screen, `FlowDriver.frame` moves on to that segment by itself ({{loc:pq1.driver.FlowDriver.frame}}).

Executed on `batch/transfers`: sign transaction 1, SIGNED 1 plays, and the walk lands on BATCH 2 on its own, with no press.

`pq1/DESIGN.md` § Input states it as the grammar — "the mid-batch ending plays through into the next segment" — so it is device behaviour; the code's own comment at that line calls it "the demo's own advance", which is the misleading half.

**2. An entry verdict that leads to another entry.** When a PIN attempt misses and another attempt remains, the WRONG PIN verdict plays out its rest and the driver opens the next row by itself ({{loc:pq1.driver.FlowDriver._after_entry}}) — no press. The rule is written in `pq1/DESIGN.md` § Input ("then the driver moves on: a miss to the next attempt"), and it is the only reasonable behaviour: the next row is the only thing the user could do anyway.

It applies **only** where another entry follows. The last miss has nowhere to go, so LOCKED rests like any other ending; a match leaves the entry for the first screen after the attempts; a cancel returns to the ask before the entry.

Executed on `pin/unlock`: type a wrong PIN, WRONG PIN plays, and TRY 2's empty row arrives on its own.

Because that verdict leaves on a clock, the warning it carries must not be the only copy of the warning. TRY 3 of `pin/unlock` is captioned **LAST ATTEMPT** instead of ENTER PIN for exactly this reason — the caption stays while the user types, where the verdict could not (audit A11-03). Port the caption, not just the routing.

## Do / Don't

- **Don't** implement a dwell timer, an auto-advance, or a screen that leaves by itself — outside the **two** cases above. Implement those two: without the entry one, WRONG PIN hangs forever on the device.
- **Don't** ship the KIOSK spring profile. Use NAV.
- **Don't** turn a page on a clock.
- **Don't** copy the demo hold's shape as a "confirming" animation: what it draws is exactly what a real press draws, and a real press is the only thing that should draw it.
- **Do** read the GIFs and previews in this catalog as *pictures of screens*, and this section as the reason their timing is not the device's.
- **Do** keep the `next` field in mind when reading a flow module: it is the demo's route through the screens, not a device transition.

{{partial:port-notes}}
