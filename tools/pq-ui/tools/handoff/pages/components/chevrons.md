## What it is

Two small rounded triangles, one in each top corner. They are the on-screen legend of the two buttons: the left chevron speaks for the left button, the right one for the right button. A screen picks one of three poses with its `chev` field:

| `chev` | pose | meaning |
|---|---|---|
| `"lr"` | each chevron points outward (left one left, right one right) | taps navigate |
| `"up"` | both point up | a hold is armed — the resting pose of [Confirm?](../screen-types/confirm.md) |
| `None` | hidden | no input (status screens), or the caption carries the chevron instead — see [band chevron](band-chevron.md) |

`"lr"` does not mean holds are off. An [ask](../screen-types/hero-ask.md) rests in `"lr"` and hold-right still signs there. The **hint** is the reminder: on a screen with `hint` set, the chevrons turn up, bob once and turn back, again and again while the screen rests.

## When it appears

Every navigable screen. The default is filled in by `normalize_screens` ({{loc:pq1.layout.normalize_screens}}): `None` on a status screen and on a `band_chev` hero, `"up"` on a confirm screen, `"lr"` everywhere else. `hint` has no default — a flow sets it, and every ask in the live flows does. A confirm screen needs none: `Sim.draw` gives it the same envelope on the band's beat because of its *kind*, not because of a field ({{loc:pq1.flow.Sim.draw}}).

The PIN entry is a status screen, so its `chev` is `None` — but it draws the same pair itself, in the `"lr"` pose, with its own fade and its own labels beside it. See [PIN row](pin-row.md).

## Spec

{{fields:chev,hint}}

## Geometry

Fixed slots — left {{val:pq1.layout.CHEV_LEFT}}, right {{val:pq1.layout.CHEV_RIGHT}} ({{loc:pq1.layout.CHEV_LEFT}}). The right slot is the mirror of the left (x 428 − 23.5). The slots never move on flow screens; only the hint's bob shifts both chevrons in y, by {{val:pq1.motion.CHEV_BOB_PX}} px — the one resting element allowed across the {{val:pq1.layout.MARGIN}} px margin. The two idle library screens ([batch sign](../library/idle-batch-sign.md), [unknown token](../library/idle-unknown-token.md)) are the exception: they keep the right chevron pointing right and push it outward along its pointing axis by the same amount.

One chevron is `components.chevron` ({{loc:pq1.components.chevron}}): a white filled triangle, tip 4 px above its centre, base corners {{val:pq1.components.CHEV_HALF_W}} px to each side and 3.2 px below (`CHEV_PTS`), outlined with a {{val:pq1.components.CHEV_STROKE}} px round-joint stroke (`CHEV_STROKE`, the "sign" weight of `layout.STROKE`) so all three corners are round. Angle 0 points up; the angle turns the shape about its centre. Rest angles come from `chevron_angles` ({{loc:pq1.components.chevron_angles}}): `"up"` is 0 and 0, `"lr"` is a quarter turn outward on each side. Alpha is the white scaled toward black (the ground is pure black); at 0.01 or under nothing is drawn at all.

## Motion

{{motion-head}}
{{row:pose change between two screens | - | spring NAV | angle and alpha are straight blends of the two screens' rest poses, read from the transit's mix spring (clamped to 0–1) — see [glyph + chevron morph](glyph-morph.md)}}
{{row:hint: wait after the screen settles | pq1.motion.CHEV_HINT_START_MS | hold | `CHEV_HINT_START_MS` ({{loc:pq1.motion.CHEV_HINT_START_MS}}). It is a one-time lead-in: the code subtracts it BEFORE taking the modulo, so later cycles do not repeat it. Every hint phase is a whole number of panel frames}}
{{row:hint: turn from the rest pose to up | pq1.motion.CHEV_HINT_TURN_MS | ease_out | the `motion.hint_env` envelope ({{loc:pq1.motion.hint_env}}) — the same appear / rest / go shape as the confirm band and the busy caption}}
{{row:hint: bob while up | pq1.motion.CHEV_HINT_BOB_MS | sine | y offset = −{{val:pq1.motion.CHEV_BOB_PX}} px (`CHEV_BOB_PX`) × sin(π · progress): up and back once}}
{{row:hint: turn back to the rest pose | pq1.motion.CHEV_HINT_TURN_MS | ease_out | inverted — `1 − ease_out(p)`, the envelope's mirrored tail}}
{{row:hint: still until the next cycle (hero) | pq1.motion.CHEV_HINT_PERIOD_MS - (2 * pq1.motion.CHEV_HINT_TURN_MS + pq1.motion.CHEV_HINT_BOB_MS) | hold | the cycle minus the three moving phases}}
{{row:one full hint cycle on a hero | pq1.motion.CHEV_HINT_PERIOD_MS | — | repeats for as long as the screen rests}}
{{row:one full hint cycle on Confirm? | pq1.motion.BAND_SWAP_MS | — | same envelope on the [confirm band](confirm-band.md)'s beat; the chevrons already rest up, so only the bob shows}}

The whole hint is one pure function of the ms since the screen settled: `motion.chevron_hint` ({{loc:pq1.motion.chevron_hint}}) returns the turn (0–1) and the y offset. The turn pulls each chevron's angle toward 0 (up) by that fraction. It is called from the chevron block of `Sim.draw` ({{loc:pq1.flow.Sim.draw}}).

A hidden pose carries the `"lr"` angles. So `"lr"` to hidden and back is a pure fade, pointing outward. Into Confirm? the pair turns from outward to up as the disc travels; a sign from Confirm? into its ending fades the pair while it turns back outward.

What the reference does at the edges of the hint:

- The hint runs only while the screen is settled. The clock restarts from zero at every settle.
- A tap during the hint **cuts** it: on the frame the transit starts the chevrons are back in their rest pose, with no ease back.
- A live hold does **not** stop the hint. The chevrons keep turning and bobbing while the disc fills.

## Through a hold

A hold never fades a chevron. While either button is held — sign or decline, on the ask, on a detail, on the PIN row — **both** chevrons stay exactly as they rest, and keep their hint (user decision, Sep 2026: "it should keep on showing both chevrons"). Audit A11-01 once faded the corner on the un-held side so a sign and a decline would look different; that cue is retired, and `tools/check` rule I-ARMED fails the build if a hold changes the chevron row.

## Input

The chevrons take no input; they describe it. What each pose allows is on [tap left / right](../actions/tap-navigate.md), [tap on the ask](../actions/tap-hub.md), [hold right — sign](../actions/hold-right-sign.md) and [hold left — decline](../actions/hold-left-decline.md). The sustained pressed-side state is above; the short press-down acknowledgment that precedes it is specified but not rendered — see [press feedback](press-feedback.md).

## Preview

No clip of its own. The hint plays in the preview of [Hero — the ask](../screen-types/hero-ask.md); the up pose and its bob play in [Confirm?](../screen-types/confirm.md).

## Do / Don't

- **Do** compute the hint from the ms since settle, every frame. Do not run it as a free timer that survives a screen change.
- **Do** hide the pair on every status screen: hidden chevrons are how the UI says "no input now".
- **Don't** move the slots or resize the chevrons per screen.
- **Don't** port the demo's pace for the pose change: GIFs run the KIOSK spring, the device uses NAV.
- **Don't** treat the phase lengths inside the hint as tunable per screen. Only the period changes (hero vs Confirm?).
- **Don't** fade either chevron during a hold. Both stay, whichever button is down.

{{partial:port-notes}}
