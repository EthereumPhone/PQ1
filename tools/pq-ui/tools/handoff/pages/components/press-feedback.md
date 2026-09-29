## What it is

The instant acknowledgment of a button press. On **press-down** the [corner chevron](chevrons.md) on the pressed side gives a short nudge. It answers "did the device feel my finger?" before anything else can: a tap fires only on release, and a hold shows its [fill](hold-flood.md) only after the tap window has passed.

## Status: specified, not rendered

This page describes a rule that exists only on paper. **No Python in this repo draws the nudge.**

- The token exists: {{tok:pq1.motion.PRESS_FEEDBACK_MS}} ({{loc:pq1.motion.PRESS_FEEDBACK_MS}}). Nothing in the renderer, the Sim or the driver reads it.
- The reference driver says so in its own docstring ({{loc:pq1.driver}}): the pressed-side chevron nudge is "not simulated yet (spec-only in the renderer)". `FlowDriver.press` ({{loc:pq1.driver.FlowDriver.press}}) records the press time and starts the hold fill where a hold is armed — it never touches the chevrons.
- The bench player section of `pq1/DESIGN.md` lists it as not yet simulated too.
- So no GIF, no preview and no golden frame shows it. There is nothing to compare a port against except the sentences below.

## What the spec fixes

`pq1/DESIGN.md` § Input, "Taps are instant", and § Motion, "Named curves are for scripted motion":

| what | spec |
|---|---|
| trigger | press-**down** — not release, not the action |
| where | the chevron of the pressed side only |
| what it does | it "nudges" |
| duration | `PRESS_FEEDBACK_MS` |
| curve | `ease_out` — a named curve for a scripted, non-interruptible one-shot |
| relation to the action | none — the tap still fires on release, the hold still fires at completion |

## Timeline (ms since press-down)

{{motion-head}}
{{row:the pressed side's chevron nudges | pq1.motion.PRESS_FEEDBACK_MS | ease_out | one shot; the spec gives the length and the curve only}}
{{row:the press may still be a tap | pq1.motion.TAP_MAX_MS | hold | the fill draws nothing yet, so on an unarmed side the nudge is the ONLY answer a tap gets before its release}}
{{row:from here the hold fill takes over | pq1.motion.HOLD_COMMIT_MS - pq1.motion.TAP_MAX_MS | linear | see [hold right — sign](../actions/hold-right-sign.md)}}

The nudge ends before the tap window does, so a hold always sees it finish before its fill appears.

One other thing already answers a press-down, but only where a hold is armed: the press pulls a sweeping hero's disc home, from the press edge, before anything is known about the gesture (see [idle sweep](idle-sweep.md)). Where nothing is armed — hold right on a detail — the panel is still, and the nudge is the whole acknowledgment.

## What the spec leaves open

The port has to decide these, and should settle them with the designer before building:

- **The shape of the nudge.** Direction, distance, and whether it is a move, a scale or a brightness change are not written down. The only chevron motion that exists in code is the hint's bob ({{loc:pq1.motion.chevron_hint}}), which moves both chevrons and is not a press response.
- **Screens with no corner chevrons.** An [intro](../screen-types/hero-intro.md) hides the pair (its caption carries the [band chevron](band-chevron.md)) but still takes taps. Status screens hide it and take no input.
- **Unarmed presses.** Whether a press that can do nothing (hold right on a detail) still nudges. The hold fill, by rule, draws nothing on an unarmed side.
- **The PIN entry.** It draws its own chevron pair and has its own press grammar — see [PIN row](pin-row.md).
- **Meeting other chevron motion.** A press can land while the hint has the chevrons turned up or mid-bob. A quick tap releases before the nudge ends, so the nudge overlaps the start of the transit's chevron morph. The spec calls the nudge non-interruptible; how it adds to the other motion is not written down.

One number needs care. The nudge is shorter than two panel frames; the design system's own floor for a one-shot accent is {{tok:pq1.motion.VERDICT_ACCENT_MIN_MS}}. Sampled at the panel's rate, a nudge of this length can fall on a single frame. The spec generator flags the token for this (`under_two_frames`). Raise it with the designer rather than silently stretching it.

## Do / Don't

- **Do** start it on the press-down edge. Real buttons have exact edges; use them.
- **Do** keep it independent of the gesture outcome: it must not wait to learn whether the press becomes a tap, a hold or a chord.
- **Do** read the length from the token, in ms.
- **Don't** look for a reference rendering: there is none. Do not copy the hint's bob and call it press feedback.
- **Don't** let it delay or replace the tap action or the hold fill.

{{partial:port-notes}}
