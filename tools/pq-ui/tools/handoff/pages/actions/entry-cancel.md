## What it is

Holding the **left** button on an open PIN row throws the entry away. It is the same gesture that declines a transaction — the heaviest thing the left button does — and on an entry it is the *only* hold that is bound: the right hold does nothing at all, because the eighth [ENTER](entry-enter.md) is the submit.

A PIN row has no token disc, so there is nothing to fill in the middle of the screen. The progress fill rises **in all eight rings at once**: the row itself is the gauge.

## When it is armed

Whenever the row is open. `cancel` is in the driver's armed set on every slot, empty row included; the row only stops accepting it once the eighth digit has been entered — and on the device that same moment submits, so a full row is never sitting there waiting ({{loc:screens.pin.pin_entering.PinEntering._fill}} refuses to fill a done or submitted row).

The right hold is unbound here: its clock runs, but nothing is drawn and nothing fires when it completes ({{loc:pq1.driver.FlowDriver._entry_hold}}).

## The liquid

Same curve as every other hold in this UI — `motion.hold_fill` ({{loc:pq1.motion.hold_fill}}) — a different dress:

| | the token's hold | the entry's hold |
|---|---|---|
| where | inside the one disc | inside all {{val:screens.pin.pin_entering.DIGITS}} rings, the same level in each |
| the film | see-through, {{tok:pq1.components.HOLD_OVERLAY_ALPHA}}, black or white by the body | **opaque white** |
| the stroke | stays bright above the liquid | is covered — the liquid rises over the ring too |
| the glyph / digit | the disc's glyph stays as it is | the part of the digit **under the surface turns black** |

The surface in each ring is a horizontal chord, exactly as in [hold flood](../components/hold-flood.md): at level `k` it sits `r · (1 − 2k)` below that ring's centre. The row's own fade never lightens the black part of a digit, so a filled row that is fading out goes to black as one picture.

Pressing the **other** button while the left hold is rising makes a [chord](entry-enter.md): the digit is entered, the left press is spent and its fill drains. Two buttons down on an entry always mean ENTER, never cancel.

## Motion

{{motion-head}}
{{row:nothing visible: the press may still be a tap | pq1.motion.TAP_MAX_MS | hold | a tap dials; it never flashes a partial fill}}
{{row:the liquid rises in every ring | pq1.motion.HOLD_COMMIT_MS - pq1.motion.TAP_MAX_MS | linear | constant speed, one shared level}}
{{row:the cancel fires, measured from press-down | pq1.motion.HOLD_COMMIT_MS | — | only at completion — a release one frame earlier does nothing}}
{{row:released early: the liquid drains | pq1.motion.HOLD_SNAPBACK_MS | ease_out | from the level it had reached; the row is untouched, the digits are still there}}
{{row:after the cancel: the whole row fades to black | screens.pin.pin_entering.T_OUT | ease_out | rings, digits, liquid and caption on one alpha. No check beat — that belongs to the submit}}

Then the driver routes — see [outcome](entry-outcome.md). The entry's `outcome` is `"cancel"` until a fresh round opens.

## Input

{{gestures:entry — PIN row}}

`fired` on `hold left` is this page. `None` on `hold right` is the point: the gesture is genuinely unbound, not merely ineffective.

## Preview

The strip under the panel is a reading aid (which button is down) — it is not part of the display.

{{preview}}

## Do / Don't

- **Do** draw the same level in every ring. It is one gauge spread over eight shapes, not eight independent fills.
- **Do** keep the digits legible while the liquid climbs: white above the surface, black below it. That split is what makes the level readable at a glance.
- **Don't** draw anything for a right hold on an entry, and don't let it fire. The only right-button meanings on this screen are "dial +1" and "half of a chord".
- **Don't** cancel on the button going down or on an early release. The fill completing **is** the confirmation.

{{partial:port-notes}}
