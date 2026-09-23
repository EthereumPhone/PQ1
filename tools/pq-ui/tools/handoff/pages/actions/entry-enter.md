## What it is

**Both buttons together** — the chord — is ENTER on an entry. It accepts the digit the active ring is showing: the ring turns white, the cursor steps forward one slot, and the dial picks up whatever that next slot already holds. The driver returns `enter` (`submit` on the eighth).

The chord that accepts the **eighth** digit is different: it **submits**. The PIN is checked at once — no hold, no confirm screen, no second gesture ({{loc:pq1.driver.FlowDriver._enter}}). That is the whole submit path on the device.

## When it is armed

On the [PIN row](../components/pin-row.md), always, from the empty row to the last digit. The chord is unbound on every navigating screen: there the two presses are not read together at all, they stay two ordinary taps that each fire on their own release. In the truth table `both buttons` on the ask returns no gesture and the flow simply lands two screens along. That is what lets a nav tap fire immediately, with no window to wait out.

## The two ways a chord forms

The reference implementation is {{loc:pq1.driver.FlowDriver._entry_press}}:

1. **The other button is still down.** Its press is spent: its hold clock stops there — a rising cancel fill drains from where it got to — and its release later is not another tap. Neither button ever dialed, so the digit entered is the digit on screen.
2. **The other button was tapped within {{tok:pq1.motion.CHORD_MS}}.** Measured from that tap's *release* to this press-down. The first tap already fired, so it is **undone** — {{loc:screens.pin.pin_entering.PinEntering.undo_last_tick}} deletes it from the event log, and because the digit had not landed yet (see [dial](entry-dial.md)) nothing was ever shown that is now taken back.

Both paths enter the digit as it stood **before** the chord's first half. A porter must implement the undo: without it, a fast two-finger press dials +1 and then enters the wrong number.

## What ENTER changes

| | before | after |
|---|---|---|
| the ring | active: yellow, lifted, dialing | white, 2 px, at rest |
| the cursor | slot `c` | slot `c + 1`, bouncing |
| the dial | the digit of slot `c` | the digit slot `c + 1` already holds |
| entered count | `n` | `max(n, c + 1)` — it never shrinks |

So re-entering a digit you went BACK to fix keeps everything ahead of it: the cursor lands on the next slot, the count stays where it was, the corrected digit is kept.

## The eighth ENTER

All eight entered and the cursor past the row: the entry is `done` and the driver appends `submit` in the same call, at the same millisecond. Then, in this order:

{{motion-head}}
{{row:the hints fade out (the eighth ring is white in the same frame) | screens.pin.pin_entering.SWAP_MS | ease_out | no new hint follows and the caption does NOT swap to PIN ENTERED — ENTER PIN stays and leaves with the row}}
{{row:the row holds, checked | screens.pin.pin_entering.T_CHECK | hold | eight white rings and ENTER PIN, still: the beat in which the device compares}}
{{row:the whole picture fades to black | screens.pin.pin_entering.T_OUT | ease_out | rings, digits and caption on one alpha — no fill, there is no hold to show}}
{{row:then the verdict plays in the SAME screen | - | — | from `t_exit`; its own hold phase is the black beat before its sign — see [outcome](entry-outcome.md)}}

## Motion of an ordinary ENTER

{{motion-head}}
{{row:the entered ring goes white, the next goes yellow | - | cut | both in the same frame. {{tok:screens.pin.pin_entering.ACT_MS}} eases the FIRST activation only, as the row opens; a cursor move is a cut}}
{{row:the new active ring bounces | screens.pin.pin_entering.BOUNCE_MS | sine | the move sets the same bump a dial does — this is the whole softening}}

## Input

{{gestures:entry — PIN row}}

## Preview

The strip under the panel is a reading aid (which button is down) — it is not part of the display.

{{preview}}

## Do / Don't

- **Do** fire ENTER on the second press-down, not on a release. The chord is decided the moment both sides are known.
- **Do** submit on the eighth ENTER, at once. A hold-right submit was removed on purpose; the right hold is unbound here.
- **Do** land any pending tap when a chord arrives — except the one the chord itself consumed.
- **Do** clear both sides' last-tap memory when a chord fires: after it, the next tap starts a fresh window and neither release counts as a tap.
- **Don't** swap the caption to PIN ENTERED on a device submit, and don't show a BACK or CONFIRM hint on the full row. That state only exists in the `exit="rest"` demo, which never submits.
- **Don't** let the chord window depend on which button came first. Either side may open it.
- **Don't** port `FlowDriver.enter` ({{loc:pq1.driver.FlowDriver.enter}}): it is the bench player's `space` / `e` shortcut for harnesses with no two-edge keys, and it skips the chord detection entirely — see [bench keys](bench-keys.md). Real buttons give you the two press edges.

{{partial:port-notes}}
