## What it is

Two presses on the **same** side, close together: the cursor moves. Left is **BACK** — to the previous digit, to fix it. Right is **NEXT** — forward again over digits already entered. The driver returns `back` or `next`.

Moving is the only way to revisit a digit, and it is deliberately the *only* thing the double press does. It never enters, never deletes, never submits.

## When it is armed

On the [PIN row](../components/pin-row.md), and only where the cursor can actually go ({{loc:screens.pin.pin_entering.PinEntering.can_move}}):

| side | armed when | why |
|---|---|---|
| left (BACK) | the cursor is not on the first ring | there is a digit behind it |
| right (NEXT) | the cursor is behind the entered count | you can only walk forward over ground you entered |

On the frontier slot — the first un-entered ring — NEXT is **not** armed: there is nothing ahead to move to. The truth table below shows exactly that: with three digits entered and the cursor on the fourth, a double press right returns nothing.

Everywhere else in the UI the double press is unbound. That is what lets a tap on a hero or a detail fire immediately, with no window to wait out.

## How a double press forms

A press on one side within {{tok:pq1.motion.DOUBLE_TAP_MS}} of that side's own last tap — measured from that tap's *release* to this press-down — **and** the cursor can move that way ({{loc:pq1.driver.FlowDriver._entry_press}}). Then:

1. the first tap is undone ({{loc:screens.pin.pin_entering.PinEntering.undo_last_tick}}) — wherever the cursor CAN move, that tap's digit waits out the same {{tok:pq1.motion.DOUBLE_TAP_MS}}, so it had not landed yet and nothing is visibly taken back;
2. the cursor moves one slot;
3. the second press is spent: its release is not another tap.

If the cursor **cannot** move that way, there is no conversion: the second press is simply another dial. A fast run of taps on a fresh slot is a run of dials — the entry never eats a tap to see whether a second one is coming.

The **chord is tested first**. A press that is within {{tok:pq1.motion.CHORD_MS}} of the *other* side's tap is ENTER, even if it is also within the double-tap window of its own; only then does the driver ask whether the cursor can move.

## Nothing is taken away

This is the rule a port most easily gets wrong ({{loc:screens.pin.pin_entering._move}}):

- a **changed digit stays changed** — going BACK, dialing, and going NEXT again keeps the new value;
- a digit **dialed on a fresh slot but not entered** stays visible in its grey ring; move away and back, it is still there;
- the entered count never shrinks. BACK does not un-enter a digit; only a new ENTER on that slot re-accepts it;
- the dial the cursor arrives with is the digit that slot already holds, not zero.

A move also **lands any pending tap** at once — the beat a dial waits out (see [dial](entry-dial.md)) is over the moment the row does something else.

## Motion

{{motion-head}}
{{row:the cursor moves | - | cut | the ring left behind and the ring arrived at swap look in one frame — see [ENTER](entry-enter.md)}}
{{row:the arriving ring bounces | screens.pin.pin_entering.BOUNCE_MS | sine | the same micro-bounce a dial gets: up 2.5 px at the midpoint}}
{{row:the hint rotation keeps its own beat | screens.pin.pin_entering.L_SLOT | ease_out + hold | moving does not restart the pulse; BACK (2X) / NEXT (2X) is the third hint of three}}

## Input

{{gestures:entry — PIN row, 3 digits}}

## Preview

The strip under the panel is a reading aid (which button is down) — it is not part of the display.

{{preview}}

## Do / Don't

- **Do** measure the window per side. A left tap followed by a right press is a [chord](entry-enter.md), not a move.
- **Do** check "can the cursor move" **before** converting the tap. The order matters: convert first and a fast dialer loses digits.
- **Don't** clear a slot on BACK. The dial is live in the slot; the row is not a text field with a caret.
- **Don't** port the bench's dedicated double-press keys (`A` and `D` in `tools/panel/play_flow.py`, calling `double_tap` directly). Real buttons produce the two press edges.

{{partial:port-notes}}
