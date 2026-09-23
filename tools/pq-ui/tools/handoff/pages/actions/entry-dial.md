## What it is

On an entry a tap does not navigate — it turns the dial of the **active** ring. Right tap +1, left tap −1, wrapping 0 → 9 → 0. Nothing else on the row moves: the cursor stays, the entered digits stay, the caption stays. The driver returns `tick`.

This is the only context where a tap changes a value instead of a screen, and it is why the double press and the chord exist: on an entry a tap must stay cheap and repeatable, so the heavier meanings moved onto gestures a tap cannot be mistaken for.

## When it is armed

On the [PIN row](../components/pin-row.md) while it is open — `inc` and `dec` are in the driver's armed set on every slot, from the empty row to the eighth digit. It is unbound everywhere else: on a hero or a detail a tap navigates.

## The tap itself

A press under {{tok:pq1.motion.TAP_MAX_MS}} is a tap and fires on **release**, exactly as everywhere else in this UI ({{loc:pq1.driver.FlowDriver._entry_release}}). Past that the press is a hold and the dial never turns: on the left the cancel fill starts rising, on the right nothing is drawn at all. Releasing a hold before it completes returns `snapback` and leaves the row exactly as it was.

## What the eye sees, and when

The ring **bounces at the tap**. The **digit lands a beat later**. That gap is deliberate: a second press can still convert the tap into something else, and a digit that appears and is then taken back reads as a glitch ({{loc:screens.pin.pin_entering.entry_state}} keeps the tap pending until its window closes).

How long the digit waits depends on what could still take the tap away. The wait is measured from the **release** — the moment the tap fired:

| where the cursor is | what could convert the tap | the digit lands after |
|---|---|---|
| right tap with nothing entered ahead (the cursor is at the frontier) | only the chord | {{tok:pq1.motion.CHORD_MS}} |
| left tap on the first ring | only the chord | {{tok:pq1.motion.CHORD_MS}} |
| any tap on a side a double press could move — left: not the first ring; right: an entered digit ahead | the chord or the double press | {{tok:pq1.motion.DOUBLE_TAP_MS}} |

So on the frontier slot a right tap shows its digit sooner than a left tap does — right cannot move forward past what is entered, left can always go BACK. Odd but correct: the wait is exactly as long as the ambiguity ({{loc:screens.pin.pin_entering.PinEntering.can_move}}), so the conversion window and the pending window always end together and a converted tap is never flashed.

An ENTER or a move lands whatever is pending at once — no digit is ever lost by moving on.

## Motion

{{motion-head}}
{{row:press-down acknowledgment on the pressed chevron | pq1.motion.PRESS_FEEDBACK_MS | ease_out | SPEC-ONLY: see [press feedback](../components/press-feedback.md); the Python does not draw it yet}}
{{row:the tap fires on release, under this | pq1.motion.TAP_MAX_MS | cut | past it the press is a hold instead}}
{{row:ring micro-bounce, from the tap | screens.pin.pin_entering.BOUNCE_MS | sine | up 2.5 px at the midpoint, back to the 3 px active lift: `2.5 · sin(π · b / BOUNCE_MS)`}}
{{row:the digit lands — nowhere for the cursor to move that way | pq1.motion.CHORD_MS | cut | measured from the release; the number changes in one frame, it does not fade}}
{{row:the digit lands — a double press on that side could move | pq1.motion.DOUBLE_TAP_MS | cut | the longer wait, because there are two ways to take the tap back}}

The bounce fires on the tap, not on the landing: the row answers the button immediately, then tells the truth about the value.

## Input

{{gestures:entry — PIN row, empty}}

`tick` is the dial turning. `enter` is [the chord](entry-enter.md); `back` / `next` are [the double press](entry-move.md); `fired` on a left hold is [the cancel](entry-cancel.md); a right hold does nothing at all.

## Preview

{{preview}}

## Do / Don't

- **Do** wrap the digit (0 → 9 → 0) and keep both directions available on every slot. There is no "you are at the end" state on a dial.
- **Do** repeat freely: a fast run of taps on a fresh slot is a run of dials, never a move. The conversion only bites where the cursor could actually go.
- **Don't** draw the new digit at the press. Bounce at the tap, land the value when the window closes.
- **Don't** accumulate the dial per frame. The value is a replay of the event log; any frame must be recomputable from the log alone.
- **Don't** copy the log's `tick` event: that is the scripted demo's dial and it changes the digit at once. A live button writes `tap`, the one that waits ({{loc:screens.pin.pin_entering.PinEntering.input}}).

{{partial:port-notes}}
