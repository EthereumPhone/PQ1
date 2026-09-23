## What it is

The negative space of the grammar: what the two buttons do **not** do. A port that binds more than this is no longer the same device, and a port that assumes an unbound gesture is *inert* will be wrong — outside an entry, the driver has no combined gestures at all, so each button simply acts on its own.

Everything below is executed against the reference driver, not read off the spec.

## Outside an entry there is no chord and no double-tap

`FlowDriver.press` and `FlowDriver.release` route to the entry grammar only on an entry screen ({{loc:pq1.driver.FlowDriver.press}}). On a hero, a detail, a value or a Confirm? there is no recognizer for "both buttons" and none for "twice": every press starts its own tap-or-hold clock, and every release inside {{tok:pq1.motion.TAP_MAX_MS}} fires its own tap.

| what the user does | what the device does |
|---|---|
| presses both buttons and lets go | **two taps**, in the order the buttons came up — on the ask: left `enter`s the details, then right `forward`s one detail |
| presses the **right** button twice quickly | **two right taps** — on the ask: `enter`, then `forward`: two screens in |
| presses the **left** button twice quickly | **two left taps** — on the ask: `enter`, then `back`: in and straight out again |
| holds both to completion | one decline **or** one sign: see the race below |

The tables prove it. On the ask, `both buttons (chord)` and `double press right` both leave the flow two screens in; `double press left` ends where it started:

{{gestures:hero — the ask}}

The `result` cell of the chord and double-press rows reads `None` because the harness records what the second *press* returned, and a press on its own returns nothing — the taps fire on the releases. The `to` cell is what actually happened.

On a detail, `both buttons (chord)` is a back tap followed by a forward tap, which lands where it started:

{{gestures:detail — middle}}

This is deliberate. Binding a double-tap on a navigation screen would force every tap to wait {{tok:pq1.motion.DOUBLE_TAP_MS}} to find out whether a second one is coming. Taps are instant, so the double press stays unbound where reading happens, and is bound only on an [entry](entry-move.md), where a tap is a reversible selection change that can be taken back.

## The right hold where nothing commits

`commit` is false on every detail, every value and every [intro](../screen-types/hero-intro.md). There the right hold is unbound, and unbound means **invisible**:

- `press()` starts the fill only when the side's action is in `armed()` ({{loc:pq1.driver.FlowDriver.press}}), so `Sim.hold` is never created — **no fill is drawn at any point**.
- At {{tok:pq1.motion.HOLD_COMMIT_MS}} the pending hold is offered to `_hold()`, which finds no `commit` and returns nothing ({{loc:pq1.driver.FlowDriver._hold}}).
- The release then reports `snapback` anyway — the driver returns that string for any press past the tap window that did not fire. **`snapback` here does not mean anything drained**; nothing was ever on screen. Do not use the result string to decide whether to draw.

Executed on a detail: press right, hold past the commit, release — the screen does not change and the token never fills.

The **entry** is the fourth place the right hold is unbound, and it draws nothing there either. The PIN row's fill is the left hold's cancel; its liquid function returns nothing for the right side ({{loc:screens.pin.pin_entering.PinEntering._fill}}), so a right hold on an open row is two seconds of nothing. See [entry — hold left cancels the row](entry-cancel.md).

## During an ending, every input is ignored

A looping ending is no exception: the bench's `y` / `n` are not gestures, they are the host answering the film ([bench keys](bench-keys.md), [loading loop](../transitions/loading-loop.md)).

Once a status screen is on the panel the flow is dispatched and the buttons are dead — `armed()` returns an empty set for a status screen ({{loc:pq1.driver.FlowDriver.armed}}), and `press`, `enter`, `double_tap` and `hold` all return immediately while the state is not `navigating`, and `release` fires nothing because no press was ever recorded.

Executed on the ending of `send_token`, both while it is `resolving` and once it is `finished`: press left, release left, both buttons, a double press and a full hold all return nothing, and the ending plays on undisturbed. The corner chevrons are hidden there, which is the visible half of the same rule — declining has to happen before dispatch.

The one exception is an **entry**, which is a status-kind screen that is navigable while its row is open — it takes the entry column of the grammar ([PIN entry](entry-dial.md)).

## The race between two holds

Only one fill exists at a time: `Sim.hold_begin` keeps the first live hold and ignores a second button pressed during it ({{loc:pq1.flow.Sim.hold_begin}}). Both press clocks keep running, though, and `FlowDriver.frame` commits whichever reaches {{tok:pq1.motion.HOLD_COMMIT_MS}} first ({{loc:pq1.driver.FlowDriver.frame}}). Executed: both buttons pressed in the same instant on the ask and held — the flow **declines**, because `frame()` walks left before right. Press right first and it signs. The loser's pending hold is dropped when the winner leaves the screen.

## Do / Don't

- **Do** treat the two buttons as independent outside an entry: one press, one clock, one action.
- **Do** hide the chevrons and refuse every edge while an ending is playing.
- **Do** decide what to draw from what is armed, never from a result code.
- **Don't** add a chord, a double press or a long-press menu to a navigation screen because the hardware makes it easy.
- **Don't** draw a fill on a side that cannot commit — an unarmed hold must look like nothing at all.
- **Don't** treat "both buttons" as a safe no-op the way it is on many devices. Here it is two taps, and on an [entry](entry-enter.md) it is ENTER.

{{partial:port-notes}}
