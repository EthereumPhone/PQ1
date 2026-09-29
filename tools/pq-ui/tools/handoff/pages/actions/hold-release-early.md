## What it is

Letting go of a hold before the fill is full. The level freezes where it got to, drains back to empty, and **nothing happens**. It is the escape hatch of the two committing gestures: as long as the disc is not full, the signer can still change their mind.

"Slow where the user decides, fast where the system responds" — the rise takes {{tok:pq1.motion.HOLD_COMMIT_MS}}, the retreat {{tok:pq1.motion.HOLD_SNAPBACK_MS}}.

## When it appears

Any press on an armed side that comes up after the tap window and before the commit: [hold right — sign](hold-right-sign.md) on an ask or a Confirm?, [hold left — decline](hold-left-decline.md) anywhere, and the left hold that cancels a [PIN row](entry-cancel.md).

## The curve

One pure function covers the whole gesture, rise and retreat: `motion.hold_fill(t_since_press, t_release)` ({{loc:pq1.motion.hold_fill}}).

- The level is frozen at the value it had at the release — `k_at(min(t, t_release))` — so nothing jumps at the moment the button comes up.
- That frozen level is then multiplied by `1 − ease_out(elapsed / HOLD_SNAPBACK_MS)`: a release at a quarter full drains a quarter of the disc, in the same time a release at nine tenths drains nine tenths. The snap-back is a **constant duration, not a constant speed**.
- Both arguments are ms since press-down. Any frame can be recomputed from the two press edges alone; nothing accumulates.

`Sim.hold_release` records the release and `Sim.draw` drops the hold once the snap-back has run ({{loc:pq1.flow.Sim.hold_release}}).

## Timeline (ms since press-down)

{{motion-head}}
{{row:released inside the tap window: it was a tap | pq1.motion.TAP_MAX_MS | hold | no fill was ever drawn, so there is nothing to drain — the hold record clears at once and the tap fires}}
{{row:released mid-rise: the level freezes | - | hold | the level is whatever the linear rise had reached}}
{{row:the fill drains from there to empty | pq1.motion.HOLD_SNAPBACK_MS | ease_out | measured from the RELEASE, not from the press}}
{{row:for comparison, a completed hold | pq1.motion.HOLD_COMMIT_MS | linear | the action fires only here — [hold right](hold-right-sign.md)}}

## Input

{{gestures:hero — the ask}}

{{gestures:detail — middle}}

Two things to read carefully in those rows:

- On the ask, `release a hold early` returns `snapback` and the screen is unchanged. A near-complete hold is worth no more than a hold that barely started.
- On a detail the same row **also** says `snapback` — but the right hold is not armed there, so no fill was ever drawn. The driver returns the string for any press past {{tok:pq1.motion.TAP_MAX_MS}} that did not fire ({{loc:pq1.driver.FlowDriver.release}}). The result is not evidence the signer saw anything; see [unbound gestures](unbound-gestures.md).

## A gap in the reference driver — fix it in the port

Press again **while the previous fill is still draining** and the reference driver shows no rising fill, yet still commits.

`Sim.hold_begin` keeps only one hold record and refuses a new one while the old is present ({{loc:pq1.flow.Sim.hold_begin}}); the drained record is not dropped until `Sim.draw` sees the snap-back finish, {{tok:pq1.motion.HOLD_SNAPBACK_MS}} after the release. The second press therefore never gets a record of its own. The driver's own press clock has no such guard: it starts fresh, and at {{tok:pq1.motion.HOLD_COMMIT_MS}} the action fires.

Executed — hold right on the ask, release at about half fill, press right again a frame later:

1. The old fill finishes draining, as if the button were still up.
2. The disc then sits **empty for the whole** {{tok:pq1.motion.HOLD_COMMIT_MS}} of the second press. Nothing rises, nothing hints that a hold is running.
3. At the commit the flow signs — and because `Sim.hold_commit` finds no live hold it back-dates one ({{loc:pq1.flow.Sim.hold_commit}}), so the disc jumps straight to **full** and fades out over the leg.

On the device that is a signature announced by a fill that appears only after the fact. Start the new fill from zero on the new press-down instead, and drop whatever is left of the old one.

## Preview

{{preview}}

## Do / Don't

- **Do** compute the level from the two press edges each frame, never by stepping a counter.
- **Do** hold the snap-back to the same duration whatever level it starts from.
- **Do** treat a release inside the tap window as a tap, with no visual trace of a fill.
- **Don't** fire anything on a release, at any level below full. There is no "close enough".
- **Don't** let a draining fill block the next press — see the gap above; on the device a new press must start a new fill from zero.
- **Don't** trust a laptop for this. The [bench player](bench-keys.md) infers the release from a gap in the terminal's key-repeat stream, so it can see one late enough that the hold has already committed. Real buttons give exact edges — port from the edges, not from the player's behaviour.

{{partial:port-notes}}
