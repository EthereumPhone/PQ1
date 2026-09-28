{{doc-self}}

This is the only library screen that takes input: `interactive` is true, so the driver types into the
animation instead of navigating away from it ({{loc:screens.pin.pin_entering.PinEntering}}). It is
also token-less (`rests_on_token` false) — the ring row is the whole picture, and it is the row, not
a disc, that the cancel hold fills.

The drawing of a row lives in [PIN row](../components/pin-row.md); the four gestures have their own
pages — [dial](../actions/entry-dial.md), [ENTER](../actions/entry-enter.md),
[BACK / NEXT](../actions/entry-move.md), [cancel](../actions/entry-cancel.md) — and what happens
after the row is [entry outcome](../actions/entry-outcome.md). This page is the module: its clocks.

Two clocks matter. The **screen clock** `t` runs from the first frame and drives the handoff. The
**round clock** `tr` runs from `t0`, the time the current round opened — 0 normally, the restart
event's time when a cancelled row reopens in place. The opening rows below are on `tr`; every gesture
row is measured from its own event (the press, the tap, the 8th ENTER). The row itself is a replay of an event log, so every frame is a pure function of time
({{loc:screens.pin.pin_entering.entry_state}}).

## Timeline

One table: the module has no presets. Rows marked DEMO are the scripted GIF dialing itself — on the
device nothing on those lines happens without a button.

{{motion-head}}
{{row:the incoming token crossfades out | screens.pin.pin_entering.T_FADE | ease_out | on the SCREEN clock, not the round's: a restart does not replay it ({{loc:screens.pin.pin_entering.PinEntering.draw_handoff}})}}
{{row:the eight rings fade in | screens.pin.pin_entering.T_FADE | ease | one alpha over the whole row, on the round clock. No ring is active yet}}
{{row:the first slot activates | screens.pin.pin_entering.ACT_MS | ease | released at {{tok:screens.pin.pin_entering.T_UI}}. Ring colour 70 percent white to YELLOW, stroke 2 to 2.5 px, lift 0 to 3 px up — one curve, and it runs ONCE per round, not per slot}}
{{row:captions and hint labels fade in | screens.pin.pin_entering.T_TEXT | ease_out | also released at {{tok:screens.pin.pin_entering.T_UI}}: the rings settle first, then the words}}
{{row:the corner chevrons trail the labels | screens.pin.pin_entering.CHEV_STAGGER | ease_out | the same {{tok:screens.pin.pin_entering.T_TEXT}} fade, started this much later}}
{{row:hint 1 of the rotation fades in | screens.pin.pin_entering.L_FADE | ease_out | the rotation clock also starts at {{tok:screens.pin.pin_entering.T_UI}}. The hints are − / + , then ENTER (BOTH), then BACK (2X) / NEXT (2X)}}
{{row:… the hint stays lit | screens.pin.pin_entering.L_SHOW | hold | full alpha, nothing moving}}
{{row:… the hint fades out | screens.pin.pin_entering.L_FADE | ease_out | the fade-in's curve mirrored — alpha is 1 − ease_out(p) ({{loc:screens.pin.pin_entering.seg_alpha}})}}
{{row:… then nothing before the next hint | screens.pin.pin_entering.L_GAP | hold | the row is legible with no words on it}}
{{row:one hint slot, and the rotation repeats every three | screens.pin.pin_entering.L_SLOT | — | three slots make one full rotation; it keeps turning for as long as the row is open}}
{{row:DEMO: the beat before the script starts typing | screens.pin.pin_entering.T_SETTLE | hold | do not port. On the device the row waits for a press, however long that takes}}
{{row:DEMO: the scripted dial pace | screens.pin.pin_entering.STEP_TICK | hold | do not port: one tick per +1, then {{tok:screens.pin.pin_entering.STEP_SETTLE}} resting on the digit and {{tok:screens.pin.pin_entering.STEP_ADV}} to advance ({{loc:screens.pin.pin_entering.script}})}}
{{row:a live tap bounces the ring at once | screens.pin.pin_entering.BOUNCE_MS | sine | a half sine, 2.5 px up at the midpoint and back to the lift. Drawn on the ACTIVE ring only: every dial, ENTER and cursor move bounces the ring the cursor is on, and the 8th ENTER — which leaves no active slot — bounces nothing}}
{{row:… but its digit LANDS only when it can no longer be taken back | pq1.motion.DOUBLE_TAP_MS | cut | this window when a double press on that side COULD move the cursor (right only over entered digits, left off the first slot), {{tok:pq1.motion.CHORD_MS}} when it could not. A tap that turns into ENTER or BACK is undone before the ring ever shows a number it then retracts}}
{{row:hold left to cancel: flat, it may still be a tap | pq1.motion.TAP_MAX_MS | hold | the shared hold curve ({{loc:pq1.motion.hold_fill}}). The RIGHT hold is unbound on an entry and draws nothing}}
{{row:… the liquid rises in all eight rings | pq1.motion.HOLD_COMMIT_MS - pq1.motion.TAP_MAX_MS | linear | opaque white, over the stroke too; the part of each digit under the surface turns black. One level for the whole row}}
{{row:… released early, the liquid drains | pq1.motion.HOLD_SNAPBACK_MS | ease_out | from the level it reached, and nothing happens}}
{{row:the cancel fires: the whole picture fades | screens.pin.pin_entering.T_OUT | ease_out | at once, with no check beat — rings, digits, captions and liquid on one alpha}}
{{row:PREVIEW ONLY: the caption swaps to PIN ENTERED | screens.pin.pin_entering.SWAP_MS * 2 | ease_out | sequential: ENTER PIN fades fully out over {{tok:screens.pin.pin_entering.SWAP_MS}}, then PIN ENTERED fades in ({{loc:screens.pin.pin_entering.swap}}). Only `exit="rest"`, which never submits, ever shows this}}
{{row:the 8th ENTER: the hints leave | screens.pin.pin_entering.SWAP_MS | ease_out | the rotation fades out and no hint follows. The caption does NOT swap on a submit — ENTER PIN stays and leaves with the row}}
{{row:the check beat | screens.pin.pin_entering.T_CHECK | hold | eight white rings, the device comparing. Input is already dead}}
{{row:the row fades to black | screens.pin.pin_entering.T_OUT | ease_out | the entry ENDS EMPTY: there is no fill on a submit, because there was no hold to show}}
{{row:the black before the verdict's sign | - | — | the spliced verdict starts at `t_exit` = submit + {{tok:screens.pin.pin_entering.T_CHECK}} + {{tok:screens.pin.pin_entering.T_OUT}}, and its own hold phase is that black beat — {{tok:anim:verdict/pin_mismatch:T_HOLD}} for WRONG PIN}}
{{row:a submit with no verdict rests on black | screens.pin.pin_entering.T_BLACK | hold | the PIN-gate case, `match=None`: nothing plays and the flow moves on}}
{{row:DEMO: the rest tail of the GIF loop | screens.pin.pin_entering.REST_MS | hold | do not port — `exit="rest"` resting on PIN ENTERED}}

## Variants

{{variants}}

Those totals are the **scripted demo's**: `t_resolve` and `duration` are the end of a typed round, and
the result hold is this screen's own GIF tail ({{tok:screens.pin.pin_entering.STEP_ADV}} to advance,
then {{tok:screens.pin.pin_entering.REST_MS}} at rest), not the shared result hold every other status
screen uses. A live entry has no duration at all — it is open until a submit or a cancel.

## Phases

{{phases}}

## Constants

{{constants}}

## Spec a flow splices in

{{spec}}

{{used-in}}

## Preview

{{preview}}

## Do / Don't

- **Do** drive the row from an event log replayed by time. Undoing a converted tap is a deletion from
  that log, which is why a chord or a double press never flashes a digit it then takes back.
- **Do** end the entry empty. The verdict plays in the same screen from `t_exit`, with its handoff
  switched off, because the row left nothing on the canvas to hand over.
- **Don't** arm the right hold. On an entry only the left hold is bound, and only while the row is
  open: a done row never fills.
- **Don't** port the dial pace, the settle beat, the rest tail, or `typed` and `exit` — they exist so
  the GIF can type itself. On the device the row moves only when a button does.

{{partial:port-notes}}
