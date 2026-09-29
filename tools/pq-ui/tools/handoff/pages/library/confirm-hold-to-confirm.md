{{doc-self}}

## Timeline

This screen is a **scripted demo of a live gesture**. It performs the press itself, at a fixed time, and either completes it or lets go. Nothing here is driven by a button. On the device the same fill is drawn on a [hero — the ask](../screen-types/hero-ask.md) or a [Confirm?](../screen-types/confirm.md) by the real [hold right](../actions/hold-right-sign.md) — same curve, same drawing, no script. Port the curve, not the clock.

`t` is milliseconds since the screen's t 0. Both endings share the opening.

**Shared: drift, then the hold.**

{{motion-head}}
{{row:chevrons fade in, both in the up (hold-armed) pose | pq1.status.BUSY_FADE_MS | ease_out | `components.chevron_pair(cv, 0, 0)` — no hint bob, no rotation}}
{{row:the caption fades in — steady, not breathing | pq1.status.BUSY_FADE_MS | ease_out | HOLD TO CONFIRM is a gesture caption, so `busy_pulse` is false. See [busy caption](../components/busy-caption.md)}}
{{row:idle drift, until the scripted press | screens.confirm.hold_to_confirm.T_IDLE | sine | a plain sine of absolute `t` on the sweep period {{tok:pq1.motion.SWEEP_PERIOD_MS}}, amplitude {{val:screens.confirm.hold_to_confirm.DRIFT_AMP}} px — the idle sweep divided by 8. No delay, no chase, no trail. DEMO: the press lands here}}
{{row:the press pulls the drift home | screens.confirm.hold_to_confirm.T_RECENTER | ease_out | the sine keeps running underneath; only its amplitude decays to zero, so the disc glides to the centre and the fill rises in a disc that stands still}}
{{row:fill flat at zero — the press may still be a tap | pq1.motion.TAP_MAX_MS | hold | measured from the press. A tap never flashes a partial fill}}
{{row:fill rises to full | pq1.motion.HOLD_COMMIT_MS - pq1.motion.TAP_MAX_MS | linear | `motion.hold_fill` ({{loc:pq1.motion.hold_fill}}) drawn by `components.hold_flood` ({{loc:pq1.components.hold_flood}}) — a see-through liquid at opacity {{val:pq1.components.HOLD_OVERLAY_ALPHA}}, black over the teal body, white inside a near-black one. See [hold flood](../components/hold-flood.md)}}

**`confirm` — the default, and the `hold_confirm_success` preset.** The fill completes.

{{motion-head}}
{{row:the commit fires: the disc is full | screens.confirm.hold_to_confirm.T_COMMIT | — | a time, not a length: the idle plus {{tok:pq1.motion.HOLD_COMMIT_MS}}}}
{{row:the hold composition fades out | screens.confirm.hold_to_confirm.T_FADE | ease_out | token, fill and chevrons together on one alpha. The caption rides its own slightly longer fade ({{tok:pq1.status.BUSY_FADE_MS}}, from the commit) and is down to a few thousandths of full when the cut comes — no pop}}
{{row:the qubit film starts | screens.confirm.hold_to_confirm.T_COMMIT + screens.confirm.hold_to_confirm.T_FADE | cut | a whole inner `status.QubitStatus` on the SAME spec minus `busy`, forced to `state="done"` / `result="check"` — so a branded demo lands on its branded resting disc}}
{{row:the film, hold to resolved | qubit:t7 | — | every phase of it on [status — the qubit film](../screen-types/status-qubit.md)}}
{{row:resolved | anim:confirm/hold_to_confirm:t_resolve | — | }}
{{row:result hold | pq1.status.RESULT_HOLD_MS | hold | see [result hold](../transitions/result-hold.md)}}
{{row:whole screen | anim:confirm/hold_to_confirm:duration | — | }}

**`hold_confirm_cancel` — the release.** The button comes up at {{val:screens.confirm.hold_to_confirm.RELEASE_K}} of the fill.

{{motion-head}}
{{row:the release | screens.confirm.hold_to_confirm.T_REL | cut | a time: the idle plus `motion.hold_fill_ms(RELEASE_K)`. Derived from the curve, never typed}}
{{row:the fill drains | pq1.motion.HOLD_SNAPBACK_MS | ease_out | from the level it had reached — see [release early](../actions/hold-release-early.md)}}
{{row:the chevrons fade out | pq1.motion.FADE_MS | ease_out | from the release. The caption starts at the same instant but takes {{tok:pq1.status.BUSY_FADE_MS}}, so the words are the last thing to go}}
{{row:the token fades out | pq1.motion.FADE_MS | ease_out | starts only once the fill has finished draining: drain first, then disappear}}
{{row:the pop | screens.confirm.hold_to_confirm.T_POP | cut | a time: release plus the drain plus the fade. `burst.draw` is entered at exactly the offset where the MINOR boom begins (`MINOR.qubit.t6` plus `MINOR.t_clump`), so no loading leg and no clump ever play — the bloom and ring constants are reused, never copied. The rings take the ending's own colour, red either way}}
{{row:the failed disc arrives | screens.confirm.hold_to_confirm.T_IN | ease_out + arrive | the verdict entrance law: alpha 0 to 1 while the radius rises {{val:pq1.motion.ARRIVE_FROM}} to 1 of {{tok:pq1.layout.CIRCLE_R}}. It runs over the blast, not after it}}
{{row:the beat before the caption | screens.confirm.hold_to_confirm.T_WAIT | — | nothing moves but the rings still flying out}}
{{row:the caption fades in | screens.confirm.hold_to_confirm.T_TEXT | ease_out | TRANSACTION CANCELLED}}
{{row:resolved | anim:confirm/hold_to_confirm@hold_confirm_cancel:t_resolve | — | }}
{{row:result hold | pq1.status.RESULT_HOLD_MS | hold | }}
{{row:whole screen | anim:confirm/hold_to_confirm@hold_confirm_cancel:duration | — | }}

### What the endings rest on

`confirm` lands the film's own resolve: the check on the spec's resting look. `cancel` builds a failed spec (`state="failed"`, `result="x"`) and, if the spec is branded, swaps the brand fill for the failed red while keeping the rest of that family's SIGNED resting — flush black ring, the family's mark colour on the X. Unbranded it is the black disc with a red stroke and a red X. See [the resting look](../screen-types/resting-look.md).

Watch that swap when you read the demo as a reference: a real family's DECLINED ending rests on the red disc with a **black** X (`status.branded_resting`, DESIGN.md § Color), and only a family whose mark is already black (SAFE) renders the same here. `--family cowswap` leaves the navy mark on the X — the demo's own shortcut, not the endings rule.

The demo's own token is the placeholder teal ramp {{val:pq1.gradients.TEAL_RAMP}} with the ETH glyph. `--family safe` re-dresses it from a flow family's `DEFAULTS` and its done ending's `resting`, which is the whole point of the screen: the hold film is resolved once, in `components.hold_style` ({{loc:pq1.components.hold_style}}), so a new brand gets it for free.

## Variants

{{variants}}

`(default)` is `hold_confirm_success` — identical specs, so the build renders it once. Both rest on a token, so a flow morphs out of them normally; neither can lead.

## Phases

{{phases}}

## Constants

{{constants}}

`T_COMMIT`, `T_REL` and `T_POP` are **derived**: `T_IDLE` plus the system hold curve, plus the snap-back and the fade. Do not re-type them — recompute them from {{tok:pq1.motion.HOLD_COMMIT_MS}}, {{tok:pq1.motion.HOLD_SNAPBACK_MS}} and `motion.hold_fill_ms`, so a change to the gesture moves this screen with it. `DRIFT_AMP` is {{tok:pq1.motion.SWEEP_AMP}} over 8.

## Spec a flow splices in

{{spec}}

{{used-in}}

## Preview

{{preview}}

## Do / Don't

- **Do** take only the fill from this screen: `hold_fill` from ms since press-down, `hold_flood` for the drawing, `hold_style` for the shade. They are the device's, and they are shared with the flow Sim.
- **Do** keep the recentre. A fill that rises in a drifting disc reads as two motions; the press must stop the drift first.
- **Don't** port `T_IDLE`, `T_COMMIT`, `T_REL` or `T_POP`. They are the demo's script for a press the device gets from a button.
- **Don't** re-run a loading film for the cancel. The pop enters `burst.draw` mid-boom on purpose — a cancellation did no work, so it shows none.

{{partial:port-notes}}
