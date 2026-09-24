{{doc-self}}

## Timeline

One class, two directions, two mechanism windows. `t` is milliseconds since the screen's own t 0. Everything below is a pure function of `t` — no frame counting, no accumulation.

**`lock` (the default) — the shackle turns in and seats.** The mechanism window is `T_MECH`; the entrance runs *inside* it, under the turn-in.

{{motion-head}}
{{row:black hold — the flow's token hands over | screens.verdict.padlock.Padlock.T_HOLD | ease_out | no padlock on the canvas yet; longer than the base verdict hold ({{tok:pq1.verdict.VerdictAnim.T_HOLD}}). The token crossfade runs only where the spec's `handoff` survives — in the PIN ladder it is dropped and the hold is plain black — see [handoff](../transitions/handoff.md)}}
{{row:icon entrance — fade + rise | pq1.motion.ARRIVE_MS | ease_out + arrive | alpha 0 to 1; the WHOLE composite scales {{val:pq1.motion.ARRIVE_FROM}} to 1 via `body_r`. Starts at the same instant as the turn-in, so the lock is already mid-turn when it becomes solid}}
{{row:shackle turns in | screens.verdict.padlock.T_TURN | ease | `spin` pi to 0 rad: fully open-mirrored to seated. The spin is a z-rotation about the seated right leg, drawn as horizontal foreshortening x' = px + (x - px) cos(spin), floor 0.06 so it is never edge-on}}
{{row:shackle drops onto the body | screens.verdict.padlock.T_DROP | ease_out | `lift` {{val:screens.verdict.padlock.OPEN_LIFT}} px to 0 — the open shackle's rest raise falls away}}
{{row:the click | screens.verdict.padlock.T_CLICK | recoil | the shackle bites down 0.9 px and the body nudges 0.7 px, both times the unit curve, which peaks at 0.58 about a third of the way in — so about half a pixel and four tenths of one: a settle, not a jolt}}
{{row:beat before the caption — none on this screen | screens.verdict.padlock.Padlock.T_WAIT | — | the click IS the beat; the caption starts the instant the mechanism ends}}
{{row:caption fades in | pq1.verdict.VerdictAnim.T_TEXT | ease_out | LOCKED on the y {{val:pq1.layout.BASELINE_Y}} baseline}}
{{row:rest, then the flow moves on | pq1.status.RESULT_HOLD_MS | hold | see [result hold](../transitions/result-hold.md)}}

**`unlock` — the lock arrives shut and springs open.** Here the mechanism window *adds* the entrance: `T_MECH_UNLOCK` = entrance + kick + pause + swing, and nothing moves until the lock has arrived.

{{motion-head}}
{{row:black hold — the flow's token hands over | screens.verdict.padlock.Padlock.T_HOLD | ease_out | identical to `lock`; this is the one screen in the live flows whose handoff actually runs (`unlock_batch`)}}
{{row:icon entrance — the CLOSED lock fades + rises | pq1.motion.ARRIVE_MS | ease_out + arrive | `spin` 0, `lift` 0: a seated padlock. The mechanism clock starts only when this ends}}
{{row:shackle snaps up | screens.verdict.padlock.T_SNAP | ease_out | `lift` 0 to {{val:screens.verdict.padlock.OPEN_LIFT}} px. Exactly {{tok:pq1.motion.VERDICT_ACCENT_MIN_MS}} — two panel frames, the shortest accent allowed}}
{{row:the body takes the reaction | screens.verdict.padlock.T_KICK | recoil | `drop` = {{val:screens.verdict.padlock.KICK}} px times the unit curve: the body is knocked down, peaking 5.8 px about a third in, and is back at rest before the swing. Runs from the same instant as the snap, and only the body moves — the shackle keeps its place, so the two visibly part}}
{{row:pause — the beat after the kick | screens.verdict.padlock.T_PAUSE | — | nothing moves; the shackle sits raised and seated. Measured from the end of the kick, not of the snap}}
{{row:shackle swings out | screens.verdict.padlock.T_TURN_OUT | ease | `spin` 0 to pi rad, the unhurried mirror of the lock's turn-in}}
{{row:beat before the caption — none on this screen | screens.verdict.padlock.Padlock.T_WAIT | — | the swing's own ease-in-out tail is the beat}}
{{row:caption fades in | pq1.verdict.VerdictAnim.T_TEXT | ease_out | UNLOCKED}}
{{row:rest, then the flow moves on | pq1.status.RESULT_HOLD_MS | hold | }}

**The rig** ({{loc:pq1.procedural.padlock.draw}}). A body disc of radius {{tok:pq1.procedural.padlock.BODY_R}} (every other measure scaled by `f` = body_r / BODY_R), a black halo ring {{val:pq1.procedural.padlock.HALO}} px thick so the legs read as passing behind it, a keyhole (round bore + tapered slot), and a polyline shackle of arm radius {{val:pq1.procedural.padlock.ARM_R}} px stroked {{val:pq1.procedural.padlock.LW}} px with round caps. `(cx, cy)` is the CLOSED composite's measured ink centroid, not its bounding-box middle: the body therefore sits {{val:pq1.procedural.padlock.BODY_DY}} px below cy. The long leg always reaches 2 px into the disc however far the kicked body and the flying shackle have parted — a real shackle never leaves its body.

## Variants

{{variants}}

`(default)` is the `lock` preset — identical specs, so the build renders it once. Only `unlock` resolves `state: "done"` (green); `lock` is `failed` (red).

## Phases

{{phases}}

## Constants

{{constants}}

`OPEN_LIFT` and `KICK` are UI pixels; `T_MECH` and `T_MECH_UNLOCK` are the two `T_IN` values (`T_IN` is set per direction in `__init__`), derived from the phases above — do not re-type them, sum them.

## Input

None. It is a verdict: an ending accepts no press from its first frame to its last ({{loc:pq1.driver.FlowDriver.press}}), and the corner chevrons are hidden. It also owns its canvas, so the flow leaves it by fading to black — see [token-less transit](../transitions/tokenless-fade.md).

## Spec a flow splices in

{{spec}}

{{used-in}}

`lock` is also the PIN ladder's terminal miss and `unlock` its match: `flows/pin/__init__.py` splices them inside an attempt, as the verdict the typed digits earn — which is why they do not show up as flow screens of their own.

## Preview

{{preview}}

## Do / Don't

- **Do** keep the snap at `T_SNAP` and the kick on `recoil`. The two panel frames of spring-up against the body's dip are what make it read as a real padlock letting go; slow the snap and it becomes a slide.
- **Do** run the lock's entrance *under* the turn-in and the unlock's *before* the snap. That asymmetry is deliberate: LOCKED arrives already moving, UNLOCKED arrives still.
- **Don't** round the click away. Its amplitudes are sub-pixel; the panel shows it only because the rig is drawn supersampled ({{val:pq1.layout.SUP}}x) and downsampled. Draw at 1x with integer coordinates and the click disappears.
- **Don't** give this screen a beat: `T_WAIT` is zero in both directions and the caption follows the mechanism immediately.

{{partial:port-notes}}
