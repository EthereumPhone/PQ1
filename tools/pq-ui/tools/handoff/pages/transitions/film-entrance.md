## What it is

The one transit that is **not** a [spring morph](spring-morph.md): entering a loading film. A film's first job is to turn the flow's token into its first qubit, and a spring cannot do that — a leg would carry a full-size disc into a screen that opens on a small one. So the entrance is sequential, like the [page flip](page-flip.md): the screen the flow is leaving goes out first, with its circle **parked** where it stands; the bare circle holds a beat alone on black; then the film takes the canvas and does the travelling itself. The circle it was handed travels to the film's centre, shrinks from the token's visible radius to a qubit and tints into the film's colour, its ring and its art fading out on the way. A **bare qubit** lands on the frame the split begins, and divides into its identical twin.

The seed replaced the film's old opening hold, so a film is never handed a cold canvas. The two pops the old entrance had — the disc's edge stepping out by the token inset on the film's first frame, and the body jumping to the film colour — are gone with it.

## When it appears

Every entry into a film whose animation opens on a seed: `StatusAnim.seeds` ({{loc:pq1.status.StatusAnim.seeds}}) says which — the [qubit film](../screen-types/status-qubit.md) and the plain [explosion](../library/fx-explosion.md) do; a [led screen](lead-film.md) seeds when its lead does (`status.seeded`, {{loc:pq1.status.seeded}}). On a flow that is the sign: [hold right](../actions/hold-right-sign.md) from the ask or the Confirm? into a done ending, and the failure film where a flow names one ([loading loop](loading-loop.md)).

Two entries keep the ordinary leg. A **token-less source** — leaving a PIN row into a film — has no circle to hand over ([token-less transit](tokenless-fade.md)). An explosion with a [side entrance](side-entrance.md) does its own travelling — the entrance IS the travel — so no circle is handed to it either. In both, the film still seeds: in place, at its own centre, from the token's visible radius.

## How it draws

**The beat — the flow's half.** `Sim.go_to` ({{loc:pq1.flow.Sim.go_to}}) arms no spring when the destination seeds. It records the circle as drawn on that frame — centre, the token's VISIBLE radius (the layout radius {{val:qubit:r_big}} less the {{val:pq1.components.TOKEN_INSET}} px inset the stroke sits inside), fill, ring, icon and icon colour — and starts one timer: {{tok:pq1.motion.FADE_MS}} of fade, then {{tok:pq1.motion.SEED_HOLD_MS}} of hold. Over it, in `Sim.draw` ({{loc:pq1.flow.Sim.draw}}):

- every spring is frozen: the circle does not move, shrink or sweep, and the follower chain stops stepping;
- the text, the corner chevrons, the trail's palette and a committed hold fill all multiply by `1 − ease_out(k)` — they fade where they stand;
- the circle itself is drawn at full alpha the whole beat. It is parked, not dissolved;
- once the fade is done the bare circle **holds** alone on black for {{tok:pq1.motion.SEED_HOLD_MS}} — fade, hold, morph (user rule, Sep 2026).

When the beat ends the pose is handed to the film — `StatusAnim.enter_from` ({{loc:pq1.status.StatusAnim.enter_from}}), set once before the film's time 0 so every frame of it stays a pure function of `t` — the current screen snaps to the film, the idle clock restarts (that is the film's time 0) and the chain is dropped. Nothing is drawn differently on that frame: the seed opens on exactly the parked circle.

**The seed — the film's half.** `loading.qubit_pose` ({{loc:pq1.loading.qubit_pose}}) owns the morph, which is why a standalone render seeds as well. Over {{tok:qubit:T_SEED}} one `ease_out` progress drives three things at once: the travel (the source centre to `gc`), the radius (the visible radius to {{val:qubit:r_q}} — exactly the qubit's, not area-conserving) and, in `loading.draw_status` ({{loc:pq1.loading.draw_status}}), the body's tint (the token's fill to the film colour). The dress — the token's art, then its stroke over it, the token's own layer order — fades over the first {{tok:pq1.motion.SEED_ART}} of the window on **linear time**, not on the eased progress: `ease_out` front-loads, and on it the dress would be gone inside one panel frame. The follower stream is dark over the seed; one arriving body has nothing to trail. The art that leaves is the icon the flow was drawing (the handed-over `icon` / `icon_color`); the film's own icon dresses only a seed nobody handed over.

The split starts the frame the seed lands, and both halves are already a qubit's size ({{val:qubit:r_q}}): the seed IS a qubit, so it divides rather than shrinking as it parts. Every later phase of the film sits {{tok:qubit:T_SEED}} in, where the hold used to be, and the whole stock film is {{tok:pq1.motion.STATUS_DWELL}}.

## Motion

{{motion-head}}
{{row:the beat — text, chevrons, trail and a hold fill fade, circle PARKED | pq1.motion.FADE_MS | ease_out | `1 − ease_out(k)` on everything but the circle; no spring moves, the chain stops}}
{{row:the hold — the bare circle alone on black, PARKED | pq1.motion.SEED_HOLD_MS | hold | nothing moves; the screen has gone and the circle waits}}
{{row:the pose is handed over — the film's time 0 | - | cut | `enter_from`, then the snap; the seed opens on the parked circle, so nothing changes on this frame}}
{{row:the seed — travel, shrink and tint | qubit:T_SEED | ease_out | one progress for all three; lands as one BARE qubit of {{val:qubit:r_q}} at `gc`}}
{{row:the dress leaves — art, then ring | qubit:T_SEED * pq1.motion.SEED_ART | linear | the first half of the seed window on raw time — two panel frames}}
{{row:the split begins | qubit:T_SEED | — | the frame the seed lands — see [the qubit film](../screen-types/status-qubit.md)}}
{{row:the whole entrance — fade, hold, then seed | pq1.motion.FADE_MS + pq1.motion.SEED_HOLD_MS + qubit:T_SEED | — | from the commit to two qubits parting}}

## Input

The commit that started the beat already made the film the current screen, so the driver reports `resolving` and refuses every press ({{loc:pq1.driver.FlowDriver.press}}) — as on any leg into a status screen.

## Preview

{{preview}}

## Do / Don't

- **Do** keep it sequential. The fade, the hold and the seed never overlap; the circle does not start to move until the text has gone and it has held.
- **Do** hand the film the VISIBLE radius. The layout radius is the stroke's outer edge; a seed that opens there steps the disc out by the inset on one frame.
- **Do** fade the dress on linear time. On the eased progress it empties in under one panel frame and reads as a cut.
- **Do** land at exactly the qubit radius. The two halves of the split are not scaled from the seed — they are qubits from their first frame.
- **Don't** spring into a film. There is no leg; a port that reuses the morph spring carries a full disc into the film and pops.
- **Don't** hold inside the film. The seed replaced the film's opening hold; the one hold is the flow's beat ({{tok:pq1.motion.SEED_HOLD_MS}}), so the film's own seams stay where they are.
- **Don't** dress the seed with the film's own icon when a flow handed one over. What leaves is what the user was looking at.

{{partial:port-notes}}
