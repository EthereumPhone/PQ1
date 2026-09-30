## What it is

The progress fill of a hold: a see-through liquid rising inside the token disc from the bottom up, level `k` from 0 to 1. `k` comes from `motion.hold_fill` ({{loc:pq1.motion.hold_fill}}); the drawing is `components.hold_flood` ({{loc:pq1.components.hold_flood}}).

## Geometry

The surface is a horizontal chord of the disc. For level `k` the surface sits `r · (1 − 2k)` below the centre; at `k = 1` the whole disc is covered. Levels at or under `LEVEL_EPS` ({{val:pq1.motion.LEVEL_EPS}}) draw nothing; levels within `LEVEL_EPS` of 1 draw the full circle. That is a *level*, not an alpha, which is why it is not the panel's `ALPHA_FLOOR`.

The full test is one function, `motion.hold_full` ({{loc:pq1.motion.hold_full}}) — ms since press-down at or past `hold_fill_ms(1 − LEVEL_EPS)`. The draw uses it to paint the whole disc, and the driver and the Sim fire the hold on it, so the first frame that shows a full disc is the frame the hold fires: there is no full-but-not-yet-signed frame in which a release still cancels.

## Three dresses, one rule

The film's opacity is always {{tok:pq1.components.HOLD_OVERLAY_ALPHA}}. Only its shade follows the body it rises in — resolved in one place, `components.hold_style` ({{loc:pq1.components.hold_style}}):

| body under the fill | the film | layer |
|---|---|---|
| a coloured disc (ramp solid, unknown gradient, brand art, logo art) | **black** | over the art and the glyph, under the ring |
| a near-black disc (luma under {{val:pq1.components.HOLD_DARK_BODY}}, no art) | **white** | inside the disc, under the ring and the glyph |
| the PIN row (hold-left cancel) | opaque white in the rings | see [PIN row](pin-row.md) |

The ring always stays bright; the liquid never paints over the token's identity.

## Motion

{{motion-head}}
{{row:flat at zero | pq1.motion.TAP_MAX_MS | hold | a tap shows no fill}}
{{row:rise to full | pq1.motion.HOLD_COMMIT_MS - pq1.motion.TAP_MAX_MS | linear | drawn full — and the hold fires — from `hold_full`, a hair before the linear rise reaches 1}}
{{row:snap back after an early release | pq1.motion.HOLD_SNAPBACK_MS | ease_out | from the level it had reached}}
{{row:fade out after the commit | - | spring NAV | alpha follows the transit's mix spring}}

## Preview

{{preview}}

## Do / Don't

- **Do** compute the level from the ms since press-down — never accumulate it per frame.
- **Don't** ease the rise: it is linear on purpose (a constant-speed gauge).
- **Don't** draw the fill where the hold is not armed.
- **Don't** test "full" and "fire" separately: one `hold_full` answers both, or a frame shows a full disc that a release still cancels.

{{partial:port-notes}}
