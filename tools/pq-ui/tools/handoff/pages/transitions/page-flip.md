## What it is

How a screen that carries `pages` changes page: the showing page fades **away**, and only then does the next one fade **in**. Sequential, never a crossfade — the two pages are the same value, and overlapping them would read as garbled text. It happens inside one screen; the disc does not move and the label does not change.

## When it appears

Only on a screen whose dict has `pages` — a [paged detail](../screen-types/detail-paged.md) or a [paged value](../screen-types/value-paged.md), i.e. one value too long for three lines. On the device it is started by a tap ([tap on a paged screen](../actions/tap-page.md)); nothing turns a page on its own.

## Spec

{{fields:pages}}

## Motion

The envelope is `motion.page_flip(t)` ({{loc:pq1.motion.page_flip}}), a pure function of ms since the flip began returning `(a_out, a_in)`. Both alphas multiply the screen's own text alpha, so a flip caught by a [spring morph](spring-morph.md) simply fades out with the screen.

{{motion-head}}
{{row:showing page fades away | pq1.motion.PAGE_FADE_MS | ease_out | inverted — the alpha is `1 − ease_out(t / PAGE_FADE_MS)`, so it drops fast and tails off}}
{{row:the pager number switches | - | cut | at the boundary between the two halves, while nothing is drawn}}
{{row:next page fades in | pq1.motion.PAGE_FADE_MS | ease | cubic in-out, from the boundary; the flip is cleared when it reaches 1}}
{{row:whole swap | 2 * pq1.motion.PAGE_FADE_MS | ease_out + ease | }}

At the boundary both alphas are zero: for a frame or two the value region is **empty** while the label and the pager stay up. That gap is the effect — do not close it. Sampled at the panel's rate from a flip that starts on a frame, the outgoing page reads 0.44, 0.14, 0.02, then the blank frame, then the incoming page 0.03, 0.31, 0.85, 1.00 — the fade-out is nearly done in its first two frames, which is what `ease_out` buys.

The label and every other fixed text are drawn straight through, at the screen's own alpha ({{loc:pq1.flow.Sim._draw_pages}}). The pager reads the page actually on the glass: the outgoing number while `a_out` is still above zero, the incoming one after.

Entering a paged screen never flips. `go_to` resets it to its first page — or to its **last** page when entered backwards, so a left tap undoes a right tap — and discards any flip left in flight on it ({{loc:pq1.flow.Sim.go_to}}). The first page therefore arrives on the transition's own text alpha, and the last page leaves on it.

## Input

{{gestures:detail — paged}}

Right turns the page until the last, then leaves for the next screen. Left turns back until the first, then leaves for the previous screen — which is entered on *its* last page.

## Do / Don't

- **Do** drive it from one `t0` per screen and the pure envelope. Any frame is then seekable, and a dropped frame costs nothing.
- **Do** keep the two halves sequential and equal.
- **Do** end the flip when `a_in` reaches 1, not on a timer: at the panel's rate that is the first frame past the whole swap.
- **Do** ignore a tap that names the page already pending — `flip_page` returns without starting anything.
- **Don't** port the demo page-turn clock ({{tok:pq1.motion.PAGE_SWAP_MS}}, one page per detail dwell, the flip starting {{tok:pq1.motion.PAGE_FADE_MS}} before the slot ends). The reference driver pins every dwell to infinity; on the device only a tap turns a page.
- **Don't** crossfade the two pages, and don't slide them.

> **Known rough edge.** A flip is restarted from the *pending* page, not the visible one: `flip_page` writes the new page into `self.page[i]` immediately, so a tap that reverses a flip already in flight takes `frm` from the page you have not seen yet ({{loc:pq1.flow.Sim.flip_page}}). Measured on `eip1271/personal_counterfactual_hash`: tapping left halfway through a 1 → 2 flip makes page 2 pop in at full opacity and fade away before page 1 returns. A port that latches the visible page as `frm` is closer to the intent.

{{partial:port-notes}}
