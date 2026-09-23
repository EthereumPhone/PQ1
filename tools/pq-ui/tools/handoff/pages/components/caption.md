## What it is

The one line of text in the bottom band: the hero's question (`SEND 12,500 TOSHI?`), an ending's resolved line (`TRANSACTION CONFIRMED`), a verdict's word (`LOCKED`). One type role — the question caps — centred on the panel and **baseline-aligned** to y {{val:pq1.layout.BASELINE_Y}}.

It is output only. It never wraps, never scrolls, never shrinks to fit: a caption that does not fit is a content bug, not a layout case.

Two other things live in the same band and are **not** this: the detail [label](detail-text.md) (smaller, SemiBold, centred on the circle's column) and the [confirm band](confirm-band.md) (two alternating units with a chevron). The [band chevron](band-chevron.md) is this caption with one chevron beside it.

## When it appears

- a `hero` screen's `bottom` — the ask, or an intro's line
- a `status` screen's `bottom` — the resolved caption, drawn by the animation when it resolves
- a `busy` line while a film runs — see [busy caption](busy-caption.md)
- library idle screens (the unknown-token and batch-sign rests) draw it at alpha 1 every frame — no fade in, no fade out ({{loc:pq1.components.caption}})

A `detail` screen has no caption: its band carries the [label](detail-text.md) instead. A `value` screen's band is empty — `layout_of` lays a label out only on a `words` value ({{loc:pq1.layout.layout_of}}), and the live firmware screen leaves even that off.

## Spec

{{fields:hero.bottom,status.bottom}}

## Geometry

| part | value |
|---|---|
| text | caps, Regular, white |
| size | {{val:pq1.typography.SIZE_QUESTION}} (`SIZE_QUESTION`) |
| tracking | {{val:pq1.typography.LS_QUESTION}} px (`LS_QUESTION`) |
| centre x | {{val:pq1.layout.CENTER_X}} |
| baseline y | {{val:pq1.layout.BASELINE_Y}} — the band is y {{val:pq1.layout.BAND_TOP}}–{{val:pq1.layout.BAND_BOTTOM}}, but the text is **baselined, not centred in it** |
| usable width | {{val:pq1.layout.W}} px minus two {{val:pq1.layout.MARGIN}} px margins |

Tracking is applied by hand, glyph by glyph ({{loc:pq1.canvas.Canvas.text}}): the run's width is the sum of the glyph advances plus the tracking times the gaps, and that run is centred on x. Measure a caption the same way — `typography.text_width(s, size)` plus `LS_QUESTION × (len(s) − 1)` — or the last letter drifts off centre.

Alpha is not compositing: a colour is scaled toward black and drawn ({{loc:pq1.canvas.Canvas.text}}). On a black panel the result is the same, and nothing under the text is disturbed. At alpha 0.01 or below nothing is drawn at all.

## One look, three code paths

| who draws it | how | used by |
|---|---|---|
| `layout_of` → `components.draw_text` ({{loc:pq1.components.draw_text}}) | a text spec in the screen's own text list, under that screen's alpha | hero, intro |
| `components.caption` ({{loc:pq1.components.caption}}) | called by the animation with an alpha | every status / verdict / PIN screen |
| `loading.draw_status` ({{loc:pq1.loading.draw_status}}) | its own text call at the end of the frame | the qubit film's resolved caption |

All three draw the same thing, but the size and tracking are re-typed as bare numbers in the layout and the film instead of being read from `pq1.typography`. **Port one caption routine** and call it from all three places; do not copy the duplication.

## Motion

The caption has no motion of its own. It fades with whatever owns it.

{{motion-head}}
{{row:navigable screens: the outgoing caption starts fading the instant a leg begins | - | spring NAV | its screen's alpha spring is retargeted to 0 — see [spring morph](../transitions/spring-morph.md)}}
{{row:the incoming caption is released this long after the leg begins | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | the disc leads, the words land just after it — see [text-in delay](../transitions/text-in-delay.md)}}
{{row:both captions are on screen together during a leg | - | spring NAV | a crossfade, not a sequential swap (the [page flip](../transitions/page-flip.md) is the sequential one)}}
{{row:a qubit or resolve ending: the caption lands behind the result glyph | 120 | linear | an unnamed literal in {{loc:pq1.loading.qubit_pose}} — see [flash ring](flash-ring.md)}}
{{row:… and fades in over | 350 | linear | the same literal, twice more in {{loc:pq1.status.ResolveStatus.draw}}}}
{{row:a verdict or an arriving ending: the caption fades in after the beat | pq1.verdict.VerdictAnim.T_TEXT | ease_out | the verdict law's last phase — see [verdict law](../transitions/verdict-law.md); an arriving ending re-declares the same span in `status.ArriveStatus.T_TEXT` ({{loc:pq1.status.ArriveStatus}}) — port ONE token}}
{{row:leaving an ending that rests on the token: the caption is cut | - | cut | the film stops being drawn on the first frame of the transit; the disc morphs on without it}}
{{row:leaving a screen that owns its canvas (verdict, PIN row): the whole frame dims | - | spring NAV | caption included — see [token-less transit](../transitions/tokenless-fade.md)}}
{{row:demo only: a hero holds its caption this long, then advances itself | pq1.motion.HERO_DWELL | — | **do not port** — on the device nothing moves without a press}}

The cut is real and verifiable: leave a `qubit` ending and the band is black on the next frame, while the incoming caption only starts at {{tok:pq1.motion.TEXT_IN_DELAY_MS}}. It shows as a short blank band between two screens. Keep it, or fade it with the screen, but decide it with the designer — do not let it fall out of the port by accident.

A live hold changes nothing here. The disc fills, the sweep recentres, the caption stays put at full strength.

## Preview

No clip of its own. Every preview in the catalog carries one; [hero — the ask](../screen-types/hero-ask.md) shows the crossfade and [status — the qubit film](../screen-types/status-qubit.md) the resolve.

## Do / Don't

- **Do** treat the text as data. The amount, the symbol, the version number in `UPDATE TO 1.0.3?` are per-transaction values; the flow fixes the screen, never the value.
- **Do** baseline-align to y {{val:pq1.layout.BASELINE_Y}}. Vertically centring it in the band puts it a pixel or two off every other band annotation.
- **Do** keep questions and status lines in caps.
- **Don't** ellipsize, truncate or auto-shrink. Shorten the string upstream.
- **Don't** give the caption its own fade clock on a navigable screen — it rides its screen's alpha spring, so a reversal mid-flight carries it.
- **Don't** draw two captions at once. The band holds one line; the busy line and the resolved line never overlap.

{{partial:port-notes}}
