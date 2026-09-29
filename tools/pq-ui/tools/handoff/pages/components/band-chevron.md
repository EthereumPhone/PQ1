## What it is

One chevron that sits in the bottom band, right after the caption, pointing right. The caption and the chevron form one unit: `ERC-7730 CLEAR SIGNING ▸`. It says "press on — this screen only introduces". While it shows, the two [corner chevrons](chevrons.md) are hidden.

It is the same unit the [confirm band](confirm-band.md) uses for `OR VIEW MORE ▸`, drawn by the same function, `components._band_unit` ({{loc:pq1.components._band_unit}}). The shape is the corner chevron's shape ({{loc:pq1.components.chevron}}), not a font glyph.

## When it appears

Only on a hero with `band_chev` set — the [intro](../screen-types/hero-intro.md) ahead of an ask. Three families build one: the ERC-7730 intro, the firmware key-fingerprint intro, and the announce form of a batch hero (`BATCH SIGN TX 1 OF 3 ▸`, which also carries the [pager](pager.md)). The last transaction of a batch has nothing to point on to, so it never wears it.

## Spec

{{fields:band_chev,chev,commit}}

Setting `band_chev` makes `chev` default to `None` ({{loc:pq1.layout.normalize_screens}}). A hero's `commit` still defaults to **true**, so `band_chev` does not disarm the sign hold by itself: the flow helpers that build an intro set `commit` false explicitly. An intro asks nothing, so there is nothing to sign on it.

## Geometry

| part | value |
|---|---|
| caption centre x | {{val:pq1.components.VIEW_MORE_CX}} — the panel centre ({{val:pq1.layout.CENTER_X}}) nudged left, so text plus chevron read centred together |
| caption baseline y | {{val:pq1.layout.BASELINE_Y}}, the shared band baseline |
| caption type | the question caps: size {{val:pq1.typography.SIZE_QUESTION}}, letter spacing {{val:pq1.typography.LS_QUESTION}}, white |
| chevron centre x | right edge of the text + {{val:pq1.components.VIEW_MORE_CHEV_GAP}} px |
| chevron centre y | {{val:pq1.components.VIEW_MORE_CHEV_CY}} — the optical centre of the caps, not the baseline |
| chevron angle | a quarter turn clockwise from up: it points right |

The text width used for the chevron's x is the sum of the glyph advances plus the letter spacing between glyphs. The caption is data, so the chevron's x is computed per caption, never fixed. With the live captions it lands between x 316 and x 347.

The nudge is applied in `components.draw_text` ({{loc:pq1.components.draw_text}}): a caption whose layout text carries `band_chev` is shifted by the difference between the two centres and drawn as a band unit. The layout marks the text in `layout_of` ({{loc:pq1.layout.layout_of}}).

## Motion

{{motion-head}}
{{row:the unit arrives and leaves with its screen | - | spring NAV | text and chevron share ONE alpha: the screen's own text-alpha spring. There is no separate chevron fade}}
{{row:incoming caption waits for the disc | pq1.motion.TEXT_IN_DELAY_MS | hold | see [text-in delay](../transitions/text-in-delay.md)}}
{{row:corner chevrons fade out / in beside it | - | spring NAV | hidden ↔ `"lr"` is a pure fade on the transit's mix spring — see [chevrons](chevrons.md)}}

The band chevron itself never moves: no bob, no hint, no pulse. On the way from the intro to the ask, the unit fades out with the intro's caption while the corner pair fades in, already pointing outward.

## Input

{{gestures:hero — an intro}}

The chevron points right, but **either** tap leads on: the signer never has to pick a side on a hero. The right hold is unbound here (no fill is drawn). The left hold declines as everywhere. The chord and the double press are not gestures outside a PIN entry: the driver reads them as two plain taps, which is why those rows end two screens on.

Where the intro sits ahead of an ask (ERC-7730, a batch), the walkthrough never comes back to it: a left tap from the first detail lands on the ask. In the firmware update flow the band-chevron hero sits directly ahead of the words screen, so there a left tap from the words does return to it.

## Preview

No clip of its own. It shows in the preview of [Hero — an intro](../screen-types/hero-intro.md).

## Do / Don't

- **Do** draw the chevron as the vector shape, at the same size as a corner chevron.
- **Do** centre the text on the nudged x and hang the chevron off its measured right edge.
- **Don't** show corner chevrons and the band chevron together.
- **Don't** arm the sign hold on a screen that wears it.
- **Don't** give the left side a band chevron on a hero. A left-pointing unit exists only in the [confirm band](confirm-band.md).

{{partial:port-notes}}
