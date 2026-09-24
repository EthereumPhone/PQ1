## What it is

The screen that says which network is being signed for. It is a [detail](detail.md)
with no label, whose whole content is one caption and the network's mark — and a
flow writes it as a single field:

```python
dict(id="CHAIN", kind="detail", side="right", chain=8453, label=None, chev="lr"),
```

`chain` is the numeric EIP-155 chain id. Everything the screen shows is derived from
it — the mark, the disc fill, the trail ramp, the caption and its tier
({{loc:pq1.chains}}, expanded in {{loc:pq1.layout.normalize_screens}}). A flow sets no
`icon`, no `lines`, no `size`, and no `circle_x` / `text_x`.

**Why it is one field.** Before, a flow typed the icon and the caption separately, so
nothing stopped a screen pairing the Base mark with "on Mainnet". On a signer the disc
is part of what the user is checking, so the art and the words must not be able to name
different networks. One id, one identity — and `tools/check` rule `F-CHAIN` fails the
build on a hand-written chain icon.

{{example}}

## Composition

The caption and the disc are **one group, centred**, with a fixed
{{tok:pq1.layout.CHAIN_GAP}} of air between the caption's right edge and the disc's left
edge ({{loc:pq1.layout.chain_compose}}). The disc is *not* pinned to a column: it moves
with the length of the network's name so the spacing reads identical on every chain.

Two consequences worth porting deliberately:

- the caption's centre is **constant** — its offset from the group centre depends only
  on the gap and the disc radius, never on the text width. So the caption never moves
  between chain screens; only the disc does.
- nothing can run under the disc any more, so the tier rule is "the group fits between
  the margins", not "clear the disc" ({{loc:pq1.layout.chain_caption_size}}). Every
  network in the registry clears the top tier; the ladder is the safety net for a longer
  name later.

{{geometry}}

## Colour

The disc wears the **chain's** identity, not the flow's, and hands the palette back on
the next screen. Ramps are pinned by name under a `CHAIN:` prefix
({{loc:pq1.colors.CHAIN_COLORS}}) — namespaced deliberately, because `OP`, `BNB`, `BASE`
and `SCROLL` are also token tickers and a bare key would repaint those *tokens* with a
*chain's* colours.

The mark is knocked out of the fill: white, or black once the fill is light
({{loc:pq1.colors.chain_mark_color}}, reading `luma` off the disc's actual fill). A chain
whose body cannot come from its ramp at all — a black brand, or a mark on white — pins
the fill in {{loc:pq1.colors.CHAIN_DISC_FILL}} and keeps the ramp for its trail. Only
those: a merely dark brand darkens its own ramp instead, because pinning a dark disc
over a bright ramp puts the nearest follower above the token in luminance and inverts
the trail law. See [token disc](../components/token-disc.md).

## An unknown chain

A chain id the registry does not hold is **not** an error and does not fall back to the
ether mark. The disc shows the **first letter of the network's name** — the `letter:<X>`
glyph namespace, resolved by shape rather than registered
({{loc:pq1.components.letter_glyph}}) — on a solid disc whose ramp is hashed from the
chain id, so the same unrecognised network looks identical on every device and every run.
The circle stays exactly where it is.

```python
dict(id="CHAIN", kind="detail", chain=42220, chain_name="Celo", label=None),
```

This narrows the ether fallback rather than replacing it: the ether mark is still the
honest answer for a token or a mark the device cannot resolve, but drawing Ethereum's
mark for another network would state something false rather than merely generic. The
disc is never empty either way.

{{used-in}}

{{preview}}

## Do / Don't

- **Do** derive everything from the id. A port that carries `chain` can rebuild the mark,
  the colour and the caption itself; `flows.json` publishes the id beside the icon it
  resolved to.
- **Do** keep the caption-to-disc gap constant and let the disc move. It is the one piece
  of this screen a reader notices when it is wrong.
- **Don't** write `icon=`, `lines=`, `size=`, `circle_x=` or `text_x=` on a chain screen.
- **Don't** give a chain ramp a bare ticker name, and don't let an unknown chain borrow
  another network's mark.
