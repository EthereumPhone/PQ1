"""Rounded-edge Ethereum glyph — THE ether mark, as procedural art.

The one Ethereum mark on the device (audit ICO-02): the white logo the SEND
flow and the unknown-token idle screen wear on every ramp, the schema's
default icon and the fallback for art the device lacks (DESIGN.md
§ Components), and the Mainnet chain badge — GLYPHS["eth"] and
GLYPHS["mainnet"] are this same function. Traced as two rounded polygons —
the upper kite and the lower wedge with its concave notch — from the
raster logo it replaced (reference/logos/eth-logo.png, 400 px, glyph rows
82..307, width 0.58 of height), so it scales cleanly and recolours like
every vector glyph (a brand family's icon_color renders it black on the
brand disc; the raster could not). glyph() returns the components-registry
signature.
"""
import math

from PIL import Image, ImageDraw

from . import geometry
from .. import colors
from ..layout import SUP

# outline points in half-height units (y down), measured from the PNG
UPPER = ((0.0, -1.0), (0.578, -0.111), (0.0, 0.209), (-0.578, -0.111))
LOWER = ((-0.582, 0.220), (0.0, 0.404), (0.582, 0.220), (0.0, 1.0))
ROUND = 0.13          # corner trim, fraction of the half-height
ROUND_TIP = 0.24      # the top and bottom points round off softer
UPPER_RR = (ROUND_TIP, ROUND, ROUND, ROUND)
LOWER_RR = (ROUND, ROUND, ROUND, ROUND_TIP)
LOGO_SCALE = 0.56     # half-height per glyph r: inks 18 x 30 px at r 30 — the
#                       procedural height the owner kept (Sep 2026; the raster
#                       it replaced inked 16 x 27, so the two never matched)


def draw(cv, cx, cy, *, r, color, alpha=1.0, rot=0.0):
    """the rounded-edge eth mark, half-height r, centred on (cx, cy).
    True alpha compositing (marks.base_mark's model): the mark sits on a
    disc, so a colour-scaled fill would read wrong while fading."""
    if alpha <= colors.ALPHA_FLOOR:
        return
    col = tuple(color)
    R = r * SUP
    pad = 4
    w = int(math.ceil(2 * 0.582 * R)) + 2 * pad
    h = int(math.ceil(2 * R)) + 2 * pad
    w, h = w + w % 2, h + h % 2        # even sides: a whole-pixel centre (ICO-09)
    mask = Image.new("L", (w, h), 0)
    d = ImageDraw.Draw(mask)
    ca, sa = math.cos(rot), math.sin(rot)

    def xy(p):
        px, py = p
        return (w / 2 + (px * ca - py * sa) * R,
                h / 2 + (px * sa + py * ca) * R)

    a = int(round(255 * alpha))
    for poly, rrs in ((UPPER, UPPER_RR), (LOWER, LOWER_RR)):
        d.polygon(geometry.rounded_polygon([xy(p) for p in poly],
                                           [q * R for q in rrs]), fill=a)
    tile = Image.new("RGBA", (w, h), (*col, 255))
    tile.putalpha(mask)
    cv.paste(tile, int(round(cx * SUP - w / 2)),        # rounded, never
             int(round(cy * SUP - h / 2)), tile)         # truncated (ICO-09)


def glyph(scale=LOGO_SCALE):
    """components glyph signature; the mark's half-height = scale * r"""
    def fn(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        draw(cv, cx, cy, r=scale * r,
             color=tuple(color or colors.WHITE), alpha=alpha, rot=rot)
    return fn
