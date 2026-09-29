"""Blind-signing mark — pq1/assets/blind_icon.svg as procedural art.

The exclamation the blind-signing flows wear inside the token (the device
signs a call it cannot decode): a bar tapering from a round tip to a
narrower round foot, and a dot below it — the SVG's two paths (viewBox
8 x 42) traced as one polygon and three ellipses, so the mark scales
cleanly at any radius and recolours like every vector glyph (a family's
icon_color). Vector, never a rasterized PNG: image art is for full-bleed
logos only. glyph() returns the components-registry signature;
components.GLYPHS["blind"] is this art.
"""
import math

from PIL import Image, ImageDraw

from .. import colors
from ..layout import SUP

# the SVG geometry in its own units (x right, y down, the box 8 x 42)
W, H = 8.0, 42.0
BAR = ((0.771, 3.318), (7.229, 3.318), (6.568, 27.501), (1.432, 27.501))   # tapering body
TIP = ((4.0, 3.318), 3.229, 3.318)      # round top cap: centre, rx, ry — reaches y 0
FOOT = ((4.0, 27.501), 2.568, 2.499)    # round base cap — reaches y 30
DOT = ((4.0, 37.794), 4.0, 4.206)       # the dot, y 33.59..42
MARK_SCALE = 0.56   # half-height per glyph r — the ether mark's optics (eth.LOGO_SCALE)


def draw(cv, cx, cy, *, r, color, alpha=1.0, rot=0.0):
    """the blind mark, half-height r, its box centred on (cx, cy). True
    alpha compositing (base_mark's rationale): the mark sits on a disc, so
    a colour-scaled fill would read wrong while fading."""
    if alpha <= 0.01:
        return
    u = 2.0 * r * SUP / H                       # one SVG unit, supersampled px
    pad = 4
    side = int(math.ceil(math.hypot(W, H) * u)) + 2 * pad   # rotation never clips
    mask = Image.new("L", (side, side), 0)
    d = ImageDraw.Draw(mask)
    ox, oy = side / 2 - W / 2 * u, side / 2 - H / 2 * u     # the box, centred

    def xy(p):
        return (ox + p[0] * u, oy + p[1] * u)

    a = int(round(255 * alpha))
    d.polygon([xy(p) for p in BAR], fill=a)
    for c, rx, ry in (TIP, FOOT, DOT):
        x, y = xy(c)
        d.ellipse((x - rx * u, y - ry * u, x + rx * u, y + ry * u), fill=a)
    if rot:
        mask = mask.rotate(-math.degrees(rot), resample=Image.BICUBIC)
    tile = Image.new("RGBA", (side, side), (*tuple(color), 255))
    tile.putalpha(mask)
    cv.paste(tile, int(cx * SUP - side / 2), int(cy * SUP - side / 2), tile)


def glyph(scale=MARK_SCALE):
    """components glyph signature; the mark's half-height = scale * r"""
    def fn(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        draw(cv, cx, cy, r=scale * r,
             color=tuple(color or colors.WHITE), alpha=alpha, rot=rot)
    return fn
