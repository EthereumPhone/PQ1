"""Blind-signing mark — pq1/assets/blind_icon.svg as procedural art.

The exclamation the blind-signing flows wear inside the token (the device
signs a call it cannot decode): a bar tapering from a round tip to a
narrower round foot, and a dot below it — the SVG's one path (viewBox
8 x 42, two closed subpaths: the bar, then the dot). The path data is
carried VERBATIM and flattened through geometry.svg_subpaths into two
polygons filled in an alpha mask, so the mark scales cleanly at any radius
and recolours like every vector glyph (a family's icon_color). It used to
be re-modelled by hand as a polygon and three ellipses — close (IoU 0.9945
against the path) but not the source: a mark that carries its path can be
diffed against the SVG it claims to be, a re-model only eyeballed (audit
ICO-10). Vector, never a rasterized PNG: image art is for full-bleed logos
only. glyph() returns the components-registry signature;
components.GLYPHS["blind"] is this art.
"""
import math

from PIL import Image, ImageDraw

from . import geometry
from .. import colors
from ..layout import SUP

W, H = 8.0, 42.0   # the SVG viewBox; the art fills it edge to edge
PATH = (
    # the bar: round foot at y 30, the tapered flanks, round tip at y 0
    "M6.56824 27.5009C6.53025 28.892 5.39161 30 4 30C2.60839 30 1.46975 28.892 "
    "1.43176 27.5009L0.771447 3.31792C0.721817 1.50032 2.18173 0 4 0C5.81828 0 "
    "7.27818 1.50032 7.22855 3.31791L6.56824 27.5009Z"
    # the dot, y 33.59..42
    "M4.02837 33.5881C6.35461 33.5881 8 35.3778 8 37.8239C8 40.2699 6.35461 42 "
    "4.02837 42C1.70213 42 0 40.2699 0 37.8239C0 35.3778 1.70213 33.5881 "
    "4.02837 33.5881Z"
)
MARK_SCALE = 0.56   # half-height per glyph r — the ether mark's optics (eth.LOGO_SCALE)

PARTS = geometry.svg_subpaths(PATH)   # the bar, the dot — SVG units (x right, y down)


def draw(cv, cx, cy, *, r, color, alpha=1.0, rot=0.0):
    """the blind mark, half-height r, its box centred on (cx, cy). True
    alpha compositing (marks.base_mark's model): the mark sits on a disc,
    so a colour-scaled fill would read wrong while fading."""
    if alpha <= colors.ALPHA_FLOOR:
        return
    u = 2.0 * r * SUP / H                       # one SVG unit, supersampled px
    pad = 4
    side = int(math.ceil(math.hypot(W, H) * u)) + 2 * pad   # rotation never clips
    side += side % 2   # even, so the centre is a whole pixel: an odd side or a
    #                    truncated paste sat every mark half a supersampled
    #                    pixel up and left (audit ICO-09)
    mask = Image.new("L", (side, side), 0)
    d = ImageDraw.Draw(mask)
    ox, oy = side / 2 - W / 2 * u, side / 2 - H / 2 * u     # the box, centred
    a = int(round(255 * alpha))
    for pts in PARTS:                           # disjoint, so union = fill both
        d.polygon([(ox + x * u, oy + y * u) for x, y in pts], fill=a)
    if rot:
        mask = mask.rotate(-math.degrees(rot), resample=Image.BICUBIC)
    tile = Image.new("RGBA", (side, side), (*tuple(color), 255))
    tile.putalpha(mask)
    cv.paste(tile, int(round(cx * SUP - side / 2)),        # rounded, never
             int(round(cy * SUP - side / 2)), tile)         # truncated (ICO-09)


def glyph(scale=MARK_SCALE):
    """components glyph signature; the mark's half-height = scale * r"""
    def fn(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        draw(cv, cx, cy, r=scale * r,
             color=tuple(color or colors.WHITE), alpha=alpha, rot=rot)
    return fn
