"""Fingerprint mark — pq1/assets/fingerprint.svg as procedural art.

The mark the fingerprint flows wear inside the token: three ridges of a
fingerprint (the SVG's one path, viewBox 32 x 32, three closed subpaths —
the outer, middle and inner ridge, disjoint bands, so the SVG's evenodd
rule and a plain fill agree). The path data is carried verbatim and
flattened through geometry.svg_subpaths into three polygons filled in an
alpha mask, so the mark scales cleanly at any radius and recolours like
every vector glyph (icon_color — the fingerprint family pins it BLACK on
its white disc). Vector, never a rasterized PNG: image art is for
full-bleed logos only. glyph() returns the components-registry signature;
components.GLYPHS["fingerprint"] is this art.
"""
import math

from PIL import Image, ImageDraw

from . import geometry
from .. import colors
from ..layout import SUP

W, H = 32.0, 32.0   # the SVG viewBox
PATH = (
    # the outer ridge
    "M7.82689 2.26027C-2.21832 9.02179 -2.67731 22.9588 6.93013 29.4728C9.38923 "
    "31.1413 9.38476 31.0922 6.62638 26.1656C3.35428 20.3199 3.03824 14.8539 "
    "5.70617 10.2409C8.15633 6.00653 14.0584 3.10418 18.2898 4.053C22.2933 "
    "4.95165 27.0943 9.72998 27.9274 13.6473C29.0385 18.8704 29.4607 19.655 "
    "30.8834 19.1407C32.8623 18.4256 32.0873 11.777 29.5321 7.56434C25.1232 "
    "0.294197 14.5766 -2.28314 7.82689 2.26027Z"
    # the middle ridge
    "M10.8354 8.62492C7.26516 11.1783 5.56881 17.4084 7.1278 22.2358C9.01735 "
    "28.0815 12.467 32 15.7235 32C16.8328 32 17.4304 30.698 16.7072 "
    "29.8568L15.1003 27.988C8.99055 20.8821 9.11339 12.4088 15.3359 "
    "11.6755C19.5327 11.1806 21.6691 13.2527 21.6691 17.8212C21.6691 20.2001 "
    "22.682 22.7991 24.3906 24.8085C26.9256 27.7884 27.2417 27.8797 28.9883 "
    "26.1246C30.7427 24.3615 30.7114 24.1562 28.5003 22.9474C27.0552 22.1582 "
    "26.1361 20.5411 26.1361 18.7883C26.1361 15.0272 23.3163 9.56234 20.6137 "
    "8.08551C17.5572 6.4148 13.6217 6.63148 10.8354 8.62492Z"
    # the inner ridge
    "M14.275 15.4127C13.3727 17.8132 16.6705 26.5933 19.4344 29.1478C20.6964 "
    "30.3145 22.3682 30.8299 23.4804 30.3943C25.1332 29.7465 24.9758 29.2265 "
    "22.2353 26.307C20.4831 24.4391 18.8001 21.0954 18.4249 18.7358C17.7046 "
    "14.2118 15.4152 12.378 14.275 15.4127Z"
)
MARK_SCALE = 0.40   # half-height per glyph r — a square mark reads heavier
                    # than the tall ether mark (rotate.MARK_SCALE, the same)

RIDGES = geometry.svg_subpaths(PATH)   # the three ridges, SVG units (y down)


def draw(cv, cx, cy, *, r, color, alpha=1.0, rot=0.0):
    """the fingerprint mark, half-height r, its box centred on (cx, cy).
    True alpha compositing (components.base_mark's rationale): the mark
    sits on a disc, so a colour-scaled fill would read wrong while fading."""
    if alpha <= 0.01:
        return
    u = 2.0 * r * SUP / H                       # one SVG unit, supersampled px
    pad = 4
    side = int(math.ceil(math.hypot(W, H) * u)) + 2 * pad   # rotation never clips
    mask = Image.new("L", (side, side), 0)
    d = ImageDraw.Draw(mask)
    ox, oy = side / 2 - W / 2 * u, side / 2 - H / 2 * u     # the box, centred
    a = int(round(255 * alpha))
    for pts in RIDGES:
        d.polygon([(ox + x * u, oy + y * u) for x, y in pts], fill=a)
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
