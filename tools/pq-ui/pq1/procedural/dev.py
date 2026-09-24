"""Dev mark — pq1/assets/dev_icon.svg as procedural art.

The mark the ERC-7730 flows wear inside the intro token: code brackets
around a slash, ‹/› (the SVG's three paths, viewBox 37 x 24, one closed
subpath each). The path data is carried verbatim and flattened through
geometry.svg_subpaths into three polygons filled in an alpha mask, so the
mark scales cleanly at any radius and recolours like every vector glyph
(icon_color). Vector, never a rasterized PNG: image art is for full-bleed
logos only. glyph() returns the components-registry signature;
components.GLYPHS["dev"] is this art.
"""
import math

from PIL import Image, ImageDraw

from . import geometry
from .. import colors
from ..layout import SUP

W, H = 37.0, 24.0   # the SVG viewBox
PATH = (
    # the slash
    "M21.437 0C22.1044 0 22.5901 0.637544 22.4166 1.28612L16.5431 "
    "23.2446C16.4239 23.6904 16.0221 24 15.5635 24C14.8961 23.9999 14.4106 "
    "23.3626 14.584 22.7141L20.4575 0.755356C20.5768 0.309716 20.9783 "
    "3.11023e-05 21.437 0Z"
    # the right bracket
    "M24.472 6.76182C24.4721 5.93395 25.3409 5.39798 26.074 5.77368L36.3064 "
    "11.0183C36.7319 11.2363 37 11.6761 37 12.1566C37 12.637 36.7319 13.077 "
    "36.3064 13.2951L26.074 18.5394C25.3409 18.9152 24.4721 18.3794 24.472 "
    "17.5515C24.472 17.1256 24.7144 16.7373 25.0956 16.5524L34.0042 "
    "12.2333V12.0798L25.0956 7.76069C24.7144 7.57583 24.472 7.18766 24.472 "
    "6.76182Z"
    # the left bracket
    "M10.926 5.59746C11.6591 5.22184 12.5279 5.75776 12.528 6.5856C12.528 "
    "7.01147 12.2854 7.39963 11.9042 7.58447L2.99579 11.9036V12.0571L11.9042 "
    "16.3762C12.2854 16.561 12.528 16.9494 12.528 17.3753C12.5279 18.2031 "
    "11.6591 18.7389 10.926 18.3632L0.693362 13.1188C0.267899 12.9008 0 "
    "12.4608 0 11.9803C3.57212e-05 11.4999 0.267932 11.0601 0.693362 "
    "10.842L10.926 5.59746Z"
)
MARK_SCALE = 0.52   # half-WIDTH per glyph r — the mark is wide (37 x 24),
                    # so its width, not its height, sets the optics

SHAPES = geometry.svg_subpaths(PATH)   # slash + brackets, SVG units (y down)


def draw(cv, cx, cy, *, r, color, alpha=1.0, rot=0.0):
    """the dev mark, half-width r, its box centred on (cx, cy). True alpha
    compositing (components.base_mark's rationale): the mark sits on a disc,
    so a colour-scaled fill would read wrong while fading."""
    if alpha <= 0.01:
        return
    u = 2.0 * r * SUP / W                       # one SVG unit, supersampled px
    pad = 4
    side = int(math.ceil(math.hypot(W, H) * u)) + 2 * pad   # rotation never clips
    mask = Image.new("L", (side, side), 0)
    d = ImageDraw.Draw(mask)
    ox, oy = side / 2 - W / 2 * u, side / 2 - H / 2 * u     # the box, centred
    a = int(round(255 * alpha))
    for pts in SHAPES:
        d.polygon([(ox + x * u, oy + y * u) for x, y in pts], fill=a)
    if rot:
        mask = mask.rotate(-math.degrees(rot), resample=Image.BICUBIC)
    tile = Image.new("RGBA", (side, side), (*tuple(color), 255))
    tile.putalpha(mask)
    cv.paste(tile, int(cx * SUP - side / 2), int(cy * SUP - side / 2), tile)


def glyph(scale=MARK_SCALE):
    """components glyph signature; the mark's half-width = scale * r"""
    def fn(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        draw(cv, cx, cy, r=scale * r,
             color=tuple(color or colors.WHITE), alpha=alpha, rot=rot)
    return fn
