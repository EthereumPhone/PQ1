"""Download mark — pq1/assets/download_icon.svg as procedural art.

The mark the firmware-update flows wear inside the token (the device
taking a new firmware image onto itself): an arrow pointing down into a
tray — the SVG's one path (viewBox 36 x 36, two closed subpaths: the
tray bar, then the arrow whose shaft and head are one outline). The
path data is carried verbatim and flattened through geometry.svg_subpaths
into two polygons filled in an alpha mask, so the mark scales cleanly at
any radius and recolours like every vector glyph (icon_color — the
firmware family pins it BLACK on its white disc). Vector, never a
rasterized PNG: image art is for full-bleed logos only. glyph() returns
the components-registry signature; components.GLYPHS["download"] is
this art.
"""
import math

from PIL import Image, ImageDraw

from . import geometry
from .. import colors
from ..layout import SUP

W, H = 36.0, 36.0   # the SVG viewBox (the art spans x 6-30, y 3-33 — centred)
PATH = (
    # the tray bar
    "M7.49609 32.9995C6.66767 32.9995 5.99609 32.3279 5.99609 31.4995C5.99609 "
    "30.6711 6.66767 29.9995 7.49609 29.9995H28.4961C29.3245 29.9995 29.9961 "
    "30.6711 29.9961 31.4995C29.9961 32.3279 29.3245 32.9995 28.4961 "
    "32.9995H7.49609Z"
    # the arrow: shaft + head, one outline
    "M19.5748 24.9698C18.7741 25.9992 17.2181 25.9992 16.4174 24.9697L8.75138 "
    "15.1135C8.24049 14.4566 8.70859 13.4995 9.54073 13.4995H12.4961C13.0484 "
    "13.4995 13.4961 13.0518 13.4961 12.4995V4.99951C13.4961 3.89494 14.3915 "
    "2.99951 15.4961 2.99951H20.4961C21.6007 2.99951 22.4961 3.89494 22.4961 "
    "4.99951V12.4995C22.4961 13.0518 22.9438 13.4995 23.4961 13.4995H26.4515C27.2836 "
    "13.4995 27.7517 14.4566 27.2408 15.1135L19.5748 24.9698Z"
)
MARK_SCALE = 0.46   # half-height per glyph r — the box is 36, the art 30 of it,
                    # so the arrow reads at the fingerprint mark's height


PARTS = geometry.svg_subpaths(PATH)   # the tray, the arrow — in SVG units (x right, y down)


def draw(cv, cx, cy, *, r, color, alpha=1.0, rot=0.0):
    """the download mark, half-height r, its box centred on (cx, cy). True
    alpha compositing (components.base_mark's rationale): the mark sits on
    a disc, so a colour-scaled fill would read wrong while fading."""
    if alpha <= 0.01:
        return
    u = 2.0 * r * SUP / H                       # one SVG unit, supersampled px
    pad = 4
    side = int(math.ceil(math.hypot(W, H) * u)) + 2 * pad   # rotation never clips
    mask = Image.new("L", (side, side), 0)
    d = ImageDraw.Draw(mask)
    ox, oy = side / 2 - W / 2 * u, side / 2 - H / 2 * u     # the box, centred
    a = int(round(255 * alpha))
    for pts in PARTS:
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
