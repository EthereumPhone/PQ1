"""The chain marks — every supported EVM chain's logo as procedural art.

One module for the whole set, the way `marks.py` holds check / x /
exclamation together: a chain mark is not its own idea, it is one row of a
table. Each entry carries its SVG path data VERBATIM from
`reference/logos/<name>.svg` (24x24 viewBox, art centred on 12,12) and is
flattened once at import by `geometry.svg_outline`, which reads the whole
SVG command set — arcs, relative forms and the smooth curves these logos
use, none of which the older `geometry.svg_subpaths` can see.

Filling: subpaths XOR within one `<path>` element and union across
elements, so a counter reads as a hole (the O and P of the OP wordmark,
zkSync's chevrons) and Arbitrum's ring keeps its centre.

MARK_SCALE is an optical judgement per chain, not a constant — `op` and
`zksync` are wide and short and scale off their half WIDTH, the rest off
half height. Same reasoning as `rotate` / `fingerprint` sitting at 0.40
while the tall ether mark sits at 0.56.

Ethereum mainnet is deliberately absent: chain id 1 wears the existing
rounded-edge mark in `eth.py`, registered as GLYPHS["mainnet"].

API convention (pq1/procedural/__init__.py): draw(cv, cx, cy, *, r, color,
alpha=1.0, rot=0.0); glyph(name, scale) returns the components glyph
signature.
"""
import math

from PIL import Image, ImageChops, ImageDraw

from .. import colors
from ..layout import SUP
from . import geometry

W = H = 24.0   # every logo's viewBox; the art is centred on (12, 12)

MARKS = {   # name: (svg stem, MARK_SCALE, scale axis)
    "arbitrum": ("arbitrum", 0.52, "h"),   # an outlined mark reads lighter
    "avalanche": ("avalanche", 0.44, "w"),
    "base": ("base", 0.42, "h"),
    "bnb": ("bnb", 0.54, "h"),   # a cube of thin diamonds reads light
    "linea": ("linea", 0.42, "h"),
    "mantle": ("mantle", 0.54, "h"),
    "op": ("op", 0.52, "w"),
    "polygon": ("polygon", 0.46, "w"),
    "scroll": ("scroll", 0.44, "h"),
    "zksync": ("zksync", 0.52, "w"),
}

# Optical centring, in SVG units (y down), applied on top of the viewBox
# centre. A mark whose ink is lopsided sits wrong even when its bounding box is
# dead centre: Avalanche's "A" is bottom-heavy — a wide base under a point — so
# its centre of MASS measured a shade below the disc's. Measured, not eyeballed.
NUDGE = {
    "avalanche": (0.0, -2.05),
    "linea": (1.89, -1.29),     # the L's mass is all bottom-left of the dot
}

PATHS = {
    # reference/logos/arbitrum.svg
    "arbitrum": (
        ("m13.353 13.368-.885 2.39a.3.3 0 0 0 0 .205"
         "l1.523 4.112 1.76-1.001-2.113-5.706a.152.152 0 0 0-.285 0"
         "m1.774-4.019a.152.152 0 0 0-.285 0l-.885 2.39a.3.3 0 0 0 0 .205"
         "l2.494 6.732 1.761-1.001z",
         "nonzero"),
        ("M11.998 4.115a.3.3 0 0 1 .126.033l6.715 3.818"
         "a.25.25 0 0 1 .126.214v7.635c0 .089-.048.17-.126.214l-6.715 3.819"
         "a.25.25 0 0 1-.126.032.3.3 0 0 1-.125-.032l-6.715-3.815"
         "a.25.25 0 0 1-.126-.215V8.182c0-.089.048-.17.126-.215l6.715-3.818"
         "a.26.26 0 0 1 .125-.034m0-1.115c-.238 0-.478.06-.692.183L4.593 7"
         "A1.36 1.36 0 0 0 3.9 8.182v7.635c0 .487.264.938.693 1.181"
         "l6.714 3.819a1.41 1.41 0 0 0 1.386 0l6.714-3.818"
         "a1.36 1.36 0 0 0 .693-1.182V8.182A1.36 1.36 0 0 0 19.407 7"
         "l-6.716-3.817A1.4 1.4 0 0 0 11.998 3",
         "nonzero"),
        ("m7.559 18.685.617-1.666 1.244 1.018-1.163 1.046zm3.874-11.05H9.731"
         "a.3.3 0 0 0-.285.197l-3.649 9.852 1.761 1.001 4.018-10.849"
         "a.15.15 0 0 0-.143-.2",
         "nonzero"),
        ("M14.412 7.635h-1.703a.3.3 0 0 0-.284.197"
         "l-4.167 11.25 1.761 1 4.535-12.246a.15.15 0 0 0-.142-.2",
         "nonzero"),
    ),
    # reference/logos/avalanche.svg
    "avalanche": (
        ("M7.515 19.56H4.492c-.637 0-.952 0-1.142-.114"
         "a.7.7 0 0 1-.248-.245.7.7 0 0 1-.101-.327c-.012-.216.145-.475.46-1"
         "l7.47-12.461c.32-.53.484-.794.687-.891a.79.79 0 0 1 .697 0"
         "c.202.097.36.361.675.89l1.542 2.538.005.011"
         "c.253.36.454.75.596 1.16.085.325.085.676 0 1.005"
         "a4.7 4.7 0 0 1-.596 1.172l-3.926 6.567-.011.021"
         "a4.7 4.7 0 0 1-.766 1.08 2.4 2.4 0 0 1-.927.513"
         "c-.32.08-.676.08-1.392.08m7.647 0h4.33c.648 0 .968 0 1.16-.12"
         "a.7.7 0 0 0 .246-.244.7.7 0 0 0 .101-.327"
         "c.012-.21-.14-.459-.443-.951l-.034-.053-2.171-3.51-.023-.043"
         "c-.304-.487-.461-.735-.658-.832a.77.77 0 0 0-.692 0"
         "c-.202.097-.36.357-.675.874l-2.172 3.516v.011"
         "c-.32.517-.477.777-.466.988a.7.7 0 0 0 .102.329"
         "c.06.1.145.185.246.248.187.113.507.113 1.149.113",
         "nonzero"),
    ),
    # reference/logos/base.svg
    "base": (
        ("M3 4.706c0-.585 0-.877.11-1.101.106-.215.28-.39.496-.495"
         "C3.83 3 4.122 3 4.706 3h14.588"
         "c.585 0 .876 0 1.101.11.215.105.389.28.494.495.111.225.111.517.111 1.101"
         "v14.588"
         "c0 .585 0 .876-.11 1.101-.106.215-.28.389-.495.494-.225.111-.517.111-1.101.111"
         "H4.706c-.585 0-.876 0-1.101-.11a1.08 1.08 0 0 1-.494-.495"
         "C3 20.17 3 19.878 3 19.294z",
         "nonzero"),
    ),
    # reference/logos/bnb.svg
    "bnb": (
        ("M7.09 5.755 12 3l4.91 2.755-1.8 1.02L12 5.035l-3.105 1.74z"
         "m9.82 3.48-1.8-1.02L12 9.955l-3.105-1.74-1.805 1.02v2.035l3.1 1.74"
         "v3.475l1.81 1.02 1.805-1.02V13.01l3.105-1.74zm0 5.515v-2.04"
         "l-1.8 1.02v2.035zm1.285.72-3.105 1.735v2.04l4.91-2.76v-5.51"
         "l-1.805 1.015zM16.39 7.495l1.8 1.02v2.035L20 9.535v-2.04"
         "l-1.805-1.02L16.39 7.5zm-6.2 10.45v2.035L12 21l1.805-1.02v-2.03"
         "L12 18.965l-1.805-1.02zm-3.1-3.2 1.8 1.02V13.73l-1.8-1.02v2.04z"
         "m3.1-7.25L12 8.515l1.805-1.02L12 6.475 10.195 7.5z"
         "m-4.385 1.02 1.805-1.02-1.8-1.02L4 7.5v2.04l1.805 1.015zm0 3.475"
         "L4 10.975v5.51l4.91 2.76V17.2l-3.1-1.735v-3.48z",
         "nonzero"),
    ),
    # reference/logos/linea.svg
    "linea": (
        ("M17.633 21H3.478V5.921h3.238v12.157h10.917zm.001-12.159"
         "c1.595 0 2.889-1.307 2.889-2.92S19.229 3 17.633 3"
         "c-1.595 0-2.888 1.308-2.888 2.92 0 1.614 1.293 2.921 2.889 2.921",
         "nonzero"),
    ),
    # reference/logos/mantle.svg
    "mantle": (
        ("m12.928 6.082.461-2.975A9 9 0 0 0 12 3h-.005v6.075H12"
         "c.259 0 .506.034.754.096l.787-2.96a6 6 0 0 0-.613-.129"
         "m-2.39 3.387-1.52-2.605a6 6 0 0 0-.511.338L6.7 4.727"
         "a8.5 8.5 0 0 1 1.2-.743l1.378 2.683c.282-.14.563-.264.861-.36"
         "L9.204 3.44a9 9 0 0 1 1.373-.327l.484 3.027a5 5 0 0 0-.608.13"
         "l.788 2.907a2.7 2.7 0 0 0-.704.293M3.972 7.922l2.734 1.39"
         "c-.14.28-.265.562-.36.86l-2.914-.945q.219-.674.54-1.305"
         "m13.163 1.097-2.605 1.518c.13.22.225.45.293.698l2.908-.787"
         "q.085.303.13.607l3.025-.478a9 9 0 0 0-.331-1.378l-2.87.939"
         "a5.5 5.5 0 0 0-.354-.866l2.678-1.378a9 9 0 0 0-.737-1.198"
         "L16.798 8.5c.124.169.236.338.338.518m-2.368-5.586"
         "c.45.146.888.326 1.305.54L14.683 6.7a6 6 0 0 0-.855-.354z"
         "m.219 3.375-1.53 2.655c.225.13.427.281.607.467l4.287-4.303"
         "a9 9 0 0 0-1.07-.917L15.51 7.151a5 5 0 0 0-.523-.337z"
         "m-5.524 3.735-2.655-1.53a8 8 0 0 1 .343-.523L4.71 6.718"
         "c.281-.382.585-.742.917-1.069L9.93 9.936q-.272.27-.467.607"
         "m-3.251-.084 2.959.787a3 3 0 0 0-.096.754H3"
         "c0-.467.034-.94.112-1.395l2.97.461c.034-.202.08-.41.13-.607"
         "m11.081 4.23 2.734 1.39c.214-.423.393-.862.54-1.306l-2.914-.945"
         "c-.096.293-.22.585-.36.86m-3.825-.158 1.508 2.605"
         "q.271-.152.517-.338l1.806 2.475a8.5 8.5 0 0 1-1.198.743"
         "l-1.378-2.683a6 6 0 0 1-.867.36l.94 2.868"
         "c-.45.14-.912.253-1.379.326l-.478-3.026q.304-.043.608-.13"
         "l-.788-2.907q.373-.1.704-.293zm-6.604.45 2.605-1.518"
         "a2.7 2.7 0 0 1-.293-.698l-2.908.787a5 5 0 0 1-.13-.607l-3.026.478"
         "q.112.702.332 1.378l2.87-.94q.143.447.353.867L3.99 16.106"
         "c.214.416.461.821.737 1.198L7.202 15.5a5 5 0 0 1-.338-.518"
         "m2.368 5.586a9 9 0 0 1-1.305-.54L9.311 17.3q.422.21.86.354z"
         "m-.219-3.375 1.53-2.655a3 3 0 0 1-.607-.462L5.649 18.38"
         "c.332.326.692.635 1.07.91l1.771-2.435q.253.178.523.338"
         "m5.524-3.735 2.65 1.53a5 5 0 0 1-.338.529l2.435 1.766"
         "q-.413.575-.91 1.074l-4.304-4.292q.272-.27.467-.607"
         "m-3.29 1.372-.788 2.96c.202.055.405.095.613.128l-.461 2.976"
         "a9 9 0 0 0 1.389.107h.006v-6.075H12a3 3 0 0 1-.754-.096"
         "m3.582-2.075a3 3 0 0 0 .096-.754H21c0 .467-.034.94-.113 1.395"
         "l-2.97-.461a7 7 0 0 1-.129.607z",
         "nonzero"),
    ),
    # reference/logos/op.svg
    "op": (
        ("M3.966 15.8"
         "q.979.7 2.512.7 1.854 0 2.962-.838 1.108-.85 1.559-2.562.27-1.05.464-2.163.063-.398.064-.663 0-.874-.451-1.499"
         "a2.7 2.7 0 0 0-1.237-.95Q9.053 7.5 8.062 7.5q-3.644 0-4.52 3.437"
         "a40 40 0 0 0-.477 2.163q-.058.335-.065.674 0 1.314.966 2.026"
         "m4.65-2.775"
         "c-.247.957-.926 1.58-1.958 1.58-1.02 0-1.368-.69-1.184-1.58"
         "a27 27 0 0 1 .464-2.05"
         "c.265-1.034.89-1.58 1.956-1.58 1.017 0 1.348.68 1.173 1.58"
         "a30 30 0 0 1-.451 2.05m3.902 3.385q.076.09.214.089h1.704"
         "a.38.38 0 0 0 .238-.089.36.36 0 0 0 .138-.232l.538-2.52h1.733"
         "c1.094 0 1.95-.53 2.576-1.002"
         "q.953-.707 1.266-2.186.075-.348.075-.67 0-1.117-.851-1.71-.84-.591-2.23-.591"
         "h-3.333a.38.38 0 0 0-.238.09.38.38 0 0 0-.138.232l-1.73 8.356"
         "a.3.3 0 0 0 .038.232m6.09-5.966c-.157.689-.757 1.319-1.462 1.319"
         "h-1.44l.496-2.369h1.503c.512 0 .94.102.94.665q0 .165-.037.385",
         "evenodd"),
    ),
    # reference/logos/polygon.svg
    "polygon": (
        ("m16.364 15.217 4.27-2.435a.73.73 0 0 0 .366-.627V7.284"
         "a.72.72 0 0 0-.366-.627l-4.27-2.435a.74.74 0 0 0-.732 0"
         "l-4.27 2.435a.72.72 0 0 0-.366.627v8.704l-2.994 1.707-2.994-1.707"
         "v-3.415l2.994-1.707 1.974 1.127V9.702l-1.608-.918"
         "a.75.75 0 0 0-.732 0l-4.27 2.435a.72.72 0 0 0-.366.627v4.87"
         "c0 .258.14.498.366.627l4.27 2.436a.75.75 0 0 0 .732 0l4.27-2.436"
         "a.72.72 0 0 0 .366-.626V8.012l.053-.03 2.94-1.677 2.994 1.707"
         "v3.415l-2.994 1.707-1.972-1.124v2.291l1.606.916"
         "a.75.75 0 0 0 .732 0z",
         "nonzero"),
    ),
    # reference/logos/scroll.svg
    "scroll": (
        ("M5.247 9.971C4.55 9.317 4.07 8.466 4.07 7.462v-.109"
         "c.066-1.702 1.462-3.098 3.164-3.142H18.12c.284.022.502.219.502.502"
         "v9.229c.24.044.371.087.611.153.196.065.458.218.458.218v-9.6"
         "a1.597 1.597 0 0 0-1.592-1.57H7.233A4.31 4.31 0 0 0 3 7.462"
         "c0 1.374.633 2.552 1.636 3.359.066.066.131.13.328.13.327 0 .545-.261.523-.523 0-.24-.087-.327-.24-.458",
         "nonzero"),
        ("M17.836 14.552h-8.53A1.03 1.03 0 0 0 8.28 15.6v1.222"
         "c.021.567.501 1.047 1.069 1.047h.632v-1.047H9.35v-1.2h.349"
         "c1.069 0 1.876 1.003 1.876 2.072 0 .96-.873 2.16-2.313 2.073-1.287-.087-1.985-1.222-1.985-2.073"
         "V7.287a.866.866 0 0 0-.85-.85h-.852v1.069h.633v10.21"
         "c-.044 2.073 1.483 3.12 3.054 3.12l8.596.022"
         "A3.143 3.143 0 0 0 21 17.716c-.022-1.767-1.418-3.164-3.164-3.164"
         "m2.073 3.208a2.09 2.09 0 0 1-2.073 2.007l-5.977-.022"
         "c.48-.545.763-1.265.763-2.05 0-1.223-.72-2.074-.72-2.074h5.956"
         "c1.135 0 2.073.939 2.073 2.073zM15.545 7.68H9.107V6.61h6.436"
         "a.53.53 0 0 1 .524.524c0 .306-.218.546-.524.546",
         "nonzero"),
        ("M15.545 12.698H9.107v-1.069h6.436a.53.53 0 0 1 .524.524"
         "c0 .305-.218.545-.524.545m1.137-2.509H9.107v-1.07h7.571"
         "a.536.536 0 0 1 0 1.07",
         "nonzero"),
    ),
    # reference/logos/zksync.svg
    "zksync": (
        ("m21 12-5.106-4.498v3.296l-5.07 3.298 5.07.002V16.5zM3 12l5.106 4.5"
         "v-3.263l5.034-3.3-5.032-.002V7.5z",
         "evenodd"),
    ),
}


# flattened once at import: name -> [ [subpath, ...] per <path> element ]
SHAPES = {n: [geometry.svg_outline(d) for d, _rule in ps]
          for n, ps in PATHS.items()}
# name -> (width, height) of the art's bounding box, in SVG units
_SPAN = {}
for _n, _elems in SHAPES.items():
    _pts = [p for _s in _elems for _sub in [_s] for _sp in _sub for p in _sp]
    _SPAN[_n] = (max(x for x, _ in _pts) - min(x for x, _ in _pts),
                 max(y for _, y in _pts) - min(y for _, y in _pts))


def _mask(name, side, u, alpha):
    """the mark as an L mask on a `side` square, one SVG unit = u px"""
    m = Image.new("L", (side, side), 0)
    nx, ny = NUDGE.get(name, (0.0, 0.0))   # optical centring (see NUDGE)
    ox = side / 2 - 12.0 * u + nx * u      # the 24-unit box, centred
    oy = side / 2 - 12.0 * u + ny * u
    a = int(round(255 * alpha))
    for subs in SHAPES[name]:              # one entry per <path> element
        layer = Image.new("L", (side, side), 0)
        for pts in subs:                   # subpaths XOR -> counters read as holes
            one = Image.new("L", (side, side), 0)
            ImageDraw.Draw(one).polygon(
                [(ox + x * u, oy + y * u) for x, y in pts], fill=a)
            layer = ImageChops.difference(layer, one)
        m = ImageChops.lighter(m, layer)   # elements union
    return m


def draw(cv, cx, cy, *, name, r, color, alpha=1.0, rot=0.0):
    """a chain mark, half-extent r on its dominant axis, centred on (cx, cy).
    True alpha compositing (components.base_mark's rationale): the mark sits
    on a coloured disc, so a colour-scaled fill would read wrong while fading."""
    if alpha <= 0.01:
        return
    scale, axis = MARKS[name][1], MARKS[name][2]
    span = _SPAN[name][0 if axis == "w" else 1]
    u = 2.0 * r * SUP / span               # one SVG unit, supersampled px
    pad = 4
    side = int(math.ceil(math.hypot(W, H) * u)) + 2 * pad   # rotation never clips
    mask = _mask(name, side, u, alpha)
    if rot:
        mask = mask.rotate(-math.degrees(rot), resample=Image.BICUBIC)
    tile = Image.new("RGBA", (side, side), (*tuple(color), 255))
    tile.putalpha(mask)
    cv.paste(tile, int(cx * SUP - side / 2), int(cy * SUP - side / 2), tile)


def glyph(name, scale=None):
    """components glyph signature; the mark's half-extent = scale * r"""
    k = MARKS[name][1] if scale is None else scale

    def fn(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        draw(cv, cx, cy, name=name, r=k * r,
             color=tuple(color or colors.WHITE), alpha=alpha, rot=rot)
    return fn


NAMES = tuple(MARKS)
