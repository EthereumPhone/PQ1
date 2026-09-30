"""PQ1 components — the reusable pieces every screen is built from.

All functions take a pq1.canvas.Canvas as their first argument and UI-pixel
coordinates. The token is the centrepiece: a solid fill + white ring for a
KNOWN token, or the gradient disc reserved for UNKNOWN tokens (see
pq1.colors). A glyph inside the token is a traced vector mark
(pq1/procedural — the ether mark is the default and the fallback), a
popular token's full-bleed logo art, or the monogram.
"""
import functools
import math
import os

from PIL import Image, ImageChops, ImageDraw

from . import colors, motion, typography
from .procedural.marks import base_mark, check, dots, exclamation, minus, plus, x_mark  # noqa: F401
from .procedural import blind as blind_mark
from .procedural import chains as chain_marks
from .procedural import dev as dev_mark
from .procedural import download as download_mark
from .procedural import eth as eth_logo
from .procedural import fingerprint as fingerprint_mark
from .procedural import rotate as rotate_mark
from .layout import (BASELINE_Y, CENTER_X, CHEV_LEFT, CHEV_RIGHT, GO_BACK_CX, STROKE, SUP,
                     VIEW_MORE_CX)

ASSET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")


# ------------------------------------------------------ unknown-token disc --
R_MASTER = 30.0   # master-tile radius (= layout.CIRCLE_R); discs resize from it


@functools.lru_cache(maxsize=None)
def _master_tile(ramp):
    """supersampled gradient square for one placeholder ramp at R_MASTER
    (the only per-pixel pass; one tile per ramp, ever)"""
    s = SUP
    r = R_MASTER
    size = int(math.ceil(2 * r * s))
    stops = colors.ramp_stops(ramp)
    tile = Image.new("RGB", (size, size), colors.BLACK)
    tp = tile.load()
    # projection axis matches the CSS gradient (-0.8r,-r) -> (0.8r,r)
    ax, ay = 1.6 * r * s, 2.0 * r * s
    den = ax * ax + ay * ay
    for y in range(size):
        for x in range(size):
            u = ((x - (size / 2 - 0.8 * r * s)) * ax +
                 (y - (size / 2 - 1.0 * r * s)) * ay) / den
            tp[x, y] = colors.grad_color(u, stops)
    return tile


@functools.lru_cache(maxsize=256)
def _gradient_tile(ramp, r):
    """disc tile + ellipse mask at radius r: the ramp's master tile resized
    (the gradient pattern is scale-invariant) with an exact ellipse mask —
    no radius quantizing (the qubit film animates r through dozens of
    values; resizing keeps a cache miss cheap). Re-verified 2026-08: even
    self-consistent 0.25 px quantizing (tile+mask+offset together) measures
    up to 62/255 at the disc edge — keep radii exact."""
    size = int(math.ceil(2 * r * SUP))
    tile = _master_tile(ramp).resize((size, size), Image.LANCZOS)
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).ellipse([0, 0, size - 1, size - 1], fill=255)
    return tile, mask


def unknown_disc(cv, cx, cy, r, ramp, alpha=1.0):
    """the unknown-token treatment: a gradient disc on one placeholder ramp
    (dark top-left -> bright bottom-right). ramp comes from token_ramp() so
    the same unknown token always wears the same gradient. alpha fades the
    disc toward the black background (a scaled copy of the cached mask)."""
    s = SUP
    tile, mask = _gradient_tile(ramp, r)
    if alpha < 1.0:
        mask = mask.point(lambda v: int(v * alpha))
    cv.paste(tile, int(round((cx - r) * s)), int(round((cy - r) * s)), mask)


# --------------------------------------------------------------- logo art --
# Image art is full-bleed LOGO art only (safe, cowswap, usdc, dai, tether):
# a mark is always traced vector art in pq1/procedural — the raster ether
# mark that used to live here, recoloured white from a PNG, is gone (audit
# ICO-02): it was a second Ethereum at a second size and ignored icon_color.
_IMAGES = {}      # path -> decoded RGBA
_SIZED = {}       # (path, size) -> resized RGBA


def _load_rgba(path):
    if path not in _IMAGES:
        if os.path.exists(path):
            _IMAGES[path] = Image.open(path).convert("RGBA")
        else:
            _IMAGES[path] = Image.new("RGBA", (2, 2), (0, 0, 0, 0))
    return _IMAGES[path]


def _sized(path, size):
    key = (path, size)
    if key not in _SIZED:
        _SIZED[key] = _load_rgba(path).resize((size, size), Image.LANCZOS)
    return _SIZED[key]


def circle_image(cv, path, cx, cy, r, alpha=1.0, rot=0.0):
    """image fitted and circular-masked to the token circle (avatar/logo);
    square or circular art both work"""
    if alpha <= colors.ALPHA_FLOOR:
        return
    size = max(2, int(2 * r * SUP))
    im = _sized(path, size)
    if rot:
        im = im.rotate(-math.degrees(rot), resample=Image.BICUBIC)
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).ellipse([0, 0, size - 1, size - 1], fill=255)
    mask = ImageChops.multiply(mask, im.getchannel("A"))
    if alpha < 1:
        mask = mask.point(lambda v: int(v * alpha))
    cv.paste(im, int(cx * SUP - size / 2), int(cy * SUP - size / 2), mask)


# ------------------------------------------------------------- the monogram --
MONOGRAM_SCALE = 1.34   # cap height ~= a chain mark's, so a letter disc and a
#                         mark disc carry the same weight in a walk


@functools.lru_cache(maxsize=256)
def _ink(f, ch):
    """the inked box of `ch` drawn at the origin with anchor "ls" — measured
    from pixels, because font.getbbox counts the pen origin as ink and so
    misses the left side bearing"""
    x0, y0, x1, y1 = f.getbbox(ch, anchor="ls")
    pad = 2
    im = Image.new("L", (int(x1 - x0) + 2 * pad, int(y1 - y0) + 2 * pad), 0)
    ImageDraw.Draw(im).text((pad - x0, pad - y0), ch, font=f, fill=255,
                            anchor="ls")
    b = im.getbbox() or (pad, pad, pad, pad)
    return (b[0] - pad + x0, b[1] - pad + y0, b[2] - pad + x0, b[3] - pad + y0)


def monogram(letter):
    """glyph function drawing the first letter of a symbol.

    BOLD: unlike every other caption on the device this letter stands alone as
    a disc's entire content — an unknown chain's initial (pq1.chains) or a
    long-tail token's (token_defaults) — so it
    carries the weight a mark would, not the weight of running text. Drawn
    through base_mark like every mark that rests on a disc (audit ICO-01):
    the letter sits on a solid hashed-ramp fill, where a colour-scaled glyph
    would fade as a dark shape mid-morph.

    CENTRED ON THE INK, not the font's line box: anchor "mm" sat a capital
    ~0.1 r low and shifted it by its side bearings. The letter's ink is
    centred across, and the cap height (not the letter's own box, so a Q's
    tail never lifts it) is centred down."""
    ch = (letter or "?")[0].upper()

    def draw(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        f = typography.font(MONOGRAM_SCALE * r, "bold")
        x0, x1 = _ink(f, ch)[::2]
        cap = -_ink(f, "H")[1]

        def paint(d, ox, oy, R, a):
            d.text((ox - (x0 + x1) / 2, oy + cap / 2), ch, font=f, fill=a,
                   anchor="ls")
        base_mark(cv, paint, cx, cy, r, color, alpha, rot)
    return draw


# ---------------------------------------------------------- glyph registry --
_ETHER = eth_logo.glyph()   # THE Ethereum mark (audit ICO-02) — the rounded-edge
#                             logo traced in pq1/procedural/eth.py, at LOGO_SCALE
GLYPHS = {
    "eth": _ETHER,        # the schema default and the fallback (DESIGN.md § Components)
    "mainnet": _ETHER,    # chain id 1 — the same art under the chain family's name
    # the chain marks — every network the device can name, traced from its
    # logo (pq1/procedural/chains.py). Registered EAGERLY here, never from a
    # flow package: the legal icon set the handoff spec publishes must not
    # depend on which flows happened to be imported (audit G17-07). Ethereum
    # mainnet is not in the set — chain id 1 wears "mainnet" above.
    **{n: chain_marks.glyph(n) for n in chain_marks.NAMES},
    "blind": blind_mark.glyph(),  # blind-signing mark (assets/blind_icon.svg traced)
    "dev": dev_mark.glyph(),  # ERC-7730 intro mark (assets/dev_icon.svg traced)
    "rotate": rotate_mark.glyph(),  # slot-rotation mark (assets/rotate_icon.svg traced)
    "fingerprint": fingerprint_mark.glyph(),  # digest mark (assets/fingerprint.svg traced)
    "download": download_mark.glyph(),  # firmware-update mark (assets/download_icon.svg traced)
    "check": check,
    "x": x_mark,
    "exclamation": exclamation,
    "dots": dots,        # the 3 x 3 dot grid — the setup family's mark
    "plus": plus,        # the entry signs beside the corner chevrons
    "minus": minus,
}


LETTER_PREFIX = "letter:"   # an unknown chain (pq1.chains) or a long-tail
#                             token (token_defaults) wears its initial


@functools.lru_cache(maxsize=64)
def _letter_glyph(ch):
    """the monogram glyph for one character, built once.

    Deliberately NOT a GLYPHS entry: the registry is dumped as the legal icon
    set the handoff spec publishes (introspect.screens_schema), so registering
    letters lazily at draw time would make that set depend on what had been
    rendered first — the same import-order trap warm_registries() exists to
    close (audit G17-07). The namespace is published instead; the dict stays
    a constant."""
    return monogram(ch)


def letter_glyph(name):
    """the glyph for a "letter:X" name, or None if this is not one"""
    if isinstance(name, str) and name.startswith(LETTER_PREFIX):
        ch = name[len(LETTER_PREFIX):]
        if len(ch) == 1:
            return _letter_glyph(ch.upper())
    return None


def register_glyph(name, fn):
    GLYPHS[name] = fn


def resolve_glyph(icon=None, logo=None, symbol=None):
    """glyph lookup: named icon -> image logo -> the symbol's monogram"""
    if icon and icon in GLYPHS:
        return GLYPHS[icon]
    fn = letter_glyph(icon)
    if fn is not None:
        return fn
    if logo:
        path = logo if os.path.isabs(logo) else os.path.join(ASSET_DIR, logo)
        if os.path.exists(path):
            # full-bleed art fills the token's VISIBLE disc (r - TOKEN_INSET —
            # the solid disc's and the trail circles' radius), never the
            # layout radius: the token is exactly the size of its trail
            return lambda cv, cx, cy, r, alpha=1.0, color=None, rot=0.0: \
                circle_image(cv, path, cx, cy, visible_r(r), alpha, rot)
    if symbol:
        return monogram(symbol)
    return monogram("?")


def glyph(cv, name, cx, cy, r, alpha=1.0, color=None, rot=0.0):
    """draw a registered glyph.

    A "letter:X" name draws that initial — an unknown CHAIN says which network
    it is rather than borrowing another one's mark (pq1.chains). Any other
    unregistered name still falls back to the ether mark, which stays the
    deliberate answer for art the device genuinely lacks (DESIGN.md,
    Components; tools/check F-ICON keeps it from ever answering a typo)."""
    fn = letter_glyph(name) or GLYPHS.get(name, GLYPHS["eth"])
    fn(cv, cx, cy, r, alpha=alpha, color=color, rot=rot)


def same_art(a, b):
    """do two glyph names draw the same function — one mark under two names
    ("eth" and "mainnet")? Then a morph between them draws it once at full
    alpha instead of dipping through no glyph at the midpoint (token)."""
    if a == b:
        return True
    return (a is not None and b is not None and
            (letter_glyph(a) or GLYPHS.get(a)) is (letter_glyph(b) or GLYPHS.get(b)))


# ------------------------------------------------------ token logo assets --
# Popular tokens whose logo ships in pq1/assets/ (400x400 RGBA, the art
# full-bleed like safe.png / cowswap.png): the disc WEARS the art, on the
# mono trail. token_defaults(symbol) is the one switch point between that
# look and the placeholder ramp. ETH is not listed: its identity is the
# white ether mark on the mono body (GLYPHS["eth"], the SEND flow). A new logo:
# rasterize the SVG to a 400x400 PNG (flow-builder skill § Token logos),
# drop it in pq1/assets/, add one row.
TOKEN_LOGOS = {"USDC": "usdc", "USDT": "tether", "DAI": "dai"}   # symbol -> glyph / file stem


def register_logo(name, file):
    """register full-bleed logo art (pq1/assets/<file>) as glyph `name`,
    flagged as art (is_art) so the hold film rises OVER it"""
    fn = resolve_glyph(logo=file)
    fn.full_bleed = os.path.exists(file if os.path.isabs(file)
                                   else os.path.join(ASSET_DIR, file))
    register_glyph(name, fn)
    return fn


def is_art(name):
    """does glyph `name` fill the disc with image art (a logo)?"""
    return bool(getattr(GLYPHS.get(name), "full_bleed", False))


for _sym, _stem in TOKEN_LOGOS.items():
    register_logo(_stem, _stem + ".png")


def token_icon(symbol):
    """the glyph name of a token's logo art when the symbol is in
    TOKEN_LOGOS, else None (the placeholder treatment applies)"""
    return TOKEN_LOGOS.get((symbol or "").upper())


ETHER_SYMBOLS = ("ETH", "WETH")   # ether and its ERC-20 wrapper wear the ether mark


def token_defaults(symbol):
    """a flow's DEFAULTS for the token it signs for — the ONE switch point
    between the recognized looks and the placeholder (DESIGN.md § Color):
    a symbol in TOKEN_LOGOS wears its logo art under a WHITE edge stroke
    (the explicit ring: flush at the disc edge, over the art — the same
    stroke every token circle carries, the mono body's default ring made
    explicit; user rule, Sep 2026) on a trail in the token's own colour
    (colors.TOKEN_GRADIENTS, pinned by symbol — the mono trail when no ramp
    is registered), ETH / WETH the white ether mark on the mono body (its
    default white ring), any other symbol its INITIAL — the Bold monogram,
    the "letter:X" namespace an unknown chain answers with — on the SOLID
    placeholder disc + trail hashed from the symbol (token_ramp): a long-tail
    token names itself rather than borrowing the ether mark (user rule, Sep
    2026). A symbol with no letter or digit to show keeps the ether mark, so
    the disc is never empty. One flow serves every token on device; a flow's
    SAMPLES cycle the popular tokens through its example renders."""
    sym = (symbol or "").upper()
    icon = token_icon(sym)
    if icon:
        palette = sym if sym in colors.TOKEN_GRADIENTS else colors.MONO_RAMP
        return dict(icon=icon, token=dict(palette=palette, ring=list(colors.WHITE)))
    if sym in ETHER_SYMBOLS:
        return dict(icon="eth", token=dict(palette=colors.MONO_RAMP))
    initial = sym[:1]
    icon = LETTER_PREFIX + initial if initial.isalnum() else "eth"
    return dict(icon=icon, token=dict(palette=symbol))


# ------------------------------------------------------------------- token --
TOKEN_RING_W = STROKE["ring"]   # the token ring — the "ring" weight of layout.STROKE
TOKEN_INSET = 1.2    # disc, ring AND full-bleed art sit inside the layout radius
                     # by this much; the token's VISIBLE edge is r - TOKEN_INSET —
                     # the trail circles' exact radius (the top circle is never
                     # bigger than its trail; user rule, Sep 2026)



def visible_r(r):
    """the token's VISIBLE edge for a layout radius r: r - TOKEN_INSET.

    One rule decides which radius a component measures from (audit RAD-09):
    anything that IS the token — its disc, its ring, full-bleed art, the
    trail links — sits at visible_r(r); anything that LEAVES it — the pulse
    rings, the resolve flash, the handoff wash, a branded flush resting
    ring — measures from the layout radius r."""
    return r - TOKEN_INSET

def token(cv, cx, cy, r, *, variant="solid", fill=None, ring_color=None,
          ring_w=TOKEN_RING_W, inset=TOKEN_INSET, glyph_a=None, glyph_b=None,
          mix=1.0, ramp=None, glyph_color=None, alpha=1.0, hold=None):
    """The main token circle.

    variant "solid"   — solid fill + ring. EVERY live token, recognized or
                        not (the default, and what token_style_from_spec
                        resolves); an unknown token's fill is simply the
                        ramp hashed from its identity.
    variant "unknown" — gradient disc + ring, coloured by the placeholder
                        ramp index `ramp` (neutral grey if None). RESERVED:
                        no flow and no library screen asks for it and a port
                        must not implement it (audit A11-12, Sep 2026).
    glyph_a/glyph_b/mix crossfade the inner glyph during transitions.

    The default white ring sits UNDER the glyph, so full-bleed logo art
    (circle_image at the visible radius r - inset, the trail circles' size)
    covers it. An explicit ring_color is a deliberate stroke and draws OVER
    the glyph, flush at that same visible edge, stroking inward (cv.ring) —
    the popular tokens' white stroke on their art, the SAFE token's black
    edge stroke on its #13FF7F logo art. alpha fades the whole token toward the black
    background (the flow's alpha idiom); 1.0 draws exactly as before.

    hold — the hold gesture's progress fill (DESIGN.md § Input), a dict
    (k, placement, color, alpha) from hold_style + motion.hold_fill: a
    see-through liquid rising in the disc from the bottom to level k.
    placement "under" pours it beneath the ring and the glyph (the white
    film inside a black body); "over" lays it over the art and the glyph,
    up to the ring's inner edge (the black film over a coloured body).
    """
    over = ring_color is not None
    fill = fill if fill is not None else colors.BLACK
    ring_color = ring_color if over else colors.WHITE
    if alpha < 1.0:
        fill, ring_color = colors.scale(fill, alpha), colors.scale(ring_color, alpha)
    cv.circle(cx, cy, r - inset, colors.BLACK if variant == "unknown" else fill)
    if variant == "unknown":
        unknown_disc(cv, cx, cy, r - inset,
                     colors.NEUTRAL_RAMP if ramp is None else ramp, alpha)
    if hold and hold["placement"] == "under":
        hold_flood(cv, cx, cy, r - inset, hold["k"], hold["color"], hold["alpha"])
    if not over:
        cv.ring(cx, cy, r - inset, ring_color, ring_w)
    if glyph_a is not None or glyph_b is not None:
        ga = glyph_a if glyph_a is not None else glyph_b
        gb = glyph_b if glyph_b is not None else glyph_a
        if same_art(ga, gb):
            glyph(cv, gb, cx, cy, r, alpha, color=glyph_color)
        else:
            glyph(cv, ga, cx, cy, r, alpha * max(0.0, 1 - mix * 2), color=glyph_color)
            glyph(cv, gb, cx, cy, r, alpha * max(0.0, mix * 2 - 1), color=glyph_color)
    if hold and hold["placement"] == "over":   # over the art, up to the ring's inner edge
        if is_art(glyph_b if glyph_b is not None else glyph_a) and not over:
            fr = r - inset                         # full-bleed art, no ring: to its edge
        else:
            fr = r - inset - ring_w                # the ring's inner edge (default or explicit)
        hold_flood(cv, cx, cy, fr, hold["k"], hold["color"], hold["alpha"])
    if over:                                       # flush at the visible edge, over the art
        cv.ring(cx, cy, r - inset, ring_color, ring_w)


def token_ramp(spec=None):
    """The placeholder-ramp index for a screen's token — the ONE place token
    identity becomes colour, so disc and trail can never diverge.

    Resolution: token "palette" (ramp index or symbol) -> "address" ->
    "symbol" -> the screen's "icon" -> colors.NEUTRAL_RAMP. Keys hash via
    colors.placeholder_index (crc32, case-folded), so the same token gets
    the same ramp on every run; "address" outranks "symbol" because two
    tokens can share a ticker but never a contract.

    A "palette" naming a brand ramp (colors.BRAND_GRADIENTS, e.g. "SAFE")
    resolves to that name instead — an explicit pin, outside the hash space,
    so brand colours appear only where a flow asks for them."""
    sp = spec or {}
    tok = sp.get("token") or {}
    for k in ("palette", "address", "symbol"):
        if k in tok:
            if (k == "palette" and isinstance(tok[k], str)
                    and tok[k].upper() in colors.BRAND_GRADIENTS):
                return tok[k].upper()
            return colors.placeholder_index(tok[k])
    if sp.get("icon"):
        return colors.placeholder_index(sp["icon"])
    return colors.NEUTRAL_RAMP


def token_style_from_spec(spec=None):
    """resolve a screen's optional "token" field
    -> dict(variant, fill, ring, ramp, film, icon_color, art)

    The default variant is "solid" — the gradient disc ("unknown") must be
    asked for explicitly. "palette" (ramp index or token symbol) picks a
    placeholder ramp for a known token that has no image: fill = the ramp's
    palette fill. An explicit "fill" still wins. fill / ring are None when
    unset (token() then applies its black-body / white-ring defaults).
    "ramp" is the resolved placeholder ramp (token_ramp); "film" is the
    colour status-film bodies take — the ramp's brightest stop when a
    palette is named, so a black-filled token (MONO_RAMP) never renders
    black-on-black qubits. "art" flags a full-bleed logo glyph (is_art) so
    the hold film rises over the art instead of hiding under it. "icon_color"
    is the screen's own when it sets one (a family's mark colour, a chain's
    knock-out); otherwise the default mark takes the disc-wide luma rule a
    chain disc already obeyed (colors.mark_color, audit ICO-13): WHITE, or
    BLACK once the fill is light enough to swallow it — so a light brand
    under the default mark can never render white-on-light. Logo art keeps
    its own colours (None).
    """
    tok = (spec or {}).get("token") or {}
    ramp = token_ramp(spec)
    fill = tuple(tok["fill"]) if "fill" in tok else None
    if fill is None and "palette" in tok:
        fill = colors.ramp_palette(ramp)[0]
    film = fill
    if "fill" not in tok and "palette" in tok:
        film = colors.hex_to_rgb(colors.ramp_gradient(ramp)[-1])
    sp = spec or {}
    art = is_art(sp.get("icon"))
    if "icon_color" in sp:
        icon_color = tuple(sp["icon_color"])
    else:
        icon_color = None if art else colors.mark_color(fill)
    return dict(variant=tok.get("variant", "solid"),
                fill=fill, film=film, ramp=ramp, icon_color=icon_color,
                ring=tuple(tok["ring"]) if "ring" in tok else None,
                art=art)


def token_styled(cv, cx, cy, r, st, glyph_a=None, glyph_b=None, mix=1.0, alpha=1.0,
                 hold=None):
    """token() driven by a pre-resolved token_style_from_spec() dict --
    for callers that cache the style instead of re-resolving per frame"""
    token(cv, cx, cy, r, variant=st["variant"], fill=st["fill"], ring_color=st["ring"],
          ramp=st["ramp"], glyph_a=glyph_a, glyph_b=glyph_b, mix=mix,
          glyph_color=st.get("icon_color"), alpha=alpha, hold=hold)


def token_from_spec(cv, cx, cy, r, spec=None, glyph_a=None, glyph_b=None, mix=1.0):
    """token() driven by a screen description's optional "token" field
    (see token_style_from_spec for the "palette" placeholder rule)"""
    token_styled(cv, cx, cy, r, token_style_from_spec(spec),
                 glyph_a=glyph_a, glyph_b=glyph_b, mix=mix)


def trail_palette_from_spec(spec=None):
    """follower colours for a screen: the resolved placeholder ramp's five
    trail stops when the token names a "palette" or is unknown (identity ->
    ramp via token_ramp, matching the disc), else the neutral grey trail.
    Pass the result to trail_static / trail_chain."""
    tok = (spec or {}).get("token") or {}
    if "palette" in tok or tok.get("variant") == "unknown":
        return colors.ramp_palette(token_ramp(spec))[1]
    return colors.placeholder_palette(colors.NEUTRAL_RAMP)[1]


# -------------------------------------------------- chevrons + text pieces --
# The corner chevron's geometry — ONE polygon every reader shares: the tip
# 4 px above the centre, the base corners CHEV_HALF_W to each side and 3.2
# below, outlined with the "sign" weight of layout.STROKE, round joints.
# The PIN screen measures its hint anchors off CHEV_HALF_W and the handoff
# cites these, so a reshape here moves everything that depends on it.
CHEV_PTS = ((0, -4), (-4.2, 3.2), (4.2, 3.2))
CHEV_STROKE = STROKE["sign"]                       # 4.5
CHEV_HALF_W = max(abs(x) for x, _ in CHEV_PTS)     # 4.2: the base half-width


def chevron(cv, cx, cy, ang, alpha=1.0):
    if alpha <= colors.ALPHA_FLOOR:
        return
    col = tuple(int(round(c * alpha)) for c in colors.WHITE)
    ca, sa = math.cos(ang), math.sin(ang)
    poly = [((cx + px * ca - py * sa) * SUP, (cy + px * sa + py * ca) * SUP)
            for px, py in CHEV_PTS]
    cv.d.polygon(poly, fill=col, outline=col)
    # loop through the first two points again so every vertex (incl. the
    # tip, where the stroke starts and ends) gets a curved joint
    cv.d.line(poly + [poly[0], poly[1]], fill=col,
              width=int(round(CHEV_STROKE * SUP)), joint="curve")


def chevron_angles(chev):
    """resting angles for a chevron state: "up" points up, "lr" points out"""
    return (0.0, 0.0) if chev == "up" else (-math.pi / 2, math.pi / 2)


def chevron_pair(cv, ang_l, ang_r, y_off=0.0, alpha=1.0):
    """both corner chevrons in their PQ1 slots — always BOTH, at one alpha.

    A hold never fades either of them (user decision, Sep 2026: "it should
    keep on showing both chevrons"): the pressed-side fade of audit A11-01
    was retired, so a live sign or decline hold leaves the pair exactly as it
    rests (DESIGN.md § Input; tools/check I-ARMED)."""
    if alpha <= colors.ALPHA_FLOOR:
        return
    chevron(cv, CHEV_LEFT[0], CHEV_LEFT[1] + y_off, ang_l, alpha)
    chevron(cv, CHEV_RIGHT[0], CHEV_RIGHT[1] + y_off, ang_r, alpha)


def caption(cv, s, alpha=1.0, color=colors.WHITE):
    """bottom-band caption: the Question caps (SIZE_QUESTION, LS_QUESTION),
    centred, baseline y 128"""
    cv.text(s, CENTER_X, BASELINE_Y, typography.SIZE_QUESTION, alpha,
            ls=typography.LS_QUESTION, color=color, baseline=True)


PAGER_BASELINE = 24     # the pager's top-centre spot, between the corner chevrons
PAGER_ALPHA = colors.INK_PAGING   # the pager's ink tint (DESIGN.md § Color)


def pager(cv, n, m, alpha=1.0):
    """page indicator "n/m": the LABEL face (SIZE_LABEL, SemiBold, LS_LABEL
    — the detail label's, so every band-edge annotation reads alike; user
    decision, Sep 2026), INK_PAGING white, top centre — drawn when a screen
    has more than one page, or a hero declares its position in a sequence
    (DESIGN.md § Typography, Label; § Layout grid, Pager)"""
    if m < 2:
        return
    cv.text(f"{n}/{m}", CENTER_X, PAGER_BASELINE, typography.SIZE_LABEL, alpha,
            ls=typography.LS_LABEL, weight=typography.WEIGHT_LABEL,
            color=colors.scale(colors.WHITE, PAGER_ALPHA), baseline=True)


VIEW_MORE_TEXT = "OR VIEW MORE"
GO_BACK_TEXT = "TO GO BACK"
# the units' text centres are grid anchors (imported from layout):
# VIEW_MORE_CX 206 for the unit whose chevron follows the text, and its
# mirror GO_BACK_CX 222 for the one whose chevron leads it
VIEW_MORE_CHEV_GAP = 13     # chevron centre this far past the text edge
VIEW_MORE_CHEV_CY = 121.5   # optical centre of question caps on baseline 128


def _band_unit(cv, s, alpha, right, cx=None):
    """one confirm-band unit: question-style caps + a pointing chevron —
    after the text pointing right (text centred on VIEW_MORE_CX), or before
    it pointing left (on GO_BACK_CX, the mirror), so the two messages that
    alternate every 5 s share one visual centre; a band_chev hero passes
    the x its layout reports"""
    if alpha <= colors.ALPHA_FLOOR:
        return
    if cx is None:
        cx = VIEW_MORE_CX if right else GO_BACK_CX
    cv.text(s, cx, BASELINE_Y, typography.SIZE_QUESTION, alpha,
            ls=typography.LS_QUESTION, baseline=True)
    tw = (typography.text_width(s, typography.SIZE_QUESTION)
          + typography.LS_QUESTION * (len(s) - 1))
    if right:
        chevron(cv, cx + tw / 2 + VIEW_MORE_CHEV_GAP,
                VIEW_MORE_CHEV_CY, math.pi / 2, alpha)
    else:
        chevron(cv, cx - tw / 2 - VIEW_MORE_CHEV_GAP,
                VIEW_MORE_CHEV_CY, -math.pi / 2, alpha)


def confirm_band(cv, a_more, a_back, alpha=1.0):
    """confirm-screen band: "OR VIEW MORE" ▸ (right-tap — the remaining
    details) and ◂ "TO GO BACK" (left-tap) share the slot;
    motion.confirm_band alternates their alphas every 5 s. The corner
    chevrons rest in the up (hold-armed) pose beside it, bobbing on the
    same beat."""
    _band_unit(cv, VIEW_MORE_TEXT, alpha * a_more, right=True)
    _band_unit(cv, GO_BACK_TEXT, alpha * a_back, right=False)


TRANSITION_GAP = 0.5   # chevron centre past each value's edge, per text px


def transition_row(cv, t, alpha=1.0):
    """one value becoming another on one row (DESIGN.md § Text rules,
    Transitions): the old value, the system chevron pointing right, the new
    value — the run centred on the text's x, the chevron on its y"""
    old, new = t["transition"]
    size, w = t["size"], t.get("weight", "regular")
    wo, wn = typography.text_width(old, size, w), typography.text_width(new, size, w)
    gap = TRANSITION_GAP * size
    x0 = t["x"] - (wo + wn + 2 * gap) / 2
    cv.text(old, x0 + wo / 2, t["y"], size, alpha, weight=w)
    chevron(cv, x0 + wo + gap, t["y"], math.pi / 2, alpha)
    cv.text(new, x0 + wo + 2 * gap + wn / 2, t["y"], size, alpha, weight=w)


def draw_text(cv, t, alpha=1.0):
    """render one text spec from layout_of() — a transition row (a detail
    line {"transition": [old, new]}) lays out old ▸ new centred on x; a
    band_chev hero caption carries the right-pointing band chevron"""
    if "transition" in t:
        transition_row(cv, t, alpha)
        return
    if t.get("band_chev"):
        # the confirm band's unit, at the x the layout reports (layout_of
        # places a band_chev caption on VIEW_MORE_CX)
        _band_unit(cv, t["str"], alpha, right=True, cx=t["x"])
        return
    cv.text(t["str"], t["x"], t["y"], t["size"], alpha,
            ls=t.get("ls", 0), color=t.get("color", colors.WHITE),
            baseline=t.get("base", False), weight=t.get("weight", "regular"))


# ---------------------------------------------------- streaks / pulse ------
def trail_static(cv, cx, cy, r, gap=22, direction=-1, palette=None):
    """resting follower stream: solid gradient steps, farthest drawn first

    `r` is the token's layout radius; links are drawn at the token's visible
    radius (r - TOKEN_INSET) so every link is exactly the size of the circle.
    """
    palette = palette or colors.placeholder_palette(colors.NEUTRAL_RAMP)[1]
    rr = visible_r(r)
    for i in range(len(palette) - 1, -1, -1):
        cv.circle(cx + direction * gap * (i + 1), cy, rr, palette[i])


def trail_chain(cv, chain, hx, hy, r, palette=None):
    """draw a FollowerChain behind a head at (hx, hy); coincident links skipped

    `r` is the token's layout radius; links match the token's visible edge.
    """
    palette = palette or colors.placeholder_palette(colors.NEUTRAL_RAMP)[1]
    rr = visible_r(r)
    pts = chain.points
    for i in range(len(pts) - 1, -1, -1):
        p = pts[i]
        ahead = dict(x=hx, y=hy) if i == 0 else pts[i - 1]
        if abs(p["x"] - ahead["x"]) < 0.8 and abs(p["y"] - ahead["y"]) < 0.8:
            continue
        cv.circle(p["x"], p["y"], rr, palette[min(i, len(palette) - 1)])


def pulse(cv, cx, cy, r, t, color, alpha=1.0, period=2000):
    """two staggered rings expanding r+1.5 .. r+8.5 px and fading out
    (TOKEN_RING_W stroke — the system ring weight)"""
    if alpha <= colors.ALPHA_FLOOR:
        return
    for k in range(2):
        phase = ((t / period) + k * 0.5) % 1.0
        rad = r + 1.5 + phase * 7
        a = (1 - phase) * colors.PULSE_PEAK_ALPHA * alpha
        if a <= colors.ALPHA_FLOOR:
            continue
        X, Y, R = cx * SUP, cy * SUP, rad * SUP
        cv.d.ellipse([X - R, Y - R, X + R, Y + R],
                     outline=(*color, int(255 * a)),
                     width=int(round(TOKEN_RING_W * SUP)))


def flash_ring(cv, cx, cy, r, color, alpha, width=TOKEN_RING_W):
    """expanding one-shot ring, colour faded toward black — stroked at the
    system ring weight like every other ring the token casts (user
    decision, audit RAD-01: the old 2.5 was a third of a pixel heavier and
    had no name)"""
    if alpha <= colors.ALPHA_FLOOR:
        return
    cv.ring(cx, cy, r, colors.scale(color, alpha), width)


# ------------------------------------------------------------ hold fill ----
# The hold gesture's progress fill (DESIGN.md § Input; curve motion.hold_fill):
# a see-through liquid rising in the token disc from the bottom up, full at
# HOLD_COMMIT_MS. Drawn inside token() so it sits in the right layer.
HOLD_OVERLAY_ALPHA = 0.30   # the film's opacity — black over colour, white in black
HOLD_DARK_BODY = 0.15       # body luma below this = a black body: the film goes white


def hold_style(st):
    """(placement, RGBA colour) of a screen's hold fill — THE resolver, the
    one switch point. The hold is a 30 % see-through liquid rising in the
    disc; only its shade follows the body it rises in, so a new brand family
    gets it for free. A coloured body — a placeholder-ramp solid, an unknown
    token's gradient disc, brand logo art — DARKENS: black rising OVER the
    art and the glyph, under the ring (the ring stays bright). A black body
    (the ETH mono token, any near-black fill) would hide a black film, so it
    LIGHTENS instead: white rising inside the disc, UNDER the ring and the
    glyph — a dark grey that leaves the logo crisp. Either way the liquid
    never paints over the token's identity. Full-bleed logo art on a black
    body (a popular token's logo on the mono trail, token_style_from_spec's
    "art") would hide an under-film, so it darkens like brand art."""
    a = int(round(255 * HOLD_OVERLAY_ALPHA))
    body = st["fill"] if st["fill"] is not None else colors.BLACK
    if (st["variant"] == "solid" and colors.luma(body) < HOLD_DARK_BODY
            and not st.get("art")):
        return "under", (255, 255, 255, a)
    return "over", (0, 0, 0, a)


def hold_flood(cv, cx, cy, r, k, color, alpha=1.0):
    """the hold-progress fill: the disc of radius r filled from the bottom
    up to level k (0..1, motion.hold_fill) — the cap under a horizontal
    surface (cv.chord). The colour is hold_style's RGBA film: its alpha is
    scaled by `alpha` and composited; a plain RGB colour fades toward black
    instead (the flow's alpha idiom)."""
    if k <= motion.LEVEL_EPS or alpha <= colors.ALPHA_FLOOR:
        return
    if len(color) == 4:
        col = (*color[:3], int(round(color[3] * alpha)))
    else:
        col = colors.scale(color, alpha)
    if k >= 1 - motion.LEVEL_EPS:
        cv.circle(cx, cy, r, col)
        return
    d = r * (1 - 2 * k)                       # the surface, below the centre
    a = math.degrees(math.asin(max(-1.0, min(1.0, d / r))))
    cv.chord(cx, cy, r, a, 180 - a, col)      # the bottom cap: angles a -> 180 - a


# pill() and badge() lived here and were RETIRED (audit COL-06, Sep 2026):
# no screen ever drew one, and badge's default — 100 % white text on a typed
# (255, 255, 255, 26) tint — contradicted the type table it claimed to
# follow. A component nothing draws is a promise to the port that the device
# does not keep. The chip shape is not forbidden; it is simply not part of
# this system until a screen needs one, and then it arrives with its tint
# named here and its tier taken from typography.
