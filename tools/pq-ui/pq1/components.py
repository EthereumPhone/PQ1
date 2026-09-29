"""PQ1 components — the reusable pieces every screen is built from.

All functions take a pq1.canvas.Canvas as their first argument and UI-pixel
coordinates. The token is the centrepiece: a solid fill + white ring for a
KNOWN token, or the gradient disc reserved for UNKNOWN tokens (see
pq1.colors). Glyphs inside the token resolve image -> vector -> monogram.
"""
import functools
import math
import os

from PIL import Image, ImageChops, ImageDraw

from . import colors, typography
from .procedural.marks import check, exclamation, minus, plus, x_mark  # noqa: F401
from .procedural import blind as blind_mark
from .procedural import chains as chain_marks
from .procedural import dev as dev_mark
from .procedural import download as download_mark
from .procedural import eth as eth_logo
from .procedural import fingerprint as fingerprint_mark
from .procedural import rotate as rotate_mark
from .layout import BASELINE_Y, CENTER_X, CHEV_LEFT, CHEV_RIGHT, SUP

ASSET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
ETH_LOGO = os.path.join(ASSET_DIR, "eth-logo.png")


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


# ------------------------------------------------------------ image glyphs --
_IMAGES = {}      # (path, recolor) -> decoded RGBA
_SIZED = {}       # (path, recolor, size) -> resized RGBA


def _load_rgba(path, recolor_white):
    key = (path, recolor_white)
    if key not in _IMAGES:
        if os.path.exists(path):
            im = Image.open(path).convert("RGBA")
            if recolor_white:
                px = im.load()
                for y in range(im.height):
                    for x in range(im.width):
                        r, g, b, a = px[x, y]
                        lum = max(r, g, b)
                        px[x, y] = (255, 255, 255, min(a, lum))
        else:
            im = Image.new("RGBA", (2, 2), (0, 0, 0, 0))
        _IMAGES[key] = im
    return _IMAGES[key]


def _sized(path, recolor_white, size):
    key = (path, recolor_white, size)
    if key not in _SIZED:
        _SIZED[key] = _load_rgba(path, recolor_white).resize((size, size), Image.LANCZOS)
    return _SIZED[key]


def image_glyph(path, recolor_white=False, scale=0.78):
    """glyph function pasting an image centred in the token at scale*r"""
    def draw(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        if alpha <= 0.01:
            return
        g = scale * r * SUP
        im = _sized(path, recolor_white, max(1, int(2 * g)))
        if rot:
            im = im.rotate(-math.degrees(rot), resample=Image.BICUBIC)
        if alpha < 1:
            im = im.copy()
            a = im.getchannel("A").point(lambda v: int(v * alpha))
            im.putalpha(a)
        cv.paste(im, int(cx * SUP - g), int(cy * SUP - g), im)
    return draw


def circle_image(cv, path, cx, cy, r, alpha=1.0, rot=0.0):
    """image fitted and circular-masked to the token circle (avatar/logo);
    square or circular art both work"""
    if alpha <= 0.01:
        return
    size = max(2, int(2 * r * SUP))
    im = _sized(path, False, size)
    if rot:
        im = im.rotate(-math.degrees(rot), resample=Image.BICUBIC)
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).ellipse([0, 0, size - 1, size - 1], fill=255)
    mask = ImageChops.multiply(mask, im.getchannel("A"))
    if alpha < 1:
        mask = mask.point(lambda v: int(v * alpha))
    cv.paste(im, int(cx * SUP - size / 2), int(cy * SUP - size / 2), mask)


# ----------------------------------------------------------- vector glyphs --
def eth_mark(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
    """vector Ethereum diamond (fallback when no image logo is available)"""
    if alpha <= 0.01:
        return
    col = tuple(int(round(c * alpha)) for c in (color or colors.WHITE))
    X, Y, R = cx * SUP, cy * SUP, r * SUP
    ca, sa = math.cos(rot), math.sin(rot)

    def pt(px, py):
        return (X + (px * ca - py * sa) * R, Y + (px * sa + py * ca) * R)

    cv.d.polygon([pt(0, -.56), pt(.34, -.02), pt(0, .18), pt(-.34, -.02)], fill=col)
    cv.d.polygon([pt(-.34, .10), pt(0, .58), pt(.34, .10), pt(0, .30)], fill=col)


MONOGRAM_SCALE = 1.34   # cap height ~= a chain mark's, so a letter disc and a
#                         mark disc carry the same weight in a walk


def monogram(letter):
    """glyph function drawing the first letter of a symbol.

    BOLD: unlike every other caption on the device this letter stands alone as
    a disc's entire content — an unknown chain's initial (pq1.chains) — so it
    carries the weight a mark would, not the weight of running text."""
    ch = (letter or "?")[0].upper()

    def draw(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        cv.text(ch, cx, cy, MONOGRAM_SCALE * r, alpha,
                color=color or colors.WHITE, weight="bold")
    return draw


# ---------------------------------------------------------- glyph registry --
GLYPHS = {
    "eth": image_glyph(ETH_LOGO, recolor_white=True),
    "mainnet": eth_logo.glyph(),  # rounded-edge eth, black on chain discs
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
    "plus": plus,        # the entry signs beside the corner chevrons
    "minus": minus,
}
VECTOR_SYMBOLS = {"ETH": eth_mark}


LETTER_PREFIX = "letter:"   # pq1.chains — an unknown chain wears its initial


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
    """glyph lookup: named icon -> image logo -> vector for symbol -> monogram"""
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
                circle_image(cv, path, cx, cy, r - TOKEN_INSET, alpha, rot)
    if symbol:
        if symbol.upper() in VECTOR_SYMBOLS:
            return VECTOR_SYMBOLS[symbol.upper()]
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


# ------------------------------------------------------ token logo assets --
# Popular tokens whose logo ships in pq1/assets/ (400x400 RGBA, the art
# full-bleed like safe.png / cowswap.png): the disc WEARS the art, on the
# mono trail. token_defaults(symbol) is the one switch point between that
# look and the placeholder ramp. ETH is not listed: its identity is the
# white mark on the mono body (eth-logo.png, the SEND flow). A new logo:
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
    default white ring), any other symbol the SOLID placeholder disc + trail
    hashed from the symbol (token_ramp). One flow serves every token on
    device; a flow's SAMPLES cycle the popular tokens through its example
    renders."""
    sym = (symbol or "").upper()
    icon = token_icon(sym)
    if icon:
        palette = sym if sym in colors.TOKEN_GRADIENTS else colors.MONO_RAMP
        return dict(icon=icon, token=dict(palette=palette, ring=list(colors.WHITE)))
    if sym in ETHER_SYMBOLS:
        return dict(icon="eth", token=dict(palette=colors.MONO_RAMP))
    return dict(icon="eth", token=dict(palette=symbol))


# ------------------------------------------------------------------- token --
TOKEN_RING_W = 2.4   # white ring stroke width
TOKEN_INSET = 1.2    # disc, ring AND full-bleed art sit inside the layout radius
                     # by this much; the token's VISIBLE edge is r - TOKEN_INSET —
                     # the trail circles' exact radius (the top circle is never
                     # bigger than its trail; user rule, Sep 2026)


def token(cv, cx, cy, r, *, variant="unknown", fill=None, ring_color=None,
          ring_w=TOKEN_RING_W, inset=TOKEN_INSET, glyph_a=None, glyph_b=None,
          mix=1.0, ramp=None, glyph_color=None, alpha=1.0, hold=None):
    """The main token circle.

    variant "solid"   — known token: solid fill + ring (the normal case)
    variant "unknown" — unrecognized token: gradient disc + ring, coloured
                        by the placeholder ramp index `ramp` (token_ramp
                        resolves it from a spec; neutral grey if None)
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
        if ga == gb:
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
    -> dict(variant, fill, ring, ramp, film)

    The default variant is "solid" — the gradient disc ("unknown") must be
    asked for explicitly. "palette" (ramp index or token symbol) picks a
    placeholder ramp for a known token that has no image: fill = the ramp's
    palette fill. An explicit "fill" still wins. fill / ring are None when
    unset (token() then applies its black-body / white-ring defaults).
    "ramp" is the resolved placeholder ramp (token_ramp); "film" is the
    colour status-film bodies take — the ramp's brightest stop when a
    palette is named, so a black-filled token (MONO_RAMP) never renders
    black-on-black qubits. "art" flags a full-bleed logo glyph (is_art) so
    the hold film rises over the art instead of hiding under it.
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
    return dict(variant=tok.get("variant", "solid"),
                fill=fill, film=film, ramp=ramp,
                icon_color=(tuple(sp["icon_color"])
                            if "icon_color" in sp else None),
                ring=tuple(tok["ring"]) if "ring" in tok else None,
                art=is_art(sp.get("icon")))


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
def chevron(cv, cx, cy, ang, alpha=1.0):
    if alpha <= 0.01:
        return
    col = tuple(int(round(c * alpha)) for c in colors.WHITE)
    pts = [(0, -4), (-4.2, 3.2), (4.2, 3.2)]
    ca, sa = math.cos(ang), math.sin(ang)
    poly = [((cx + px * ca - py * sa) * SUP, (cy + px * sa + py * ca) * SUP)
            for px, py in pts]
    cv.d.polygon(poly, fill=col, outline=col)
    # loop through the first two points again so every vertex (incl. the
    # tip, where the stroke starts and ends) gets a curved joint
    cv.d.line(poly + [poly[0], poly[1]], fill=col,
              width=int(round(4.5 * SUP)), joint="curve")


def chevron_angles(chev):
    """resting angles for a chevron state: "up" points up, "lr" points out"""
    return (0.0, 0.0) if chev == "up" else (-math.pi / 2, math.pi / 2)


def chevron_pair(cv, ang_l, ang_r, y_off=0.0, alpha=1.0):
    """both corner chevrons in their PQ1 slots"""
    if alpha <= 0.01:
        return
    chevron(cv, CHEV_LEFT[0], CHEV_LEFT[1] + y_off, ang_l, alpha)
    chevron(cv, CHEV_RIGHT[0], CHEV_RIGHT[1] + y_off, ang_r, alpha)


def caption(cv, s, alpha=1.0, color=colors.WHITE):
    """bottom-band caption: 18 px caps, centred, baseline y 128"""
    cv.text(s, CENTER_X, BASELINE_Y, typography.SIZE_QUESTION, alpha,
            ls=typography.LS_QUESTION, color=color, baseline=True)


PAGER_BASELINE = 24     # the pager's top-centre spot, between the corner chevrons
PAGER_ALPHA = 0.8       # 80 % white (DESIGN.md § Typography, Paging)


def pager(cv, n, m, alpha=1.0):
    """page indicator "n/m": the LABEL size (16 px — the detail label's, so
    the two band-edge annotations read at one size; user request, Sep 2026),
    80 % white, top centre — drawn when a screen has more than one page, or
    a hero declares its position in a sequence (DESIGN.md § Typography,
    Paging)"""
    if m < 2:
        return
    cv.text(f"{n}/{m}", CENTER_X, PAGER_BASELINE, typography.SIZE_LABEL, alpha,
            ls=1.0, color=colors.scale(colors.WHITE, PAGER_ALPHA), baseline=True)


VIEW_MORE_TEXT = "OR VIEW MORE"
GO_BACK_TEXT = "TO GO BACK"
VIEW_MORE_CX = 206          # unit nudged left so text + chevron read centred
VIEW_MORE_CHEV_GAP = 13     # chevron centre this far past the text edge
VIEW_MORE_CHEV_CY = 121.5   # optical centre of question caps on baseline 128


def _band_unit(cv, s, alpha, right, cx=VIEW_MORE_CX):
    """one confirm-band unit: question-style caps + a pointing chevron —
    after the text pointing right, or before it pointing left; the text
    centred on cx (the confirm band's nudge, or a band_chev hero's)"""
    if alpha <= 0.01:
        return
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
        # the confirm band's unit, the run nudged left like OR VIEW MORE
        # so text + chevron read centred
        _band_unit(cv, t["str"], alpha, right=True,
                   cx=t["x"] + VIEW_MORE_CX - CENTER_X)
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
    rr = r - TOKEN_INSET
    for i in range(len(palette) - 1, -1, -1):
        cv.circle(cx + direction * gap * (i + 1), cy, rr, palette[i])


def trail_chain(cv, chain, hx, hy, r, palette=None):
    """draw a FollowerChain behind a head at (hx, hy); coincident links skipped

    `r` is the token's layout radius; links match the token's visible edge.
    """
    palette = palette or colors.placeholder_palette(colors.NEUTRAL_RAMP)[1]
    rr = r - TOKEN_INSET
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
    if alpha <= 0.01:
        return
    for k in range(2):
        phase = ((t / period) + k * 0.5) % 1.0
        rad = r + 1.5 + phase * 7
        a = (1 - phase) * 0.4 * alpha
        if a <= 0.02:
            continue
        X, Y, R = cx * SUP, cy * SUP, rad * SUP
        cv.d.ellipse([X - R, Y - R, X + R, Y + R],
                     outline=(*color, int(255 * a)),
                     width=int(round(TOKEN_RING_W * SUP)))


def flash_ring(cv, cx, cy, r, color, alpha, width=2.5):
    """expanding one-shot ring, colour faded toward black"""
    if alpha <= 0.01:
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
    if k <= 0.003 or alpha <= 0.01:
        return
    if len(color) == 4:
        col = (*color[:3], int(round(color[3] * alpha)))
    else:
        col = colors.scale(color, alpha)
    if k >= 0.997:
        cv.circle(cx, cy, r, col)
        return
    d = r * (1 - 2 * k)                       # the surface, below the centre
    a = math.degrees(math.asin(max(-1.0, min(1.0, d / r))))
    cv.chord(cx, cy, r, a, 180 - a, col)      # the bottom cap: angles a -> 180 - a


# --------------------------------------------------------- pills / badges --
def pill(cv, box, radius, fill=None, outline=None, width=1.0):
    """rounded-rect chip; RGBA fills composite (e.g. (255,255,255,26) tint)"""
    cv.rounded_rect(box, radius, fill=fill, outline=outline, width=width)


def badge(cv, s, x, y, *, size=None, fg=None, bg=(255, 255, 255, 26),
          pad=(8, 3), radius=9):
    """small labelled pill centred at (x, y); returns its box"""
    size = size or typography.SIZE_PAGING
    fg = fg or colors.WHITE
    tw = typography.text_width(s, size)
    box = (x - tw / 2 - pad[0], y - size / 2 - pad[1],
           x + tw / 2 + pad[0], y + size / 2 + pad[1])
    pill(cv, box, radius, fill=bg)
    cv.text(s, x, y, size, color=fg)
    return box
