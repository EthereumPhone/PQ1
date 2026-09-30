"""PQ1 typography — Aileron and the type scale.

PQ1 type scale (all sizes in UI pixels; font() supersamples internally)
  36/32 big - 28 mid - 22 default - 18 question caps - 16 label caps
  (SEMIBOLD) — six sizes on the scale, plus the 40 DISPLAY digit (the
  LAST ATTEMPT reel: one digit alone on the panel). Three faces: Regular
  for every value; SemiBold for the label caps and every band-edge
  annotation (the detail label, the pager n/m, the PIN hints, a verdict's
  label), for a name line inside a value and for the entry / display
  digits; Bold only for the monogram — a lone letter standing as a disc's
  whole content (font(px, weight="semibold" | "bold")). Nothing renders
  below SIZE_LABEL.

ROLES is the scale as the handoff publishes it (tools/handoff/introspect
-> screens.schema.json "typography"); the ladder the detail region climbs
is layout.fit_tiers / layout.fit_size.

Font resolution order:
  1. $PQ1_FONT (absolute path override, used by the render-verification harness)
  2. the bundled copies in pq1/assets/ (Aileron-Regular/SemiBold/Bold.otf, so
     pq1 is self-contained)
  3. system font directories
  4. PIL's built-in default (last resort)
A warning is printed once if the face that loads is not Aileron, so a missing
font can never silently restyle the UI again.
"""
import functools
import os
import sys

from PIL import Image, ImageDraw, ImageFont

# layout reads this module's tokens; the supersample factor this module needs
# back from layout is imported lazily inside font() / text_width(), so the
# pair never forms an import cycle

# -------------------------------------------------------------- type scale --
SIZE_XL = 36        # hero values
SIZE_L = 32         # big values
SIZE_M = 28         # mid values
SIZE_BODY = 22      # default / addresses
SIZE_QUESTION = 18  # question caps (bottom band)
SIZE_LABEL = 16     # label caps — the floor: nothing on the panel renders smaller
SIZE_DISPLAY = 40   # the display digit — the LAST ATTEMPT reel, one digit alone

LS_QUESTION = 0.5   # letter spacing for question caps
LS_LABEL = 1.0      # letter spacing for label caps
WEIGHT_LABEL = "semibold"   # the label caps' face — every band-edge annotation wears it

# the scale as roles — what each size is for, in which face, with what
# tracking (DESIGN.md § Typography). The handoff's typography block is
# generated from this table, so a port reads the roles, not the prose.
ROLES = (
    dict(role="display", px=SIZE_DISPLAY, weight="semibold", tracking=0,
         use="one digit alone on the panel — the LAST ATTEMPT reel"),
    dict(role="big", px=SIZE_XL, weight="regular", tracking=0,
         use="short one-liners: an amount, 'Unlimited', a chain caption"),
    dict(role="big", px=SIZE_L, weight="regular", tracking=0,
         use="a one-liner too long for 36"),
    dict(role="mid", px=SIZE_M, weight="regular", tracking=0,
         use="one- or two-liners: a fee pair, a function name"),
    dict(role="default", px=SIZE_BODY, weight="regular", tracking=0,
         use="multi-line content: addresses, call data, hashes, the words grid"),
    dict(role="entry digit", px=SIZE_BODY, weight="semibold", tracking=0,
         use="the digit inside a PIN ring (pq1/procedural/pin_slots)"),
    dict(role="question", px=SIZE_QUESTION, weight="regular", tracking=LS_QUESTION,
         use="the caps ask in the bottom band"),
    dict(role="label", px=SIZE_LABEL, weight=WEIGHT_LABEL, tracking=LS_LABEL,
         use="every band-edge annotation: the detail label, the pager n/m, "
             "the PIN hints, a verdict's label"),
)

# ------------------------------------------------------------------- fonts --
_ASSET_FONTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
_FONT_NAMES = {
    "regular": ("Aileron-Regular.otf", "Aileron-Regular.ttf",
                "Aileron.otf", "Aileron.ttf"),
    "semibold": ("Aileron-SemiBold.otf", "Aileron-SemiBold.ttf"),
    "bold": ("Aileron-Bold.otf", "Aileron-Bold.ttf"),
}
_SEARCH_DIRS = (
    _ASSET_FONTS,
    os.path.expanduser("~/Library/Fonts"),
    "/Library/Fonts",
    "/System/Library/Fonts",
    "/usr/share/fonts/truetype",
    "/usr/share/fonts/truetype/dejavu",
)


@functools.lru_cache(maxsize=None)
def _font_path(weight="regular"):
    env = os.environ.get("PQ1_FONT")
    if env:                       # the pin overrides EVERY weight, so the
        if os.path.exists(env):   # render-verification harness stays exact
            return env
        print(f"pq1.typography: $PQ1_FONT={env!r} not found, ignoring", file=sys.stderr)
    for name in _FONT_NAMES[weight]:
        for d in _SEARCH_DIRS:
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
    # a missing non-regular weight falls back to the regular face
    return _font_path("regular") if weight != "regular" else None


@functools.lru_cache(maxsize=1)
def _warn_if_not_aileron():
    p = _font_path()
    if p is None:
        print("pq1.typography: Aileron not found anywhere — using PIL default",
              file=sys.stderr)
    elif "aileron" not in os.path.basename(p).lower():
        print(f"pq1.typography: rendering with {p} (not Aileron)", file=sys.stderr)
    return True


@functools.lru_cache(maxsize=None)
def font(px, weight="regular"):
    """Aileron at `px` UI pixels (supersampled internally); weight
    "regular" | "semibold" (the label caps', a name line's and the digits'
    face) | "bold" (the monogram's)."""
    from .layout import SUP     # lazy: layout imports this module's tokens
    _warn_if_not_aileron()
    p = _font_path(weight)
    if p:
        try:
            return ImageFont.truetype(p, int(round(px * SUP)))
        except OSError:
            pass
    return ImageFont.load_default()


_SCRATCH = ImageDraw.Draw(Image.new("RGB", (8, 8)))


def text_width(s, px, weight="regular"):
    """rendered width of `s` at `px`, in UI pixels"""
    from .layout import SUP
    return _SCRATCH.textlength(s, font=font(px, weight)) / SUP


@functools.lru_cache(maxsize=None)
def ink_box(s, px, weight="regular"):
    """the INK of `s` at `px`, in UI pixels about the baseline-left origin:
    (x0, y0, x1, y1), y negative above the baseline. Horizontal from the
    rendered mask (Pillow's getbbox is the advance box in x), vertical from
    the face's bbox — what an optical centring reads, never an em metric."""
    from .layout import SUP
    f = font(px, weight)
    ix0, _, ix1, _ = f.getmask(s).getbbox()
    _, y0, _, y1 = f.getbbox(s, anchor="ls")
    return ix0 / SUP, y0 / SUP, ix1 / SUP, y1 / SUP


def ink_lift(s, px, weight="regular"):
    """baseline offset (px) that centres the string's ink box on a line —
    caps and the − / + hint signs alike (the PIN screen's hint labels sit
    on the chevron line by it)"""
    _, y0, _, y1 = ink_box(s, px, weight)
    return -(y0 + y1) / 2


def ink_offset(s, px, weight="regular"):
    """(dx, dy): where the ink centre of `s` lands relative to the "mm"
    anchor a centred draw uses — the advance centre and the em middle
    (halfway between ascender and descender), in UI px, y down. A screen
    that types an optical correction for one glyph checks this at import
    so a face swap fails loudly (screens/verdict/last_attempt)."""
    from .layout import SUP
    f = font(px, weight)
    x0, y0, x1, y1 = ink_box(s, px, weight)
    asc, desc = f.getmetrics()
    em_mid = -(asc - desc) / 2 / SUP
    return (x0 + x1) / 2 - f.getlength(s) / SUP / 2, (y0 + y1) / 2 - em_mid
