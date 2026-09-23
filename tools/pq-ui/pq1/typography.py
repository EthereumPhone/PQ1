"""PQ1 typography — Aileron Regular and the type scale.

PQ1 type scale (all sizes in UI pixels; font() supersamples internally)
  36/32 big - 28 mid - 22 default - 18 question caps - 16 label caps
  (SEMIBOLD) - 12 paging. Three weights: Regular everywhere, SemiBold for
  the label caps, Bold for a monogram standing alone on a disc
  (font(px, weight="semibold" | "bold")).

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

from .layout import SUP, line_height  # noqa: F401  (line_height re-exported)

# -------------------------------------------------------------- type scale --
SIZE_XL = 36        # hero values
SIZE_L = 32         # big values
SIZE_M = 28         # mid values
SIZE_BODY = 22      # default / addresses
SIZE_QUESTION = 18  # question caps (bottom band)
SIZE_LABEL = 16     # label caps (under detail circles)
SIZE_PAGING = 12    # paging / footnotes

LS_QUESTION = 0.5   # letter spacing for question caps
LS_LABEL = 1.0      # letter spacing for label caps

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
    "regular" | "semibold" (the label caps' weight)."""
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
    return _SCRATCH.textlength(s, font=font(px, weight)) / SUP
