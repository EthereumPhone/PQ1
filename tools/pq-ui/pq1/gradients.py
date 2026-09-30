"""PQ1 gradients — the forward-facing surface for gradient/ramp material.

The data lives in pq1.colors (the color system of record); this module
re-exports it alongside the ramp helpers screen code needs, so "anything
gradient" is one import:

    from pq1 import gradients

Reminder (DESIGN.md § Color): every live disc is SOLID. A token without
art — known or unknown — uses a ramp as a solid fill + trail
(placeholder_palette), its hue chosen from the token's identity
(components.token_ramp) so the same token always gets the same ramp;
MONO_RAMP is the recognized-logo treatment (black body, white ring, grey
trail). The gradient disc is RESERVED and renders nowhere (audit A11-12) —
ramp_gradient() serves the ramp material, not a disc. Brand
ramps (BRAND_GRADIENTS, e.g. "SAFE") are pinned by NAME from a flow and
never hashed; a resolved ramp key (components.token_ramp) is a placeholder
index or a brand name — read it with ramp_gradient / ramp_palette /
ramp_stops.
"""
from functools import lru_cache

from PIL import Image

from .colors import (  # noqa: F401 — re-exports
    BRAND_GRADIENTS, BRAND_PALETTES, BRAND_RAMP_STOPS, MONO_RAMP,
    NEUTRAL_RAMP, PLACEHOLDER_GRADIENTS, PLACEHOLDER_PALETTES,
    RAMP_STOPS, grad_color, hex_to_rgb, placeholder_index,
    placeholder_palette, ramp_gradient, ramp_palette, ramp_stops, scale,
)
from .motion import clamp01, lerp

# the teal placeholder ramp (index into PLACEHOLDER_GRADIENTS) — the batch-sign
# idle screen's token colour; placeholder_palette(TEAL_RAMP) -> (fill, trail)
TEAL_RAMP = 7


def mix(c1, c2, u):
    """blend two RGB colours; u in [0, 1] (0 -> c1, 1 -> c2)"""
    u = clamp01(u)
    return tuple(int(round(lerp(a, b, u))) for a, b in zip(c1, c2))


@lru_cache(maxsize=32)
def band_mask(w_px, h_px, fade_top_px, fade_bot_px):
    """L-mode vertical alpha band (raw pixels): opaque centre, linear ramps
    to transparent over fade_top_px / fade_bot_px. Multiply it onto a
    strip's alpha channel (the digit-reel window idiom)."""
    m = Image.new("L", (w_px, h_px), 255)
    px = m.load()
    for y in range(h_px):
        a = 1.0
        if fade_top_px > 0 and y < fade_top_px:
            a = y / fade_top_px
        if fade_bot_px > 0 and y >= h_px - fade_bot_px:
            a = min(a, (h_px - 1 - y) / fade_bot_px)
        if a < 1.0:
            v = int(round(255 * a))
            for x in range(w_px):
                px[x, y] = v
    return m
