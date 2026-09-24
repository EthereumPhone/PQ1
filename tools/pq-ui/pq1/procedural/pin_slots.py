"""8-slot PIN entry ring row — the pin_entering slot strip, re-homed.

Geometry from pin_entering.py: rings of radius 21 on a 50 px pitch, the
row centred on (cx, cy). Only the drawing lives here — the entry-state
machine stays in the screen, which passes one dict per slot (every key
optional):

    digit      int | None  digit shown in the ring (None = empty)
    active     0..1        activation ease: ring colour mixes color_idle
                           -> color_active, stroke 2 -> 2.5 px
    committed  bool        digit locked in: ring turns white
    lift       px          upward offset (the source lifts 3 * active)
    bounce     px          extra upward micro-bounce offset, also up
    a          0..1        per-slot fade, mixed toward black
    fill       0..1        the hold fill's level (motion.hold_fill): the
                           ring fills bottom-up with the entry's hold
                           liquid — OPAQUE white (color_fill), rising over
                           the stroke too, and the part of the digit below
                           its surface turns BLACK (user request, Sep
                           2026 — gold first, then white); DESIGN.md § Input
    fill_a     0..1        the liquid's own presence (a drain, or the
                           liquid alone leaving while the ring stays),
                           default 1. The slot's `a` fades the whole
                           picture — disc included — but never lightens
                           the black digit inside the liquid, so a filled
                           row fades to black as one piece

active wins over committed (mutually exclusive in the source script).
Colours follow the port table: active #E8CA20 -> colors.YELLOW, idle
#6F6F6F -> the 70 % white tint; digits SIZE_BODY SemiBold (the design
canvas's weight — the user asked for the heavier face, Sep 2026), all
constants normalized to r (the source proportions hold at r 21)."""
from PIL import Image, ImageChops, ImageDraw

from .. import colors, gradients, typography
from ..layout import CENTER_X, CIRCLE_CY, SUP
from ..motion import clamp01, lerp
from ..typography import SIZE_BODY

DIGIT_WEIGHT = "semibold"     # the digit inside the ring: the 600 face


def draw(cv, cx=CENTER_X, cy=CIRCLE_CY, *, slots, r=21.0, pitch=50.0,
         color_active=colors.YELLOW, color_idle=None, alpha=1.0,
         color_fill=colors.WHITE):
    """the slot row (slots = one dict per slot, keyword-only), centred on
    (cx, cy); r scales each ring (stroke and digit follow the source
    proportions for r 21)"""
    if alpha <= 0.01:
        return
    if color_idle is None:
        color_idle = colors.scale(colors.WHITE, 0.7)
    s = r / 21.0
    x0 = cx - (len(slots) - 1) / 2.0 * pitch
    for i, slot in enumerate(slots):
        a = clamp01(slot.get("a", 1.0)) * alpha
        if a <= 0.01:
            continue
        x = x0 + i * pitch
        y = cy - slot.get("lift", 0.0) - slot.get("bounce", 0.0)
        act = clamp01(slot.get("active", 0.0))
        if act > 0:
            col = gradients.mix(color_idle, color_active, act)
            lw = lerp(2.0, 2.5, act)
        elif slot.get("committed"):
            col, lw = colors.WHITE, 2.0
        else:
            col, lw = color_idle, 2.0
        cv.ring(x, y, r, gradients.mix(colors.BLACK, col, a), lw * s)
        k = clamp01(slot.get("fill", 0.0))
        fa = clamp01(slot.get("fill_a", 1.0))
        cap = None
        if k > 0.003 and fa * a > 0.003:
            # the hold liquid: opaque white rising over the whole ring —
            # stroke included — composited so it fades with the row
            # (components imports this package, so the import stays local)
            from .. import components
            components.hold_flood(cv, x, y, r, k, (*color_fill, 255), fa * a)
            cap = (y, r, k, fa)
        digit = slot.get("digit")
        if digit is not None:
            _digit(cv, x, y + 1.5 * s, SIZE_BODY * s, str(digit), a, cap)


def _digit(cv, x, y, size, ch, a, cap=None):
    """the slot's digit, centred like cv.text; with a cap ((cy, r, k, fa) —
    the liquid's circle, level and presence) the glyph is split at the
    surface: white above it (fading with the slot's a), black inside the
    liquid (black stays black while the picture fades)"""
    if a <= 0.01:
        return
    if cap is None:
        cv.text(ch, x, y, size, alpha=a, weight=DIGIT_WEIGHT)
        return
    f = typography.font(size, DIGIT_WEIGHT)
    X, Y = x * SUP, y * SUP
    bx0, by0, bx1, by1 = cv.d.textbbox((X, Y), ch, font=f, anchor="mm")
    pad = 3
    x0, y0 = int(bx0) - pad, int(by0) - pad
    w, h = int(bx1) + pad - x0, int(by1) + pad - y0
    glyph = Image.new("L", (w, h), 0)
    ImageDraw.Draw(glyph).text((X - x0, Y - y0), ch, font=f, fill=255,
                               anchor="mm")
    cy, r, k, fa = cap
    liquid = Image.new("L", (w, h), 0)
    d = ImageDraw.Draw(liquid)
    CX, CY, R = X - x0, cy * SUP - y0, r * SUP
    d.ellipse([CX - R, CY - R, CX + R, CY + R], fill=int(round(255 * fa)))
    top = CY + R * (1 - 2 * k)          # the surface, in the glyph box
    if top > 0:
        d.rectangle([0, 0, w, min(h, top)], fill=0)   # above it: no liquid
    black = ImageChops.multiply(glyph, liquid)
    white = ImageChops.subtract(glyph, black)
    if a < 1.0:
        white = white.point(lambda v: int(v * a))
    cv.paste(Image.new("RGB", (w, h), colors.WHITE), x0, y0, white)
    cv.paste(Image.new("RGB", (w, h), colors.BLACK), x0, y0, black)
