"""Masked slot-machine digit reel — the last-attempt countdown counter.

A strip of two adjacent digits rolls down through a rectangular window
whose top and bottom fade to transparent, ported from the last_attempt
mockup (draw_reel) and rebuilt PIL-native: the strip is an RGBA image and
the window fade is gradients.band_mask multiplied onto its alpha channel.

All window geometry normalizes to `size` (source values in parentheses,
at the mockup's 40 px digit): the opaque band spans win_up * size above
to win_dn * size below the digit centerline (19 / 12 px), fade ramps
extend fade * size (11.2 px) past each opaque edge, the window is
win_w * size wide and consecutive digits sit travel * size apart.

Pose-parametric only: p is raw progress 0..1 through the roll; the decel
sweep and settle-spring easing are the caller's job, so p may wobble past
1 during the bounce — the digits keep tracking and the fade window
swallows whatever rolls out, exactly like the source.
"""
from PIL import Image, ImageChops, ImageDraw

from .. import gradients, typography
from ..layout import SUP


def draw(cv, cx, cy, *, p, size=36, color, alpha=1.0, start=8, end=1,
         weight="regular", travel=1.16, fade=0.28, win_w=1.1, win_up=0.475,
         win_dn=0.30):
    """digit reel rolling start -> end, digit centerline on (cx, cy)

    p        progress: 0 = start digit centred, 1 = end digit centred
             (may exceed 1 while a settle bounce plays out)
    size     digit size in UI px; the window geometry scales with it
    weight   the digit's face, "regular" | "semibold" (typography.font)
    travel   distance between consecutive digits, x size
    fade     fade-ramp extent past each opaque edge, x size
    win_w    window width, x size
    win_up   opaque band above the centerline, x size
    win_dn   opaque band below the centerline, x size
    """
    if alpha <= 0.01:
        return
    col = tuple(int(round(c * alpha)) for c in color)
    s = SUP
    fpx = fade * size
    top_off = win_up * size + fpx
    bot_off = win_dn * size + fpx
    sw = int(round(win_w * size * s))
    sh = int(round((top_off + bot_off) * s))

    strip = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
    sd = ImageDraw.Draw(strip)
    f = typography.font(size, weight=weight)
    mx, my = sw / 2, top_off * s
    step = travel * size * s

    n = start - end
    pp = p * n
    if n <= 0 or pp <= 0:
        sd.text((mx, my), str(start), font=f, fill=col, anchor="mm")
    else:
        i = min(n - 1, int(pp))
        u = pp - i
        # u may pass 1 during the final bounce; the band mask hides the
        # digit wherever the overshoot carries it out of the window
        sd.text((mx, my + step * u), str(start - i), font=f, fill=col,
                anchor="mm")
        sd.text((mx, my - step * (1 - u)), str(start - 1 - i), font=f,
                fill=col, anchor="mm")

    fs = int(round(fpx * s))
    strip.putalpha(ImageChops.multiply(
        strip.getchannel("A"), gradients.band_mask(sw, sh, fs, fs)))
    cv.paste(strip, int(round((cx - win_w * size / 2) * s)),
             int(round((cy - top_off) * s)), strip)
