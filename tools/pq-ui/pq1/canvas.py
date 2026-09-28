"""PQ1 canvas — the supersampled drawing surface.

All coordinates are UI pixels (428 x 142); the canvas draws at 3x and
LANCZOS-downscales in out(). Alpha on text/fills follows the flow idiom of
scaling the colour toward black, which is exact on the pure-black background;
the draw context is RGBA-mode so components may also composite true alpha
(pulse rings, badges).
"""
import math

from PIL import Image, ImageDraw

from . import colors, typography
from .layout import H, SUP, W


class Canvas:
    """supersampled RGB canvas with the shared primitives"""

    def __init__(self, w=W, h=H, bg=colors.BLACK):
        self.w, self.h = w, h
        self.img = Image.new("RGB", (w * SUP, h * SUP), bg)
        self.d = ImageDraw.Draw(self.img, "RGBA")

    def circle(self, cx, cy, r, fill):
        s = SUP
        self.d.ellipse([(cx - r) * s, (cy - r) * s, (cx + r) * s, (cy + r) * s], fill=fill)

    def ring(self, cx, cy, r, color, width):
        s = SUP
        self.d.ellipse([(cx - r) * s, (cy - r) * s, (cx + r) * s, (cy + r) * s],
                       outline=color, width=int(round(width * s)))

    def chord(self, cx, cy, r, a0, a1, color):
        """the cap of the circle (cx, cy, r) cut off by the straight line between
        angles a0 and a1 (degrees, Pillow's clockwise-from-3-o'clock convention),
        filled — the rising liquid of the hold fill. Rasterised as a polygon of
        arc points, NOT ImageDraw.chord: Pillow 12's chord leaks its fill outside
        the ellipse for some spans (bars across the whole frame at hold levels
        12-49 %); a closed polygon never can."""
        s = SUP
        n = max(12, int(math.ceil(abs(a1 - a0) / 3)))     # ~3 degrees per edge
        pts = [((cx + r * math.cos(math.radians(a0 + (a1 - a0) * i / n))) * s,
                (cy + r * math.sin(math.radians(a0 + (a1 - a0) * i / n))) * s)
               for i in range(n + 1)]
        self.d.polygon(pts, fill=color)                    # closes along the surface

    def line(self, pts, color, width, joint="curve"):
        self.d.line([(x * SUP, y * SUP) for x, y in pts], fill=color,
                    width=int(round(width * SUP)), joint=joint)

    def polygon(self, pts, fill=None, outline=None):
        self.d.polygon([(x * SUP, y * SUP) for x, y in pts], fill=fill, outline=outline)

    def rounded_rect(self, box, radius, fill=None, outline=None, width=1.0):
        x0, y0, x1, y1 = box
        self.d.rounded_rectangle([x0 * SUP, y0 * SUP, x1 * SUP, y1 * SUP],
                                 radius=radius * SUP, fill=fill, outline=outline,
                                 width=int(round(width * SUP)))

    def text(self, s, x, y, size, alpha=1.0, ls=0.0, color=colors.WHITE,
             baseline=False, weight="regular"):
        """centred text; baseline=True aligns the glyph baseline to y"""
        if alpha <= 0.01:
            return
        f = typography.font(size, weight)
        col = tuple(int(round(c * alpha)) for c in color)
        px = x * SUP
        py = y * SUP
        anchor = "ms" if baseline else "mm"
        if ls:
            # manual tracking: lay out glyph by glyph around the centre
            gaps = ls * SUP
            widths = [self.d.textlength(ch, font=f) for ch in s]
            total = sum(widths) + gaps * (len(s) - 1)
            cx = px - total / 2
            for ch, w in zip(s, widths):
                self.d.text((cx, py), ch, font=f, fill=col,
                            anchor="ls" if baseline else "lm")
                cx += w + gaps
        else:
            self.d.text((px, py), s, font=f, fill=col, anchor=anchor)

    def dim(self, k):
        """fade everything drawn so far toward black by k (0 = untouched,
        1 = black): a black film over the whole frame — the flow's transit
        fade of a screen that owns its canvas (flow.Sim.draw)"""
        if k <= 0.003:
            return
        self.d.rectangle([0, 0, self.w * SUP, self.h * SUP],
                         fill=(0, 0, 0, int(round(255 * min(1.0, k)))))

    def paste(self, im, px, py, mask=None):
        """paste at supersampled pixel coordinates (components use this)"""
        self.img.paste(im, (px, py), mask)

    def out(self, scale=1):
        img = self.img.resize((self.w, self.h), Image.LANCZOS)
        if scale > 1:
            img = img.resize((self.w * scale, self.h * scale), Image.NEAREST)
        return img
