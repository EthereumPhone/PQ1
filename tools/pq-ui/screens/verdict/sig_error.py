"""Sig error — the warning triangle reports a failed check, detail-grid.

The one detail-grid verdict: the red triangle arrives in a circle column
carrying a black exclamation, throws two decaying attention pulses, then
the label and the detail lines fade in together. draw() is fully owned —
detail layout, not the centred circle.

The detail text is VARIABLE (DESIGN.md § Typography): "lines" (1-3, a str
or a {"str", "weight"} name line) and "label" are the screen's content,
and "size" is FITTED by the system's one rule (layout.fit_size — the
largest tier whose every line MEASURES inside the region, in its own
face) unless a spec pins it. "side" docks the triangle in either column, the text
opposite. The sample is a placeholder, not content:

    screens.spec("sig_error", lines=["Signature", "verify failed"], label="SIG CHECK")
    python3 -m screens sig_error --lines "Signature" "verify failed"

The message is the device's own words, so it follows DESIGN.md § Text
rules, Case: sentence case, no shouting, no abbreviation; the label names
the check in caps (audit HS-13).
"""
from pq1 import colors, status, typography
from pq1.layout import (BASELINE_Y, CIRCLE_CY, COL_LEFT_CX, COL_RIGHT_CX,
                        DETAIL_TEXT_CX, TEXT_CY, fit_size, fit_tiers,
                        line_height, line_str, line_weight)
from pq1.motion import VERDICT_HOLD_MS, attention_pulse, clamp01, ease_out
from pq1.procedural import marks, warning_triangle
from pq1.verdict import VerdictAnim

ANIM = "sig_error"
SPEC = dict(state="failed", bottom="", label="SIG CHECK",
            lines=["Signature", "verify failed"], side="left")
# the secure-boot checks this notice reports (audit HS-10) — the device's own
# words, sentence case, the label naming the check (DESIGN.md § Text rules, Case)
PRESETS = dict(
    sig_verify_fail=dict(label="SIG CHECK", lines=["Signature", "verify failed"]),
    type1_sig_fail=dict(label="TYPE 1 SIG", lines=["Type 1 signature", "failed"]),
)

# the triangle's height is the notice token — the sign box sizes its
# width, the column slot the same size as tamper's centred slot
# (warning_triangle.NOTICE_H, audit ICO-03 / ICO-06); TRI_H is the name
# the handoff pages cite, never a second number
TRI_H = warning_triangle.NOTICE_H

SIDES = {"left": COL_LEFT_CX, "right": COL_RIGHT_CX}

TIERS = fit_tiers()   # the ladder, for the --size CLI choices


class SigError(VerdictAnim):
    T_HOLD = VERDICT_HOLD_MS   # the law's hold: 429 + 300 + 900 + 300 -> t_resolve 1929
    T_WAIT = 900    # two decaying attention pulses

    def __init__(self, spec):
        super().__init__(spec)
        self.lines = list(spec.get("lines", SPEC["lines"]))
        if not 1 <= len(self.lines) <= 3:
            raise ValueError(f"sig_error takes 1-3 detail lines, "
                             f"got {len(self.lines)}")
        self.label = spec.get("label", SPEC["label"])
        self.side = spec.get("side", SPEC["side"])
        if self.side not in SIDES:
            raise ValueError(f"unknown sig_error side {self.side!r}; "
                             f"expected one of {', '.join(SIDES)}")
        self.cx = SIDES[self.side]
        self.text_cx = DETAIL_TEXT_CX[self.side]
        self.size = spec.get("size") or fit_size(self.lines)

    def draw_icon(self, cv, t, u):
        a, s = self.entrance(u)     # fade + arrive (the entrance law)
        v = (t - (self.T_HOLD + self.T_IN)) / self.T_WAIT
        if 0.0 < v < 1.0:
            s = attention_pulse(v)
        warning_triangle.draw(cv, self.cx, CIRCLE_CY, h=TRI_H * s,
                              color=self.style["color"], alpha=a)
        # the mark sits 6.4 triangle units below the bbox centre (source);
        # k is source units to UI px — the 64.0 is the SOURCE bounding
        # box's height (72 x 64 units), not the icon box; black inside
        # the state-red fill stays black at any alpha
        k = TRI_H * s / 64.0
        marks.exclamation(cv, self.cx, CIRCLE_CY + 6.4 * k, 16 * k,
                          alpha=a, color=colors.BLACK)

    def draw_text(self, cv, ta):
        """the value on the detail grid: 1-3 lines stacked on line_height
        about TEXT_CY, the label under the circle on the band baseline"""
        lh = line_height(self.size)
        n = len(self.lines)
        for i, ln in enumerate(self.lines):
            y = TEXT_CY - (n - 1) * lh / 2 + i * lh
            cv.text(line_str(ln), self.text_cx, y, self.size, ta,
                    weight=line_weight(ln))
        if self.label:
            cv.text(self.label, self.cx, BASELINE_Y, typography.SIZE_LABEL,
                    ta, ls=typography.LS_LABEL, weight=typography.WEIGHT_LABEL,
                    baseline=True)

    def draw(self, cv, t):
        self.draw_handoff(cv, t)
        u = clamp01((t - self.T_HOLD) / self.T_IN)
        if u > 0.001:
            self.draw_icon(cv, t, u)
        ta = ease_out(clamp01((t - (self.T_HOLD + self.T_IN + self.T_WAIT))
                              / self.T_TEXT))
        if ta > colors.ALPHA_FLOOR:
            self.draw_text(cv, ta)
        self.draw_caption(cv, ta)
        self.draw_busy(cv, t)


def add_args(ap):
    ap.add_argument("--lines", nargs="+", default=None, metavar="LINE",
                    help="the detail value: 1-3 lines (default the sample)")
    ap.add_argument("--label", default=None,
                    help="the caps label under the triangle (default SIG CHECK)")
    ap.add_argument("--side", choices=sorted(SIDES), default=None,
                    help="which column the triangle docks in (default left)")
    ap.add_argument("--size", type=int, choices=[t[0] for t in TIERS],
                    default=None, help="pin the tier (default: fitted)")


def spec_from_args(a):
    over = dict(lines=a.lines, label=a.label, side=a.side, size=a.size)
    return {k: v for k, v in over.items() if v is not None}


status.register(ANIM, SigError)
