"""The rules. One function per rule, registered with @rule.

ADD A RULE: write a function that returns a list of V(where, key, msg), decorate
it, add its row to the table in .claude/skills/pq1-conformance/SKILL.md, run
`python3 -m tools.check --rule YOUR-ID`. If it flags existing debt, paste the
`--propose` blocks into baseline.toml (with a reason) — never loosen the rule.

  where  a STABLE address: "path/file.py::Class.func" or "flow:<name>" — never a
         line number (edits above it would orphan the baseline row)
  key    what exactly is wrong there (the offending expression / value)
"""
import ast
import copy
import inspect
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pq1 import colors, layout, motion, status, typography, verdict   # noqa: E402
import flows                                                # noqa: E402
import screens                                              # noqa: E402

RULES = []


def V(where, key, msg, line=None):
    return dict(where=where, key=str(key), msg=msg, line=line)


def rule(rid, severity, title, method):
    """severity: error | warn (both need a baseline row to pass) | info (reported, never fails)"""
    def deco(fn):
        RULES.append(dict(id=rid, severity=severity, title=title, method=method, fn=fn))
        return fn
    return deco


# ------------------------------------------------------------------ helpers --
def rel(p):
    return os.path.relpath(p, REPO)


def py_files(*tops):
    for top in tops:
        for root, dirs, files in os.walk(os.path.join(REPO, top)):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            for f in sorted(files):
                if f.endswith(".py"):
                    yield os.path.join(root, f)


class Scoped(ast.NodeVisitor):
    """walks a module remembering the enclosing Class.func of every node"""

    def __init__(self, path):
        self.path, self.src = path, open(path).read()
        self.stack, self.hits = [], []
        self.tree = ast.parse(self.src)

    def scope(self):
        return f"{rel(self.path)}::{'.'.join(self.stack) or '<module>'}"

    def seg(self, node):
        return " ".join((ast.get_source_segment(self.src, node) or "").split())

    def visit_ClassDef(self, node):
        self.stack.append(node.name); self.generic_visit(node); self.stack.pop()

    def visit_FunctionDef(self, node):
        self.stack.append(node.name); self.generic_visit(node); self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef


def verdict_instances():
    """[(key, anim main instance)] for every library screen x preset"""
    out, seen = [], []
    for qual, mod in sorted(screens.modules().items()):
        for p in [None] + sorted(getattr(mod, "PRESETS", {})):
            sp = screens.spec(qual, preset=p) if p else screens.spec(qual)
            if (qual, sp) in seen:              # a preset equal to the default is one instance
                continue
            seen.append((qual, sp))
            an = status.anim_for(sp)
            out.append((f"{qual}|{p}" if p else qual, an, getattr(an, "main", an)))
    return out


# ------------------------------------------------------------ verdict law ----
@rule("V-BASE", "error", "every screens/verdict/* animation subclasses VerdictAnim", "live")
def v_base():
    out = []
    for qual, mod in sorted(screens.modules().items()):
        if qual.startswith("verdict/"):
            cls = status.ANIMS.get(mod.ANIM)
            if cls is None or not issubclass(cls, verdict.VerdictAnim):
                out.append(V(f"screens/{qual}.py", mod.ANIM, "a verdict must subclass pq1.verdict.VerdictAnim"))
    return out


@rule("V-ENTRANCE", "error", "the entrance law is called, never re-derived: no arrive() outside pq1/verdict.py", "ast")
def v_entrance():
    out = []
    for p in py_files("pq1", "screens", "flows"):
        if rel(p) in ("pq1/verdict.py", "pq1/motion.py", "pq1/__init__.py"):
            continue

        class W(Scoped):
            def visit_Call(s, node):
                f = node.func
                nm = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                if nm == "arrive":
                    out.append(V(s.scope(), s.seg(node), "call self.entrance(u) (VerdictAnim) instead of "
                                 "re-deriving the entrance with motion.arrive", node.lineno))
                s.generic_visit(node)
        W(p).visit(W(p).tree) if False else None
        w = W(p); w.visit(w.tree)
    return out


@rule("V-TIN", "error", "a verdict's T_IN never exceeds ARRIVE_MS (the mechanism belongs in T_WAIT)", "live")
def v_tin():
    return [V(f"anim:{k}", f"T_IN={m.T_IN}", f"T_IN {m.T_IN} > ARRIVE_MS {motion.ARRIVE_MS}: the entrance window "
              "is the law's maximum; a mechanism lengthens T_WAIT")
            for k, an, m in verdict_instances()
            if isinstance(m, verdict.VerdictAnim) and m.T_IN > motion.ARRIVE_MS]


@rule("V-SUM", "error", "t_resolve == T_HOLD + T_IN + T_WAIT + T_TEXT for every verdict", "live")
def v_sum():
    return [V(f"anim:{k}", f"t_resolve={an.t_resolve}", "t_resolve is not the sum of the four phases")
            for k, an, m in verdict_instances()
            if isinstance(m, verdict.VerdictAnim) and an is m
            and m.t_resolve != m.T_HOLD + m.T_IN + m.T_WAIT + m.T_TEXT]


@rule("V-HOLD", "error", "every resolving screen rests RESULT_HOLD_MS after t_landed (its result fully visible)", "live")
def v_hold():
    out = []
    for k, an, m in verdict_instances():
        if not an.t_resolve:                 # an idle loop never resolves
            continue
        if getattr(an, "interactive", False):
            # an ENTRY is not an ending: its duration is the typed row plus
            # whichever verdict tail follows — the tail inside it rests the
            # 2450 (it is a verdict instance of its own), the entry does not
            continue
        hold = an.duration - an.t_landed
        if hold != status.RESULT_HOLD_MS:
            out.append(V(f"anim:{k}", f"hold={hold}", f"rests {hold} ms after resolving; the law is "
                         f"RESULT_HOLD_MS {status.RESULT_HOLD_MS}"))
    return out


@rule("V-LAWCOPY", "warn", "the verdict law's phase numbers are inherited, not re-declared", "ast+live")
def v_lawcopy():
    out = []
    law = {"T_HOLD", "T_IN", "T_WAIT", "T_TEXT"}
    for p in py_files("pq1", "screens"):
        if rel(p) == "pq1/verdict.py":
            continue
        w = Scoped(p)
        for node in ast.walk(w.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            names = set()
            for st in node.body:
                if isinstance(st, ast.Assign):
                    for t in st.targets:
                        names |= {e.id for e in (t.elts if isinstance(t, ast.Tuple) else [t]) if isinstance(e, ast.Name)}
            bases = {getattr(b, "attr", getattr(b, "id", "")) for b in node.bases}
            if len(names & law) >= 3 and "VerdictAnim" not in bases:
                out.append(V(f"{rel(p)}::{node.name}", "/".join(sorted(names & law)),
                             "re-declares the verdict phase table without inheriting VerdictAnim", node.lineno))
            if "HANDOFF_MS" in names:
                out.append(V(f"{rel(p)}::{node.name}", "HANDOFF_MS", "a second copy of the handoff span "
                             "(VerdictAnim.T_HOLD) — link it to one token", node.lineno))
    return out


@rule("V-PHASEVAR", "info", "per-verdict T_HOLD / T_WAIT that differ from the law's default", "live")
def v_phasevar():
    d = verdict.VerdictAnim
    return [V(f"anim:{k}", f"T_HOLD={m.T_HOLD} T_WAIT={m.T_WAIT}", "differs from the default "
              f"(T_HOLD {d.T_HOLD}, T_WAIT {d.T_WAIT}) — allowed for a mechanism; listed for the record")
            for k, an, m in verdict_instances()
            if isinstance(m, verdict.VerdictAnim) and (m.T_HOLD != d.T_HOLD or m.T_WAIT != d.T_WAIT)]


# --------------------------------------------------------------- icon laws ---
# What an icon MEASURES is a fact about the rendered frame, so the three rules
# below render one and count pixels instead of reading a constant back: a sign
# that derives its height from the box and then grows a shackle out of it is
# still wrong on glass. The supersampled canvas (layout.SUP) is the measuring
# stick and every number divides back into UI px. Two conventions, both learned
# in audit ICO-09: a bbox edge is EXCLUSIVE (max - min + 1), and a pixel's
# position is its CENTRE (p + 0.5) — read with inclusive indices, ink spanning
# an even number of supersampled pixels reads a phantom 0.17 px (half of one)
# up and to the left, which is what made six centred marks look off-centre.
INK_MIN = 24      # above this L value a supersampled pixel is ink; below it is
#                   the anti-aliased skirt of an edge
BOX_TOL = 1.0     # px — how far a sign's largest dimension may miss the box
CENTRE_TOL = 1.5  # px — how far ink's centre of mass may sit off the circle
SIGN_BAND_H = layout.CIRCLE_CY + layout.VERDICT_BOX / 2   # the sign box's own bottom
#   edge: the caption's ascenders stay below it, so a verdict's words are never
#   counted as its sign
SIGN_BAND_W = 2 * layout.VERDICT_BOX   # ... and the window is twice the box about the
#   sign's own centre: the widest ink the library composes (the PIN pill) fits
#   inside it, the detail column opposite (sig_error's lines) does not
MARK_TILE = 4 * layout.CIRCLE_R   # a mark is measured alone, at the token radius,
MARK_R = float(layout.CIRCLE_R)   # centred on a black tile of this side


def _ink(img, x0, x1, y0, y1):
    """what the ink of a 3x frame measures inside a UI-px window:
    dict(w, h, cx, cy, area) — the bbox in UI px, the LUMINANCE-WEIGHTED centroid
    in UI px, the inked area in UI px squared. None when the window holds no ink."""
    w, px, s = img.width, img.tobytes(), float(layout.SUP)
    a, b = max(0, int(x0 * s)), min(img.width, int(x1 * s))
    c, d = max(0, int(y0 * s)), min(img.height, int(y1 * s))
    mnx, mxx, mny, mxy, n = img.width, -1, img.height, -1, 0
    sx = sy = sv = 0.0
    for j in range(c, d):
        for i, v in enumerate(px[j * w + a:j * w + b]):
            if v > INK_MIN:
                x = a + i
                mnx, mxx = min(mnx, x), max(mxx, x)
                mny, mxy = min(mny, j), max(mxy, j)
                sx += (x + 0.5) * v
                sy += (j + 0.5) * v
                sv += v
                n += 1
    if mxx < 0:
        return None
    return dict(w=(mxx - mnx + 1) / s, h=(mxy - mny + 1) / s,
                cx=sx / sv / s, cy=sy / sv / s, area=n / s / s)


_SIGNS = []


def verdict_ink():
    """[(key, cx, ink)] — every screens/verdict/ instance measured at REST
    (an.duration - 150: deep inside RESULT_HOLD_MS, where nothing moves any
    more). cx is the sign's own centre — CENTER_X, or the detail column the
    instance docks in, which sig_error carries. Rendered once and kept: V-BOX
    and V-CENTRE read the same frames."""
    if not _SIGNS:
        from pq1 import canvas
        for key, an, m in verdict_instances():
            if not key.startswith("verdict/") or an.interactive:
                continue
            cx = getattr(m, "cx", layout.CENTER_X)
            cv = canvas.Canvas()
            an.draw(cv, an.duration - 150)
            _SIGNS.append((key, cx, _ink(cv.img.convert("L"), cx - SIGN_BAND_W / 2,
                                         cx + SIGN_BAND_W / 2, 0, SIGN_BAND_H)))
    return _SIGNS


_MARKS = {}


def mark_ink():
    """{name: ink} — every registered glyph drawn ALONE at the token radius on a
    black tile. The flows are imported first, so the family marks (SAFE's,
    CoWSwap's) are in the registry whichever rule got there first: a single-rule
    run measures the same set as a full one."""
    if not _MARKS:
        from pq1 import canvas, components
        _flow_mods()
        for name, fn in sorted(components.GLYPHS.items()):
            cv = canvas.Canvas(MARK_TILE, MARK_TILE)
            fn(cv, MARK_TILE / 2, MARK_TILE / 2, MARK_R)
            _MARKS[name] = _ink(cv.img.convert("L"), 0, MARK_TILE, 0, MARK_TILE)
    return _MARKS


DISC_ENDINGS = ("verdict/firmware_verified", "verdict/headshake", "verdict/slot_registered")
NOT_SIGNS = ("verdict/last_attempt", "verdict/pin_mismatch", "verdict/duress_differ")
OPEN_REST = "verdict/padlock|unlock"


@rule("V-BOX", "error", "a verdict sign inks its largest dimension to layout.VERDICT_BOX", "live")
def v_box():
    """One box for every sign (owner decision, Sep 2026; audit ICO-03): whatever the sign
    is — a gear, a padlock, a die, a triangle — its LARGEST ink dimension is the same, so
    no verdict lands bigger or smaller than the one before it. Measured on the resting
    frame rather than read off each screen's own constant, because a height derived from
    the box and then grown into a shackle still reads wrong on glass.

    Four instances are not signs. They are exempt HERE, in the rule with the reason, and
    not by a baseline row, because they are not debt anyone will ever pay off:

    firmware_verified, slot_registered (its construction, the rotate mark for the check)
    and headshake end on the TOKEN — the filled disc, the stroked ring —
    so the box does not govern them; they are held to the disc instead (2 * CIRCLE_R, or
    the visible 2 * visible_r(CIRCLE_R) a ring ending shows), which is what keeps the
    exemption honest. last_attempt composes a display digit beside a heart on the type
    tier, and pin_mismatch / duress_differ show the PIN pill: all three are wider than any
    box by design (owner decision). padlock's unlock preset RESTS OPEN, its shackle sprung
    clear of the body; the closed rest — the bare padlock and its lock preset — is what
    the box governs."""
    from pq1 import components
    box = float(layout.VERDICT_BOX)
    disc = (2.0 * layout.CIRCLE_R, 2.0 * components.visible_r(layout.CIRCLE_R))
    out = []
    for key, cx, ink in verdict_ink():
        if ink is None:
            out.append(V(f"anim:{key}", "no ink", "the resting frame inks nothing in the sign band"))
            continue
        got, shown = max(ink["w"], ink["h"]), f'{ink["w"]:.1f} x {ink["h"]:.1f} px'
        qual = key.split("|")[0]
        if qual in DISC_ENDINGS:
            if min(abs(got - d) for d in disc) > BOX_TOL:
                out.append(V(f"anim:{key}", shown, f"a disc ending: the ink is the token itself, so "
                             f"it measures {disc[0]:g} (the circle) or {disc[1]:g} (its visible edge), "
                             f"never a sign's box"))
        elif qual in NOT_SIGNS or key == OPEN_REST:
            continue
        elif abs(got - box) > BOX_TOL:
            out.append(V(f"anim:{key}", shown, f"the sign's largest dimension inks {got:.1f} px; the "
                         f"box is layout.VERDICT_BOX {box:g} (+- {BOX_TOL:g})"))
    return out


@rule("V-CENTRE", "error", "a sign and a mark sit on the circle: their ink's centre of mass does", "live")
def v_centre():
    """Optical centring, measured. The LUMINANCE-WEIGHTED centroid of a resting verdict's
    ink lies within CENTRE_TOL of (its own cx, CIRCLE_CY), and so does every registered
    mark's, drawn alone at the token radius (addressed here as `mark:<name>`). Bbox-
    centring is not enough on its own — a shape with one heavy corner sits on the grid and
    still reads off it — and the marks are what the eye compares, one screen against the
    next, as the device walks a flow.

    The letter namespace is exempt (owner decision, Sep 2026): a monogram is TEXT, centred
    by the font's metrics like every other glyph on the panel. "A" hangs 2.2 px low and
    should — a letter nudged onto its own centre of mass no longer sits where that letter
    sits in a word. The written exceptions carry baseline rows (ICO-04): each is a shape
    whose centre of MASS is deliberately not its optical centre."""
    out = []
    for key, cx, ink in verdict_ink():
        if ink is None:
            continue                       # V-BOX owns an empty frame
        dx, dy = ink["cx"] - cx, ink["cy"] - layout.CIRCLE_CY
        if (dx ** 2 + dy ** 2) ** 0.5 > CENTRE_TOL:
            out.append(V(f"anim:{key}", "centroid", f"the ink's centre of mass sits {dx:+.2f}, {dy:+.2f} px "
                         f"from (cx {cx:g}, CIRCLE_CY {layout.CIRCLE_CY}) — more than {CENTRE_TOL:g} px "
                         f"off the circle it arrives on"))
    for name, ink in sorted(mark_ink().items()):
        if ink is None:
            out.append(V(f"mark:{name}", "no ink", "the glyph draws nothing at the token radius"))
            continue
        dx, dy = ink["cx"] - MARK_TILE / 2, ink["cy"] - MARK_TILE / 2
        if (dx ** 2 + dy ** 2) ** 0.5 > CENTRE_TOL:
            out.append(V(f"mark:{name}", "centroid", f"drawn alone at r {MARK_R:g}, the mark's centre of "
                         f"mass sits {dx:+.2f}, {dy:+.2f} px off centre — more than {CENTRE_TOL:g} px, so "
                         f"it leans on every disc it lands on"))
    return out


EXTENT_BAND = (0.39, 0.60)    # a mark's largest ink dimension, as a fraction of the
#                               VISIBLE disc — the band the registered marks span
INK_BAND = (0.045, 0.125)     # ... and how much of that disc's area it inks
NOT_ON_A_DISC = ("plus", "minus", "exclamation")


@rule("V-MARKBAND", "warn", "a new mark lands in the tuning band the registered marks span", "live")
def v_markband():
    """Weight, not size. Two marks drawn to the same box still read as different
    typefaces if one is a hairline and the other a slab, so a mark is measured twice
    over the disc it rests on: how far its ink REACHES (the extent) and how much of the
    disc it FILLS (the ink). The band is descriptive — it is what the marks in the
    registry measure today — so it guides the next mark instead of condemning one already
    tuned by eye; hence warn, not error.

    Exempt: a chain's brand logo (procedural.chains.NAMES) is drawn as its network draws
    it and is not ours to retune; full-bleed logo art IS the disc rather than a mark on
    it, so its extent is 100 % by construction; the entry signs and the notice mark
    (plus, minus, exclamation) never rest on a disc at all — the signs flank the PIN row
    and the exclamation lives inside the warning triangle; and the letter namespace is
    text, sized by the font (audit ICO-12)."""
    from pq1 import components
    from pq1.procedural import chains as chain_marks
    vis = 2.0 * components.visible_r(layout.CIRCLE_R)
    area = 3.141592653589793 * (vis / 2.0) ** 2
    out = []
    for name, ink in sorted(mark_ink().items()):
        if ink is None or name in chain_marks.NAMES or name in NOT_ON_A_DISC \
                or components.is_art(name):
            continue
        ext, fill = max(ink["w"], ink["h"]) / vis, ink["area"] / area
        for got, band, what in ((ext, EXTENT_BAND, "reaches"), (fill, INK_BAND, "inks")):
            if not band[0] <= got <= band[1]:
                out.append(V(f"mark:{name}", f"{what} {got * 100:.1f}%",
                             f"a mark {what} {band[0] * 100:g}-{band[1] * 100:g} % of the visible disc "
                             f"({vis:g} px across); this one {what} {got * 100:.1f} % — retune it against "
                             f"the registered set, or move the band deliberately"))
    return out


# ------------------------------------------------------------------ motion ---
@rule("M-EASE", "error", "no hand-rolled power curve: (1 - x) ** n belongs in pq1/motion.py", "ast")
def m_ease():
    out = []
    for p in py_files("pq1", "screens", "flows"):
        if rel(p) == "pq1/motion.py":
            continue
        w = Scoped(p)

        class W(Scoped):
            def visit_BinOp(s, node):
                if isinstance(node.op, ast.Pow):
                    b = node.left
                    if (isinstance(b, ast.BinOp) and isinstance(b.op, ast.Sub)
                            and isinstance(b.left, ast.Constant) and b.left.value == 1):
                        out.append(V(s.scope(), s.seg(node), "an inline easing — call a named curve "
                                     "(motion.ease_out / decel / …) or add one to motion.py", node.lineno))
                s.generic_visit(node)
        w = W(p); w.visit(w.tree)
    return out


ALPHA_NAME = re.compile(r"^(a|alpha|.*_a|.*_alpha)$")


@rule("M-ROLE", "error", "an entrance is ease_out: a bare ease() result never becomes an alpha", "ast")
def m_role():
    """DESIGN.md § Motion, the role table: ease (cubic in-out) is for a change
    on something ALREADY on screen — a spin, a slide, a colour turn. An alpha
    rising from 0 is an APPEARANCE and belongs to ease_out: at 14 fps an in-out
    fade shows 1 % ink on its first panel frame where ease_out shows 37 %."""
    out = []
    for p in py_files("pq1", "screens"):
        if rel(p) == "pq1/motion.py":
            continue

        def eased(node):
            for n in ast.walk(node):
                if isinstance(n, ast.Call):
                    f = n.func
                    nm = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
                    if nm == "ease":
                        return True
            return False

        class W(Scoped):
            def visit_Assign(s, node):
                for t in node.targets:
                    if isinstance(t, ast.Name) and ALPHA_NAME.match(t.id) and eased(node.value):
                        out.append(V(s.scope(), s.seg(node), "an alpha rising from 0 is an entrance "
                                     "— ease_out, never ease (DESIGN.md § Motion)", node.lineno))
                s.generic_visit(node)

            def visit_Call(s, node):
                for kw in node.keywords:
                    if kw.arg in ("alpha", "dots") and eased(kw.value):
                        out.append(V(s.scope(), s.seg(kw.value), "an alpha rising from 0 is an "
                                     "entrance — ease_out, never ease (DESIGN.md § Motion)",
                                     node.lineno))
                s.generic_visit(node)
        w = W(p); w.visit(w.tree)
    return out


@rule("M-DIVLIT", "warn", "no bare timing divisor: x / 350 hides a duration that should be a named token", "ast")
def m_divlit():
    out = []
    skip = {"pq1/colors.py", "pq1/typography.py", "pq1/gradients.py"}
    for p in py_files("pq1", "screens"):
        if rel(p) in skip or "/procedural/" in p.replace(os.sep, "/") and not p.endswith(("burst.py", "pin_pill.py")):
            continue

        class W(Scoped):
            def visit_BinOp(s, node):
                r = node.right
                if (isinstance(node.op, ast.Div) and isinstance(r, ast.Constant)
                        and isinstance(r.value, (int, float)) and not isinstance(r.value, bool)
                        and r.value >= 100 and r.value not in (255, 360, 1000, 1000.0)):
                    out.append(V(s.scope(), s.seg(node), f"a bare {r.value:g} ms span — name it", node.lineno))
                s.generic_visit(node)
        w = W(p); w.visit(w.tree)
    return out


# timed from button edges, never frame ticks: exempt from the frame floor
GESTURE_WINDOWS = {"TAP_MAX_MS", "DOUBLE_TAP_MS", "CHORD_MS", "HOLD_COMMIT_MS", "HOLD_SNAPBACK_MS",
                   "DEBOUNCE_MS"}   # 30 ms of contact bounce is BELOW a frame on purpose:
                                    # it is filtered before the grammar ever sees an edge


@rule("M-ACCENT", "error", "no one-shot phase (screens/ T_*, motion.py / status.py *_MS) is shorter than "
      "VERDICT_ACCENT_MIN_MS (two panel frames)", "live")
def m_accent():
    out = []

    def short(v):
        return (isinstance(v, (int, float)) and not isinstance(v, bool)
                and 0 < v < motion.VERDICT_ACCENT_MIN_MS)

    def flag(where, k, v):
        out.append(V(where, f"{k}={v}", f"{v} ms is under two panel frames "
                     f"({motion.VERDICT_ACCENT_MIN_MS}) — the panel may never show it"))
    for qual, mod in sorted(screens.modules().items()):
        for k, v in vars(mod).items():
            if k.startswith("T_") and short(v):
                flag(f"screens/{qual}.py", k, v)
    for mod, where in ((motion, "pq1/motion.py"), (status, "pq1/status.py")):
        for k, v in vars(mod).items():
            if k.endswith("_MS") and k not in GESTURE_WINDOWS and k != "FRAME_MS" and short(v):
                flag(where, k, v)
    return out


@rule("M-UNUSED", "warn", "every public name in pq1/motion.py is used somewhere", "ast")
def m_unused():
    public = [n for n, v in vars(motion).items()
              if not n.startswith("_") and (n.isupper() or (inspect.isfunction(v) and v.__module__ == motion.__name__))]
    corpus = ""
    for p in py_files("pq1", "screens", "flows", os.path.join("tools", "panel")):
        if rel(p) != "pq1/motion.py":
            corpus += open(p).read()
    own = open(os.path.join(REPO, "pq1", "motion.py")).read()
    from tools.handoff.introspect import SPEC_ONLY_TOKENS    # the one list of "no reader by design"
    out = []
    for n in sorted(public):
        if re.search(rf"\b{n}\b", corpus):
            continue
        if n in SPEC_ONLY_TOKENS:     # published to the port, implemented outside the Python
            continue
        if len(re.findall(rf"\b{n}\b", re.sub(r"#.*", "", own))) > 1:     # used inside motion.py itself
            continue
        out.append(V("pq1/motion.py", n, "defined but never consumed — dead, or a behaviour nobody built yet"))
    return out


@rule("M-FPS", "info", "the panel frame rate is a named constant", "live")
def m_fps():
    names = [n for m in (motion, layout) for n in vars(m) if "FPS" in n or n == "FRAME_MS"]
    return [] if names else [V("pq1/motion.py", "PANEL_FPS", "14 fps exists only in prose and --fps defaults; "
                               "VERDICT_ACCENT_MIN_MS (145 = 2 frames) cannot be derived from anything")]


# ----------------------------------------------------------------- library ---
@rule("L-CONTRACT", "error", "every screens/ module honours the protocol: ANIM == module name, SPEC, registered", "live")
def l_contract():
    out = []
    for qual, mod in sorted(screens.modules().items()):
        name = qual.split("/")[1]
        if getattr(mod, "ANIM", None) != name:
            out.append(V(f"screens/{qual}.py", "ANIM", f"ANIM {getattr(mod, 'ANIM', None)!r} != module name {name!r}"))
        if not isinstance(getattr(mod, "SPEC", None), dict):
            out.append(V(f"screens/{qual}.py", "SPEC", "missing SPEC dict"))
        if name not in status.ANIMS:
            out.append(V(f"screens/{qual}.py", "register", "never registered with status.register"))
    return out


@rule("L-LOOP", "error", "a looping film wraps pixel-exact by whole turns; film_time is the identity at zero wraps; "
      "a live film is inf until answered, then latches t_resolve + wraps x loop_ms and still rests RESULT_HOLD_MS", "render")
def l_loop():
    import hashlib
    import math
    from pq1 import canvas, loading
    out = []

    def frame(an, t):
        cv = canvas.Canvas()
        an.draw(cv, t)
        return hashlib.sha256(cv.out().tobytes()).hexdigest()[:16]

    def quiet(spec):        # the caption runs UNWRAPPED by design: hash the pose alone
        sp = dict(spec, busy=None)
        if sp.get("lead"):
            sp["lead"] = dict(sp["lead"], busy=None)
        return sp

    cands = [(key, an) for key, an, _ in verdict_instances() if getattr(an, "loops", False)]
    core = layout.normalize_screens([dict(kind="status", bottom="X")])[0]
    cands.append(("core/qubit", status.anim_for(core)))
    for key, an in cands:
        loop, unit = an.loop, an.loop_ms
        if not loop or not unit:
            out.append(V(f"anim:{key}", "loop", "loops but names no loop region / loop_ms"))
            continue
        t_in, t_out = loop
        q = status.anim_for(quiet(an.spec))
        for a, b in ((t_out, t_out - unit), (t_in + 150, t_in + 150 + unit)):
            if frame(q, a) != frame(q, b):
                out.append(V(f"anim:{key}", f"wrap {a:g}<->{b:g}",
                             "the loop region is not pixel-periodic in loop_ms — a wrap would show a seam"))
        live = status.anim_for(dict(an.spec, live=True))
        if not math.isinf(live.duration):
            out.append(V(f"anim:{key}", "live duration", "an unanswered live film must report duration inf"))
        live.resolve(t_out + 2 * unit + 1)
        if (live.t_resolve != an.t_resolve + live.wraps * unit
                or live.duration - live.t_landed != status.RESULT_HOLD_MS):
            out.append(V(f"anim:{key}", f"latched t_resolve={live.t_resolve}",
                         "after the answer t_resolve = stock t_resolve + wraps x loop_ms, and RESULT_HOLD_MS survives the latch"))
    c = loading.QubitCfg()
    if any(loading.film_time(t, c, 0) != t for t in range(0, c.t7 + 1, 50)):
        out.append(V("pq1/loading.py::film_time", "wraps=0", "must be the identity — every existing render depends on it"))
    if loading.wraps_for(c, c.t5) != 0 or loading.wraps_for(c, c.t5 + c.loop_ms) != 1:
        out.append(V("pq1/loading.py::wraps_for", "t5 / t5+loop_ms",
                     "an answer inside the fixed prefix adds no turn; one turn late adds exactly one"))
    step, w = 1000 / 14, loading.wraps_for(c, c.t5 + 2 * c.loop_ms + 1)
    per_frame, prev = 2 * math.pi * c.orbit_r * step / c.rev_ms, None
    for i in range(int(c.t5 / step) - 2, int((c.t5 + w * c.loop_ms) / step) + 3):   # the seam, frame by frame
        P = loading.qubit_pose(loading.film_time(i * step, c, w), c)["bodies"]
        if prev and len(prev) == len(P):
            d = max(math.hypot(p["x"] - r["x"], p["y"] - r["y"]) for p, r in zip(prev, P))
            if d > per_frame + 0.5:
                out.append(V("pq1/loading.py::film_time", f"seam at {i * step:.0f}",
                             f"a body jumps {d:.1f} px across a wrap (orbit step {per_frame:.1f})"))
                break
        prev = P
    return out


# ------------------------------------------------------------------- flows ---
END_VOCAB = {"done": {"confirmed", "signed", "successful", "approved", "rotated", "updated", "unlocked"},
             "fail": {"declined", "rejected", "failed", "locked"}}


_BROKEN = []


def _flow_mods():
    """[(name, module)] — a flow that cannot even be imported is reported once by
    F-IMPORT rather than crashing every flow rule"""
    out = []
    del _BROKEN[:]
    for n in flows.names():
        try:
            out.append((n, flows.get(n)))
        except Exception as ex:                          # noqa: BLE001
            _BROKEN.append(V(f"flow:{n}", f"{type(ex).__name__}: {ex}",
                             "the module raises on import — the flow does not exist at runtime"))
    return out


@rule("F-IMPORT", "error", "every flow module imports", "live")
def f_import():
    _flow_mods()
    return list(_BROKEN)


@rule("F-NORM", "error", "every flow builds for every ending; --early works exactly when a Confirm? exists", "live")
def f_norm():
    out = []
    for n, mod in _flow_mods():
        # A BENCH flow (palettes, pin, chains) signs nothing: no ENDS, so
        # nothing for the early exit to commit TO. It still earns the
        # grammar's Confirm? once it runs past CONFIRM_MIN_DETAILS details,
        # and --early then rightly raises — the same shape flows.playable
        # already names, "a flow of attempts alone has neither". The build
        # half of this rule still runs for it; only the pairing is skipped.
        bench = not getattr(mod, "ENDS", {})
        for e in [None] + sorted(getattr(mod, "ENDS", {})):
            try:
                scr = flows.screens(n, end=e)
            except Exception as ex:                          # noqa: BLE001
                out.append(V(f"flow:{n}", f"end={e}", f"does not build: {ex}"))
                continue
            if bench:
                continue
            has_confirm = any(s["kind"] == "confirm" for s in scr)
            try:
                flows.screens(n, end=e, early=True)
                early_ok = True
            except ValueError:
                early_ok = False
            if early_ok != has_confirm:
                out.append(V(f"flow:{n}", f"end={e} early", f"early exit {'builds' if early_ok else 'fails'} "
                             f"but the flow {'has' if has_confirm else 'has no'} Confirm? screen"))
    return out


@rule("F-DEFEND", "error", "a flow with ENDS names its DEFAULT_END", "live")
def f_defend():
    out = []
    for n, mod in _flow_mods():
        ends = getattr(mod, "ENDS", {})
        if ends and getattr(mod, "DEFAULT_END", None) not in ends:
            out.append(V(f"flow:{n}", f"DEFAULT_END={getattr(mod, 'DEFAULT_END', None)}",
                         f"not one of {sorted(ends)}"))
    return out


@rule("F-STATE", "error", "every ending's state is a colors.STATE key", "live")
def f_state():
    out = []
    for n, mod in _flow_mods():
        for e, sp in sorted(getattr(mod, "ENDS", {}).items()):
            st = sp.get("state", "done")
            if st not in colors.STATE:
                out.append(V(f"flow:{n}", f"{e}.state={st}", f"not one of {sorted(colors.STATE)}"))
    return out


@rule("F-ENDVOCAB", "warn", "ENDS keys come from one vocabulary (rules.END_VOCAB)", "live")
def f_endvocab():
    ok = END_VOCAB["done"] | END_VOCAB["fail"]
    return [V(f"flow:{n}", e, f"ending key {e!r} is not in the shared vocabulary {sorted(ok)} — "
              "add it to END_VOCAB deliberately, or rename the ending")
            for n, mod in _flow_mods() for e in sorted(getattr(mod, "ENDS", {})) if e not in ok]


@rule("F-ENDPAIR", "warn", "endings follow the grammar: done = qubit + check, failing = resolve + X (qubit + X only when the flow names the film: a failure after dispatch), led by a film = arrive, or a library verdict", "live")
def f_endpair():
    out = []
    for n, mod in _flow_mods():
        for e, raw in sorted(getattr(mod, "ENDS", {}).items()):
            sp = layout.normalize_screens([copy.deepcopy(raw)], getattr(mod, "DEFAULTS", None))[0]
            if status.is_interactive(sp):
                continue
            anim = sp.get("anim") or status.default_anim(sp)
            if issubclass(status.anim_class(sp), verdict.VerdictAnim):
                continue                        # a library verdict IS a legitimate ending (LOCKED)
            done = sp.get("state", "done") == "done"
            if sp.get("lead"):                  # after a lead film the look ARRIVES on the empty canvas
                want = ("arrive", "check" if done else "x")
            elif not done and sp.get("anim") == "qubit":
                # a post-dispatch FAILURE: the flow names the film and it collides
                # into the red X (the host said no after the work started). A user
                # decline never names it and stays the film-less resolve.
                want = ("qubit", "x")
            else:
                want = ("qubit", "check") if done else ("resolve", "x")
            got = (anim, sp.get("result"))
            if got != want:
                out.append(V(f"flow:{n}", f"{e}: {got[0]}/{got[1]}", f"expected {want[0]}/{want[1]} for state "
                             f"{sp.get('state', 'done')!r}" + (" (led by a film)" if sp.get("lead") else "")))
    return out


@rule("F-CONFIRM", "error", "Confirm? sits at CONFIRM_INDEX of every segment with CONFIRM_MIN_DETAILS+ details, and nowhere else", "live")
def f_confirm():
    out = []
    for n, _ in _flow_mods():
        scr = flows.screens(n)
        for a, b in layout._segments(scr):
            seg = scr[a:b + 1]
            details = [s for s in seg if s["kind"] in ("detail", "value")]
            conf = [i for i, s in enumerate(seg) if s["kind"] == "confirm"]
            if len(details) >= layout.CONFIRM_MIN_DETAILS:
                if conf != [layout.CONFIRM_INDEX]:
                    out.append(V(f"flow:{n}", f"segment {a}-{b} confirm at {conf}",
                                 f"{len(details)} details: Confirm? belongs at index {layout.CONFIRM_INDEX}"))
            elif conf:
                out.append(V(f"flow:{n}", f"segment {a}-{b} confirm at {conf}",
                             f"only {len(details)} details: no Confirm? below {layout.CONFIRM_MIN_DETAILS}"))
    return out


@rule("F-ICON", "error", "every icon a flow or a library screen names is registered in components.GLYPHS", "live")
def f_icon():
    """The Ethereum-mark fallback is DELIBERATE (owner decision, Sep 2026; audit G17-01), so the
    renderer keeps `GLYPHS.get(name, GLYPHS["eth"])` and nothing here changes what the device
    draws. This rule protects the decision instead: it catches a name the registry does not hold
    BEFORE it ships, so the fallback only ever answers art the device genuinely lacks — never a
    typo, and never a brand mark whose family was not imported (audit G17-07).

    A "letter:X" name is legal and resolves (components.letter_glyph): it is the namespace an
    unknown CHAIN answers with, so the device names the network instead of borrowing Ethereum's
    mark (pq1.chains; owner decision, Sep 2026). It is a namespace, not a registry entry, so it
    is checked by shape here rather than added to GLYPHS."""
    from pq1 import components
    out = []
    seen = set()
    for n, mod in _flow_mods():                     # importing every flow registers every family mark
        for e in [None] + sorted(getattr(mod, "ENDS", {})):
            try:
                scr = flows.screens(n, end=e)
            except Exception:                                # noqa: BLE001  (F-NORM owns that)
                continue
            for s_ in scr:
                ic = s_.get("icon")
                if ic and components.letter_glyph(ic) is not None:
                    continue
                if ic and ic not in components.GLYPHS and (n, ic) not in seen:
                    seen.add((n, ic))
                    out.append(V(f"flow:{n}", f"icon={ic!r}",
                                 f"not in components.GLYPHS ({', '.join(sorted(components.GLYPHS))}) — "
                                 f"it would silently draw the Ethereum fallback"))
    for qual, mod in sorted(screens.modules().items()):
        specs = [getattr(mod, "SPEC", {})] + list(getattr(mod, "PRESETS", {}).values())
        for sp in specs:
            ic = sp.get("icon")
            if ic and components.letter_glyph(ic) is not None:
                continue
            if ic and ic not in components.GLYPHS:
                out.append(V(f"screens/{qual}.py", f"icon={ic!r}", "not in components.GLYPHS"))
    return out


@rule("F-CHAIN", "error", "a chain screen names its network with chain=<id>, never a bare chain icon", "live")
def f_chain():
    """One id, one identity (owner decision, Sep 2026). `chain=<id>` derives the mark, the disc
    colour, the trail ramp and the caption from pq1.chains, so the art and the words can never
    name different networks. Writing `icon="base"` by hand re-opens exactly that gap — the screen
    would still render, with a caption nothing checks against the mark beside it, and on a signer
    the disc is part of what the user is verifying. This rule is what keeps the old spelling from
    coming back after the migration."""
    from pq1 import chains
    marks = {row[2] for row in chains.CHAINS.values()}
    out, seen = [], set()
    for n, mod in _flow_mods():
        for e in [None] + sorted(getattr(mod, "ENDS", {})):
            try:
                scr = flows.screens(n, end=e)
            except Exception:                                # noqa: BLE001  (F-NORM owns that)
                continue
            for s_ in scr:
                ic = s_.get("icon")
                if ic in marks and "chain" not in s_ and (n, ic) not in seen:
                    seen.add((n, ic))
                    out.append(V(f"flow:{n}", f"icon={ic!r}",
                                 f"a chain mark written by hand — say which network instead "
                                 f"(chain=<id>, pq1.chains.CHAINS), and the mark, the colour and "
                                 f"the caption all follow from it"))
    return out


CONTRAST_MIN = 3.0    # WCAG 2.x's bar for a graphic that carries meaning (1.4.11)


def _rel_luma(color):
    """WCAG relative luminance — the checker's own, deliberately not colors.luma.

    colors.luma weights the sRGB values as they are stored: it answers "is this body
    dark or light?" for mark_color's DARK_MARK_LUMA threshold, reading a swatch the way
    a designer reads it. A contrast RATIO is a ratio of LIGHT, so the channels have to
    be linearized first (the sRGB transfer function); skipping that understates every
    mid-tone disc by roughly half — the mainnet blue measures 1.9:1 un-linearized and
    3.7:1 as WCAG defines it, and the rule would condemn a disc the eye reads fine."""
    def ch(v):
        v /= 255.0
        return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
    return 0.2126 * ch(color[0]) + 0.7152 * ch(color[1]) + 0.0722 * ch(color[2])


def _contrast(a, b):
    """the WCAG contrast ratio between two colours, 1:1 .. 21:1"""
    la, lb = _rel_luma(a), _rel_luma(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


@rule("F-MARKCONTRAST", "error", "a mark reads on its own disc: CONTRAST_MIN between the "
      "resolved mark colour and the disc fill", "live")
def f_markcontrast():
    """colors.mark_color decides WHICH way a mark knocks out of a disc — white, or black
    once the fill is light enough to swallow it (audit ICO-13) — but that decision is only
    as good as the fills it is handed, and a brand may pin its own mark colour instead.
    So the result is measured on every screen the device can show: resolve the token style
    the renderer will resolve, then hold the mark against the disc it lands on. On this
    panel the mark IS the meaning — the network, the family, the outcome — and it is read
    at 30 cm on a 1.65-inch screen (DESIGN.md § Canvas), so 3:1 is the floor, not the target.

    Logo art is skipped: a full-bleed logo has no knock-out colour to judge, it ships as
    the brand drew it. An "unknown" token wears a gradient, judged on the ramp's fill
    stop — the darkest thing the mark ever sits on."""
    from pq1 import components
    out, seen = [], set()

    def look(where, spec):
        st = components.token_style_from_spec(spec)
        if st["art"] or st["icon_color"] is None:
            return
        fill = tuple(colors.ramp_palette(st["ramp"])[0] if st["variant"] == "unknown"
                     else st["fill"] or colors.BLACK)
        mark = tuple(st["icon_color"])
        ratio = _contrast(mark, fill)
        key = f"icon={spec.get('icon')!r} {mark} on {fill}"
        if ratio < CONTRAST_MIN and (where, key) not in seen:
            seen.add((where, key))
            out.append(V(where, key, f"the mark reads {ratio:.2f}:1 against its disc, under the "
                         f"{CONTRAST_MIN:g}:1 a meaningful graphic needs — darken the fill, or pin the "
                         f"mark colour the brand wants (colors.CHAIN_MARK_COLORS)"))

    for n, mod in _flow_mods():
        for e in [None] + sorted(getattr(mod, "ENDS", {})):
            try:
                scr = flows.screens(n, end=e)
            except Exception:                                # noqa: BLE001  (F-NORM owns that)
                continue
            for s_ in scr:
                look(f"flow:{n}", s_)
    for qual, mod in sorted(screens.modules().items()):
        for sp in [getattr(mod, "SPEC", {})] + list(getattr(mod, "PRESETS", {}).values()):
            try:
                sp = layout.normalize_screens([dict(sp, kind=sp.get("kind", "status"))])[0]
            except Exception:                                # noqa: BLE001  (X-VALIDATE owns that)
                pass
            look(f"screens/{qual}.py", sp)
    return out


@rule("F-ASSET", "error", "every registered logo found its file — the '?' monogram is unreachable", "live")
def f_asset():
    """components.register_logo builds a glyph from pq1/assets/<file> and flags it
    full_bleed; when the file is NOT there, resolve_glyph falls all the way through to
    monogram("?") and the flag comes back False — the token would ship wearing a question
    mark, on the one screen where the user is checking what they are signing for.
    DESIGN.md calls a missing asset a build error (audit ICO-14 / G17-04), so this rule
    makes it one: every glyph that went through register_logo must have found its art, and
    every symbol in TOKEN_LOGOS must name a registered glyph that IS art. The flows are
    imported first — a family's mark registers on import — so the rule sees the whole
    registry rather than the part this process happened to touch."""
    from pq1 import components
    _flow_mods()
    out = []
    for name, fn in sorted(components.GLYPHS.items()):
        if hasattr(fn, "full_bleed") and not fn.full_bleed:
            out.append(V("pq1/components.py::GLYPHS", f"{name!r}", "registered as logo art whose file is "
                         "missing from pq1/assets/ — the disc would wear the '?' monogram"))
    for sym, stem in sorted(components.TOKEN_LOGOS.items()):
        if not components.is_art(stem):
            out.append(V("pq1/components.py::TOKEN_LOGOS", f"{sym} -> {stem!r}", "names a logo that is not "
                         "registered art — token_defaults would hand the token a glyph it does not have"))
    return out


def _text_screens():
    """every detail/value screen a flow can put on the panel, deduped:
    (flow, screen id, size, full-width?, [page, ...]).

    A paged value is ONE screen at one size (DESIGN.md § Text rules, Pages),
    so it is carried whole — never judged a page at a time."""
    seen, out = set(), []
    for n, mod in _flow_mods():
        variants = [dict(end=e) for e in [None] + sorted(getattr(mod, "ENDS", {}))]
        variants += [dict(sample=s.get("symbol")) for s in flows.samples(n)
                     if s.get("symbol")]
        for kw in variants:
            try:
                scr = flows.screens(n, **kw)
            except Exception:                                # noqa: BLE001
                continue          # F-NORM owns a flow that will not build
            for s in scr:
                if s["kind"] not in ("detail", "value") or s.get("words"):
                    continue
                pages = [p for p in (s.get("pages") or [s.get("lines") or []]) if p]
                if not pages:
                    continue
                key = (n, s["id"], s["size"],
                       tuple(tuple(layout.line_str(ln) for ln in p) for p in pages))
                if key in seen:
                    continue
                seen.add(key)
                out.append((n, s["id"], s["size"], s["kind"] == "value", pages))
    return out


@rule("T-WIDTH", "error", "every detail line MEASURES inside the text region, in its own face "
      "(a character count is not a width)", "live")
def t_width():
    out = []
    for n, sid, size, full, pages in _text_screens():
        budget = layout.TEXT_REGION_FULL_W if full else layout.TEXT_REGION_W
        for pi, page in enumerate(pages):
            for ln in page:
                w = layout.line_width(ln, size)
                if w > budget:
                    pg = f" page {pi + 1}" if len(pages) > 1 else ""
                    out.append(V(f"flow:{n}", f"{sid}{pg}: {layout.line_str(ln)!r}@{size}",
                                 f"measures {w:.1f} px in a {budget:.0f} px region — the line "
                                 f"clips. Drop a tier, re-break the value, or page it "
                                 f"(DESIGN.md § Typography, Choosing the size)"))
    return out


@rule("T-FIT", "info", "detail screens whose typed size is below the largest tier that fits "
      "(reported only — a typed size is the author's pin)", "live")
def t_fit():
    out = []
    for n, sid, size, full, pages in _text_screens():
        budget = layout.TEXT_REGION_FULL_W if full else layout.TEXT_REGION_W
        try:                      # one size for the whole screen: its widest page
            best = min(layout.fit_size(p, full=full) for p in pages)
        except ValueError:
            continue              # T-WIDTH owns a screen that fits no tier
        if best > size:
            widest = max((layout.line_width(ln, best) for p in pages for ln in p))
            out.append(V(f"flow:{n}", sid,
                         f"typed {size}, measures to {best} "
                         f"({widest:.1f} px of {budget:.0f})"))
    return out


@rule("C-RAMP", "error", "the mono ramp is reached only by an explicit pin — the hash space excludes it", "live")
def c_ramp():
    """MONO_RAMP is the treatment for a token the device RECOGNIZES: black body, white ring,
    white mark, grey trail (DESIGN.md § Color), and the SEND flow pins ETH to it. So a HASHED
    key must never land there — while `placeholder_index` hashed over all 14 ramps, roughly one
    unrecognized symbol or contract address in 14 rendered pixel-identical to ether on a signing
    screen, where the disc is part of what the user checks (audit COL-01). The hash now stops at
    MONO_RAMP; this rule is what keeps it stopped as the code moves. The only way to ramp 13 is
    an explicit integer pin — `token={"palette": colors.MONO_RAMP}`, which `token_defaults` sets
    for ETH / WETH and for a logo token with no ramp of its own. A brand name (FINGERPRINT,
    FIRMWARE) that reuses the mono STOPS resolves to its own key, not to 13, so it is not this
    rule's business."""
    from pq1 import components
    out, seen = [], set()

    def check(where, sp):
        if components.token_ramp(sp) != colors.MONO_RAMP:
            return
        pal = (sp.get("token") or {}).get("palette")
        if isinstance(pal, int) and not isinstance(pal, bool):
            return                                   # the explicit pin: what mono is for
        key = f"token={(sp.get('token') or {})!r} icon={sp.get('icon')!r}"
        if (where, key) in seen:
            return
        seen.add((where, key))
        out.append(V(where, key, "resolves to colors.MONO_RAMP without pinning it — the "
                                 "recognized-token look (black body, white ring, ether mark) "
                                 "would dress a token the device does not recognize"))

    for n, mod in _flow_mods():
        for e in [None] + sorted(getattr(mod, "ENDS", {})):
            try:
                scr = flows.screens(n, end=e)
            except Exception:                                # noqa: BLE001  (F-NORM owns that)
                continue
            for s_ in scr:
                check(f"flow:{n}", s_)
    for qual, mod in sorted(screens.modules().items()):
        for sp in [getattr(mod, "SPEC", {})] + list(getattr(mod, "PRESETS", {}).values()):
            check(f"screens/{qual}.py", sp)
    return out


CHAIN_RAMP_MIN_DE = 20.0   # CIE76 ΔE: below this, two discs read as one colour at 30 cm


def _lab(color):
    """sRGB -> CIELAB (D65), for a perceptual distance between two disc fills"""
    def ch(v):
        v /= 255.0
        return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(v) for v in color[:3])
    x = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047
    y = 0.2126 * r + 0.7152 * g + 0.0722 * b
    z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883
    f = lambda t: t ** (1 / 3) if t > 0.008856 else 7.787 * t + 16 / 116   # noqa: E731
    return 116 * f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z))


def _delta_e(a, b):
    return sum((p - q) ** 2 for p, q in zip(_lab(a), _lab(b))) ** 0.5


@rule("C-CHAINRAMP", "error", "no hashable placeholder ramp wears the Mainnet chain disc's "
      "colour", "live")
def c_chainramp():
    """The chain screen for id 1 fills its disc #627EEA — Ethereum's own blue — and says "on
    Mainnet". Ramp 12 used to fill #4C73CF, ΔE 10.5 from it, so roughly one unknown token in
    thirteen arrived dressed as the network the user was about to sign on (user decision, Sep
    2026; the ramp was replaced by leaf green in place). A HASHED ramp is the one colour the
    device chooses without knowing what the token is, so it must not borrow the identity the
    chain screen just established. Only the ramps `placeholder_index` can reach from a string
    are measured — an explicit int pin is a flow's own choice."""
    out = []
    main = colors.BRAND_PALETTES["CHAIN:MAINNET"][0]
    for i in range(colors.MONO_RAMP):              # the string hash space, 0..MONO_RAMP-1
        fill = colors.placeholder_palette(i)[0]
        d = _delta_e(fill, main)
        if d < CHAIN_RAMP_MIN_DE:
            out.append(V("pq1/colors.py", f"PLACEHOLDER_GRADIENTS[{i}] fill {tuple(fill)}",
                         f"sits ΔE {d:.1f} from the Mainnet disc {tuple(main)}, under "
                         f"{CHAIN_RAMP_MIN_DE:g} — an unknown token would wear Ethereum's "
                         f"colour; move the ramp's hue away"))
    return out


@rule("C-INK", "error", "an ink tint is a named token — no bare alpha typed into colors.scale", "ast")
def c_ink():
    """The greys are a vocabulary of three tiers (INK_SECONDARY / INK_PAGING / INK_MUTED,
    pq1/colors.py), and a screen names the tier it means. Before audit COL-06 the same 80 %
    was a constant in one module and a typed 0.8 in another, and the 70 % ring had no name
    at all — so handoff/spec/colors.json could publish only the half that had names, and a
    port had to read the rest out of prose. A literal here is how that comes back: it draws
    correctly today and drifts from its tier tomorrow. Pass the token instead; if a genuinely
    new tier is needed, it gets a name in colors.py first. colors.py itself is exempt — that
    is where the numbers live.

    A FADE is not a tint, which is why only scale(WHITE, ...) counts: the canvas takes the
    screen's alpha as its own argument, so scaling some other colour by a computed factor is
    the alpha idiom doing its job, not an ink tier being retyped."""
    out = []
    white = {"WHITE", "colors.WHITE"}
    for p in py_files("pq1", "screens"):
        if rel(p) == "pq1/colors.py":
            continue

        class W(Scoped):
            def visit_Call(s, node):
                f = node.func
                if (getattr(f, "attr", getattr(f, "id", "")) == "scale" and len(node.args) >= 2
                        and s.seg(node.args[0]) in white):
                    k = node.args[1]
                    if (isinstance(k, ast.Constant) and isinstance(k.value, (int, float))
                            and not isinstance(k.value, bool) and k.value not in (0, 1)):
                        out.append(V(s.scope(), s.seg(node), f"a bare {k.value:g} ink tint — "
                                     f"name it in colors.py and pass the token", node.lineno))
                s.generic_visit(node)
        w = W(p); w.visit(w.tree)
    return out


@rule("I-ARMED", "error", "a live hold never fades a chevron: both corner chevrons stay, "
      "whichever side is held", "live")
def i_armed():
    """DESIGN.md § Input: a hold keeps BOTH chevrons (user decision, Sep 2026 — "it should
    keep on showing both chevrons"). Audit A11-01 had the un-held corner fade so a sign and a
    decline would differ; the user retired that cue, and this rule keeps it retired.

    Measured through the real driver, cropped to the chevron row so the disc's own hold fill
    (and a hero's circle pulled home by the press) cannot answer a question asked about the
    chevrons: on the ask and on a detail, a left hold and a right hold draw the chevron row
    exactly as an untouched screen does, at every sampled moment of the hold."""
    import hashlib
    from pq1.driver import FlowDriver, LEFT, RIGHT
    step = motion.FRAME_MS
    CHEV_BAND_H = 40        # the chevron row: slots at y 19, half-height ~4, bob 4
    out = []

    def walk(taps, side, offsets):
        """chevron-row hashes at `offsets` after a press of `side` on the screen `taps`
        right taps in — side=None presses nothing (the control)"""
        scr, sign, decline = flows.playable("send")
        d = FlowDriver(scr, sign, decline)
        t = 0.0
        for _ in range(40):
            d.frame(t); t += step
        for _ in range(taps):                       # tap forward into the details
            d.press(RIGHT, t); d.release(RIGHT, t + 50)
            for _ in range(40):
                t += step; d.frame(t)
        if side is not None:
            d.press(side, t)
        return [hashlib.sha256(d.frame(t + o).crop((0, 0, layout.W, CHEV_BAND_H))
                               .tobytes()).hexdigest() for o in offsets]

    offsets = [motion.TAP_MAX_MS - step, 800, 1500]
    for taps, where in ((0, "flow:send hero"), (1, "flow:send detail")):
        rest = walk(taps, None, offsets)
        for side, name in ((LEFT, "left"), (RIGHT, "right")):
            for o, a, b in zip(offsets, walk(taps, side, offsets), rest):
                if a != b:
                    out.append(V(where, f"{name} hold t+{o:g} ms",
                                 "the chevron row changes while a hold is live — both "
                                 "chevrons must stay, whichever side is held"))
    return out


@rule("I-LEFT", "error", "a left tap on an idle screen never goes forward — back one screen or "
      "nothing", "live")
def i_left():
    """DESIGN.md § Input, "The ask is the hub; left never leads on" (user rule, Sep 2026).
    Until then a hero had "no left or right": either tap entered the details, so pressing
    LEFT on an idle screen moved the signer forward. Measured through the real driver on
    every hero of every flow: the left tap must land behind the screen or not move
    (layout.back_target). The chevrons are NOT part of it: a hero keeps both even where
    left does nothing (user decision, Sep 2026)."""
    from pq1.driver import FlowDriver, LEFT
    out, seen = [], 0
    for n, _ in _flow_mods():
        try:
            scr, sign, decline = flows.playable(n)
        except Exception:                                    # noqa: BLE001  (F-NORM owns that)
            continue
        for i, s_ in enumerate(scr):
            if s_.get("kind") != "hero":
                continue
            seen += 1
            d = FlowDriver(scr, sign, decline)
            d.sim.go_to(i, 0)
            d.sim.cur = i
            d._tap(LEFT, 10)
            land = d.sim.cur
            if land > i:
                out.append(V(f"flow:{n}", f"{s_.get('id')} (screen {i})",
                             f"a left tap goes FORWARD to screen {land} — left never leads on"))
    if not seen:
        out.append(V("flows", "no hero", "I-LEFT measured nothing — the flow walk is broken"))
    return out


@rule("C-CONTRAST", "error", "the colour system's own legibility floors hold: a placeholder "
      "disc carries its white ring and mark, an ink reads on black, a mark reads through the "
      "hold film", "live")
def c_contrast():
    """The floors existed only as a comment in colors.py until Sep 2026 (audit A11-05).

    A placeholder ramp's fill stop is the one colour in the system chosen AGAINST something
    drawn on top of it — the white ring every token wears and the white mark inside it — so
    its luminance is a constraint, not taste. The darkest ramp today measures 4.506 against
    a 4.5 floor: six thousandths of headroom, which is exactly why one "darken ramp 12 a
    touch" edit must fail the build rather than ship. The panel quantises to RGB565, which
    only eats margin, never adds it.

    Two cheaper guards ride along, both passing today with room to spare, both there so a
    future edit cannot take them silently: every named ink tier has to read on the black
    panel, and a mark has to survive the hold film rising over its disc (the film is 30 %
    black over a coloured body, so the mark's ground darkens to 70 % of the fill exactly
    when the user is committing — the worst moment to lose it).

    Chain brand colours are NOT measured here: a chain mark is a logo, F-MARKCONTRAST holds
    it to the 3:1 a graphic needs, and three of them (mainnet 3.69, op 3.97, avalanche 3.99)
    sit between the two floors by design."""
    from pq1 import components
    out = []
    floor = colors.PLACEHOLDER_MIN_CONTRAST
    for i, ramp in enumerate(colors.PLACEHOLDER_GRADIENTS):
        if i == colors.MONO_RAMP:
            continue                      # the black body: its mark and ring are the point
        fill = colors.placeholder_palette(i)[0]
        ratio = _contrast(fill, colors.WHITE)
        if ratio < floor:
            out.append(V("pq1/colors.py", f"PLACEHOLDER_GRADIENTS[{i}] fill {tuple(fill)}",
                         f"reads {ratio:.3f}:1 against the white ring and mark, under the "
                         f"{floor:g}:1 floor — darken the fill stop (the taper leaves stop 1 "
                         f"alone so the far trail keeps its values)"))
    for name in ("INK_SECONDARY", "INK_PAGING", "INK_MUTED"):
        ink = colors.scale(colors.WHITE, getattr(colors, name))
        ratio = _contrast(ink, colors.BLACK)
        if ratio < floor:
            out.append(V("pq1/colors.py", f"{name} {tuple(ink)}",
                         f"reads {ratio:.3f}:1 on the black panel, under {floor:g}:1"))
    seen = set()
    for i, ramp in enumerate(colors.PLACEHOLDER_GRADIENTS):
        fill = tuple(colors.placeholder_palette(i)[0])
        under = tuple(colors.scale(fill, 1 - components.HOLD_OVERLAY_ALPHA))
        mark = tuple(colors.mark_color(fill))
        ratio = _contrast(mark, under)
        key = (mark, under)
        if ratio < CONTRAST_MIN and key not in seen:
            seen.add(key)
            out.append(V("pq1/components.py", f"hold film over ramp {i} {under}",
                         f"the mark reads {ratio:.2f}:1 once the film has risen over it, under "
                         f"{CONTRAST_MIN:g}:1 — the fill is too light for a black film"))
    return out


@rule("T-TOKEN", "error", "a type size or tracking is a typography token — no bare size= / ls= "
      "number, no typed *_SIZE / *_LS constant, outside pq1/typography.py", "ast")
def t_token():
    """The scale lives in pq1/typography.py and nowhere else (audit TY-08). Before this rule
    the hero caption, the Confirm? prompt, both label sites and the loading film's caption
    typed 18 / 0.5 / 36 / 16 / 1 as bare numbers that merely EQUALLED the tokens, and the
    PIN hints typed a 0.5 tracking that matched nothing — so changing SIZE_LABEL or
    LS_QUESTION would have restyled half the captions and none of the rest, and the handoff
    had to warn the port not to copy the duplication. A size= or ls= keyword reads a
    typography token (or a value computed from one); a module constant named *_SIZE or
    *_LS is derived from one, never typed. typography.py itself is exempt — that is where
    the numbers live. flows/ type size= by design (the author's fitted pin, which T-FIT
    reports) and are not walked."""
    out = []
    typed = re.compile(r".+_(SIZE|LS)$")
    for p in py_files("pq1", "screens"):
        if rel(p) == "pq1/typography.py":
            continue

        class W(Scoped):
            def visit_Call(s, node):
                for kw in node.keywords:
                    v = kw.value
                    if (kw.arg in ("size", "ls") and isinstance(v, ast.Constant)
                            and isinstance(v.value, (int, float))
                            and not isinstance(v.value, bool)):
                        out.append(V(s.scope(), s.seg(node)[:60], f"a bare {kw.arg}={v.value:g} — "
                                     f"read the typography token", node.lineno))
                s.generic_visit(node)

            def visit_Assign(s, node):
                t = node.targets
                if (not s.stack and len(t) == 1 and isinstance(t[0], ast.Name)
                        and typed.match(t[0].id) and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, (int, float))
                        and not isinstance(node.value.value, bool)):
                    out.append(V(s.scope(), t[0].id, f"{t[0].id} = {node.value.value:g} typed — "
                                 f"derive it from a typography token", node.lineno))
                s.generic_visit(node)
        w = W(p); w.visit(w.tree)
    return out


#: the two shortenings DESIGN.md § Text rules sanctions, and nothing else.
#: Both spell the gap with the real Aileron ellipsis — three ASCII periods are
#: never right, which is how the legacy Safe hash read as accidental (TY-02).
ELLIPSIS = "…"
DATA_HASH_HALF = 12     # DATA HASH: first 12 + … + last 12 at 28, a fingerprint
NAMED_ADDR_HALF = 8     # a resolved recipient: first 8 + … + last 8 under its name


def _screen_lines(s):
    """every value line of one screen, page by page — normalize_screens back-fills
    `lines` from pages[0], so the pages carry what `lines` alone would miss"""
    out = list(s.get("lines") or [])
    for p in s.get("pages") or []:
        out += list(p)
    return out


def _sanctioned(s, text):
    """is this shortened line one of the two DESIGN.md names? (the real … only)"""
    head, _, tail = text.partition(ELLIPSIS)
    if ELLIPSIS in tail:                       # one gap per value, never two
        return False
    lines = [layout.line_str(ln) for ln in _screen_lines(s)]
    label = (s.get("label") or s.get("id") or "").upper()
    if label == "DATA HASH":
        # the head rides the line ABOVE: [first 12, "…" + last 12] at 28
        return (head == "" and len(tail) == DATA_HASH_HALF
                and len(lines) == 2 and len(lines[0]) == DATA_HASH_HALF)
    # a resolved recipient: first 8 + … + last 8, under its SemiBold name
    named = any(layout.line_weight(ln) == "semibold" for ln in _screen_lines(s))
    return named and len(head) == NAMED_ADDR_HALF and len(tail) == NAMED_ADDR_HALF


@rule("F-ELLIPSIS", "error", "no ellipsis in a value the signer must verify — a hash pages, it never shortens "
                             "(DESIGN.md § Text rules, The two sanctioned shortenings)", "live")
def f_ellipsis():
    """The value a signer is asked to check is the whole point of the screen, so the
    design system shows it whole: split mid-string, paged, or on its own screen. Exactly
    two values shorten — the blind-call DATA HASH (a fingerprint matched against the
    dapp, not read) and a resolved recipient under its SemiBold name — and DESIGN.md
    names both. Everything else fails here.

    This caught nothing for a year because no rule read a line's TEXT: the Safe TX HASH
    shipped 26 of 66 characters, carried verbatim out of the pre-PQ1 flow, and three
    auditors had to find it by eye (audit TY-02 / HS-01, Sep 2026)."""
    out = []
    seen = set()
    for n, mod in _flow_mods():
        for e in [None] + sorted(getattr(mod, "ENDS", {})):
            try:
                scr = flows.screens(n, end=e)
            except Exception:                                # noqa: BLE001  (F-NORM owns that)
                continue
            for s_ in scr:
                for ln in _screen_lines(s_):
                    text = layout.line_str(ln)
                    if ("..." not in text and ELLIPSIS not in text) or (n, text) in seen:
                        continue                             # every ending walks the same screens
                    seen.add((n, text))
                    if "..." in text:
                        out.append(V(f"flow:{n}", text,
                                     "three ASCII periods are never a shortening — the sanctioned "
                                     f"two spell the gap {ELLIPSIS!r}, and a value the signer "
                                     "verifies is not shortened at all: page it (`pages`)"))
                    elif ELLIPSIS in text and not _sanctioned(s_, text):
                        out.append(V(f"flow:{n}", text,
                                     f"{s_.get('label') or s_.get('id')} is shortened, but it is "
                                     "neither of the two shortenings DESIGN.md sanctions — show it "
                                     "whole: split it mid-string, or page it (`pages`)"))
    return out


@rule("F-RETURN", "warn", "the walk returns to the ask: the last navigable screen before an ending is a hero that commits", "live")
def f_return():
    out = []
    for n, mod in _flow_mods():
        # A BENCH flow signs nothing — no ENDS — so it has no ask to return
        # to: the palettes and chains tours walk their set and stop. Same
        # exemption F-NORM makes; testing for details instead only happened
        # to cover the bench flows whose screens are all heroes or all status.
        if not getattr(mod, "ENDS", {}):
            continue
        scr = flows.screens(n)
        if not any(s["kind"] in ("detail", "value") for s in scr):
            continue
        for a, b in layout._segments(scr):
            nav = [s for s in scr[a:b] if s["kind"] != "status"]
            if nav and not (nav[-1]["kind"] == "hero" and nav[-1].get("commit")):
                out.append(V(f"flow:{n}", f"segment {a}-{b} ends on {nav[-1].get('id')}",
                             "the screen before the ending is not a committing hero — where does the user sign?"))
    return out


@rule("X-VALIDATE", "warn", "unknown names raise — no silent fallback (DESIGN.md § Screen schema)", "live")
def x_validate():
    bad = {"kind": dict(kind="banner"),
           "size": dict(kind="detail", side="left", label="TO", lines=["x"], size=30),
           "side": dict(kind="detail", label="TO", lines=["x"], side="top"),
           "chev": dict(kind="hero", bottom="X?", chev="down"),
           # no per-screen nudges (audit LAY-10) and no label on a value screen
           # — a words grid has no caption (LAY-08 / LAY-14)
           "circle_x": dict(kind="detail", side="left", label="TO", lines=["x"], circle_x=291),
           "label": dict(kind="value", words=["a"] * 8, label="KEY FINGERPRINT"),
           # a words grid pages up to WORDS_TOTAL_MAX (24, the setup seed), never past it
           "words": dict(kind="value", words=["a"] * (layout.WORDS_TOTAL_MAX + 1))}
    out = []
    for name, sp in bad.items():
        try:
            layout.normalize_screens([copy.deepcopy(sp)])
            out.append(V("pq1/layout.py::normalize_screens", f"{name}={sp[name]!r}",
                         f"an unknown {name} is accepted silently"))
        except Exception:                                    # noqa: BLE001
            pass
    return out


@rule("G-CONFIRM", "error", "the Confirm? anchors are the chain composition: "
      "(CONFIRM_TEXT_X, CONFIRM_CIRCLE_X) == chain_compose(\"Confirm?\", SIZE_XL)", "live")
def g_confirm():
    got = layout.chain_compose("Confirm?", typography.SIZE_XL)
    pin = (layout.CONFIRM_TEXT_X, layout.CONFIRM_CIRCLE_X)
    if got == pin:
        return []
    return [V("pq1/layout.py::CONFIRM_TEXT_X", f"pinned {pin}",
              f"chain_compose gives {got} — the Confirm? screen is composed like the "
              f"chain screen; re-pin the two constants (DESIGN.md § Layout grid)")]


# -------------------------------------------------------------------- docs ---
_CLAIM = re.compile(r"`(?:[a-z_]+\.)?([A-Z][A-Z0-9_]{3,})`\s*(?:\(|=|:|is|of)?\s*(?:= )?(-?\d+(?:\.\d+)?)\b(\s?s\b)?(?!\s*(?:px|%|/))")


def _namespaces():
    from pq1 import components, loading
    # colors joined the list with the ink tiers (audit COL-06): DESIGN.md's
    # Color table now writes `INK_PAGING` (0.8) and the like, and a claim the
    # namespace cannot see is worse than no claim — it reads as checked and
    # silently is not.
    # typography joined for the type audit (TY-08): DESIGN.md's `SIZE_LABEL` (16)
    # and `SIZE_DISPLAY` (40) rows read as checked and were not.
    # pin_slots joined with the PIN cursor's three cues (A11-10): § Input now
    # writes `ACTIVE_LW` (3) and `ACTIVE_LIFT` (4), and a port that keeps only
    # the hue is the failure this claim exists to prevent — so it has to be
    # a claim the checker can actually see.
    from pq1.procedural import pin_slots
    mods = ([motion, status, verdict, layout, components, loading, colors, typography,
             pin_slots] + list(screens.modules().values()))
    ns = {}
    for m in mods:
        for k, v in vars(m).items():
            if k.isupper() and isinstance(v, (int, float)) and not isinstance(v, bool):
                ns.setdefault(k, set()).add(v)
    return ns


@rule("D-CLAIMS", "error", "every `NAME` (number) in pq1/DESIGN.md equals the live value", "regex")
def d_claims():
    ns = _namespaces()
    out = []
    path = os.path.join(REPO, "pq1", "DESIGN.md")
    for i, ln in enumerate(open(path).read().replace("−", "-").splitlines(), 1):
        for m in _CLAIM.finditer(ln):
            name, num = m.group(1), float(m.group(2))
            if m.group(3) and name.endswith(("_MS", "_DWELL")):
                num *= 1000                     # the doc speaks seconds, the token is ms
            if name in ns and num not in ns[name]:
                out.append(V("pq1/DESIGN.md", f"{name} {m.group(2)}", f"the doc says {m.group(2)}; the code "
                             f"says {sorted(ns[name])}", i))
    return out


# ----------------------------------------------------------------- handoff ---
@rule("S-FRESH", "error", "handoff/spec matches the live code (rebuild with python3 -m tools.handoff)", "live")
def s_fresh():
    spec_dir = os.path.join(REPO, "handoff", "spec")
    if not os.path.isdir(spec_dir):
        return []
    import json
    from tools.handoff import build
    live = build.build_specs(fast_only=True)
    out = []
    for name, data in live.items():
        p = os.path.join(spec_dir, name)
        disk = json.load(open(p)) if os.path.exists(p) else {}
        for d in build._diff(disk, json.loads(build.dump(data)))[:6]:
            out.append(V(f"handoff/spec/{name}", d, "stale — the code moved since handoff/ was built"))
    return out


@rule("S-SKILLCOPY", "error", "handoff/skill is a byte-identical copy of .claude/skills/pq1-conformance", "hash")
def s_skillcopy():
    src = os.path.join(REPO, ".claude", "skills", "pq1-conformance")
    dst = os.path.join(REPO, "handoff", "skill", "pq1-conformance")
    if not (os.path.isdir(src) and os.path.isdir(dst)):
        return []
    out = []
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in files:
            if f == ".DS_Store":
                continue
            a = os.path.join(root, f)
            b = os.path.join(dst, os.path.relpath(a, src))
            if not os.path.exists(b) or open(a, "rb").read() != open(b, "rb").read():
                out.append(V(rel(b), "differs", "edit the source under .claude/skills/, then rebuild handoff/"))
    return out


@rule("A-FLOOR", "error", "a visibility guard reads colors.ALPHA_FLOOR / FILM_FLOOR or motion.LEVEL_EPS — "
      "no bare small number compared against an alpha", "ast")
def a_floor():
    """Which frame a fading element vanishes on used to be per-file luck (audit RAD-13): 49
    guards typed 0.01, the pulse typed 0.02, the dim films 0.003 and one 0.004, and none of
    them was the panel's. The NV3007 takes RGB565 by truncation, so the first alpha that
    reaches the glass is colors.ALPHA_FLOOR (0.0137, owner decision); a black film over ink
    already drawn uses colors.FILM_FLOOR; a hold fill's LEVEL is not an alpha and uses
    motion.LEVEL_EPS. The rule flags a comparison of an ALPHA-named operand (alpha, a, al,
    ga, ta, fa, k, *_a, a_*, P["..._a"]) against a bare constant under 0.05 in pq1/ and
    screens/. Geometric and progress epsilons (a distance d, an entrance progress u, a face
    normal) are not alphas and are left alone. colors.py and motion.py are where the
    numbers live."""
    alpha_name = re.compile(r"^(alpha|a|al|ga|ta|fa|k|[a-z0-9]+_a|a_[a-z0-9]+)$")
    out = []
    for p in py_files("pq1", "screens"):
        if rel(p) in ("pq1/colors.py", "pq1/motion.py"):
            continue

        class W(Scoped):
            def visit_Compare(s, node):
                ops = [node.left] + list(node.comparators)
                small = [o for o in ops if isinstance(o, ast.Constant)
                         and isinstance(o.value, float) and 0 < o.value < 0.05]
                if small:
                    names = set()
                    for o in ops:
                        for n in ast.walk(o):
                            if isinstance(n, ast.Name):
                                names.add(n.id)
                            elif (isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant)
                                  and isinstance(n.slice.value, str)):
                                names.add(n.slice.value)
                    if any(alpha_name.match(x) for x in names):
                        out.append(V(s.scope(), s.seg(node)[:60],
                                     f"a bare {small[0].value:g} visibility floor — read "
                                     f"colors.ALPHA_FLOOR (FILM_FLOOR for a dim film, "
                                     f"motion.LEVEL_EPS for a fill level)", node.lineno))
                s.generic_visit(node)
        w = W(p); w.visit(w.tree)
    return out
