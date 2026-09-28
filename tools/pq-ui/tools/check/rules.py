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

from pq1 import colors, layout, motion, status, verdict      # noqa: E402
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


@rule("V-HOLD", "error", "every resolving screen rests RESULT_HOLD_MS after t_resolve", "live")
def v_hold():
    out = []
    for k, an, m in verdict_instances():
        if not an.t_resolve:                 # an idle loop never resolves
            continue
        hold = an.duration - an.t_resolve
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


@rule("M-ACCENT", "error", "no one-shot phase in screens/ is shorter than VERDICT_ACCENT_MIN_MS (two panel frames)", "live")
def m_accent():
    out = []
    for qual, mod in sorted(screens.modules().items()):
        for k, v in vars(mod).items():
            if (k.startswith("T_") and isinstance(v, (int, float)) and not isinstance(v, bool)
                    and 0 < v < motion.VERDICT_ACCENT_MIN_MS):
                out.append(V(f"screens/{qual}.py", f"{k}={v}", f"{v} ms is under two panel frames "
                             f"({motion.VERDICT_ACCENT_MIN_MS}) — the panel may never show it"))
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
    out = []
    for n in sorted(public):
        if re.search(rf"\b{n}\b", corpus):
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
                or live.duration - live.t_resolve != status.RESULT_HOLD_MS):
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
        for e in [None] + sorted(getattr(mod, "ENDS", {})):
            try:
                scr = flows.screens(n, end=e)
            except Exception as ex:                          # noqa: BLE001
                out.append(V(f"flow:{n}", f"end={e}", f"does not build: {ex}"))
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


@rule("F-RETURN", "warn", "the walk returns to the ask: the last navigable screen before an ending is a hero that commits", "live")
def f_return():
    out = []
    for n, _ in _flow_mods():
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
    bad = {"kind": dict(kind="banner"), "size": dict(kind="detail", label="TO", lines=["x"], size=30),
           "side": dict(kind="detail", label="TO", lines=["x"], side="top"),
           "chev": dict(kind="hero", bottom="X?", chev="down")}
    out = []
    for name, sp in bad.items():
        try:
            layout.normalize_screens([copy.deepcopy(sp)])
            out.append(V("pq1/layout.py::normalize_screens", f"{name}={sp[name]!r}",
                         f"an unknown {name} is accepted silently"))
        except Exception:                                    # noqa: BLE001
            pass
    return out


# -------------------------------------------------------------------- docs ---
_CLAIM = re.compile(r"`(?:[a-z_]+\.)?([A-Z][A-Z0-9_]{3,})`\s*(?:\(|=|:|is|of)?\s*(?:= )?(-?\d+(?:\.\d+)?)\b(\s?s\b)?(?!\s*(?:px|%|/))")


def _namespaces():
    from pq1 import components, loading
    mods = [motion, status, verdict, layout, components, loading] + list(screens.modules().values())
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
