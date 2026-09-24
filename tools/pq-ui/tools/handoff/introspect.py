"""Machine-readable specs, dumped from the LIVE code — never hand-typed.

Each builder returns plain JSON-able data; build.py writes them under
handoff/spec/ with sort_keys and no timestamps, so a rebuild of unchanged
code is byte-identical and `--check` can diff them.
"""
import ast
import copy
import hashlib
import importlib
import inspect
import math
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCHEMA_VERSION = 1
PANEL_FPS = 14                      # the NV3007's rate (pq1 has no constant for it)
FRAME_MS = 1000.0 / PANEL_FPS

from pq1 import (colors, components, driver, flow, layout, loading,  # noqa: E402
                 motion, status, typography, verdict)
from pq1.procedural import burst                                    # noqa: E402
import flows                                                        # noqa: E402
import screens                                                      # noqa: E402

# A token's SCOPE tells a porter what to do with it. Four buckets, because
# "device or not" was too coarse: it exported a live timing (FADE_MS) as demo,
# so port_diff hard-failed a port that implemented it correctly, and it exported
# dead constants as device, so a port would implement them (audit X5-01, X5-04).
DEMO_TOKENS = {          # real behaviour, but only in the GIF / kiosk loop
    "HERO_DWELL": "demo auto-advance — on the device nothing moves without a press",
    "DETAIL_DWELL": "demo auto-advance",
    "STATUS_DWELL": "demo auto-advance; also the documented invariant "
                    "QubitCfg().t7 + RESULT_HOLD_MS (asserted at pq1/status.py)",
    "CONFIRM_DWELL": "demo auto-advance",
    "PAGE_SWAP_MS": "demo page-turn clock — on the device only a tap turns a page",
    "KIOSK": "demo-loop spring pace — the device uses NAV",
}
DEAD_TOKENS = {          # no reader anywhere: do not implement
    "MOVE_MS": "a pre-spring span estimate; nothing reads it (audit D4-12)",
    "HOLD_END": "documented in a burst.py comment, read by nothing (audit D8-09)",
}
SPEC_ONLY_TOKENS = {     # specified, but no live screen or flow reaches the path
    "PRESS_FEEDBACK_MS": "the press-down chevron nudge: specified in DESIGN.md § Input, "
                         "rendered by nothing in the Python — the port implements it from the spec",
    "ENTER_MS": "the explosion's side entrance; no live flow sets enter=, so the path is "
                "exercised only by the screens library",
}
CONTRACT_TOKENS = {      # a stated design bound that no code enforces
    "SWEEP_X_MIN": "a stated bound; nothing clamps to it (audit X6-02)",
    "SWEEP_X_MAX": "a stated bound; nothing clamps to it (audit X6-02)",
    "MARGIN": "the static grid margin; the moving art is not clamped to it (audit X6-08)",
}
# never exported: build-machine paths cannot travel and would break a byte-identical dump
NONPORTABLE = {"ASSET_DIR": "an absolute path on the build machine",
               "ETH_LOGO": "an absolute path on the build machine"}
# units the name alone does not imply
NAME_UNITS = {"HOLD_END": "ms", "PAGER_BASELINE": "px", "PAGER_ALPHA": "alpha",
              "REVS": "turns", "REVS_LONG": "turns",
              "R_MASTER": "px", "W": "px", "H": "px", "MARGIN": "px",
              "BAND_TOP": "px", "BAND_BOTTOM": "px", "BASELINE_Y": "px",
              "SUP": "factor", "WORDS_SIZE": "px", "WORDS_NUM_ALPHA": "alpha"}

_WARM = False


def warm_registries():
    """Import every flow family before dumping anything.

    Icon names are registered at IMPORT time (a family's __init__ calls
    components.register_glyph), so `components.GLYPHS` — and therefore the legal
    icon set the spec publishes — depends on what happens to have been imported
    (audit G17-07). Walking every flow makes the dump complete and deterministic;
    without this, `python3 -m tools.handoff` and `python3 -m tools.check` disagree.
    """
    global _WARM
    if not _WARM:
        for n in flows.names():
            flows.get(n)
        screens.modules()
        _WARM = True


_READER_SRC = None


def _reader_census():
    """name -> [file:line] of every site outside its own module that names it.
    Scope is COMPUTED from this, not hand-listed, so a token that gains or loses
    its last reader changes scope on the next build."""
    global _READER_SRC
    if _READER_SRC is None:
        _READER_SRC = []
        for top in ("pq1", "screens", "flows"):
            for root, dirs, files in os.walk(os.path.join(REPO, top)):
                dirs[:] = sorted(d for d in dirs if d != "__pycache__")
                for fn in sorted(files):
                    if fn.endswith(".py"):
                        pth = os.path.join(root, fn)
                        _READER_SRC.append((rel(pth), open(pth).read()))
    return _READER_SRC


def _readers(name, own_file):
    """where `name` is READ (code, not its own declaration or a comment)"""
    hits = []
    pat = re.compile(rf"\b{re.escape(name)}\b")
    for f, src in _reader_census():
        for i, line in enumerate(src.splitlines(), 1):
            code = line.split("#", 1)[0]
            if not pat.search(code):
                continue
            if f == own_file and re.match(rf"\s*{re.escape(name)}\s*(=|:)", code):
                continue                      # its own declaration
            hits.append(f"{f}:{i}")
    return hits


def _scope(name, own_file):
    if name in DEMO_TOKENS:
        return "demo", DEMO_TOKENS[name]
    if name in DEAD_TOKENS:
        return "dead", DEAD_TOKENS[name]
    if name in SPEC_ONLY_TOKENS:
        return "spec-only", SPEC_ONLY_TOKENS[name]
    if name in CONTRACT_TOKENS:
        return "contract", CONTRACT_TOKENS[name]
    if not _readers(name, own_file):
        return "dead", "no reader found in pq1/, screens/ or flows/"
    return "device", ""


def rel(path):
    return os.path.relpath(path, REPO)


def frames(ms):
    return round(ms / FRAME_MS, 1)


_ADDR = re.compile(r" at 0x[0-9a-fA-F]+")


def jsonable(v, depth=0):
    """JSON-able and DETERMINISTIC: the same code must dump byte-identical JSON in
    every process, so nothing may carry a memory address (repr of a function or a
    plain object does) — functions become their name, objects their fields."""
    if isinstance(v, bool) or v is None or isinstance(v, (int, str)):
        return v
    if isinstance(v, float):
        return v if math.isfinite(v) else repr(v)
    if isinstance(v, (list, tuple, set, frozenset)):
        seq = sorted(v, key=repr) if isinstance(v, (set, frozenset)) else v
        return [jsonable(x, depth + 1) for x in seq]
    if isinstance(v, dict):
        return {str(k): jsonable(x, depth + 1) for k, x in v.items()}
    if inspect.isroutine(v):
        return f"<{getattr(v, '__module__', '?')}.{getattr(v, '__qualname__', v.__name__)}>"
    if inspect.isclass(v):
        return f"<class {v.__module__}.{v.__qualname__}>"
    if inspect.ismodule(v):
        return f"<module {v.__name__}>"
    if hasattr(v, "__dict__") and depth < 6:
        return {k: jsonable(x, depth + 1) for k, x in vars(v).items()}
    return _ADDR.sub("", repr(v))


# ------------------------------------------------------------ source lines --
_LINES = {}


def _assign_lines(mod):
    """NAME -> (line, trailing comment) for module-level assignments"""
    if mod.__name__ not in _LINES:
        src = inspect.getsource(mod)
        text = src.splitlines()
        out = {}
        for node in ast.parse(src).body:
            names = []
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        names.append(t.id)
                    elif isinstance(t, ast.Tuple):
                        names += [e.id for e in t.elts if isinstance(e, ast.Name)]
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names.append(node.target.id)
            rhs = ast.get_source_segment(src, node.value) if hasattr(node, "value") else None
            for n in names:
                ln = text[node.lineno - 1]
                out[n] = (node.lineno,
                          ln.split("#", 1)[1].strip() if "#" in ln else "",
                          " ".join(rhs.split()) if rhs else "")
        _LINES[mod.__name__] = out
    return _LINES[mod.__name__]


def _class_attr_line(cls, name):
    """line of `name = ...` inside the class body that defines it (walks the MRO)"""
    for c in cls.__mro__:
        if name in vars(c) and c is not object:
            try:
                src, first = inspect.getsourcelines(c)
            except (OSError, TypeError):
                return None
            for i, ln in enumerate(src):
                if re.match(rf"\s+{re.escape(name)}\s*(=|:)", ln) or re.match(
                        rf"\s+def {re.escape(name)}\b", ln):
                    return rel(inspect.getsourcefile(c)), first + i
            return rel(inspect.getsourcefile(c)), first
    return None


def resolve(path):
    """'pq1.motion.ARRIVE_MS' | 'pq1.verdict.VerdictAnim.T_HOLD' -> the live object"""
    parts = path.split(".")
    for cut in range(len(parts), 0, -1):
        try:
            obj = importlib.import_module(".".join(parts[:cut]))
        except ImportError:
            continue
        for p in parts[cut:]:
            obj = getattr(obj, p)       # AttributeError = a stale placeholder
        return obj
    raise ImportError(f"cannot resolve {path!r}")


def locate(path):
    """'pq1.motion.ARRIVE_MS' -> 'pq1/motion.py:326' (function, class, class attr or constant)"""
    parts = path.split(".")
    for cut in range(len(parts), 0, -1):
        try:
            mod = importlib.import_module(".".join(parts[:cut]))
        except ImportError:
            continue
        rest = parts[cut:]
        if not rest:
            return rel(mod.__file__)
        obj = getattr(mod, rest[0])
        if len(rest) == 1:
            if inspect.isfunction(obj) or inspect.isclass(obj):
                return f"{rel(inspect.getsourcefile(obj))}:{inspect.getsourcelines(obj)[1]}"
            lines = _assign_lines(mod)
            if rest[0] in lines:
                return f"{rel(mod.__file__)}:{lines[rest[0]][0]}"
            # imported into this module: find the defining module
            for m in (motion, status, layout, components, loading, verdict, colors, typography):
                if rest[0] in _assign_lines(m) and getattr(m, rest[0], None) is obj:
                    return f"{rel(m.__file__)}:{_assign_lines(m)[rest[0]][0]}"
            raise AttributeError(f"no source line for {path!r}")
        if inspect.isclass(obj):
            hit = _class_attr_line(obj, rest[1])
            if hit:
                return f"{hit[0]}:{hit[1]}"
        raise AttributeError(f"no source line for {path!r}")
    raise ImportError(f"cannot locate {path!r}")


# ------------------------------------------------------------- motion.json --
def _unit(name, value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if name in NAME_UNITS:
        return NAME_UNITS[name]
    if name.endswith("_MS") or name.endswith("_DWELL") or name.startswith("T_") or "TAU" in name:
        return "ms"
    if name.endswith("_AMP") or name.endswith("_GAP") or name.endswith("_X") or name.endswith("_Y") \
            or name.endswith("_R") or name.endswith("_CX") or name.endswith("_CY"):
        return "px"
    if "ALPHA" in name:
        return "alpha"
    return None


def _tokens(mod, only=None):
    out = {}
    for name, (line, comment, rhs) in sorted(_assign_lines(mod).items()):
        if not name.isupper() or name.startswith("_"):
            continue
        if only and not only(name):
            continue
        v = getattr(mod, name, None)
        if callable(v) or inspect.ismodule(v):
            continue
        own = rel(mod.__file__)
        scope, why = _scope(name, own)
        readers = _readers(name, own)
        ent = dict(value=jsonable(v), source=f"{own}:{line}", comment=comment, scope=scope)
        if why:
            ent["scope_reason"] = why
        if scope != "device":
            ent["do_not_port"] = scope in ("demo", "dead")
        ent["readers"] = readers[:8]
        ent["reader_count"] = len(readers)
        if rhs and not re.fullmatch(r"-?[\d._]+(e-?\d+)?", rhs):
            ent["expr"] = rhs                 # a derived token keeps its relation
        u = _unit(name, v)
        if u:
            ent["unit"] = u
        if u == "ms":
            ent["frames_14"] = frames(v)
            ent["under_two_frames"] = v < 2 * FRAME_MS
        out[name] = ent
    return out


def _samples(fn, n=33):
    try:
        return [round(fn(i / (n - 1)), 5) for i in range(n)]
    except TypeError:
        return None


def _phase_census():
    """{phase: {value: [anim keys]}} over every live anim instance — so the law can
    publish what actually happens, not just what the base class declares"""
    out = {}
    for key, qual, preset, sp in anim_instances():
        an = status.anim_for(sp)
        main = getattr(an, "main", an)
        for k in ("T_HOLD", "T_IN", "T_WAIT", "T_TEXT"):
            v = getattr(main, k, None)
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                out.setdefault(k, {}).setdefault(v, []).append(key)
    return out


def verdict_law():
    """The phase law AND its exceptions. Publishing four scalars told a porter the
    law was unanimous when it is not: T_HOLD alone takes four values across the
    library (audit X5-02). Read `default` for the rule and `values` for the truth."""
    census = _phase_census()
    law = {}
    for k in ("T_HOLD", "T_IN", "T_WAIT", "T_TEXT"):
        default = getattr(verdict.VerdictAnim, k)
        vals = census.get(k, {})
        overriders = sorted(a for v, keys in vals.items() if v != default for a in keys)
        law[k] = dict(default=default, unit="ms", frames_14=frames(default),
                      source=locate(f"pq1.verdict.VerdictAnim.{k}"),
                      unanimous=not overriders,
                      values={str(v): sorted(keys) for v, keys in sorted(vals.items())},
                      overridden_by=overriders)
    law["rule"] = ("t_resolve = T_HOLD + T_IN + T_WAIT + T_TEXT; duration = t_resolve + "
                   "RESULT_HOLD_MS. T_TEXT is the caption fade and is invariant. T_WAIT is "
                   "where a mechanism lives and varies freely. T_HOLD and T_IN carry "
                   "per-anim overrides — read them from anims.json `phases`, never from "
                   "`default` here. The icon's own fade and 0.97->1 rise always finish "
                   "within ARRIVE_MS however long T_IN is: see each anim's entrance_window_ms.")
    return law


def handoff_span():
    """The token crossfade that opens a handoff=True screen — 400 ms, declared in three
    places and exported in none of them until now (audit X5-07)."""
    from pq1.status import LedAnim
    return dict(value=verdict.VerdictAnim.T_HOLD, unit="ms",
                frames_14=frames(verdict.VerdictAnim.T_HOLD), easing="ease_out",
                when="t 0..T_HOLD of any status screen whose spec carries handoff=True: the "
                     "resting token the flow was drawing crossfades out instead of popping to black",
                declared_at=[locate("pq1.verdict.VerdictAnim.T_HOLD"),
                             locate("pq1.status.ArriveStatus.T_HOLD"),
                             locate("pq1.status.LedAnim.HANDOFF_MS")],
                led_ending_span=LedAnim.HANDOFF_MS,
                note="three unlinked declarations of one span (audit D4-02); a led ending uses "
                     "LedAnim.HANDOFF_MS, every other screen its own T_HOLD, so the crossfade "
                     "runs at 250-500 ms depending on the screen (audit X3-11)")


def motion_spec():
    warm_registries()
    easings = {}
    for name, fn in sorted(vars(motion).items()):
        if not inspect.isfunction(fn) or fn.__module__ != motion.__name__ or name.startswith("_"):
            continue
        ent = dict(signature=str(inspect.signature(fn)),
                   source=f"{rel(motion.__file__)}:{inspect.getsourcelines(fn)[1]}",
                   doc=" ".join((fn.__doc__ or "").split()),
                   code=inspect.getsource(fn))
        s = _samples(fn)
        if s is not None and name not in ("clamp01", "hold_fill_ms", "tau_k", "chevron_hint",
                                          "confirm_band", "page_flip", "hold_fill", "spring_travel"):
            ent["samples_u0_to_u1_33"] = s
            ent["range"] = [min(s), max(s)]
            # a PROGRESS curve runs 0 -> 1 and may never exceed 1 (back_out is the one
            # sanctioned exception); an ACCENT oscillates around 0 or 1 as a multiplier or
            # offset, so its excursion is the point, not a fault (audit X5-10)
            progress = abs(s[0]) < 0.02 and abs(s[-1] - 1) < 0.02
            ent["role"] = "progress" if progress else "accent"
            if progress:
                ent["overshoots_target"] = max(s) > 1.0005
        if name == "spring_travel":
            ent["default_profile"] = "KIOSK"
            ent["default_profile_scope"] = "demo"
            ent["note"] = ("the exported default is the DEMO pace; the device always passes NAV "
                           "(pq1/driver.py). Reproduce NAV per panel frame from springs.NAV.")
        easings[name] = ent

    def settle(profile, px):
        t = 0
        while (1 - motion.spring_travel(t, profile)) * px >= 1.0 and t < 5000:
            t += 1
        return t

    envelopes = {
        "hold_fill": dict(t_ms=list(range(0, 2201, 50)),
                          k=[round(motion.hold_fill(t), 4) for t in range(0, 2201, 50)]),
        "hold_fill_released_at_1000": dict(
            t_ms=list(range(1000, 1251, 25)),
            k=[round(motion.hold_fill(t, 1000), 4) for t in range(1000, 1251, 25)]),
        "page_flip": dict(t_ms=list(range(0, 651, 25)),
                          out_in=[[round(a, 4), round(b, 4)] for a, b in
                                  (motion.page_flip(t) for t in range(0, 651, 25))]),
        "confirm_band": dict(t_ms=list(range(0, 10001, 100)),
                             more_back=[[round(a, 3), round(b, 3)] for a, b in
                                        (motion.confirm_band(t) for t in range(0, 10001, 100))]),
        "chevron_hint": dict(t_ms=list(range(0, 7201, 50)),
                             up_y=[[round(a, 3), round(b, 2)] for a, b in
                                   (motion.chevron_hint(t) for t in range(0, 7201, 50))]),
        "busy_pulse_one_cycle": dict(u=[i / 20 for i in range(21)],
                                     alpha=[round(motion.busy_pulse(i / 20), 4) for i in range(21)]),
    }
    springs = {}
    for name in ("NAV", "KIOSK"):
        prof = getattr(motion, name)
        springs[name] = dict(
            profile=prof, scope=_scope(name, "pq1/motion.py")[0],
            per_panel_frame=[round(motion.spring_travel(i * FRAME_MS, prof), 4) for i in range(15)],
            ms_to_within_1px=dict(trip_100px=settle(prof, 100), trip_278px=settle(prof, 278)))
    return dict(
        schema_version=SCHEMA_VERSION, panel_fps=PANEL_FPS, frame_ms=round(FRAME_MS, 3),
        panel_fps_provenance=(
            "DECLARED BY THIS GENERATOR (tools/handoff/introspect.py), not by pq1: the design "
            "system has no frame-rate constant, so 14 fps lives in prose and in --fps defaults "
            "and is re-derived independently in several places (audit D4-05 / X5-05). Every "
            "frames_14 field and the whole frame grid below hang off this one number."),
        scopes=dict(device="implement it",
                    demo="the GIF / kiosk loop only — on the device nothing moves without a press",
                    dead="no reader in the codebase; do not implement",
                    contract="a stated design bound that no code enforces",
                    **{"spec-only": "specified in DESIGN.md but not rendered by the Python — "
                                    "implement it from the spec"}),
        handoff_span=handoff_span(),
        note="All durations are milliseconds. frames_14 = ms / (1000/14). Check every token's "
             "`scope` before porting it, and read `expr` where present: a token with an expr is "
             "DERIVED from another and the two must move together.",
        tokens=dict(
            motion=_tokens(motion), status=_tokens(status), verdict={},
            components=_tokens(components, lambda n: n not in NONPORTABLE),
            layout=_tokens(layout), burst=_tokens(burst), loading=_tokens(loading)),
        verdict_law=verdict_law(),
        qubit_timeline=jsonable(vars(loading.QubitCfg())),
        burst_tables=dict(MAJOR=jsonable(burst.MAJOR), MINOR=jsonable(burst.MINOR)),
        easings=easings, envelopes=envelopes, springs=springs)


# -------------------------------------------------------------- anims.json --
def _t_attrs(obj):
    out = {}
    for k in dir(obj):
        if k.startswith("__") or not (k.startswith("T_") or k.startswith("T0_") or k == "HANDOFF_MS"):
            continue
        try:
            v = getattr(obj, k)
        except Exception:                                   # noqa: BLE001
            continue
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            out[k] = v
    return out


_BASELINE = None


def _exceptions_for(key):
    """the conformance checker's tolerated exceptions that touch this anim, so a phase
    table that looks wrong carries its own explanation (tools/check/baseline.toml)"""
    global _BASELINE
    if _BASELINE is None:
        import tomllib
        p = os.path.join(REPO, "tools", "check", "baseline.toml")
        _BASELINE = tomllib.load(open(p, "rb")).get("known", []) if os.path.exists(p) else []
    qual = key.split("|")[0]
    out = []
    for k in _BASELINE:
        w = k.get("where", "")
        if w == f"anim:{key}" or (qual.startswith(("verdict/", "pin/", "fx/", "idle/", "confirm/"))
                                  and f"screens/{qual}.py" in w):
            out.append(dict(rule=k["rule"], key=k.get("key", ""), audit=k.get("audit", ""),
                            reason=" ".join(k.get("reason", "").split())))
    return out


CORE_SPECS = {
    "qubit": dict(kind="status", anim="qubit", bottom="CONFIRMED", state="done", result="check"),
    "resolve": dict(kind="status", anim="resolve", bottom="DECLINED", state="failed", result="x"),
    "arrive": dict(kind="status", anim="arrive", bottom="UPDATED", state="done", result="check"),
    # the post-dispatch failure: the film named on a failed ending, colliding into the X
    "qubit-fail": dict(kind="status", anim="qubit", bottom="FAILED", state="failed", result="x"),
}


def anim_instances():
    """[(key, qual or None, preset, spec)] — every library screen x preset + the core three"""
    rows = []
    for name, sp in CORE_SPECS.items():
        rows.append((f"core/{name}", None, None, layout.normalize_screens([copy.deepcopy(sp)])[0]))
    for qual, mod in sorted(screens.modules().items()):
        rows.append((qual, qual, None, screens.spec(qual)))
        for p in sorted(getattr(mod, "PRESETS", {})):
            rows.append((f"{qual}|{p}", qual, p, screens.spec(qual, preset=p)))
    return rows


def _curves_used(cls):
    try:
        src = inspect.getsource(inspect.getmodule(cls))
    except (OSError, TypeError):
        return []
    names = [n for n, f in vars(motion).items() if inspect.isfunction(f)]
    return sorted(n for n in names if re.search(rf"\b{n}\(", src))


def anims_spec():
    warm_registries()
    out = {}
    for key, qual, preset, sp in anim_instances():
        an = status.anim_for(sp)
        main = getattr(an, "main", an)
        cls = type(main)
        assert math.isfinite(an.duration), key      # a live film is inf — never in the spec
        ent = dict(
            anim=sp.get("anim"), cls=cls.__name__,
            is_verdict=isinstance(main, verdict.VerdictAnim),
            source=f"{rel(inspect.getsourcefile(cls))}:{inspect.getsourcelines(cls)[1]}",
            t_resolve=an.t_resolve, duration=an.duration,
            result_hold=an.duration - an.t_resolve,
            # T_IN is the window the icon is drawn in; a screen that folds its whole
            # mechanism into T_IN (padlock) still fades and rises within ARRIVE_MS.
            # Port THIS as the entrance, not T_IN (audit X5-03).
            entrance_window_ms=min(_t_attrs(main).get("T_IN", motion.ARRIVE_MS), motion.ARRIVE_MS),
            exceptions=_exceptions_for(key),
            frames_14=dict(t_resolve=frames(an.t_resolve), duration=frames(an.duration)),
            phases=_t_attrs(main), t_busy=jsonable(an.t_busy), t_tail=an.t_tail,
            can_lead=an.t_tail is not None, busy_pulse=bool(an.busy_pulse),
            # the loading loop: the film waits on its orbit (loop region, in this
            # film's clock) in whole loop_ms turns until the host answers
            loops=bool(getattr(an, "loops", False)), loop=jsonable(getattr(an, "loop", None)),
            loop_ms=getattr(an, "loop_ms", None),
            rests_on_token=bool(an.rests_on_token), interactive=bool(an.interactive),
            previews=jsonable(an.previews), curves_used=_curves_used(cls),
            spec=jsonable({k: v for k, v in sp.items() if k != "token"}))
        if qual:
            mod = screens.modules()[qual]
            own = _assign_lines(mod)                       # assigned here, not imported
            ent["module_constants"] = jsonable({
                k: v for k, v in vars(mod).items()
                if k in own and k.isupper() and not k.startswith("_") and k not in ("ANIM", "SPEC", "PRESETS")
                and isinstance(v, (int, float, tuple, dict, str)) and not isinstance(v, bool)})
            ent["doc"] = (mod.__doc__ or "").strip().split("\n\n")[0].replace("\n", " ")
        if getattr(an, "lead", None) is not None:
            ent["lead"] = dict(anim=an.lead.name, t_resolve=an.lead.t_resolve,
                               t_tail=an.lead.t_tail, main_starts_at=getattr(an, "t_start", None))
        out[key] = ent
    return dict(schema_version=SCHEMA_VERSION,
                note="phases are per INSTANCE (they change per preset). duration = t_resolve + "
                     "result_hold. All ms.",
                result_hold_ms=status.RESULT_HOLD_MS, anims=out)


# ----------------------------------------------------- screens.schema.json --
_FIELD = re.compile(r'^    "(\w+)"\s*:\s*(.*)$')


def schema_fields():
    """the screen-dict fields, parsed from pq1/layout.py's own schema docstring
    -> {key: {section, form, note}}; a key documented in two sections (hero
    "bottom", status "bottom") is also stored as "<section>.<key>". So the
    catalog can never name a field the design system does not document."""
    doc = layout.__doc__.split("Screen description", 1)[1]
    fields, section, cur = {}, "common", None
    for ln in doc.splitlines():
        m = _FIELD.match(ln)
        if m:
            key = m.group(1)
            parts = re.split(r"\s{2,}", m.group(2).strip(), maxsplit=1)
            cur = dict(section=section, form=parts[0], note=parts[1] if len(parts) > 1 else "")
            fields.setdefault(key, cur)
            fields[f"{section}.{key}"] = cur
        elif ln and not ln.startswith(" ") and re.match(r"^[A-Za-z]", ln):
            section, cur = ln.split("(")[0].strip().lower().split()[0], None
        elif cur is not None and ln.strip():
            indent = len(ln) - len(ln.lstrip())
            if indent >= 40:                                    # the right-hand (meaning) column
                cur["note"] = (cur["note"] + " " + ln.strip()).strip()
            else:                                               # the form runs on (a dict, an enum)
                parts = re.split(r"\s{2,}", ln.strip(), maxsplit=1)
                cur["form"] = (cur["form"] + " " + parts[0]).strip()
                if len(parts) > 1:
                    cur["note"] = (cur["note"] + " " + parts[1]).strip()
    for f in {id(v): v for v in fields.values()}.values():
        if len(f["form"]) > 90:
            f["form"] = f["form"][:87] + "…"
        if len(f["note"]) > 240:
            f["note"] = f["note"][:237].rsplit(" ", 1)[0] + " … (full text: the `pq1/layout.py` docstring)"
    return fields


def _enum_enforcement():
    """which published enums RAISE on an unknown name and which are decorative —
    `icon` silently falls back to the Ethereum mark (audit G17-01/X5-11)"""
    probes = {
        "kind": dict(kind="banner"),
        "size": dict(kind="detail", label="TO", lines=["x"], size=30),
        "side": dict(kind="detail", label="TO", lines=["x"], side="top"),
        "chev": dict(kind="hero", bottom="X?", chev="down"),
        "icon": dict(kind="detail", label="TO", lines=["x"], icon="nope"),
        "result": dict(kind="status", bottom="X", result="tick"),
        "state": dict(kind="status", bottom="X", state="maybe"),
        "anim": dict(kind="status", bottom="X", anim="nope"),
    }
    out = {}
    for name, sp in probes.items():
        stage, err = "never", None
        try:
            scr = layout.normalize_screens([copy.deepcopy(sp)])
        except Exception as e:                              # noqa: BLE001
            out[name] = dict(enforced=True, enforced_at="validation",
                             raises=f"{type(e).__name__}: {str(e)[:120]}")
            continue
        try:                                                # does it survive being drawn?
            for x in scr:
                if x.get("kind") == "status":
                    status.anim_for(x)
                    status.style_of(x)
                else:
                    layout.layout_of(x)
            flow.Sim(scr).draw(0.0)
        except Exception as e:                              # noqa: BLE001
            stage, err = "draw", f"{type(e).__name__}: {str(e)[:120]}"
        if stage == "draw":
            out[name] = dict(enforced=True, enforced_at="draw", raises=err,
                             note="normalize_screens ACCEPTS the bad value; it only fails when "
                                  "the screen is drawn, so a bad flow builds and then crashes")
        else:
            out[name] = dict(enforced=False, enforced_at="never",
                             note="an unknown value is accepted AND renders — this enum "
                                  "documents intent, it does not validate")
    return out


def screens_schema():
    warm_registries()
    kinds = ("hero", "detail", "value", "confirm", "status")
    minimal = dict(hero=dict(kind="hero", bottom="SEND?"),
                   detail=dict(kind="detail", label="TO", lines=["0x1234"]),
                   value=dict(kind="value", lines=["0x1234"]),
                   confirm=dict(kind="confirm"),
                   status=dict(kind="status", bottom="CONFIRMED"))
    defaults = {}
    for k in kinds:
        n = layout.normalize_screens([copy.deepcopy(minimal[k])])[0]
        defaults[k] = jsonable({f: v for f, v in n.items() if f not in minimal[k] or f == "kind"})
    bad = {
        "unknown kind": [dict(kind="banner")],
        "unknown size": [dict(kind="detail", label="TO", lines=["x"], size=30)],
        "words beside lines": [dict(kind="value", words=["a"], lines=["x"])],
        "too many words": [dict(kind="value", words=[str(i) for i in range(9)])],
        "single page": [dict(kind="detail", label="X", pages=[["a"]])],
        "unknown anim": [dict(kind="status", anim="nope", bottom="X")],
        "unknown result": [dict(kind="status", result="tick", bottom="X")],
        "unknown state": [dict(kind="status", state="maybe", bottom="X")],
    }
    validation = {}
    for label, scr in bad.items():
        try:
            out = layout.normalize_screens(copy.deepcopy(scr))
            for s in out:
                if s.get("kind") == "status":
                    status.anim_for(s)
                    status.style_of(s)
                else:
                    layout.layout_of(s)
            flow.Sim(out).draw(0.0)             # a bad value may only surface at draw time
            validation[label] = "ACCEPTED (no error raised, even when drawn)"
        except Exception as e:                              # noqa: BLE001
            validation[label] = f"{type(e).__name__}: {str(e)[:200]}"
    seen = {}
    for n in flows.names():
        for s in flows.screens(n):
            seen.setdefault(s["kind"], set()).update(s)
    return dict(
        schema_version=SCHEMA_VERSION, kinds=list(kinds), fields=schema_fields(),
        defaults_per_kind=defaults, validation_errors=validation,
        keys_seen_in_live_flows={k: sorted(v) for k, v in sorted(seen.items())},
        enums_enforced=_enum_enforcement(),
        enums=dict(result=list(status.RESULTS) + [None], state=sorted(colors.STATE),
                   anim=sorted(status.ANIMS), icon=sorted(components.GLYPHS),
                   # resolved by shape, not registered: an unknown chain's initial
                   # (components.letter_glyph). No live flow uses one, so the icon
                   # enum above would never teach a port the rule exists.
                   icon_namespaces=["letter:<CHAR>"],
                   chev=["lr", "up", None], side=["left", "right"],
                   size=[typography.SIZE_XL, typography.SIZE_L, typography.SIZE_M, typography.SIZE_BODY],
                   brand=sorted(colors.BRAND_GRADIENTS)),
        type_scale={k: v for k, v in vars(typography).items() if k.startswith("SIZE_")},
        layout_tokens=_tokens(layout),
        flow_shape=dict(CONFIRM_MIN_DETAILS=layout.CONFIRM_MIN_DETAILS,
                        CONFIRM_INDEX=layout.CONFIRM_INDEX,
                        rule="a segment with CONFIRM_MIN_DETAILS or more detail/value screens takes "
                             "a confirm screen at index CONFIRM_INDEX (the 6th screen)"))


# -------------------------------------------------------------- flows.json --
def flows_spec():
    warm_registries()
    out = {}
    for n in flows.names():
        mod = flows.get(n)
        ends = getattr(mod, "ENDS", {})
        scr = flows.screens(n)
        rows = []
        for s in scr:
            r = dict(id=s.get("id"), kind=s["kind"])
            for k in ("chev", "commit", "hint", "next", "icon", "band_chev", "pager", "pulse",
                      "bottom", "side", "size", "label", "sweep", "chain", "chain_name"):
                if s.get(k) not in (None, False):
                    r[k] = jsonable(s[k])
            if s.get("pages"):
                r["pages"] = len(s["pages"])
            if s.get("words"):
                r["words"] = len(s["words"])
            if s["kind"] == "status":
                an = status.anim_for(s)
                r.update(anim=s.get("anim") or status.default_anim(s), state=s.get("state"),
                         result=s.get("result"), branded="resting" in s,
                         rests_on_token=status.rests_on_token(s),
                         interactive=status.is_interactive(s), loops=status.loops(s),
                         t_resolve=an.t_resolve, duration=an.duration)
                if s.get("lead"):
                    r["lead"] = s["lead"].get("anim")
                    r["lead_gap"] = s.get("lead_gap")
                if s.get("busy"):
                    r["busy"] = jsonable(s["busy"])
            rows.append(r)
        ent = dict(source=rel(mod.__file__), screens=rows, default_end=getattr(mod, "DEFAULT_END", None),
                   segments=jsonable(layout._segments(scr)),
                   confirm_index=next((i for i, s in enumerate(scr) if s["kind"] == "confirm"), None),
                   has_early_exit=any(s["kind"] == "confirm" for s in scr), ends={})
        for e, spec_ in sorted(ends.items()):
            sp = layout.normalize_screens([copy.deepcopy(spec_)], getattr(mod, "DEFAULTS", None))[0]
            an = status.anim_for(sp)
            ent["ends"][e] = dict(bottom=sp.get("bottom"), state=sp.get("state"), result=sp.get("result"),
                                  anim=sp.get("anim") or status.default_anim(sp),
                                  branded="resting" in sp, lead=(sp.get("lead") or {}).get("anim"),
                                  t_resolve=an.t_resolve, duration=an.duration,
                                  interactive=status.is_interactive(sp), loops=status.loops(sp))
        try:
            p, si, di = flows.playable(n)
            ent["playable"] = dict(sign_index=si, decline_index=di, screens=len(p))
        except ValueError as ex:
            ent["playable"] = dict(error=str(ex))
        out[n] = ent
    return dict(schema_version=SCHEMA_VERSION, flows=out)


# ----------------------------------------------------------- gestures.json --
STEP = FRAME_MS
L, R = motion.LEFT, motion.RIGHT


class Bench:
    """a FlowDriver on a clock: scripted edges in, an event log out"""

    def __init__(self, flow_name, end=None):
        scr, si, di = flows.playable(flow_name, end)
        self.d = driver.FlowDriver(scr, si, di)
        self.now, self.log = 0.0, []
        self.run(400)

    def run(self, ms):
        end = self.now + ms
        while self.now < end:
            before = self.d.sim.cur
            self.d.frame(self.now)
            if self.d.sim.cur != before:
                self._note("moved")
            self.now += STEP

    def _note(self, what, result=None):
        d = self.d
        s = d.screens[d.sim.cur]
        self.log.append(dict(t=round(self.now), event=what, result=result, screen=s.get("id"),
                             kind=s.get("kind"), state=d.state, armed=sorted(d.armed())))

    def settle(self, cap=4000):
        t0 = self.now
        while self.now - t0 < cap:
            self.run(STEP)
            if self.d.sim.settled and self.now - t0 > 2 * STEP:
                break

    def tap(self, side, held=100):
        self.d.press(side, self.now)
        self.run(held)
        r = self.d.release(side, self.now)
        self._note(f"tap {side}", r)
        self.settle()
        return r

    def hold(self, side, ms=None):
        ms = motion.HOLD_COMMIT_MS + 3 * STEP if ms is None else ms
        cur, was = self.d.sim.cur, self.d.state
        self.d.press(side, self.now)
        self.run(ms)
        r = self.d.release(side, self.now)
        # "fired" = this gesture caused the change. On a screen that was ALREADY
        # resolving (an ending) nothing can fire, so compare against the state the
        # gesture started from — not against "navigating" (which is never true there)
        fired = self.d.sim.cur != cur or (was == "navigating" and self.d.state != "navigating")
        self._note(f"hold {side} {round(ms)}ms", "fired" if fired else r)
        self.settle()
        return "fired" if fired else r

    def chord(self):
        self.d.press(L, self.now)
        self.run(40)
        r = self.d.press(R, self.now)
        self.run(80)
        self.d.release(L, self.now)
        self.d.release(R, self.now)
        self._note("chord (both)", r)
        self.run(300)
        return r

    def double(self, side):
        self.d.press(side, self.now); self.run(60); self.d.release(side, self.now)
        self.run(80)
        r = self.d.press(side, self.now)
        self.run(60)
        self.d.release(side, self.now)
        self._note(f"double {side}", r)
        self.run(400)
        return r

    def answer(self, ok):
        """the host's word on a loading film (the bench's y / n)"""
        r = self.d.answer(self.now, ok)
        self._note(f"host answers {'yes' if ok else 'no'}", r)
        return r

    def where(self):
        s = self.d.screens[self.d.sim.cur]
        out = dict(screen=s.get("id"), kind=s.get("kind"), page=self.d.sim.page[self.d.sim.cur],
                   state=self.d.state, armed=sorted(self.d.armed()))
        if s.get("kind") == "status" and getattr(self.d._anim(), "loops", False):
            an = self.d._anim()          # a film: what it waits for, and where it landed
            out.update(pending=an.pending, outcome=an.outcome, caption=an.style["bottom"])
        return out


CONTEXTS = [  # (context, flow, setup gestures)
    ("hero — the ask (flow has details)", "send_token", []),
    ("hero — an intro (band_chev, commit False)", "erc7730/swap", []),
    ("detail — first of the section", "send_token", [("tap", R)]),
    ("detail — middle", "send_token", [("tap", R), ("tap", R)]),
    ("detail — paged, on page 1", "eip1271/personal_counterfactual_hash", "to_paged"),
    ("value — full-width text", "fingerprint/safe_tx_hash_fingerprint", [("tap", R)]),
    ("confirm — the mid-flow Confirm?", "blind/unknown_call", "to_confirm"),
    ("entry — PIN row, empty", "pin/unlock", []),
    ("entry — PIN row, 3 digits entered", "pin/unlock", [("chord",), ("chord",), ("chord",)]),
    ("status — during an ending (input-dead)", "send_token", "to_ending"),
]
GESTURES = [("tap left", ("tap", L)), ("tap right", ("tap", R)),
            ("hold left", ("hold", L)), ("hold right", ("hold", R)),
            ("release a hold early (1000 ms)", ("hold", R, 1000)),
            ("both buttons (chord)", ("chord",)),
            ("double press left", ("double", L)), ("double press right", ("double", R))]


def _setup(b, steps):
    if steps == "to_ending":
        b.hold(R)                       # sign, then sit inside the ending
        b.run(900)
        return
    if steps == "to_paged":
        for _ in range(20):
            if b.d.sim.page_count[b.d.sim.cur] > 1:
                return
            b.tap(R)
        raise RuntimeError("no paged screen reached")
    if steps == "to_confirm":
        for _ in range(20):
            if b.d.screens[b.d.sim.cur].get("kind") == "confirm":
                return
            b.tap(R)
        raise RuntimeError("no confirm screen reached")
    for st in steps:
        getattr(b, st[0])(*st[1:])


def gestures_spec():
    table = []
    for ctx, flow_name, steps in CONTEXTS:
        for gname, g in GESTURES:
            b = Bench(flow_name)
            _setup(b, steps)
            before = b.where()
            result = getattr(b, g[0])(*g[1:])
            after = b.where()
            table.append(dict(context=ctx, flow=flow_name, gesture=gname, armed_before=before["armed"],
                              result=result, **{"from": f'{before["screen"]} ({before["kind"]}, p{before["page"] + 1})',
                                                "to": f'{after["screen"]} ({after["kind"]}, p{after["page"] + 1})'},
                              state_after=after["state"]))
    # "a status screen accepts no input" is now DERIVED from the table above, not asserted
    ending = [r for r in table if r["context"].startswith("status —")]
    dead = dict(verified=bool(ending) and all(
        (not r["result"]) and r["from"] == r["to"] and not r["armed_before"] for r in ending),
        gestures_tested=len(ending),
        note="every gesture was applied while an ending was playing; none armed, none moved")
    src = open(os.path.join(REPO, "tools", "panel", "play_flow.py")).read()
    keymap = next((ast.literal_eval(n.value) for n in ast.parse(src).body
                   if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "KEYMAP"), "")
    tok = _tokens(motion, lambda n: n in ("PRESS_FEEDBACK_MS", "TAP_MAX_MS", "DOUBLE_TAP_MS", "CHORD_MS",
                                          "HOLD_COMMIT_MS", "HOLD_SNAPBACK_MS"))
    return dict(schema_version=SCHEMA_VERSION, tokens=tok,
                rule="a press <= TAP_MAX_MS is a tap and fires on RELEASE; a hold fires only when the "
                     "fill completes at HOLD_COMMIT_MS from press-down; an early release snaps back "
                     "and does nothing. Status screens accept no input.",
                truth_table=table, ending_is_input_dead=dead,
                bench_keymap_BENCH_ONLY=keymap)


# ------------------------------------------------------------- traces.json --
def traces_spec():
    """scripted sessions -> the expected event log; a port replays the same
    edges and must reach the same screens / states"""
    def run(flow_name, script, end=None):
        b = Bench(flow_name, end)
        for st in script:
            getattr(b, st[0])(*st[1:])
        return dict(flow=flow_name, script=[list(map(str, s)) for s in script], log=b.log,
                    final=b.where())
    fwd = [("tap", R)] * 3
    return dict(schema_version=SCHEMA_VERSION, frame_ms=round(STEP, 3),
                note="edges: tap = press, 100 ms, release; hold = press held HOLD_COMMIT_MS + 3 frames; "
                     "the log lists each gesture's result and every screen change with the armed set.",
                traces={
                    "walk in, sign": run("send_token", fwd + [("tap", L)] * 3 + [("hold", R)]),
                    "decline from a detail": run("send_token", [("tap", R), ("tap", R), ("hold", L)]),
                    "early release snaps back": run("send_token", [("hold", R, 1200), ("tap", R)]),
                    "right hold where commit is not armed": run("send_token", [("tap", R), ("hold", R)]),
                    "intro leads to the ask": run("erc7730/swap", [("tap", R), ("tap", R), ("tap", L)]),
                    "paged detail: page first, then screen": run(
                        "eip1271/personal_counterfactual_hash", [("tap", R)] * 9 + [("tap", L)] * 3),
                    "PIN: three digits, back, next": run(
                        "pin/unlock", [("tap", R), ("tap", R), ("chord",), ("tap", L), ("chord",),
                                       ("chord",), ("double", L), ("double", R)]),
                    "PIN: cancel the open row": run("pin/unlock", [("tap", R), ("chord",), ("hold", L)]),
                    # the loading loop: the film waits after the hold, the host answers
                    "sign, the host answers yes": run(
                        "send", fwd + [("tap", L)] * 3 + [("hold", R), ("run", 6000), ("answer", True), ("run", 6000)]),
                    "sign, the host answers no": run(
                        "send", fwd + [("tap", L)] * 3 + [("hold", R), ("run", 6000), ("answer", False), ("run", 6000)]),
                })


# -------------------------------------------------------------- build.json --
def source_hash():
    h = hashlib.sha256()
    files = []
    for top in ("pq1", "screens", "flows", os.path.join("tools", "handoff"),
                os.path.join(".claude", "skills", "pq1-conformance")):
        for root, dirs, names in os.walk(os.path.join(REPO, top)):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            for n in sorted(names):
                if n.endswith((".py", ".md", ".toml", ".json")) and n != "MANIFEST.md":
                    files.append(os.path.join(root, n))
    for p in files:
        h.update(rel(p).encode())
        h.update(open(p, "rb").read())
    return dict(schema_version=SCHEMA_VERSION, files=len(files), sha256=h.hexdigest())


SPECS = {
    "build.json": source_hash,
    "motion.json": motion_spec,
    "anims.json": anims_spec,
    "screens.schema.json": screens_schema,
    "flows.json": flows_spec,
    "gestures.json": gestures_spec,
    "traces.json": traces_spec,
}
