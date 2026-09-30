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
from pq1.canvas import Canvas                                       # noqa: E402
from pq1.procedural import (blind, chains, dev, download, eth,      # noqa: E402
                            fingerprint, marks, rotate)
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
    "DEBOUNCE_MS": "contact-bounce rejection on a raw button edge: the reference driver is "
                   "handed clean edges, so nothing in the Python filters them — the port (or "
                   "the HAL, or the button itself) implements it from the spec",
}
CONTRACT_TOKENS = {      # a stated design bound that no code enforces
    "SWEEP_X_MIN": "a stated bound; nothing clamps to it (audit X6-02)",
    "SWEEP_X_MAX": "a stated bound; nothing clamps to it (audit X6-02)",
    "MARGIN": "the static grid margin; the moving art is not clamped to it (audit X6-08)",
}
# never exported: build-machine paths cannot travel and would break a byte-identical dump
NONPORTABLE = {"ASSET_DIR": "an absolute path on the build machine"}
# units the name alone does not imply
NAME_UNITS = {"HOLD_END": "ms", "PAGER_BASELINE": "px", "PAGER_ALPHA": "alpha",
              "REVS": "turns", "REVS_LONG": "turns",
              "R_MASTER": "px", "W": "px", "H": "px", "MARGIN": "px",
              "BAND_TOP": "px", "BAND_BOTTOM": "px", "BASELINE_Y": "px",
              "SUP": "factor", "WORDS_SIZE": "px", "WORDS_NUM_ALPHA": "alpha",
              # geometry tokens whose names imply no unit (audit RAD-03)
              "TOKEN_RING_W": "px", "TOKEN_INSET": "px", "SIDES_R0": "px",
              "MONOGRAM_SCALE": "factor", "LEVEL_EPS": "level",
              "ALPHA_FLOOR": "alpha", "FILM_FLOOR": "alpha"}

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


def typography_spec():
    """the type system as a port needs it — the faces, the scale as roles, the
    detail ladder the fit rule climbs, the regions it measures against and each
    rule in one sentence — generated from pq1/typography.py and pq1/layout.py,
    never typed (audit TY-06 / TY-09)"""
    px_token = {v: k for k, v in vars(typography).items() if k.startswith("SIZE_")}
    scale = [dict(role=r["role"], token=px_token[r["px"]], px=r["px"], weight=r["weight"],
                  tracking=r["tracking"], leading=layout.line_height(r["px"]), use=r["use"])
             for r in typography.ROLES]
    tiers = [dict(px=px, token=px_token[px], max_lines=rows) for px, rows in layout.fit_tiers()]
    return dict(
        family="Aileron",
        faces={w: names[0] for w, names in typography._FONT_NAMES.items()},
        floor_px=typography.SIZE_LABEL,
        scale=scale,
        label_face=dict(px=typography.SIZE_LABEL, weight=typography.WEIGHT_LABEL,
                        tracking=typography.LS_LABEL,
                        wearers=["detail label", "pager n/m", "PIN hints", "verdict label"]),
        tracking=dict(question=typography.LS_QUESTION, label=typography.LS_LABEL),
        leading=dict(rule="layout.line_height(size): the size itself on the one-line Big "
                          "tiers, size + 8 below",
                     px={str(px): layout.line_height(px) for px, _ in layout.fit_tiers()}),
        tiers=tiers,
        regions=dict(detail=layout.TEXT_REGION_W, value=layout.TEXT_REGION_FULL_W,
                     rule="detail: the text beside a docked token; value: full width between "
                          "the margins (layout.TEXT_REGION_W / TEXT_REGION_FULL_W)"),
        fit="layout.fit_size: the largest tier whose every line, measured in its own face "
            "(typography.text_width), fits the region within the tier's line cap; nothing "
            "fits -> split or page the value, never shrink or ellipsize",
        monogram=dict(weight="bold", scale=components.MONOGRAM_SCALE,
                      px_at_rest=round(components.MONOGRAM_SCALE * layout.CIRCLE_R, 2),
                      rule="a lone letter on a disc (an unknown chain's initial): "
                           "MONOGRAM_SCALE x the disc radius, so it shrinks with the disc"),
        glyphs="proportional advances (Aileron's own); the ten digits share one advance, so "
               "amounts, the PIN reel and the pager align without a tabular face",
        source=dict(typography=rel(typography.__file__), layout=rel(layout.__file__)),
    )


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
        if k in ("detail", "value"):
            # There is NO default size: an absent size is FITTED from the
            # content (layout.fit_size — the largest tier whose every line
            # measures inside the region, in its own face). The probe above
            # would otherwise publish its own sample's answer as a constant
            # and teach a port to hard-code it.
            defaults[k]["size"] = (f"<fitted: layout.fit_size(lines, "
                                   f"full={k == 'value'})>")
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
                   # (components.letter_glyph). Only the chains bench flow renders
                   # one (flows/chains.py, the unknown-id screen), so the icon
                   # enum above alone would never teach a port the rule exists.
                   icon_namespaces=["letter:<CHAR>"],
                   chev=["lr", "up", None], side=["left", "right"],
                   size=[px for px, _ in layout.fit_tiers()],
                   brand=sorted(colors.BRAND_GRADIENTS)),
        typography=typography_spec(),
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
                    r["lead_clear"] = s.get("lead_clear")
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
    ("hero — an intro (band_chev, commit False)", "firmware/update", [("tap", R)]),
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
                                          "HOLD_COMMIT_MS", "HOLD_SNAPBACK_MS", "DEBOUNCE_MS"))
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
                    "intro leads on": run("firmware/update", [("tap", R), ("tap", R), ("tap", L)]),
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


# ------------------------------------------------------------- colors.json --
# Colour is the other half of the design system the port has to reproduce, and
# until now it reached the firmware developer as hand-typed prose: the spec
# published no colour value at all (audit COL-02). Everything the renderer can
# paint is dumped here from the live module — every ramp stop, every pin, every
# tint — each swatch in the three forms a port might want (rgb, hex, and the
# RGB565 the NV3007 actually takes).
def rgb565(rgb):
    """(r, g, b) -> the 16-bit word the panel takes (5 red, 6 green, 5 blue)"""
    r, g, b = (max(0, min(255, int(round(c)))) for c in rgb[:3])
    return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)


def swatch(c):
    """one colour in every form a port may need"""
    rgb = colors.hex_to_rgb(c) if isinstance(c, str) else tuple(int(round(x)) for x in c[:3])
    return dict(rgb=list(rgb), hex="#%02X%02X%02X" % rgb, rgb565=rgb565(rgb),
                rgb565_hex="0x%04X" % rgb565(rgb))


def _ramp(stops):
    """a six-stop ramp as the screen reads it: stop 6 is the token, 5..1 the trail"""
    fill, trail = colors._ramp_to_palette(stops)
    return dict(stops=[swatch(h) for h in stops], fill=swatch(fill),
                trail=[swatch(c) for c in trail],
                note="stop 6 = the token disc, stop 5 = the nearest follower … stop 1 = the "
                     "farthest; fill = ramp[-1] and trail = ramp[-2::-1] unless a palette "
                     "override below pins the disc")


def colors_spec():
    warm_registries()
    from pq1 import layout as _layout

    base = {}
    for name in ("BLACK", "WHITE", "YELLOW", "GREEN", "RED", "ORANGE", "COWSWAP_DARK"):
        v = getattr(colors, name)
        line = _assign_lines(colors).get(name, (0, "", ""))
        base[name] = dict(swatch(v), source=f"{rel(colors.__file__)}:{line[0]}", comment=line[1])

    placeholder = []
    for i, stops in enumerate(colors.PLACEHOLDER_GRADIENTS):
        ent = _ramp(stops)
        ent["index"] = i
        fill = colors.PLACEHOLDER_PALETTES[i][0]          # the OVERRIDE, where there is one
        if list(fill) != ent["fill"]["rgb"]:
            ent["fill_override"] = dict(swatch(fill),
                                        why="the mono entry fills BLACK: a token with a logo "
                                            "keeps the black body + white ring")
        if i == colors.MONO_RAMP:
            ent["role"] = "mono — the recognized-logo treatment; OUTSIDE the hash space"
        elif i == colors.NEUTRAL_RAMP:
            ent["role"] = "neutral grey — the keyless-unknown fallback (token_ramp's last resort)"
        placeholder.append(ent)

    brand = {k: _ramp(g) for k, g in sorted(colors.BRAND_GRADIENTS.items())}
    for k, pal in colors.BRAND_PALETTES.items():          # ROTATE/ERC7730 black, FINGERPRINT white, chain pins
        if list(pal[0]) != brand[k]["fill"]["rgb"]:
            brand[k]["fill_override"] = swatch(pal[0])
    for k in brand:
        brand[k]["pinned_by_name"] = True

    chain = dict(
        colors={k: swatch(v) for k, v in sorted(colors.CHAIN_COLORS.items())},
        disc_fill={k: swatch(v) for k, v in sorted(colors.CHAIN_DISC_FILL.items())},
        mark_colors={k: swatch(v) for k, v in sorted(colors.CHAIN_MARK_COLORS.items())},
        dark_mark_luma=colors.CHAIN_DARK_MARK_LUMA,
        mark_rule="the mark a chain disc knocks out is WHITE, or BLACK once luma(fill) > "
                  "dark_mark_luma — read off the disc's ACTUAL fill (disc_fill where pinned, "
                  "else the ramp's stop 6); a chain in mark_colors pins its own instead",
        luma_weights=[0.2126, 0.7152, 0.0722],
        key_rule="keys are namespaced CHAIN:<NAME> because OP, BNB, BASE and SCROLL are also "
                 "token tickers and token_ramp resolves any palette string matching a brand key",
        source=f"{rel(colors.__file__)}:{_assign_lines(colors).get('CHAIN_COLORS', (0,))[0]}")

    _colors_line = _assign_lines(colors)

    def _ink(name, note):
        v = getattr(colors, name)
        return dict(value=v, of="WHITE", swatch=swatch(colors.scale(colors.WHITE, v)),
                    source=f"{rel(colors.__file__)}:{_colors_line[name][0]}", note=note)

    tints = dict(
        # the three tiers, all owned by pq1/colors.py since audit COL-06
        INK_SECONDARY=_ink("INK_SECONDARY", "the PIN idle ring — ink that is not text"),
        INK_PAGING=_ink("INK_PAGING", "the n/m pager and the PIN hint labels"),
        INK_MUTED=_ink("INK_MUTED", "the seed-word numbers beside their words"),
        # the two module-level aliases a port already knows by name; they
        # carry the same values, read from the tokens above
        WORDS_NUM_ALPHA=dict(value=_layout.WORDS_NUM_ALPHA, of="WHITE", alias_of="INK_MUTED",
                             swatch=swatch(colors.scale(colors.WHITE, _layout.WORDS_NUM_ALPHA)),
                             source=f"{rel(_layout.__file__)}:{_assign_lines(_layout)['WORDS_NUM_ALPHA'][0]}",
                             note="the seed-word numbers' grey"),
        PAGER_ALPHA=dict(value=components.PAGER_ALPHA, of="WHITE", alias_of="INK_PAGING",
                         swatch=swatch(colors.scale(colors.WHITE, components.PAGER_ALPHA)),
                         source=f"{rel(components.__file__)}:{_assign_lines(components)['PAGER_ALPHA'][0]}",
                         note="the n/m pager's 80 % white"),
        # not a tint of WHITE: a true-alpha value composited over the panel
        PULSE_PEAK_ALPHA=dict(value=colors.PULSE_PEAK_ALPHA, of=None,
                              source=f"{rel(colors.__file__)}:{_colors_line['PULSE_PEAK_ALPHA'][0]}",
                              note="the pulse ring's peak alpha, decaying to 0 across its life"),
    )
    # Real tints with no constant of their own — a port still has to draw
    # them. EMPTY is the goal state (audit COL-06 emptied it); the key stays
    # so a port that reads this spec keeps its shape, and so the next stray
    # hand-typed tint has somewhere to show up. C-INK keeps it empty.
    unnamed = {}

    hold = dict(
        HOLD_OVERLAY_ALPHA=dict(value=components.HOLD_OVERLAY_ALPHA,
                                source=f"{rel(components.__file__)}:{_assign_lines(components)['HOLD_OVERLAY_ALPHA'][0]}",
                                note="the hold film's opacity — black over a coloured body, "
                                     "white inside a black one"),
        HOLD_DARK_BODY=dict(value=components.HOLD_DARK_BODY,
                            source=f"{rel(components.__file__)}:{_assign_lines(components)['HOLD_DARK_BODY'][0]}",
                            note="body luma below this counts as a black body, so the film goes white"),
    )

    # the flat table port_diff pairs against a ui_colors.h
    # role says what a port OWES for this colour, the way motion.json's scope does:
    # "base" every port defines by name (port_diff reports it MISSING); a ramp stop is
    # more often a table the port copies wholesale than a named constant, so those are
    # listed only on request (audit COL-02).
    flat = {}

    def add(name, sw, role, source=None):
        flat[name] = dict(rgb=sw["rgb"], hex=sw["hex"], rgb565=sw["rgb565"], role=role)
        if source:
            flat[name]["source"] = source

    for name, ent in base.items():
        add(name, ent, "base", ent["source"])
    for i, ent in enumerate(placeholder):
        for j, st in enumerate(ent["stops"], start=1):
            add(f"RAMP_{i:02d}_STOP_{j}", st, "ramp")
        add(f"RAMP_{i:02d}_FILL", ent.get("fill_override", ent["fill"]), "ramp")
    for k, ent in brand.items():
        key = k.replace("CHAIN:", "CHAIN_")
        for j, st in enumerate(ent["stops"], start=1):
            add(f"{key}_STOP_{j}", st, "ramp")
        add(f"{key}_FILL", ent.get("fill_override", ent["fill"]), "ramp")
    for k, sw in chain["mark_colors"].items():
        add(k.replace("CHAIN:", "CHAIN_") + "_MARK", sw, "base")

    return dict(
        schema_version=SCHEMA_VERSION,
        note="Every colour the renderer can paint, dumped from pq1/colors.py. Each swatch carries "
             "rgb, hex and the RGB565 word the NV3007 takes. `tokens` is the flat table "
             "scripts/port_diff.py pairs against a port's ui_colors.h (each row's `role`: \"base\" a "
             "colour every port defines by name, \"ramp\" one stop of a table it more likely "
             "copies whole); everything else is the "
             "structure a screen reads. Colour is identity on a signing screen: a ramp stop that "
             "differs changes what the user checks.",
        base=base,
        state={k: dict(name=[n for n in base if base[n]["rgb"] == list(v)][0], **swatch(v))
               for k, v in sorted(colors.STATE.items())},
        state_source=f"{rel(colors.__file__)}:{_assign_lines(colors).get('STATE', (0,))[0]}",
        hash_rule=dict(
            function="placeholder_index", expr="zlib.crc32(str(key).upper().encode()) % MONO_RAMP",
            space=colors.MONO_RAMP, ramps=len(colors.PLACEHOLDER_GRADIENTS),
            mono_ramp=colors.MONO_RAMP, neutral_ramp=colors.NEUTRAL_RAMP,
            source=locate("pq1.colors.placeholder_index"),
            rule="a string (symbol, name or contract address) hashes over ramps 0..mono_ramp-1, "
                 "so an unrecognized token can never wear the recognized-token look; an int wraps "
                 "over all of them, so token={'palette': MONO_RAMP} is the one way in. Resolution "
                 "order is palette -> address -> symbol -> the screen's icon -> neutral_ramp "
                 "(components.token_ramp); a palette naming a brand ramp is pinned by name, "
                 "never hashed. Enforced by the checker rule C-RAMP."),
        placeholder_ramps=placeholder,
        contrast_floors=dict(
            placeholder_fill_vs_white=colors.PLACEHOLDER_MIN_CONTRAST,
            mark_vs_disc=3.0,
            rule="a placeholder disc's fill stop must read at least "
                 f"{colors.PLACEHOLDER_MIN_CONTRAST:g}:1 against WHITE (it carries the white "
                 "ring and a white mark, so the mark is read as a glyph); any mark must read "
                 "3:1 against the disc it lands on, the bar for a meaningful graphic. WCAG "
                 "relative luminance, sRGB-linearized — NOT colors.luma, which is the "
                 "un-linearized dark/light test mark_color uses and understates a mid-tone "
                 "disc by roughly half. Ported colours must be re-measured after RGB565 "
                 "quantisation, which only eats margin. Enforced by C-CONTRAST and "
                 "F-MARKCONTRAST.",
            source=locate("pq1.colors.PLACEHOLDER_MIN_CONTRAST")),
        brand_ramps=brand,
        token_ramp_colors={k: swatch(v) for k, v in sorted(colors.TOKEN_COLORS.items())},
        ramp_steps=list(colors.RAMP_STEPS),
        ramp_steps_note="a six-stop ramp derived from one colour (colors.ramp_from): stop 6 is "
                        "the colour, stops 5..1 scale it toward black by these factors",
        chains=chain,
        ink_tints=dict(named=tints, unnamed=unnamed,
                       rule="a tint is the colour scaled toward black (colors.scale) on the "
                            "pure-black panel — the system's alpha idiom"),
        hold_film=hold,
        tokens=flat,
    )


# --------------------------------------------------------------- icons.json --
# The band today's disc marks sit in, as a fraction of the token's VISIBLE disc
# (audit ICO-07): extent is a mark's largest ink dimension over that diameter,
# ink the area it covers over that disc's area. The bounds are the owner's and
# carry headroom over the measured set — a new mark outside them is not a bug,
# it is a decision to take with the designer instead of by eye.
MARK_BAND = dict(extent_pct=(39.0, 60.0), ink_pct=(4.5, 12.5))

# Line weights that are a recorded decision OFF layout.STROKE (audit ICO-05).
# Each row CITES the line that sets it and the spec carries that line's own
# text, so a width cannot move and leave this table claiming otherwise. A
# dotted path names a token; a (function, substring) pair names a width written
# at the draw site, which has no token of its own.
STROKE_EXCEPTIONS = (
    ("the plus / minus entry hints", "screens.pin.pin_entering.HINT_STROKE",
     "a fraction of the hint sign's radius. The signs are smaller than the x mark and read "
     "heavy at its stroke, so they are drawn on the hair weight instead"),
    ("the PIN pill", "pq1.procedural.pin_pill.STROKE",
     "the pill is a container the width of a caption, not a sign: on the ring weight its "
     "outline vanished, on the sign weight it read as a button"),
    ("the PIN pill's scan line", "pq1.procedural.pin_pill.SCAN_STROKE",
     "a moving hairline INSIDE the pill — necessarily thinner than the pill it travels in"),
    ("the active PIN ring", "pq1.procedural.pin_slots.ACTIVE_LW",
     "a FULL panel pixel over the hair weight the resting rings take (2 -> 3), because the "
     "dialling ring has to read as the live one without changing size — and the hue step that "
     "used to carry that job alone measures 1.21:1 against the idle grey, near-isoluminant on "
     "black glass. It was +0.5 until Sep 2026; 0.047 mm is not a cue (audit A11-10)"),
    ("the result marks and the entry signs", "pq1.procedural.marks.SIGN_STROKE",
     "a fraction of r, not a width: check, x, plus and minus are drawn at whatever radius "
     "they are handed, so their stroke scales with them"),
    ("the shield outline", ("pq1.procedural.shield.draw", "lw if lw is not None"),
     "the traced source's own stroke, scaled with the drawn height. The shield keeps its "
     "OUTLINE — the one written exception to a sign being a filled silhouette with a black "
     "knock-out — because the shield is the container and the mark inside it is the verdict "
     "(owner, Sep 2026)"),
    ("the exclamation bar", ("pq1.procedural.marks.exclamation", "mw = "),
     "a fraction of r: the notice mark is drawn at the radius its triangle gives it"),
)
# What each named weight is FOR. Keyed by layout.STROKE, so a new weight with
# no sentence here fails the build rather than shipping unexplained.
STROKE_DRAWS = dict(hair="the PIN rings at rest and the die's edges",
                    ring="the token ring (components.TOKEN_RING_W) and the resolve flash",
                    sign="the corner chevrons",
                    heavy="the padlock's shackle")
ICON_PAD = 24      # probe-canvas margin: room for the widest mark and its rotation


def _doc1(obj):
    """the first paragraph of a docstring, collapsed onto one line"""
    return " ".join((inspect.getdoc(obj) or "").split("\n\n")[0].split())


def _source_line(where):
    """the exact line of code at 'file:line', stripped.

    A citation, not a copy: a width or a scale that moves rewrites the spec on
    the next build, which is the contract handoff/ exists to keep (audit
    ICO-14)."""
    path, ln = where.rsplit(":", 1)
    return open(os.path.join(REPO, path)).read().splitlines()[int(ln) - 1].strip()


def _line_in(func_path, needle):
    """'file:line' of the line inside a function that carries `needle` — the
    address of a constant written at the draw site, which has no token"""
    fn = resolve(func_path)
    src, first = inspect.getsourcelines(fn)
    for i, ln in enumerate(src):
        if needle in ln:
            return f"{rel(inspect.getsourcefile(fn))}:{first + i}"
    raise ValueError(f"{func_path} no longer carries {needle!r}: the stroke-exception table "
                     f"in {rel(__file__)} cites a line that moved")


def _logo_asset(fn):
    """the PNG a full-bleed logo glyph closes over, repo-relative — the art IS
    its source, and ASSET_DIR itself is a build-machine path that never travels"""
    for name, cell in zip(fn.__code__.co_freevars, fn.__closure__ or ()):
        if name == "path":
            return rel(cell.cell_contents)
    return None


def _ink_stats(fn, r):
    """one glyph drawn alone, white on black: its ink box, the box's mid and the
    luminance centroid as offsets from the glyph's own centre, and the ink area
    — all in UI px.

    Box edges are EXCLUSIVE (min, max + 1). Inclusive indices put the mid of an
    ink span half a pixel up and left whenever it spans an even number of
    supersampled pixels, and that phantom offset is what audit ICO-09 chased
    through six modules before it measured the measurement itself."""
    side = int(2 * (r + ICON_PAD))
    cv = Canvas(side, side, colors.BLACK)
    c = side / 2.0
    fn(cv, c, c, r, alpha=1.0, color=colors.WHITE)
    px = cv.img.convert("L").load()
    n, mid, s = side * layout.SUP, c * layout.SUP, float(layout.SUP)
    x0, x1, y0, y1 = n, -1, n, -1
    ink = sx = sy = 0.0
    for y in range(n):
        for x in range(n):
            v = px[x, y]
            if not v:
                continue
            x0, x1 = min(x0, x), max(x1, x)
            y0, y1 = min(y0, y), max(y1, y)
            ink += v
            sx += v * (x + 0.5)
            sy += v * (y + 0.5)
    if x1 < 0:
        raise ValueError("a glyph inked nothing at full alpha")
    return dict(ink_w=round((x1 - x0 + 1) / s, 2), ink_h=round((y1 - y0 + 1) / s, 2),
                bbox_mid_dx=round(((x0 + x1 + 1) / 2 - mid) / s, 2),
                bbox_mid_dy=round(((y0 + y1 + 1) / 2 - mid) / s, 2),
                centroid_dx=round((sx / ink - mid) / s, 2),
                centroid_dy=round((sy / ink - mid) / s, 2),
                ink_area=round(ink / 255.0 / (s * s), 1))


def _measured(fn):
    """_ink_stats at the disc's own radius, plus the two fractions of the
    visible disc the mark band is written in"""
    d = 2.0 * components.visible_r(layout.CIRCLE_R)
    m = _ink_stats(fn, layout.CIRCLE_R)
    m["extent_pct"] = round(100.0 * max(m["ink_w"], m["ink_h"]) / d, 1)
    m["ink_pct"] = round(100.0 * m["ink_area"] / (math.pi * (d / 2.0) ** 2), 1)
    return m


def _icon_entry(name, fn):
    """one row of the legal icon set: where the art comes from, how it is
    scaled, how it composites, and what it measures at rest on the disc"""
    mod = importlib.import_module(fn.__module__)
    ent = dict(source=f"{rel(inspect.getsourcefile(fn))}:{inspect.getsourcelines(fn)[1]}",
               full_bleed=bool(getattr(fn, "full_bleed", False)),
               # ONE compositing model for a mark that rests on a disc (audit
               # ICO-01). Only the marks that never rest on one scale their
               # colour toward black instead, which is exact on the black panel.
               compositing=("scaled" if fn in (marks.exclamation, marks.plus, marks.minus)
                            else "mask"),
               brand=False, fill_rule=None)
    if mod is chains:
        lines = _assign_lines(chains)
        stem, scale, axis = chains.MARKS[name]
        ent.update(kind="traced", brand=True, note=_doc1(chains.draw),
                   svg=f"reference/logos/{stem}.svg",
                   viewbox=dict(w=chains.W, h=chains.H,
                                source=f"{rel(chains.__file__)}:{lines['W'][0]}",
                                rule="the art is centred on the viewBox centre"),
                   path=[dict(d=d, fill_rule=rule) for d, rule in chains.PATHS[name]],
                   path_source=f"{rel(chains.__file__)}:{lines['PATHS'][0]}",
                   fill="subpaths XOR within one <path> element, elements union — a counter "
                        "reads as a hole",
                   scale=dict(value=scale, axis=dict(w="width", h="height")[axis],
                              token=f"chains.MARKS[{name!r}]",
                              source=f"{rel(chains.__file__)}:{lines['MARKS'][0]}",
                              rule="half-extent = scale x the glyph r, on that axis of the "
                                   "ART's own span (not of the viewBox)"))
        if name in chains.NUDGE:
            nx, ny = chains.NUDGE[name]
            ent["nudge"] = dict(x=nx, y=ny, unit="SVG units, y down",
                                source=f"{rel(chains.__file__)}:{lines['NUDGE'][0]}",
                                rule="optical centring: the mark's MASS is put on the disc "
                                     "centre, so its BOX is deliberately off")
    elif hasattr(mod, "PATH") and hasattr(mod, "MARK_SCALE"):
        lines = _assign_lines(mod)
        short = mod.__name__.rsplit(".", 1)[-1]
        # the scale axis is the one the draw divides by: the dev mark is wide
        # and scales off half its WIDTH, the rest off half height
        axis = "width" if re.search(r"/ W\b", inspect.getsource(mod.draw)) else "height"
        ent.update(kind="traced", note=_doc1(mod.draw),
                   viewbox=dict(w=mod.W, h=mod.H,
                                source=f"{rel(mod.__file__)}:{lines['W'][0]}",
                                rule="the art is scaled by the whole viewBox, so the padding "
                                     "in the box is part of the mark's size"),
                   path=[dict(d=mod.PATH, fill_rule=None)],
                   path_source=f"{rel(mod.__file__)}:{lines['PATH'][0]}",
                   fill="the flattened subpaths are disjoint, so the mark is their union "
                        "(geometry.svg_subpaths)",
                   scale=dict(value=mod.MARK_SCALE, axis=axis, token=f"{short}.MARK_SCALE",
                              source=f"{rel(mod.__file__)}:{lines['MARK_SCALE'][0]}",
                              rule=f"half-{axis} = scale x the glyph r, over the viewBox"))
    elif mod is eth:
        lines = _assign_lines(eth)
        ent.update(kind="geometry", note=_doc1(eth.draw),
                   geometry=dict(upper=eth.UPPER, lower=eth.LOWER, round=eth.ROUND,
                                 round_tip=eth.ROUND_TIP, upper_rr=eth.UPPER_RR,
                                 lower_rr=eth.LOWER_RR,
                                 source=f"{rel(eth.__file__)}:{lines['UPPER'][0]}",
                                 rule="two polygons in half-height units about the centre "
                                      "(x right, y down), corners trimmed by ROUND and the "
                                      "two points by ROUND_TIP, both fractions of the "
                                      "half-height"),
                   fill="the two polygons are disjoint — their union is the mark",
                   scale=dict(value=eth.LOGO_SCALE, axis="height", token="eth.LOGO_SCALE",
                              source=f"{rel(eth.__file__)}:{lines['LOGO_SCALE'][0]}",
                              rule="half-height = scale x the glyph r. The owner kept the "
                                   "PROCEDURAL height when the raster mark was deleted "
                                   "(audit ICO-02), so the mark grew on every default disc"))
    elif mod is marks:
        lines = _assign_lines(marks)
        ent.update(kind="geometry", note=_doc1(fn),
                   geometry=dict(sign_stroke=marks.SIGN_STROKE,
                                 source=f"{rel(marks.__file__)}:{lines['SIGN_STROKE'][0]}",
                                 rule="arms and stroke are fractions of r, listed in the "
                                      "note — there is no path to trace"),
                   scale=dict(value=1.0, axis="radius", token=None,
                              source=f"{rel(marks.__file__)}:{inspect.getsourcelines(fn)[1]}",
                              rule="drawn at the r it is handed; on a disc that is the "
                                   "disc's own radius, so the mark fills the face"))
    elif ent["full_bleed"]:
        ent.update(kind="logo", brand=True,
                   note="full-bleed art: the disc WEARS the logo, circle-masked to the "
                        "token's visible edge, and an explicit ring may be stroked over it",
                   art=_logo_asset(fn),
                   fill="the PNG's own alpha",
                   scale=dict(value=1.0, axis="diameter", token=None,
                              source=locate("pq1.components.resolve_glyph"),
                              rule="the art fills the token's VISIBLE disc "
                                   "(components.visible_r), never the layout radius"))
    else:
        raise ValueError(f"icon {name!r} ({fn.__module__}) matches no known kind — describe "
                         f"it in _icon_entry before it can be published")
    # the band is a weight rule for marks that REST on a disc: a brand's own
    # logo and a mark drawn on black are outside it by construction
    ent["in_band"] = ent["compositing"] == "mask" and not ent["brand"]
    ent["measured"] = _measured(fn)
    return ent


def icons_spec():
    """The icon set as a port re-draws it (audit ICO-07): every name in
    components.GLYPHS plus the letter namespace, each with its art, its scale,
    its compositing model and what it measures on the disc — and the three laws
    around them, the sign box, the stroke vocabulary and the mark band."""
    warm_registries()
    icons = {n: _icon_entry(n, fn) for n, fn in sorted(components.GLYPHS.items())}
    sample = "A"
    icons[components.LETTER_PREFIX + "<CHAR>"] = dict(
        kind="text", namespace=True, brand=False, full_bleed=False, fill_rule=None,
        compositing="mask", in_band=False, sample=sample,
        source=locate("pq1.components.monogram"),
        # the whole docstring, not just its first line: why the letter is the
        # one Bold glyph on the device is the part a port needs
        note=" ".join((inspect.getdoc(components.monogram) or "").split()),
        fill="the font's own rasterization, inked into the mask like any other mark",
        scale=dict(value=components.MONOGRAM_SCALE, axis="cap height",
                   token="components.MONOGRAM_SCALE",
                   source=locate("pq1.components.MONOGRAM_SCALE"),
                   rule="the font size is scale x the glyph r, so the letter shrinks with "
                        "the disc and carries a mark's weight, not running text's"),
        rule="resolved by SHAPE at draw time, never a GLYPHS entry: registering letters "
             "lazily would make the published icon set depend on render order "
             "(components.letter_glyph, audit G17-07). screens.schema.json publishes it as "
             "enums.icon_namespaces.",
        measured=_measured(components.letter_glyph(components.LETTER_PREFIX + sample)))

    band = [n for n, e in sorted(icons.items()) if e["in_band"]]

    def _edge(key, lowest):
        vals = [(icons[n]["measured"][key], n) for n in band]
        v, n = (min(vals) if lowest else max(vals))
        return dict(value=v, icon=n)

    exceptions = []
    for label, where, why in STROKE_EXCEPTIONS:
        loc = _line_in(*where) if isinstance(where, tuple) else locate(where)
        val = None if isinstance(where, tuple) else resolve(where)
        exceptions.append(dict(name=label, value=val, source=loc, code=_source_line(loc),
                               reason=why))
    return dict(
        schema_version=SCHEMA_VERSION,
        measured_at=dict(
            r=layout.CIRCLE_R, disc=round(2.0 * components.visible_r(layout.CIRCLE_R), 2),
            supersample=layout.SUP,
            rule="each glyph drawn alone, white on black, at the disc's layout radius; the "
                 "ink box and both centres in UI px about the glyph's own centre. Box edges "
                 "are EXCLUSIVE (min, max + 1) — inclusive indices read a phantom half-pixel "
                 "offset whenever the ink spans an even number of supersampled pixels "
                 "(audit ICO-09)."),
        compositing=dict(
            mask=dict(model="an L mask inked at the mark's alpha, pasted in the mark's "
                            "colour; the tile side is EVEN and the paste is rounded",
                      source=locate("pq1.procedural.marks.base_mark"),
                      note=_doc1(marks.base_mark),
                      applies="every mark that rests on a disc — check, x and the monogram "
                              "through base_mark itself, the traced marks building the same "
                              "tile, the logos through their PNG's alpha"),
            scaled=dict(model="the mark's colour scaled toward black by alpha, drawn straight "
                              "onto the canvas",
                        source=locate("pq1.procedural.marks.exclamation"),
                        applies="the exclamation inside its own triangle and the plus / minus "
                                "entry signs on the black panel — the only two places a mark "
                                "never meets a lit body"),
            rule="ONE model for a mark on a disc (audit ICO-01): colour-scaling is exact only "
                 "against black, so a scaled check on the SAFE green stayed green-black at "
                 "alpha 0 and cut in at full strength on frame one while the caption faded."),
        optical_centre=dict(
            rule="a mark's ink sits on the circle grid in the resting frame: the box is "
                 "centred by construction, and where the ink is lopsided the art is nudged "
                 "until the MASS lands there instead.",
            exceptions=[
                "chains.NUDGE — avalanche and linea centre their mass, so their box is "
                "deliberately off centre",
                f"{components.LETTER_PREFIX}<CHAR> — a letter is text, centred by the font's "
                "metrics rather than by its ink",
                "screens/verdict/last_attempt.py — the display digit and the heart are "
                "composed as a pair by the type tier (owner, Sep 2026)"]),
        verdict_box=dict(
            value=layout.VERDICT_BOX, unit="px", source=locate("pq1.layout.VERDICT_BOX"),
            readers=_readers("VERDICT_BOX", rel(layout.__file__))[:12],
            rule="a verdict SIGN — a triangle, a padlock, a shield, a gear, a die — inks its "
                 "LARGEST dimension to VERDICT_BOX and centres it on the circle grid. One "
                 "size for every sign that stands where the token would; tools/check rule "
                 "V-BOX measures the resting frame.",
            exempt=[
                dict(what="screens/verdict/firmware_verified.py",
                     art="the token's own disc, filled white",
                     size=2.0 * layout.CIRCLE_R,
                     why="a disc ending IS the token, not a sign — it already carries the "
                         "system's one radius"),
                dict(what="screens/verdict/headshake.py",
                     art="the token's visible disc, ringed in the state colour",
                     size=round(2.0 * components.visible_r(layout.CIRCLE_R), 2),
                     why="a ring ending is the token's visible disc; the ring is the verdict"),
                dict(what="screens/verdict/padlock.py, the unlock rest", art="the open padlock",
                     size=None,
                     why="the shackle is sprung at rest, so the OPEN pose stands taller than "
                         "the box the closed one fits"),
                dict(what="screens/verdict/last_attempt.py",
                     art="a display digit beside the heart", size=None,
                     why="composed by the type tier, not drawn as a sign (owner, Sep 2026)"),
                dict(what="screens/verdict/pin_mismatch.py, screens/verdict/duress_differ.py",
                     art="the PIN pill", size=None,
                     why="the pill is the row the user typed into, not a sign")]),
        stroke=dict(
            widths=dict(sorted(layout.STROKE.items())), unit="px",
            draws={k: STROKE_DRAWS[k] for k in sorted(layout.STROKE)},
            source=locate("pq1.layout.STROKE"),
            readers=[h for h in _readers("STROKE", rel(layout.__file__))
                     if "STROKE[" in _source_line(h)][:12],
            rule="every line weight the port draws, by name. A width off this scale is a "
                 "recorded decision, named where it is drawn.",
            not_an_exception=[
                dict(name="the resolve flash ring", source=locate("pq1.components.flash_ring"),
                     note="it takes the system ring weight by default (components."
                          "TOKEN_RING_W); it used to carry a width of its own and no "
                          "longer does")],
            exceptions=exceptions),
        mark_band=dict(
            extent_pct=list(MARK_BAND["extent_pct"]), ink_pct=list(MARK_BAND["ink_pct"]),
            of="the token's VISIBLE disc, 2 x components.visible_r(layout.CIRCLE_R)",
            source=f"{rel(__file__)}:{_assign_lines(importlib.import_module(__name__))['MARK_BAND'][0]}",
            rule="every mark that RESTS on a disc and is not a brand's own logo sits inside "
                 "the band. It is a weight rule, not a size law — the sign box above is what "
                 "fixes a verdict's size.",
            members=band,
            measured=dict(extent_pct=dict(min=_edge("extent_pct", True),
                                          max=_edge("extent_pct", False)),
                          ink_pct=dict(min=_edge("ink_pct", True),
                                       max=_edge("ink_pct", False))),
            exempt=[
                "chain brand logos — their proportions are the network's, not ours",
                "full-bleed token art — the art IS the disc",
                f"{components.LETTER_PREFIX}<CHAR> — a letter is sized by the font's cap "
                "height",
                "exclamation, plus and minus — they never rest on a disc"]),
        icons=icons,
    )


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
    "colors.json": colors_spec,
    "anims.json": anims_spec,
    "screens.schema.json": screens_schema,
    "icons.json": icons_spec,
    "flows.json": flows_spec,
    "gestures.json": gestures_spec,
    "traces.json": traces_spec,
}
