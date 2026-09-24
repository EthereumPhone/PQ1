"""The page engine: prose with placeholders in, markdown with LIVE numbers out.

A page under tools/handoff/pages/ never types a duration, a frame count or a
file:line — it names the token and the engine resolves it against the running
code. A stale name, a raw "300 ms" in prose or an easing that pq1.motion does
not define FAILS the build: that is what keeps handoff/ from drifting.

Placeholders
  {{val:PATH}}              the bare value                       300
  {{tok:PATH}}              name + value + frames                `ARRIVE_MS` 300 ms (4.2 f)
  {{loc:PATH}}              where it is defined                  `pq1/motion.py:326`
  {{row:phase | EXPR | easing | note}}   one motion-table row (after {{motion-head}})
  {{motion-head}}           the motion table's header
  {{lit:TEXT}}              a literal the raw-number guard should let through
  {{partial:NAME}}          pages/_partials/NAME.md
  {{doc:MODULE}}            a module's docstring (as a quote block)
  {{fields:a,b,c}}          schema rows for screen-dict keys (from pq1/layout.py's docstring)
  ... plus the per-entry blocks build.py registers: {{example}} {{used-in}}
      {{preview}} {{variants}} {{phases}} {{gestures:CONTEXT}} {{owners}} {{geometry}}

PATH is a dotted python path (pq1.motion.ARRIVE_MS, pq1.verdict.VerdictAnim.T_HOLD),
or anim:<key>:<attr> for a per-preset value from the live instance
(anim:verdict/padlock@unlock:T_IN, anim:core/qubit:duration — '@' names the preset), or qubit:<field>
(loading.QubitCfg), or burst:MAJOR.<field> / burst:MINOR.<field>.
EXPR may add / subtract / multiply PATHs and numbers: pq1.motion.HOLD_COMMIT_MS - pq1.motion.TAP_MAX_MS
"""
import ast
import inspect
import os
import re

from . import introspect as I
from pq1 import loading, motion, status
from pq1.procedural import burst

PAGES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")
EASINGS_EXTRA = {"linear", "spring", "spring NAV", "spring KIOSK", "tau_chase", "cut", "hold", "—",
                 "raised cosine", "sine"}
_PH = re.compile(r"\{\{\s*([a-z-]+)\s*(?::((?:(?!\{\{|\}\}).)*))?\}\}", re.S)   # innermost first
_RAW = re.compile(r"(?<![\w{:.|/-])\d+(?:\.\d+)?\s?(?:ms|fps|frames?)\b")


class PageError(Exception):
    pass


_ANIMS = {}


def _anim(key):
    if not _ANIMS:
        for k, qual, preset, sp in I.anim_instances():
            _ANIMS[k] = status.anim_for(sp)
    if key not in _ANIMS:
        raise PageError(f"unknown anim key {key!r}; one of {', '.join(sorted(_ANIMS))}")
    return _ANIMS[key]


def value_of(path):
    """(value, display name, location or None)"""
    path = path.strip()
    if path.startswith("anim:"):
        _, key, attr = path.split(":", 2)
        an = _anim(key.replace("@", "|"))      # '@' names the preset: '|' is the row separator
        main = getattr(an, "main", an)
        obj = an if attr in ("t_resolve", "duration", "t_tail") else main
        if not hasattr(obj, attr):
            raise PageError(f"{key} has no attribute {attr!r}")
        cls = type(obj)
        hit = I._class_attr_line(cls, attr)
        return getattr(obj, attr), attr, (f"{hit[0]}:{hit[1]}" if hit else None)
    if path.startswith("qubit:"):
        f = path.split(":", 1)[1]
        cfg = loading.QubitCfg()
        if not hasattr(cfg, f):
            raise PageError(f"QubitCfg has no field {f!r}")
        return getattr(cfg, f), f"QubitCfg.{f}", I.locate("pq1.loading.QubitCfg")
    if path.startswith("burst:"):
        table, f = path.split(":", 1)[1].split(".", 1)
        cfg = getattr(burst, table)
        v = getattr(cfg, f) if hasattr(cfg, f) else cfg[f]
        return v, f"burst.{table}.{f}", I.locate(f"pq1.procedural.burst.{table}")
    try:
        return I.resolve(path), path.rsplit(".", 1)[-1], I.locate(path)
    except (ImportError, AttributeError) as e:
        raise PageError(f"stale placeholder {path!r}: {e}") from None


def eval_expr(expr):
    """(number, 'NAME + NAME', first location) for PATHs joined by + - * /"""
    names, locs = [], []
    tokens = re.split(r"(\s[+\-*/]\s|\(|\))", expr.strip())
    py = []
    for t in tokens:
        ts = t.strip()
        if not ts:
            continue
        if ts in "+-*/()":
            py.append(ts)
            names.append(ts)
        elif re.fullmatch(r"\d+(\.\d+)?", ts):
            py.append(ts)
            names.append(ts)
        else:
            v, nm, loc = value_of(ts)
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise PageError(f"{ts!r} is not a number ({v!r})")
            py.append(repr(v))
            names.append(nm)
            if loc:
                locs.append(loc)
    node = ast.parse(" ".join(py), mode="eval")
    for n in ast.walk(node):
        if not isinstance(n, (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant, ast.Add, ast.Sub,
                              ast.Mult, ast.Div, ast.USub)):
            raise PageError(f"unsupported expression {expr!r}")
    return eval(compile(node, "<expr>", "eval")), " ".join(names), (locs[0] if locs else "")


def fmt_num(v):
    if isinstance(v, float) and abs(v - round(v)) < 1e-9:
        v = int(round(v))
    return f"{v:g}" if isinstance(v, float) else str(v)


def fmt_frames(ms):
    return f"{ms / I.FRAME_MS:.1f}"


MOTION_HEAD = ("| phase | ms | frames @14 fps | easing | token | defined at | notes |\n"
               "|---|---:|---:|---|---|---|---|")


def check_easing(name, where):
    base = name.strip().strip("`")
    parts = [p.strip() for p in re.split(r"[+,/]| then ", base)]
    for p in parts:
        p0 = p.split("(")[0].strip()
        if p0 in EASINGS_EXTRA:
            continue
        if not (hasattr(motion, p0) and inspect.isfunction(getattr(motion, p0))):
            raise PageError(f"{where}: easing {p0!r} is not a pq1.motion function "
                            f"(nor one of {sorted(EASINGS_EXTRA)})")


def render(text, where, blocks=None, schema_fields=None):
    """expand every placeholder; raise PageError on anything stale"""
    blocks = blocks or {}

    def sub(m):
        kind, arg = m.group(1), (m.group(2) or "").strip()
        if kind == "val":
            return fmt_num(value_of(arg)[0])
        if kind == "tok":
            v, nm, _ = value_of(arg)
            unit = I._unit(nm, v) or ("ms" if arg.startswith(("anim:", "qubit:")) and isinstance(v, (int, float)) else None)
            if unit == "ms":
                return f"`{nm}` {fmt_num(v)} ms ({fmt_frames(v)} f)"
            return f"`{nm}` {fmt_num(v) if isinstance(v, (int, float)) else v}" + (f" {unit}" if unit else "")
        if kind == "loc":
            loc = value_of(arg)[2]
            if not loc:
                raise PageError(f"{where}: no location for {arg!r}")
            return f"`{loc}`"
        if kind == "row":
            cells = [c.strip() for c in arg.split("|")]
            if len(cells) < 3:
                raise PageError(f"{where}: row needs 'phase | EXPR | easing [| note]': {arg!r}")
            phase, expr, easing = cells[:3]
            note = cells[3] if len(cells) > 3 else ""
            check_easing(easing, where)
            if expr in ("-", "—", ""):
                return f"| {phase} | — | — | {easing} | — | — | {note} |"
            v, names, loc = eval_expr(expr)
            return (f"| {phase} | {fmt_num(round(v, 1))} | {fmt_frames(v)} | {easing} | "
                    f"`{names}` | {f'`{loc}`' if loc else '—'} | {note} |")
        if kind == "motion-head":
            return MOTION_HEAD
        if kind == "lit":
            return arg
        if kind == "partial":
            p = os.path.join(PAGES, "_partials", arg + ".md")
            if not os.path.exists(p):
                raise PageError(f"{where}: no partial {arg!r}")
            return render(open(p).read().strip(), f"_partials/{arg}", blocks, schema_fields)
        if kind == "doc":
            mod = I.resolve(arg)
            doc = inspect.getdoc(mod) or ""
            return "\n".join("> " + ln if ln else ">" for ln in doc.splitlines())
        if kind == "fields":
            rows = ["| key | form | meaning |", "|---|---|---|"]
            for k in [a.strip() for a in arg.split(",") if a.strip()]:
                f = (schema_fields or {}).get(k)
                if f is None:
                    raise PageError(f"{where}: {k!r} is not a documented screen-dict key (pq1/layout.py docstring)")
                form = f["form"].replace("|", "\\|")
                note = f["note"].replace("|", "\\|")
                rows.append(f"| `{k}` | `{form}` | {note} |")
            return "\n".join(rows)
        if kind in blocks:
            b = blocks[kind]
            return b(arg) if callable(b) else b
        raise PageError(f"{where}: unknown placeholder {{{{{kind}}}}}")

    # the raw-number guard runs on the SOURCE, outside placeholders and code
    stripped = text
    for _ in range(6):
        stripped = _PH.sub("", stripped)
    stripped = re.sub(r"```.*?```", "", stripped, flags=re.S)
    hit = _RAW.search(stripped)
    if hit:
        line = text[:text.find(hit.group(0))].count("\n") + 1
        raise PageError(f"{where}:{line}: raw number {hit.group(0)!r} in prose — name the token "
                        f"({{{{tok:pq1.motion.X}}}}) so it cannot drift, or wrap it in {{{{lit:...}}}}")
    out = text
    for _ in range(6):                          # innermost placeholders first, then the rows holding them
        nxt = _PH.sub(sub, out)
        if nxt == out:
            break
        out = nxt
    if "{{" in out:
        raise PageError(f"{where}: unresolved placeholder near {out[out.find('{{'):][:60]!r}")
    return out
