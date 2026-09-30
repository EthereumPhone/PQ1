#!/usr/bin/env python3
"""port_diff — do a port's constants match the PQ1 spec?

    python3 port_diff.py path/to/ui_tokens.h [more files ...] [--spec DIR] [--strict]
    python3 port_diff.py path/to/ui_colors.h --colors          (the colour table instead)

Reads spec/motion.json — or spec/colors.json with --colors (the base and state
colours, every ramp stop, the pinned chain discs and marks) — dumped from the
live Python by `python3 -m tools.handoff`, and the port's own source — C / C++ headers (#define, const, constexpr, enum),
Rust (const / static), MicroPython / Python (NAME = 300, NAME = const(300)) or a
JSON file — and compares every token it can pair by name.

  MATCH     same value
  MISMATCH  the port disagrees with the design system            -> exit 1
  DEMO      the port carries a demo-only token (dwell timers, the
            KIOSK spring pace): on the device nothing moves
            without a press                                       -> exit 1
  MISSING   a device token the port does not define (it may be
            inlined — check by hand; --strict makes this exit 1).
            With --colors: a colour every port names (role "base");
            ramp stops are counted, and listed with --all / --strict
  EXTRA     a timing-looking constant in the port that the spec
            does not know (a new behaviour? name it in pq1 first)

Names pair case-insensitively after dropping a project prefix (PQ1_, UI_, K_,
PQ_UI_) — so PQ1_ARRIVE_MS, kArriveMs and arrive_ms all pair with ARRIVE_MS.
In --colors mode a port value MATCHES when it equals the spec swatch in ANY
form the panel might store it: 0xRRGGBB, the RGB565 word, or an {r, g, b}
triple — how it is stored is the port's business, which colour it is is not.
Stdlib only; imports nothing from the PQ-UI repo, so it runs inside the port.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FRAME_MS = 1000.0 / 14

PATTERNS = [
    re.compile(r"^\s*#\s*define\s+(\w+)\s+\(?\s*(-?[\d._]+(?:[eE]-?\d+)?)[uUlLfF]*\s*\)?\s*(?://.*|/\*.*)?$"),
    re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:static\s+|const\s+|constexpr\s+|inline\s+)+[\w:<>\s*&]*?\b(\w+)\s*"
               r"(?::\s*[\w:<>]+\s*)?=\s*(-?[\d._]+(?:[eE]-?\d+)?)(?:_?[a-zA-Z]\w*)?\s*;"),
    re.compile(r"^\s*(\w+)\s*=\s*(?:const\()?\s*(-?[\d._]+(?:[eE]-?\d+)?)\s*\)?\s*(?:#.*)?$"),
    re.compile(r"^\s*(\w+)\s*=\s*(-?[\d._]+)\s*,\s*(?://.*)?$"),
]
PREFIX = re.compile(r"^(pq1|pq_ui|pqui|ui|k|cfg|motion|anim)_?", re.I)


def canon(name):
    n = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)       # kArriveMs -> k_Arrive_Ms
    n = PREFIX.sub("", n.upper().replace("__", "_")).strip("_")
    return n.replace("_", "")


def parse_source(path):
    out = {}
    if path.endswith(".json"):
        def walk(d, pre=""):
            for k, v in d.items():
                if isinstance(v, dict) and "value" in v and not isinstance(v["value"], (dict, list)):
                    out[k] = v["value"]
                elif isinstance(v, dict):
                    walk(v, k)
                elif isinstance(v, (int, float)) and not isinstance(v, bool):
                    out[k] = v
        walk(json.load(open(path)))
        return out
    for ln in open(path, errors="replace"):
        for pat in PATTERNS:
            m = pat.match(ln)
            if m:
                try:
                    out[m.group(1)] = float(m.group(2).replace("_", ""))
                except ValueError:
                    pass
                break
    return out


def find_spec(arg, want="motion.json"):
    cands = [arg] if arg else []
    cands += [os.path.join(HERE, "..", "spec"), os.path.join(HERE, "..", "..", "..", "spec"),
              os.path.join(os.getcwd(), "handoff", "spec"), os.path.join(os.getcwd(), "spec")]
    for c in cands:
        if c and os.path.exists(os.path.join(c, want)):
            return os.path.abspath(c)
    sys.exit(f"cannot find spec/{want} — pass --spec <folder holding {want}>")


# ------------------------------------------------------------------ colours --
COLOR_PATTERNS = [
    # #define NAME 0xRRGGBB | 0xRGB565 | 0xAARRGGBB
    re.compile(r"^\s*#\s*define\s+(\w+)\s+\(?\s*(0[xX][0-9A-Fa-f]{4,8})\s*\)?"),
    # const uint16_t NAME = 0x1234;  /  static NAME: u32 = 0xRRGGBB;
    re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:static\s+|const\s+|constexpr\s+|inline\s+)+"
               r"[\w:<>\s*&]*?\b(\w+)\s*(?::\s*[\w:<>]+\s*)?=\s*(0[xX][0-9A-Fa-f]{4,8})"),
    # NAME = (r, g, b) | {r, g, b} | [r, g, b]
    re.compile(r"^\s*(?:#\s*define\s+|(?:pub\s+)?(?:static\s+|const\s+|constexpr\s+)*"
               r"[\w:<>\s*&]*?\b)(\w+)\s*(?::\s*[\w:<>\[\]; ]+)?\s*=?\s*"
               r"[({\[]\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*[)}\]]"),
    # NAME = "#RRGGBB"
    re.compile(r"^\s*(?:#\s*define\s+)?(\w+)\s*=?\s*[\"']#([0-9A-Fa-f]{6})[\"']"),
]


def parse_colors(path):
    """name -> the raw value as written (an int, or an (r, g, b) tuple)"""
    out = {}
    if path.endswith(".json"):
        def walk(d):
            for k, v in d.items():
                if isinstance(v, dict):
                    if "rgb" in v and isinstance(v["rgb"], list):
                        out[k] = tuple(v["rgb"][:3])
                    elif "hex" in v and isinstance(v["hex"], str):
                        out[k] = int(v["hex"].lstrip("#"), 16)
                    else:
                        walk(v)
                elif isinstance(v, str) and re.fullmatch(r"#?[0-9A-Fa-f]{6}", v):
                    out[k] = int(v.lstrip("#"), 16)
                elif isinstance(v, list) and len(v) == 3 and all(isinstance(x, int) for x in v):
                    out[k] = tuple(v)
        walk(json.load(open(path)))
        return out
    for ln in open(path, errors="replace"):
        for pat in COLOR_PATTERNS:
            m = pat.match(ln)
            if not m:
                continue
            g = m.groups()
            if len(g) == 4:
                out[g[0]] = tuple(int(x) for x in g[1:])
            elif pat is COLOR_PATTERNS[-1]:
                out[g[0]] = int(g[1], 16)
            else:
                out[g[0]] = int(g[1], 16)
            break
    return out


def color_forms(ent):
    """every value a port may legitimately hold for this swatch"""
    r, g, b = ent["rgb"]
    return {int(ent["hex"].lstrip("#"), 16),          # 0xRRGGBB
            ent["rgb565"],                            # the panel word
            0xFF000000 | (r << 16) | (g << 8) | b,    # 0xAARRGGBB, opaque
            (r, g, b)}


def diff_colors(spec_dir, files, strict, show_all):
    spec = json.load(open(os.path.join(spec_dir, "colors.json")))["tokens"]
    by_canon = {canon(k): k for k in spec}
    port = {}
    for f in files:
        for k, v in parse_colors(f).items():
            port[k] = (v, f)
    rows, paired = [], set()
    for pname, (pval, pfile) in sorted(port.items()):
        sname = by_canon.get(canon(pname))
        if sname is None:
            rows.append(("EXTRA", pname, pval, None, os.path.basename(pfile),
                         "a colour the spec does not know — name it in pq1/colors.py first"))
            continue
        paired.add(sname)
        ent = spec[sname]
        ok = pval in color_forms(ent)
        rows.append(("MATCH" if ok else "MISMATCH", pname, pval, ent["hex"],
                     os.path.basename(pfile), ent.get("source", "")))
    for sname in sorted(spec):
        # a "base" colour is one every port names; a ramp stop is usually a table the port
        # copies whole, so it is only listed on request
        if sname not in paired and (show_all or strict or spec[sname].get("role") == "base"):
            rows.append(("MISSING", sname, None, spec[sname]["hex"], "",
                         spec[sname].get("source", "")))
    order = {"MISMATCH": 0, "MISSING": 1, "EXTRA": 2, "MATCH": 3}
    rows.sort(key=lambda r: (order[r[0]], r[1]))
    counts = {}

    def shown(v):
        if v is None:
            return ""
        if isinstance(v, tuple):
            return "%d,%d,%d" % v
        return "0x%X" % v
    for r in rows:
        counts[r[0]] = counts.get(r[0], 0) + 1
        if r[0] == "MATCH" and not show_all:
            continue
        print(f"{r[0]:9} {r[1]:28} port={shown(r[2]):>12}  spec={r[3] or '':>9}  {r[4]} {r[5]}")
    print("\n" + " · ".join(f"{k} {counts.get(k, 0)}" for k in ("MATCH", "MISMATCH", "MISSING", "EXTRA")))
    if not (show_all or strict):
        n_ramp = sum(1 for k, v in spec.items() if v.get("role") != "base" and k not in paired)
        if n_ramp:
            print(f"({n_ramp} ramp stops unpaired — a port usually copies those as a table; "
                  f"--all lists them)")
    bad = counts.get("MISMATCH", 0) + (counts.get("MISSING", 0) if strict else 0)
    return 1 if bad else 0


def spec_tokens(spec_dir):
    m = json.load(open(os.path.join(spec_dir, "motion.json")))
    toks = {}
    for group, d in m["tokens"].items():
        for name, ent in d.items():
            if isinstance(ent.get("value"), (int, float)) and not isinstance(ent["value"], bool):
                toks[name] = dict(value=ent["value"], scope=ent.get("scope", "device"), unit=ent.get("unit"),
                                  source=ent.get("source", ""), group=group)
    for name, ent in m.get("verdict_law", {}).items():
        toks["VERDICT_" + name] = dict(value=ent["value"], scope="device", unit="ms",
                                       source=ent["source"], group="verdict_law")
    for name, v in m.get("qubit_timeline", {}).items():
        if isinstance(v, (int, float)) and not isinstance(v, bool) and name.isupper():
            toks["QUBIT_" + name] = dict(value=v, scope="device", unit="ms", source="pq1/loading.py", group="qubit")
    return toks


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--spec", help="folder holding motion.json (default: the skill's own spec/, or handoff/spec)")
    ap.add_argument("--strict", action="store_true", help="MISSING device timing tokens also exit 1")
    ap.add_argument("--all", action="store_true", help="list MATCH rows too")
    ap.add_argument("--colors", action="store_true",
                    help="compare colours against spec/colors.json instead of timings")
    a = ap.parse_args()
    if a.colors:
        return diff_colors(find_spec(a.spec, "colors.json"), a.files, a.strict, a.all)
    spec = spec_tokens(find_spec(a.spec))
    by_canon = {canon(k): k for k in spec}
    port = {}
    for f in a.files:
        for k, v in parse_source(f).items():
            port[k] = (v, f)
    rows, paired = [], set()
    for pname, (pval, pfile) in sorted(port.items()):
        sname = by_canon.get(canon(pname))
        if sname is None:
            if re.search(r"(_MS|MS$|Ms$|_DWELL|TAU|DELAY|PERIOD|^T_)", pname):
                rows.append(("EXTRA", pname, pval, None, os.path.basename(pfile), ""))
            continue
        paired.add(sname)
        s = spec[sname]
        if s["scope"] == "demo":
            rows.append(("DEMO", pname, pval, s["value"], os.path.basename(pfile), "demo-only token — do not port"))
        elif abs(float(s["value"]) - pval) > 1e-6:
            rows.append(("MISMATCH", pname, pval, s["value"], os.path.basename(pfile), s["source"]))
        else:
            rows.append(("MATCH", pname, pval, s["value"], os.path.basename(pfile), s["source"]))
    for sname, s in sorted(spec.items()):
        if sname not in paired and s["scope"] == "device" and s["unit"] == "ms" and s["group"] in ("motion", "status", "verdict_law"):
            rows.append(("MISSING", sname, None, s["value"], "", s["source"]))
    order = {"MISMATCH": 0, "DEMO": 1, "MISSING": 2, "EXTRA": 3, "MATCH": 4}
    rows.sort(key=lambda r: (order[r[0]], r[1]))
    counts = {}
    for r in rows:
        counts[r[0]] = counts.get(r[0], 0) + 1
        if r[0] == "MATCH" and not a.all:
            continue
        frames = f"{r[3] / FRAME_MS:5.1f} f" if isinstance(r[3], (int, float)) else "       "
        print(f"{r[0]:9} {r[1]:28} port={'' if r[2] is None else f'{r[2]:g}':>8}  spec={'' if r[3] is None else f'{r[3]:g}':>8}  {frames}  {r[4]} {r[5]}")
    print("\n" + " · ".join(f"{k} {counts.get(k, 0)}" for k in ("MATCH", "MISMATCH", "DEMO", "MISSING", "EXTRA")))
    bad = counts.get("MISMATCH", 0) + counts.get("DEMO", 0) + (counts.get("MISSING", 0) if a.strict else 0)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
