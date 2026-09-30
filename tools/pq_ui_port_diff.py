#!/usr/bin/env python3
"""Run upstream PQ-UI `port_diff` over the firmware's motion / input / film
constants and fail on any MISMATCH or DEMO row that is not a recorded
deviation (tools/pq-ui/PORT_DEVIATIONS.toml).

The pairing, parsing and verdict logic is upstream's (imported from the
vendored `handoff/skill/pq1-conformance/scripts/port_diff.py`); only the
spec loader is replaced, because the vendored `motion.json` dumps
`verdict_law` entries as {default, values, ...} rather than {value, source}
and the upstream loader crashes on that shape (reported upstream). MISSING
and EXTRA rows are informational: a device token the port inlines, or a
device-only constant (the SysTick debounce) the reference does not name.
"""
import json
import os
import re
import sys
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "tools", "pq-ui", "handoff", "skill", "pq1-conformance", "scripts")
SPEC = os.path.join(ROOT, "tools", "pq-ui", "handoff", "spec")
DEVIATIONS = os.path.join(ROOT, "tools", "pq-ui", "PORT_DEVIATIONS.toml")
FILES = [
    "pqsigner-ui-px/src/motion.rs",
    "pqsigner-ui-px/src/input.rs",
    "pqsigner-ui-px/src/loading.rs",
]
# Colour tables. `spec/colors.json` reached the handoff only in 198bbcb9, so
# until 2026-09-30 nothing bound these at all — which is how the port kept the
# reference's PRE-fix `placeholder_index` modulus (audit COL-01: a hashed key
# reaching the mono ramp renders an unrecognized token as ether) and two stale
# ramps. A timing gate that does not read the palette cannot see any of that.
COLOR_FILES = {
    "ramps": "pqsigner-ui-px/src/scene.rs",
    "base": "pqsigner-ui-px/src/raster.rs",
    "hash": "pqsigner-ui-px/src/screen.rs",
}
# port name -> spec/colors.json `base` name
BASE_COLORS = {
    "BLACK": "BLACK", "WHITE": "WHITE", "YELLOW": "YELLOW",
    "GREEN": "GREEN", "RED": "RED", "ORANGE": "ORANGE",
    "COWSWAP_NAVY": "COWSWAP_DARK",
}

sys.path.insert(0, SKILL)
import port_diff  # noqa: E402  (vendored upstream)


def spec_tokens(spec_dir):
    m = json.load(open(os.path.join(spec_dir, "motion.json")))
    toks = {}
    for group, d in m["tokens"].items():
        for name, ent in d.items():
            v = ent.get("value") if isinstance(ent, dict) else None
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                toks[name] = dict(value=v, scope=ent.get("scope", "device"), unit=ent.get("unit"),
                                  source=ent.get("source", ""), group=group)
    for name, ent in m.get("verdict_law", {}).items():
        v = ent.get("value", ent.get("default")) if isinstance(ent, dict) else None
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            toks["VERDICT_" + name] = dict(value=v, scope="device", unit="ms",
                                           source=ent.get("source", ""), group="verdict_law")
    for name, v in m.get("qubit_timeline", {}).items():
        if isinstance(v, (int, float)) and not isinstance(v, bool) and name.isupper():
            toks["QUBIT_" + name] = dict(value=v, scope="device", unit="ms", source="pq1/loading.py", group="qubit")
    return toks


def _rgb_triples(text):
    return [tuple(int(x, 16) for x in m)
            for m in re.findall(r"Rgb::new\(0x([0-9A-Fa-f]{2}),\s*0x([0-9A-Fa-f]{2}),\s*0x([0-9A-Fa-f]{2})\)", text)]


def check_colors(spec_dir):
    """The palette half of the port diff: the 14 placeholder ramps, the base
    colours, the three token ramp fills, and the hash rule that picks a ramp.

    Returns (rows, bad). A row is (verdict, what, port, spec, detail)."""
    with open(os.path.join(spec_dir, "colors.json"), encoding="utf-8") as f:
        spec = json.load(f)
    rows, bad = [], 0

    # --- the placeholder ramps, every stop
    src = open(os.path.join(ROOT, COLOR_FILES["ramps"]), encoding="utf-8").read()
    blk = src[src.index("pub const PLACEHOLDER_RAMPS"):]
    blk = blk[:blk.index("\n];")]
    port_ramps = [_rgb_triples(l) for l in blk.splitlines() if l.strip().startswith("[Rgb::new")]
    ref_ramps = [[tuple(st["rgb"]) for st in r["stops"]] for r in spec["placeholder_ramps"]]
    if len(port_ramps) != len(ref_ramps):
        rows.append(("MISMATCH", "PLACEHOLDER_RAMPS", f"{len(port_ramps)} ramps", f"{len(ref_ramps)} ramps", ""))
        bad += 1
    for i, (p, r) in enumerate(zip(port_ramps, ref_ramps)):
        for j, (a, b) in enumerate(zip(p, r)):
            if a != b:
                rows.append(("MISMATCH", f"RAMP_{i}_STOP_{j + 1}",
                             "#%02X%02X%02X" % a, "#%02X%02X%02X" % b, "colors.PLACEHOLDER_GRADIENTS"))
                bad += 1
            else:
                rows.append(("MATCH", f"RAMP_{i}_STOP_{j + 1}", "", "", ""))

    # --- the token ramp fills
    for name, key in (("RAMP_USDC", "USDC"), ("RAMP_USDT", "USDT"), ("RAMP_DAI", "DAI")):
        line = next((l for l in src.splitlines() if l.startswith("pub const " + name)), None)
        if line is None:
            rows.append(("MISSING", name, "<absent>", "", ""))
            continue
        fill = _rgb_triples(line)[-1]
        ref = tuple(spec["token_ramp_colors"][key]["rgb"])
        verdict = "MATCH" if fill == ref else "MISMATCH"
        bad += verdict == "MISMATCH"
        rows.append((verdict, name + "_FILL", "#%02X%02X%02X" % fill, "#%02X%02X%02X" % ref, "colors.TOKEN_GRADIENTS"))

    # --- the base colours
    ras = open(os.path.join(ROOT, COLOR_FILES["base"]), encoding="utf-8").read()
    for pname, sname in BASE_COLORS.items():
        m = re.search(r"pub const %s: Self = Self::new\(([^)]*)\)" % pname, ras)
        if not m:
            rows.append(("MISSING", pname, "<absent>", "", ""))
            continue
        vals = tuple(int(x.strip(), 0) for x in m.group(1).split(","))
        ref = tuple(spec["base"][sname]["rgb"])
        verdict = "MATCH" if vals == ref else "MISMATCH"
        bad += verdict == "MISMATCH"
        rows.append((verdict, pname, "#%02X%02X%02X" % vals, "#%02X%02X%02X" % ref, "colors." + sname))

    # --- the hash rule (audit COL-01). The modulus is the whole finding: the
    # reference hashes over MONO_RAMP, not over every ramp, so an unrecognized
    # token can never wear the recognized-token look.
    scr = open(os.path.join(ROOT, COLOR_FILES["hash"]), encoding="utf-8").read()
    m = re.search(r"pub const MONO_RAMP: u8 = (\d+);", scr)
    port_mono = int(m.group(1)) if m else None
    ref_mono = spec["hash_rule"]["mono_ramp"]
    verdict = "MATCH" if port_mono == ref_mono else "MISMATCH"
    bad += verdict == "MISMATCH"
    rows.append((verdict, "MONO_RAMP", port_mono if port_mono is not None else "<absent>", ref_mono,
                 spec["hash_rule"]["source"]))
    m = re.search(r"\(\(!crc\) % u32::from\((\w+)\)\) as u8", scr)
    modulus = m.group(1) if m else "<not found>"
    verdict = "MATCH" if modulus == "MONO_RAMP" else "MISMATCH"
    bad += verdict == "MISMATCH"
    rows.append((verdict, "placeholder_ramp modulus", modulus, "MONO_RAMP", spec["hash_rule"]["expr"]))
    return rows, bad


def main():
    with open(DEVIATIONS, "rb") as f:
        allowed = {d["token"]: d for d in tomllib.load(f).get("deviation", [])}
    spec = spec_tokens(SPEC)
    by_canon = {port_diff.canon(k): k for k in spec}
    port = {}
    for f in FILES:
        path = os.path.join(ROOT, f)
        if os.path.exists(path):
            for k, v in port_diff.parse_source(path).items():
                port[k] = (v, f)
    bad = 0
    rows = []
    for pname, (pval, pfile) in sorted(port.items()):
        sname = by_canon.get(port_diff.canon(pname))
        if sname is None:
            continue
        s = spec[sname]
        if s["scope"] == "demo":
            rows.append(("DEMO", pname, pval, s["value"], pfile, "demo-only token — do not port"))
            bad += 1
        elif abs(float(s["value"]) - pval) > 1e-6:
            dev = allowed.get(sname) or allowed.get(pname)
            if dev and abs(float(dev["device"]) - pval) < 1e-6 and abs(float(dev["reference"]) - s["value"]) < 1e-6:
                rows.append(("DEVIATION", pname, pval, s["value"], pfile, f"recorded {dev['decided']}"))
            else:
                rows.append(("MISMATCH", pname, pval, s["value"], pfile, s["source"]))
                bad += 1
        else:
            rows.append(("MATCH", pname, pval, s["value"], pfile, ""))
    for sname, tok in allowed.items():
        if sname not in spec:
            print(f"UNKNOWN   {sname:28} PORT_DEVIATIONS.toml names a token the spec does not have")
            bad += 1
    counts = {}
    for r in rows:
        counts[r[0]] = counts.get(r[0], 0) + 1
        if r[0] != "MATCH":
            print(f"{r[0]:9} {r[1]:28} port={r[2]:>8g}  spec={r[3]:>8g}  {r[4]} {r[5]}")
    print(" · ".join(f"{k} {counts.get(k, 0)}" for k in ("MATCH", "DEVIATION", "MISMATCH", "DEMO")))

    crows, cbad = check_colors(SPEC)
    bad += cbad
    ccounts = {}
    for r in crows:
        ccounts[r[0]] = ccounts.get(r[0], 0) + 1
        if r[0] != "MATCH":
            print(f"{r[0]:9} {r[1]:28} port={str(r[2]):>10}  spec={str(r[3]):>10}  {r[4]}")
    print("colours: " + " · ".join(f"{k} {ccounts.get(k, 0)}" for k in ("MATCH", "MISMATCH", "MISSING")))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
