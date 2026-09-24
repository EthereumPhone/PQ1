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
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
