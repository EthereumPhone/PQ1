#!/usr/bin/env python3
"""Analyse an SE050 read-only probe log (`make se050-probe-hw`) and give a verdict.

Usage:
    report.py LOG [--out DIR]

Reads the semihosting log the `se050-probe` image printed (`[SPROBE] …` lines),
decodes the identity, inventory, free-memory and plain-command-matrix facts,
applies the §6B rules, and prints a short verdict plus (with --out) a markdown
summary.

The probe firmware is the source of truth for pass/fail (it prints
`=== SPROBE DONE OK ===` or `=== SPROBE DONE FINDINGS ===`); this tool
cross-checks the decoded facts and flags anything the firmware's inline checks
do not, so a human does not have to eyeball hex.

Exit status: 0 = DONE OK and no host-side finding;
             1 = findings (firmware or host-side);
             2 = inconclusive (no DONE marker, or no data).
"""

from __future__ import annotations

import argparse
import re
import sys

SPROBE = re.compile(r"\[SPROBE\]\s*(.*)")

# Object IDs that are legitimately present on a bench SE050E2 and are NOT a
# finding if the inventory lists them. Everything in a production or
# unexpected range is flagged by the firmware; this is the host allow-set for
# the known bench leftovers.
BENCH_OK_RANGES = [
    (0x7B5E_0000, 0x7B5E_FFFF, "stress-carveout"),
    (0x7B5F_0000, 0x7B5F_FFFF, "stress-stranded (harmless NVM leak)"),
    (0x7FFF_0000, 0x7FFF_FFFF, "nxp-reserved"),
]


def classify_ok(oid: int) -> bool:
    return any(lo <= oid <= hi for lo, hi, _ in BENCH_OK_RANGES)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    try:
        with open(args.log, "r", errors="replace") as fh:
            raw = fh.read()
    except OSError as e:
        print(f"se050-probe report: cannot read {args.log}: {e}", file=sys.stderr)
        return 2

    facts = [m.group(1).strip() for m in (SPROBE.match(line.strip()) or
             SPROBE.search(line) for line in raw.splitlines()) if m]
    # The regex above is awkward; just re-extract cleanly:
    facts = [SPROBE.search(line).group(1).strip()
             for line in raw.splitlines() if SPROBE.search(line)]

    done_ok = "=== SPROBE DONE OK ===" in raw
    done_find = "=== SPROBE DONE FINDINGS ===" in raw
    aborted = "=== SPROBE ABORT ===" in raw

    findings: list[str] = []
    identity = []
    inventory = []  # (oid, class, size)
    free = {}
    plain = []

    for f in facts:
        if f.startswith("6B.1 applet") or f.startswith("6B.1 GetVersionExt"):
            identity.append(f)
        elif f.startswith("6B.3   id="):
            m = re.search(r"id=0x([0-9a-f]+) class=(\S+).*size=(\d+)", f)
            if m:
                inventory.append((int(m.group(1), 16), m.group(2), int(m.group(3))))
        elif f.startswith("6B.4 free-memory"):
            m = re.search(r"\[(\S+)\]\s*=\s*(\d+)", f)
            if m:
                free[m.group(1)] = int(m.group(2))
        elif f.startswith("6B.6 plain"):
            plain.append(f)
        if "FINDING:" in f:
            findings.append(f)

    # Host cross-checks.
    for oid, cls, _size in inventory:
        if cls in ("PRODUCTION(v6)", "UNEXPECTED") and not classify_ok(oid):
            findings.append(f"host: object 0x{oid:08x} in range {cls} — not a known bench leftover")

    # Plain matrix: a plain read of a secret object returning data is fatal
    # (the firmware already flags it; double-check here).
    for p in plain:
        if "Read(ENTROPY_OBJ)" in p:
            m = re.search(r"SW=0x([0-9a-f]+) datalen=(\d+)", p)
            if m and m.group(1) == "9000" and int(m.group(2)) > 0:
                findings.append("host: plain read of ENTROPY_OBJ returned data (half_E in clear)")

    lines = []
    lines.append("# SE050 read-only probe (§6B) — report\n")
    lines.append(f"- log: `{args.log}`")
    lines.append(f"- firmware verdict: {'DONE OK' if done_ok else 'DONE FINDINGS' if done_find else 'ABORT' if aborted else 'NO MARKER'}")
    lines.append("\n## Identity (6B.1)")
    lines += [f"- {i}" for i in identity] or ["- (none)"]
    lines.append("\n## Free memory (6B.4)")
    lines += [f"- {k}: {v} bytes" for k, v in free.items()] or ["- (none)"]
    lines.append(f"\n## Inventory (6B.3) — {len(inventory)} object(s)")
    lines += [f"- 0x{oid:08x}  {cls}  size={sz}" for oid, cls, sz in inventory] or ["- (none)"]
    lines.append("\n## Plain (no-SCP03) read-class matrix (6B.6)")
    lines += [f"- {p}" for p in plain] or ["- (none)"]
    lines.append("\n## Findings")
    lines += [f"- {x}" for x in findings] or ["- none"]

    report = "\n".join(lines) + "\n"
    print(report)
    if args.out:
        import os
        os.makedirs(args.out, exist_ok=True)
        path = os.path.join(args.out, "se050-probe-report.md")
        with open(path, "w") as fh:
            fh.write(report)
        print(f"wrote {path}")

    if not (done_ok or done_find):
        return 2
    return 1 if (findings or done_find) else 0


if __name__ == "__main__":
    sys.exit(main())
