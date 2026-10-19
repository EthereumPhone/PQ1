#!/usr/bin/env python3
"""Analyse an SE050 read-only probe log (`make se050-probe-hw`) and give a verdict.

Usage:
    report.py LOG [--out DIR]

Reads the semihosting log the `se050-probe` image printed (`[SPROBE] …` lines),
decodes the identity, inventory, free-memory and plain-command-matrix facts,
applies the §6B rules, and prints a short verdict plus (with --out) a markdown
summary.

The probe firmware prints `=== SPROBE DONE OK ===` or `=== SPROBE DONE
FINDINGS ===`, but it does not fail the run for cleanup findings (leftover
e2e/retired objects); every `FINDING:` line it prints is a finding here. This
tool also re-checks the decoded facts so a human does not have to eyeball hex.

Exit status: 0 = DONE OK and no finding;
             1 = findings (firmware or host-side);
             2 = inconclusive (no DONE marker, or no data).
"""

from __future__ import annotations

import argparse
import os
import re
import sys

SPROBE = re.compile(r"\[SPROBE\]\s*(.*)")
INVENTORY = re.compile(r"id=0x([0-9a-f]+) class=(\S+).*size=(\d+|err)")
FREE = re.compile(r"\[(\S+)\]\s*=\s*(\d+)")
PLAIN_READ = re.compile(r"SW=0x([0-9a-f]+) datalen=(\d+)")
# `6B.6 plain[<leg>] <cmd> SW=0x....` — leg is the link state the row ran in.
PLAIN_LEG = re.compile(r"^6B\.6 plain\[([a-z-]+)\] (\S+) SW=0x([0-9a-f]+)")
# Legs with no SCP03 session alive: what a keyless bus party gets.
PRE_SESSION_LEGS = ("pre-select", "pre-session")

# Classes the firmware assigns (`se050::probe::classify`) that are findings:
# production or unknown objects on a bench die, and objects an e2e run or a
# retired firmware generation should have deleted.
FINDING_CLASSES = {
    "PRODUCTION(v6)": "production-range object on a bench die",
    "UNEXPECTED": "object outside every known range",
    "e2e-test": "stale e2e object (the run that wrote it should have deleted it)",
    "retired-prod": "object from a retired firmware generation",
}

# `GetFreeMemory` saturates here; a value at the cap is a floor, not a count.
FREE_MEMORY_CAP = 0x7FFF


def analyse(raw: str) -> dict:
    facts = [m.group(1).strip() for m in map(SPROBE.search, raw.splitlines()) if m]

    findings: list[str] = []
    identity: list[str] = []
    inventory: list[tuple[int, str, int | None]] = []
    free: dict[str, int] = {}
    plain: list[str] = []
    paging: list[str] = []

    for f in facts:
        if f.startswith("6B.1 applet") or f.startswith("6B.1 GetVersionExt"):
            identity.append(f)
        elif f.startswith("6B.3   id="):
            m = INVENTORY.search(f)
            if m:
                size = None if m.group(3) == "err" else int(m.group(3))
                inventory.append((int(m.group(1), 16), m.group(2), size))
        elif f.startswith("6B.4 free-memory"):
            m = FREE.search(f)
            if m:
                free[m.group(1)] = int(m.group(2))
            elif " ERR " in f:
                findings.append(f"host: {f}")
        elif f.startswith("6B.6 plain"):
            plain.append(f)
            if " ERR " in f:
                findings.append(f"host: {f} (matrix row unverified)")
        elif f.startswith("6B.3b"):
            paging.append(f)
        if "FINDING:" in f:
            findings.append(f)

    for oid, cls, _size in inventory:
        if cls in FINDING_CLASSES:
            findings.append(f"host: 0x{oid:08x} {cls}: {FINDING_CLASSES[cls]}")

    # A plain read of the secret object returning data is fatal (the firmware
    # already flags it; double-check here).
    for p in plain:
        if "Read(ENTROPY_OBJ)" in p:
            m = PLAIN_READ.search(p)
            if m and m.group(1) == "9000" and int(m.group(2)) > 0:
                findings.append("host: plain read of ENTROPY_OBJ returned data (half_E in clear)")

    # Pre-session surface: every plain command a power-on chip answered with
    # 9000 before any SCP03 session existed. Not a finding by itself (GetRandom
    # or SELECT data is not secret); the ENTROPY_OBJ rule above is the fatal one.
    pre_session_open: list[str] = []
    for p in plain:
        m = PLAIN_LEG.search(p)
        if m and m.group(1) in PRE_SESSION_LEGS and m.group(3) == "9000":
            pre_session_open.append(f"{m.group(1)} {m.group(2)}")

    saturated = sorted(k for k, v in free.items() if v >= FREE_MEMORY_CAP)

    if "=== SPROBE DONE OK ===" in raw:
        verdict = "DONE OK"
    elif "=== SPROBE DONE FINDINGS ===" in raw:
        verdict = "DONE FINDINGS"
    elif "=== SPROBE ABORT ===" in raw:
        verdict = "ABORT"
    else:
        verdict = "NO MARKER"

    return {
        "verdict": verdict,
        "identity": identity,
        "inventory": inventory,
        "free": free,
        "saturated": saturated,
        "plain": plain,
        "pre_session_open": pre_session_open,
        "paging": paging,
        "findings": findings,
    }


def render(log: str, r: dict) -> str:
    lines = ["# SE050 read-only probe (§6B) — report\n"]
    lines.append(f"- log: `{log}`")
    lines.append(f"- firmware verdict: {r['verdict']}")
    lines.append("\n## Identity (6B.1)")
    lines += [f"- {i}" for i in r["identity"]] or ["- (none)"]
    lines.append("\n## Free memory (6B.4)")
    lines += [
        f"- {k}: {v} bytes" + (" (saturated: floor only, cannot show a leak)" if k in r["saturated"] else "")
        for k, v in r["free"].items()
    ] or ["- (none)"]
    lines.append(f"\n## Inventory (6B.3) — {len(r['inventory'])} object(s)")
    lines += [
        f"- 0x{oid:08x}  {cls}  size={'err' if sz is None else sz}" for oid, cls, sz in r["inventory"]
    ] or ["- (none)"]
    lines.append("\n## ReadIDList offset unit (6B.3b)")
    lines += [f"- {p}" for p in r["paging"]] or ["- (none)"]
    lines.append("\n## Plain (no-SCP03) read-class matrix (6B.6)")
    lines += [f"- {p}" for p in r["plain"]] or ["- (none)"]
    lines.append("\n### Answered 9000 with no session alive (pre-select / pre-session legs)")
    lines += [f"- {p}" for p in r["pre_session_open"]] or ["- none"]
    lines.append("\n## Findings")
    lines += [f"- {x}" for x in r["findings"]] or ["- none"]
    return "\n".join(lines) + "\n"


def exit_code(r: dict) -> int:
    if r["verdict"] not in ("DONE OK", "DONE FINDINGS"):
        return 2
    return 1 if (r["findings"] or r["verdict"] == "DONE FINDINGS") else 0


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

    r = analyse(raw)
    report = render(args.log, r)
    print(report)
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        path = os.path.join(args.out, "se050-probe-report.md")
        with open(path, "w") as fh:
            fh.write(report)
        print(f"wrote {path}")
    return exit_code(r)


if __name__ == "__main__":
    sys.exit(main())
