#!/usr/bin/env python3
"""Pixel-UI screen catalogue from a QEMU `make e2e-px` log
(`tools/ui_screens_export.py --px LOG`).

The log carries, per Safe scenario, one `[UI-PX] idx/total pN …` human line
and one `[UI-PXR] idx pN <512 hex>` record line for every (screen, page) the
secure world presented. This module groups them by scenario, renders every
record with the REAL engine and the baked atlas (the crate's `render_record`
example — no Python re-implementation of the renderer), and writes
`docs/ui-screens/px/<scenario>/NN-<id>-pN.png` plus a README index with the
record text. The records are the proven transcript bytes; the PNGs are what
the panel showed for them.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "ui-screens" / "px"

SCENARIO_RE = re.compile(r"^\[NS\]\[e2e\] Scenario ([0-9A-Za-z]+): (.*?)\s*$")
HUMAN_RE = re.compile(r"^\[UI-PX\] ([0-9a-f]{4})/([0-9a-f]{4}) p(\d) (.*)$")
RECORD_RE = re.compile(r"^\[UI-PXR\] ([0-9a-f]{4}) p(\d) ([0-9a-f]{512})\s*$")


def parse(log: Path) -> dict[str, dict]:
    """scenario key -> {title, screens: [(idx, page, human, hex)]}"""
    scenarios: dict[str, dict] = {}
    cur = None
    pending_human: dict[tuple[int, int], str] = {}
    for line in log.read_text(errors="replace").splitlines():
        m = SCENARIO_RE.match(line)
        if m:
            cur = m.group(1)
            scenarios.setdefault(cur, {"title": m.group(2), "screens": []})
            pending_human = {}
            continue
        if cur is None:
            continue
        m = HUMAN_RE.match(line)
        if m:
            pending_human[(int(m.group(1), 16), int(m.group(3)))] = m.group(4)
            continue
        m = RECORD_RE.match(line)
        if m:
            idx, page = int(m.group(1), 16), int(m.group(2))
            human = pending_human.pop((idx, page), "")
            scenarios[cur]["screens"].append((idx, page, human, m.group(3)))
    return {k: v for k, v in scenarios.items() if v["screens"]}


def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower() or "screen"


def record_id(hexrec: str) -> str:
    raw = bytes.fromhex(hexrec)
    return raw[12:20].decode("ascii", "replace").rstrip()


def export(log: Path, out: Path = OUT) -> int:
    scenarios = parse(log)
    if not scenarios:
        sys.exit(f"no [UI-PXR] records in {log} (run `E2E_LOG_KEEP=... make e2e-px`)")
    out.mkdir(parents=True, exist_ok=True)
    batch_lines = []
    index = ["# Pixel trusted-UI screens (QEMU `make e2e-px` transcripts)", "",
             "Every record below is a proven `[UI-PXR]` transcript screen; the PNG is the",
             "settled frame the engine renders for it (`pqsigner-ui-px` `render_record`).",
             "Regenerate with `E2E_LOG_KEEP=/tmp/e2e.log make e2e-px && python3 tools/ui_screens_export.py --px /tmp/e2e.log`.", ""]
    total = 0
    for key, sc in scenarios.items():
        d = out / f"scenario-{slug(key)}"
        d.mkdir(parents=True, exist_ok=True)
        for old in d.glob("*.png"):
            old.unlink()
        index.append(f"## Scenario {key}: {sc['title']}")
        index.append("")
        index.append("| # | id | page | record text | frame |")
        index.append("|---|----|------|-------------|-------|")
        for idx, page, human, hexrec in sc["screens"]:
            rid = record_id(hexrec)
            name = f"{idx:02d}-{slug(rid)}-p{page}.png"
            batch_lines.append(f"{d / name} {page} {hexrec}")
            text = human.split(" ", 1)[1] if " " in human else human
            text = text.replace("|", "\\|")
            index.append(f"| {idx} | `{rid}` | {page + 1} | {text} | ![{rid}]({d.name}/{name}) |")
            total += 1
        index.append("")
        (d / "records.txt").write_text("".join(f"{idx:04x} p{page} {hexrec}\n" for idx, page, _, hexrec in sc["screens"]))
    batch = out / "_batch.txt"
    batch.write_text("\n".join(batch_lines) + "\n")
    subprocess.run(
        ["cargo", "run", "--locked", "--quiet", "-p", "pqsigner-ui-px", "--features", "std",
         "--example", "render_record", "--", str(batch)],
        cwd=ROOT, check=True,
    )
    batch.unlink()
    # The engine's PNG writer is a stored (uncompressed) deflate so it stays
    # dependency-free; re-encode for the repository (Pillow, ~10x smaller).
    try:
        from PIL import Image
    except ImportError:  # pragma: no cover — the catalogue is optional tooling
        print("warning: Pillow missing, PNGs left uncompressed", file=sys.stderr)
    else:
        for png in out.rglob("*.png"):
            Image.open(png).save(png, optimize=True)
    (out / "README.md").write_text("\n".join(index) + "\n")
    print(f"wrote {total} pixel screens across {len(scenarios)} scenarios → {out}")
    return total


if __name__ == "__main__":
    export(Path(sys.argv[1]))
