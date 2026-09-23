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
# Port step 4: the screens outside the sign dialog (boot, PIN, wizard,
# verdicts, the firmware-update / address / sync consents) are not reachable
# from the QEMU e2e (it auto-provisions and pre-unlocks); their records come
# from the secure host test that emits them (`ui_px_status_map`).
LIFECYCLE = ROOT / "pqsigner-ui-px" / "tests" / "fixtures" / "lifecycle"

SCENARIO_RE = re.compile(r"^\[NS\]\[e2e\] Scenario ([0-9A-Za-z-]+): (.*?)\s*$")
HUMAN_RE = re.compile(r"^\[UI-PX\] ([0-9a-f]{4})/([0-9a-f]{4}) p(\d) (.*)$")
RECORD_RE = re.compile(r"^\[UI-PXR\] ([0-9a-f]{4}) p(\d) ([0-9a-f]{512})\s*$")


def parse(log: Path) -> dict[str, dict]:
    """scenario key -> {title, screens: [(dialog, idx, page, human, hex)]}

    A scenario can open more than one dialog (the slot-rotation consent, then
    the sign confirmation); a new dialog starts where screen 0 page 0 comes
    round again after other screens."""
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
            shown = scenarios[cur]["screens"]
            dialog = shown[-1][0] if shown else 0
            if shown and idx == 0 and page == 0 and (shown[-1][1], shown[-1][2]) != (0, 0):
                dialog += 1
            shown.append((dialog, idx, page, human, m.group(3)))
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
        multi = len({dlg for dlg, *_ in sc["screens"]}) > 1
        for dlg, idx, page, human, hexrec in sc["screens"]:
            rid = record_id(hexrec)
            name = (f"d{dlg + 1}-" if multi else "") + f"{idx:02d}-{slug(rid)}-p{page}.png"
            batch_lines.append(f"{d / name} {page} {hexrec}")
            text = human.split(" ", 1)[1] if " " in human else human
            text = text.replace("|", "\\|")
            pos = f"{dlg + 1}.{idx}" if multi else f"{idx}"
            index.append(f"| {pos} | `{rid}` | {page + 1} | {text} | ![{rid}]({d.name}/{name}) |")
            total += 1
        index.append("")
        (d / "records.txt").write_text("".join(
            (f"d{dlg + 1} " if multi else "") + f"{idx:04x} p{page} {hexrec}\n"
            for dlg, idx, page, _, hexrec in sc["screens"]))
    for fx in sorted(LIFECYCLE.glob("*.hex")):
        d = out / f"lifecycle-{slug(fx.stem)}"
        d.mkdir(parents=True, exist_ok=True)
        for old in d.glob("*.png"):
            old.unlink()
        index.append(f"## Lifecycle: {fx.stem} (host fixture `{fx.relative_to(ROOT)}`)")
        index.append("")
        index.append("| # | id | caption | frame |")
        index.append("|---|----|---------|-------|")
        for idx, hexrec in enumerate(l.strip() for l in fx.read_text().splitlines() if l.strip()):
            rid = record_id(hexrec)
            cap = bytes.fromhex(hexrec)[32:64].decode("ascii", "replace").rstrip().replace("|", "\\|")
            name = f"{idx:02d}-{slug(rid)}-p0.png"
            batch_lines.append(f"{d / name} 0 {hexrec}")
            index.append(f"| {idx} | `{rid}` | {cap} | ![{rid}]({d.name}/{name}) |")
            total += 1
        index.append("")
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
