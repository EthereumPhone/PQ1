#!/usr/bin/env python3
"""Verify a device's option bytes and flash against a declared profile. READ-ONLY.

This is the external half of invariant #10(a): "ship at RDP-0 so anyone can
verify flash + option bytes (including staged WRP) + OTP over SWD,
connect-under-reset BEFORE first power, against the reproducible build."

Why external verification is the only kind that counts
------------------------------------------------------
Draft 1.2 §2.2 is blunt about it, and the point survives the A-vs-B decision
(Option B was adopted): at RDP-0 the code doing any on-device check is the same
flash an attacker can rewrite. A malicious FSBL will "verify" itself, "heal"
nothing, print the published 8 words — they are public — and lock RDP-2 on the
attacker's terms. So on-device self-verification is worth zero against
interdiction; it catches factory escapes, not attacks.

This tool is therefore deliberately OFF the device: a probe, a published
profile, and a comparison the operator can repeat. That is the only shape of
RDP-0 verification that means anything.

What it proves, and what it does not
------------------------------------
PROVES: the option bytes and the named flash regions on THIS die, read over
SWD right now, match the declared profile byte for byte.

DOES NOT PROVE: that the profile itself is right (review it separately); that
the die is the one you think it is (that needs attestation, #249); that nothing
changes after you unplug. It is a snapshot, and a snapshot is exactly what
invariant #10(a) asks for — taken before first power, when the device has not
yet self-locked.

Read-only by construction
-------------------------
Every programmer invocation is built here and checked against an allow-list of
read verbs before it runs (`--connect`, `--optionbytes displ`, `--read`).
Anything that could write — `-ob` with assignments, `-w`, `-e`, `-rdu`,
`--optionbytes` with `=` in it — aborts the run rather than being filtered out,
so a future edit that adds a write cannot pass silently.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")

# Any of these appearing in a built argv aborts the run.
WRITE_VERBS = {
    "-w", "--write", "-e", "--erase", "-rdu", "--readunprotect",
    "-d", "--download", "--hardRst", "-ssp", "--ssp", "-lockRDP2",
}


def assert_read_only(argv):
    """Abort if a built command could modify the device."""
    for a in argv:
        if a in WRITE_VERBS:
            sys.exit(f"REFUSING TO RUN: '{a}' can modify the device. This tool is read-only.")
        # `-ob RDP=0xBB` style assignment; `-ob displ` is fine.
        if a.startswith("-ob") or a.startswith("--optionbytes"):
            continue
    for i, a in enumerate(argv):
        if a in ("-ob", "--optionbytes"):
            rest = argv[i + 1 :]
            for r in rest:
                if r.startswith("-"):
                    break
                if "=" in r:
                    sys.exit(f"REFUSING TO RUN: option-byte assignment '{r}'. This tool is read-only.")
    return argv


def run(cli, port, mode, extra):
    argv = assert_read_only([cli, "--connect", f"port={port}", f"mode={mode}", *extra])
    r = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    return ANSI.sub("", r.stdout + r.stderr)


def read_option_bytes(cli, port, mode):
    out = run(cli, port, mode, ["--optionbytes", "displ"])
    ob = {}
    for line in out.splitlines():
        m = re.match(r"\s+([A-Za-z0-9_]+)\s*:\s*(0x[0-9A-Fa-f]+)", line)
        if m:
            ob[m.group(1)] = int(m.group(2), 16)
    if not ob:
        sys.exit("FAIL: could not read option bytes — is the probe attached and the board powered?\n" + out[-600:])
    return ob


def read_flash(cli, port, mode, addr, length):
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        path = f.name
    out = run(cli, port, mode, ["--read", hex(addr), hex(length), path])
    data = Path(path).read_bytes()
    Path(path).unlink(missing_ok=True)
    if len(data) != length:
        sys.exit(f"FAIL: read {len(data)} of {length} B at {addr:#x}\n" + out[-600:])
    return data


def main():
    ap = argparse.ArgumentParser(description="Read-only ship-state verifier (invariant #10a).")
    ap.add_argument("profile", help="path to a JSON profile under tools/ship-profiles/")
    ap.add_argument("--cli", default=str(Path.home() / "STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI"))
    ap.add_argument("--port", default="SWD")
    ap.add_argument("--mode", default="UR",
                    help="UR = connect under reset. Invariant #10(a) specifies "
                         "connect-under-reset BEFORE first power; do not change this "
                         "for a ship-state check.")
    ap.add_argument("--json", action="store_true", help="machine-readable result")
    a = ap.parse_args()

    prof = json.loads(Path(a.profile).read_text())
    pending = [k for k, v in prof.get("option_bytes", {}).items() if isinstance(v, str) and "PENDING" in v]
    if pending:
        sys.exit(
            f"REFUSING: profile '{prof['name']}' still has unresolved fields: {', '.join(pending)}.\n"
            "It is a template, not a checkable profile. Fill them once the decision "
            "they depend on is made — see the profile's `blocked_on` field."
        )

    print(f"==> ship-state verification: {prof['name']}")
    print(f"    {prof.get('description','')}")
    print(f"    connect: port={a.port} mode={a.mode}  (read-only)")

    ob = read_option_bytes(a.cli, a.port, a.mode)
    results, bad = [], 0

    for key, want in prof.get("option_bytes", {}).items():
        want_v = int(want, 16) if isinstance(want, str) else want
        got = ob.get(key)
        ok = got == want_v
        if got is None:
            ok, note = False, "NOT REPORTED by the programmer"
        else:
            note = f"got {got:#x}, want {want_v:#x}"
        results.append((key, ok, note))
        if not ok:
            bad += 1

    for reg in prof.get("flash", []):
        addr, length = int(reg["addr"], 16), int(reg["len"], 16) if isinstance(reg["len"], str) else reg["len"]
        data = read_flash(a.cli, a.port, a.mode, addr, length)
        got = hashlib.sha256(data).hexdigest()
        want = reg["sha256"]
        ok = got == want
        results.append((f"flash:{reg['name']} @{addr:#x}+{length}", ok, f"sha256 {got[:16]}… vs {want[:16]}…"))
        if not ok:
            bad += 1

    print()
    for name, ok, note in results:
        print(f"    [{'OK  ' if ok else 'FAIL'}] {name:<20} {note}")

    print()
    if bad:
        print(f"==> ship-state: FAIL — {bad} of {len(results)} checks did not match")
    else:
        print(f"==> ship-state: OK — all {len(results)} checks match the declared profile")
        print("    This says the die matches the PROFILE. It does not say the profile is")
        print("    correct, nor that this is the die you think it is (that needs")
        print("    attestation), nor anything about state after you disconnect.")

    if a.json:
        print(json.dumps({"profile": prof["name"], "failed": bad,
                          "checks": [{"name": n, "ok": o, "note": t} for n, o, t in results]}, indent=2))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
