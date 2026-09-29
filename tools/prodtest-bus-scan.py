#!/usr/bin/env python3
"""Scan the pq1 auxiliary I2C bus and report which LED-driver ICs answer.

WHY THIS EXISTS, separately from `factory-prodtest-runner.py`
-------------------------------------------------------------

The full runner is a factory acceptance sequence: it ends with an
operator-interactive button test on 10-second timeouts, and it sweeps the RGB
LEDs through four colours. That is right for a production line and wrong for
answering one question on a bench board that may have neither buttons wired nor
LEDs attached.

This sends exactly one command — `CMD_PRODTEST_RGB_TEST` with the LEDs off and
the RGB driver's enable low — and prints the bus scan it returns. Nothing
lights up, no operator is needed.

The question it answers (#705): **is the AW99703 backlight driver populated and
answering on THIS board?**

That matters because the FSBL's fail-closed display policy refuses handoff when
its I2C stage fails. The bus scan that found the AW99703 at 0x36 was run on the
SEALED EVT unit; that the part is also populated on the bench board is an
inference from "same PCB, mainboard part". Before restructuring a board's flash
for a marker-FSBL run, it is worth five minutes to turn that inference into a
reading.

Expected on a healthy pq1: `0x1c` (AW21036 broadcast), `0x34` (AW21036),
`0x36` (AW99703).

Usage
-----
    python3 tools/prodtest-bus-scan.py

Requires prodtest firmware on the board (`make build-hw-prodtest BOARD=pq1`,
then flash) and the device enumerated over USB.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# The runner's filename has hyphens, so it cannot be imported by name.
_RUNNER = Path(__file__).with_name("factory-prodtest-runner.py")
_spec = importlib.util.spec_from_file_location("prodtest_runner", _RUNNER)
if _spec is None or _spec.loader is None:
    sys.exit(f"cannot load {_RUNNER}")
runner = importlib.util.module_from_spec(_spec)
# MUST be registered before exec_module: the runner uses @dataclass, and
# dataclasses resolves field types via sys.modules[cls.__module__], which is
# None for a module that is mid-execution and not yet registered. Without this
# the import dies with a bare "'NoneType' object has no attribute '__dict__'".
sys.modules[_spec.name] = runner
_spec.loader.exec_module(runner)

# Addresses the pq1 schematic says are on this bus, with what each one proves.
EXPECTED = {
    0x1C: "AW21036 broadcast",
    0x34: "AW21036 RGB driver",
    0x36: "AW99703 backlight driver  <-- the #705 question",
}


def main() -> int:
    tx = runner.ProdtestTransport(runner.USB_VID_DEFAULT, runner.USB_PID_DEFAULT)
    try:
        tx.connect()
    except Exception as exc:  # noqa: BLE001 - surface the real reason
        print(f"connect failed: {exc}")
        print("  is prodtest firmware flashed, and the device enumerated?")
        return 2

    try:
        # LEDs off, enable low: this is a bus probe, not a light test.
        in_data = bytes([0, 0, 0, 0, 0, 0])
        status, resp = tx.send_cmd(
            runner.CMD_PRODTEST_RGB_TEST, in_data, out_size=runner.RGB_OUT_LEN
        )
    finally:
        try:
            tx.close()
        except Exception:  # noqa: BLE001 - closing must not mask the result
            pass

    if len(resp) != runner.RGB_OUT_LEN:
        print(f"status=0x{status:08x}, got {len(resp)} bytes "
              f"(expected {runner.RGB_OUT_LEN}) — command not supported?")
        return 2

    seen = runner.decode_rgb_scan(resp[: runner.RGB_SCAN_LEN])
    ver, reset_id, acks_ok, acks_total = resp[16:20]

    print(f"status   0x{status:08x}")
    print(f"bus      [{' '.join(f'0x{a:02x}' for a in seen)}]")
    print(f"AW21036  ver=0x{ver:02x} id=0x{reset_id:02x} acks={acks_ok}/{acks_total}")
    print()

    for addr, what in EXPECTED.items():
        print(f"  0x{addr:02x}  {'PRESENT' if addr in seen else 'ABSENT ':8}  {what}")

    extra = [a for a in seen if a not in EXPECTED]
    if extra:
        print(f"\n  unexpected: {' '.join(f'0x{a:02x}' for a in extra)}")

    print()
    if 0x36 in seen:
        print("AW99703 ANSWERS on this board — the marker-FSBL run can use it.")
        return 0
    if seen:
        print("AW99703 ABSENT but the bus is alive (something else answered), so")
        print("this is about the part or its supply, not the bus wiring.")
    else:
        print("NOTHING answered — the bus itself is the fault (pins, pull-ups, or")
        print("the rail). A dead bus reads identically to 'no devices', so this")
        print("does NOT prove the AW99703 is unpopulated.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
