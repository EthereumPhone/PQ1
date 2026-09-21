#!/usr/bin/env python3
"""Drive CMD_PRODTEST_RGB_TEST (INS 0x8A) against a connected pq1 unit.

The factory runner (`factory-prodtest-runner.py`) owns the response decoder and
the failure hints, and its unit tests cover them; this script is only a
transport adapter plus a colour sweep, so there is exactly one decoder and it
cannot drift from the tested one.

Why this exists next to the runner: the runner executes the whole acceptance
profile, including the operator-interactive button test, which is not what you
want while bringing up one subsystem.

Usage:
  tools/prodtest_rgb.py                      # red → green → blue → white → off
  tools/prodtest_rgb.py --rgb ff 00 00       # one colour
  tools/prodtest_rgb.py --rgb ff ff ff --gcc 0x60   # brighter
  tools/prodtest_rgb.py --en 0 --rgb ff 0 0  # negative control: EN held low
  tools/prodtest_rgb.py --hold 3             # seconds to hold each colour

Exit status: 0 if every step passed, 1 otherwise, 2 if no device was found.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
import time
from pathlib import Path

from hid_smoke import HidRaw, find_hidraw, send

_RUNNER_PATH = Path(__file__).with_name("factory-prodtest-runner.py")
_spec = importlib.util.spec_from_file_location("factory_prodtest_runner", _RUNNER_PATH)
assert _spec and _spec.loader
runner = importlib.util.module_from_spec(_spec)
# Register before exec: the runner uses @dataclass, which resolves its own
# module out of sys.modules and fails with an unregistered spec.
sys.modules[_spec.name] = runner
_spec.loader.exec_module(runner)

SW_OK = 0x9000


class HidRawTransport:
    """Adapter presenting `hid_smoke`'s hidraw path as the runner's transport.

    Deliberately mirrors `ProdtestTransport.send_cmd`'s contract: SW_OK maps to
    the runner's STATUS_OK, any other SW is returned unchanged, and the data is
    returned even on failure — the device writes its diagnostic regardless of
    status, which is the whole point of this command.
    """

    def __init__(self, hid: HidRaw, verbose: bool = False) -> None:
        self.hid = hid
        self.verbose = verbose

    def send_cmd(
        self, cmd: int, in_data: bytes = b"", out_size: int = 0
    ) -> tuple[int, bytes]:
        ins = runner.INS_FOR_CMD.get(cmd)
        if ins is None:
            return runner.STATUS_INTERNAL_ERROR, b""
        if self.verbose:
            print(f"[hid] cmd={cmd} INS=0x{ins:02x} in={in_data.hex()}")
        sw, data = send(self.hid, ins, in_data)
        if sw == runner.SW_INS_NOT_SUPPORTED:
            print(
                "!! device answered INS_NOT_SUPPORTED (0x6D00) — this firmware "
                "predates CMD_PRODTEST_RGB_TEST; flash the new prodtest image"
            )
        return (runner.STATUS_OK if sw == SW_OK else sw), data


def parse_byte(text: str) -> int:
    """Hex byte, with or without an `0x` prefix (`int(.., 16)` takes both)."""
    value = int(text, 16)
    if not 0 <= value <= 0xFF:
        raise argparse.ArgumentTypeError(f"{text} is not a byte")
    return value


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--rgb",
        nargs=3,
        metavar=("R", "G", "B"),
        help="one colour as hex bytes (default: sweep red/green/blue/white/off)",
    )
    ap.add_argument("--gcc", default="0", help="global current, hex; 0 = firmware default")
    ap.add_argument("--en", type=int, default=1, choices=(0, 1), help="drive RGB_EN")
    ap.add_argument("--hold", type=float, default=1.5, help="seconds per colour")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    node = find_hidraw()
    if node is None:
        print("!! no PQSigner hidraw node — board not enumerated")
        return 2
    print(f"== device: {node}")

    gcc = parse_byte(args.gcc)
    if args.rgb:
        r, g, b = (parse_byte(v) for v in args.rgb)
        steps = [(r, g, b, f"{r:02x}{g:02x}{b:02x}")]
    else:
        steps = [
            (0xFF, 0x00, 0x00, "red"),
            (0x00, 0xFF, 0x00, "green"),
            (0x00, 0x00, 0xFF, "blue"),
            (0xFF, 0xFF, 0xFF, "white"),
            (0x00, 0x00, 0x00, "off"),
        ]

    failures = 0
    hid = HidRaw(node)  # no context-manager support in hid_smoke
    try:
        tx = HidRawTransport(hid, verbose=args.verbose)
        for r, g, b, label in steps:
            result = runner.test_rgb_test(
                tx, r, g, b, gcc=gcc, en=args.en, label=label
            )
            mark = "PASS" if result.passed else "FAIL"
            print(f"[{mark}] {result.name}: {result.detail}")
            if not result.passed:
                failures += 1
            if label != "off" and len(steps) > 1:
                time.sleep(args.hold)
    finally:
        hid.close()

    if args.en == 0:
        print(
            "\nNote: with --en 0 the part is in shutdown but its I2C stays "
            "accessible, so ACKs here are expected. The board must be DARK — "
            "that, not the status, is the test of the RGB_EN line."
        )
    print(f"\n{'ALL PASS' if failures == 0 else f'{failures} FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
