#!/usr/bin/env python3
"""Factory production-line test (prodtest) runner.

Orchestrates the per-component tests against a chip running the
prodtest firmware (built via `make build-hw-prodtest`). Each test
sends a USB HID command, parses the response, applies a pass/fail
criterion, and accumulates a per-unit report.

The fixture's outer script wraps this with:
  - Per-unit serial number / position tracking
  - Database write of the test results
  - Operator UI (pass/fail beacon, retest prompts, etc.)
  - On pass: flash factory_provisioning firmware + run ceremony
  - On fail: set device aside, log the offending CMD_PRODTEST_* code

This runner script is Phase A — it sends CMD_PRODTEST_GET_ID and
CMD_PRODTEST_DISPLAY_PATTERN (Phase A commands) plus the four
compute-only commands (Phase B). Phase C+ communication tests
(OPTIGA / SE050 handshake) and the button test land in subsequent
phases per work-todo §30.

Usage:
    tools/factory-prodtest-runner.py [--device /dev/hidrawN]
                                     [--report report.json]
                                     [--verbose]

The script EXITS 0 on all tests passing, non-zero on any failure.
Non-zero exit means: set this chip aside, do not flash the factory
provisioning firmware on it.

Environment variables:
    PQ_USB_VID — USB vendor ID (default 0x2c97, Ledger-compatible)
    PQ_USB_PID — USB product ID (default 0x0006)

Dependencies:
    - hidapi  (`pip install hid` or `pip install hidapi`)
    - Standard library only otherwise

This is a SCAFFOLD: USB HID transport details + per-test pass/fail
criteria need bench validation when hardware is on the line.
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

# ---------------------------------------------------------------------------
# Command IDs — mirror `proto/src/lib.rs::CMD_PRODTEST_*`. Keep STABLE
# across firmware versions so field reports remain interpretable.
# ---------------------------------------------------------------------------

CMD_PRODTEST_GET_ID = 100
CMD_PRODTEST_DISPLAY_PATTERN = 101
CMD_PRODTEST_SAES_SELFTEST = 102
CMD_PRODTEST_BHK_SELFTEST = 103
CMD_PRODTEST_FLASH_RW = 104
CMD_PRODTEST_TRNG_SAMPLE = 105

# Response status codes — mirror `proto/src/lib.rs::NscStatus`.
STATUS_OK = 0
STATUS_INVALID_POINTER = 4
STATUS_NOT_INITIALIZED = 5
STATUS_INTERNAL_ERROR = 0xFFFFFFFF  # catch-all for the dispatcher

USB_VID_DEFAULT = 0x2C97
USB_PID_DEFAULT = 0x0006

# Display test patterns
PATTERN_WHITE = 0
PATTERN_BLACK = 1
PATTERN_HSTRIPES = 2
PATTERN_VSTRIPES = 3
PATTERN_CHECKER = 4

# ---------------------------------------------------------------------------
# Test result aggregator
# ---------------------------------------------------------------------------


@dataclass
class TestResult:
    name: str
    cmd: int
    passed: bool
    status_code: int
    detail: str = ""
    raw_response: bytes = field(default=b"", repr=False)


@dataclass
class UnitReport:
    stm32_uid_hex: str = ""
    prodtest_fw_version: int = 0
    results: list[TestResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self.results)

    def to_dict(self) -> dict:
        d = asdict(self)
        for r in d["results"]:
            r["raw_response"] = r["raw_response"].hex() if r["raw_response"] else ""
        return d


# ---------------------------------------------------------------------------
# USB HID transport (placeholder — needs bench wiring)
# ---------------------------------------------------------------------------


class ProdtestTransport:
    """Minimal USB-HID transport stub for the prodtest commands.

    The real PQSigner USB stack frames commands using Ledger-style
    APDUs over USB HID (see `nonsecure/src/usb/transport.rs`). This
    class is a SCAFFOLD that documents the expected interface; the
    actual byte-level framing must be wired against the firmware's
    USB stack when bench-validating.

    Phase C work (per work-todo §30) replaces this scaffold with the
    full APDU-over-HID framing.
    """

    def __init__(self, vid: int, pid: int, verbose: bool = False) -> None:
        self.vid = vid
        self.pid = pid
        self.verbose = verbose
        self._dev = None

    def connect(self) -> None:
        try:
            import hid  # type: ignore
        except ImportError:
            print("ERROR: hidapi not installed. `pip install hid`.", file=sys.stderr)
            raise
        self._dev = hid.device()
        self._dev.open(self.vid, self.pid)
        if self.verbose:
            print(
                f"[hid] opened {self.vid:#06x}:{self.pid:#06x} "
                f"manufacturer={self._dev.get_manufacturer_string()} "
                f"product={self._dev.get_product_string()}"
            )

    def close(self) -> None:
        if self._dev is not None:
            self._dev.close()
            self._dev = None

    def send_cmd(
        self, cmd: int, in_data: bytes = b"", out_size: int = 0
    ) -> tuple[int, bytes]:
        """Send a prodtest command and read the response.

        Phase A wire format (placeholder — needs bench validation):
            request:  [u32 cmd | u32 in_len | in_data...]
            response: [u32 status | u32 out_len | out_data...]

        Returns (status_code, response_bytes).
        """
        # TODO Phase C: implement actual APDU-over-HID framing per
        # the firmware's USB transport. The framing here is a
        # placeholder so the script structure compiles.
        if self.verbose:
            print(
                f"[hid] send cmd=0x{cmd:02x} in_len={len(in_data)} "
                f"out_size={out_size}"
            )
        # Stub: return failure to make sure no one runs this against
        # silicon expecting it to work without Phase C.
        return STATUS_INTERNAL_ERROR, b""


# ---------------------------------------------------------------------------
# Per-command test wrappers
# ---------------------------------------------------------------------------


def test_get_id(tx: ProdtestTransport, report: UnitReport) -> TestResult:
    status, resp = tx.send_cmd(CMD_PRODTEST_GET_ID, b"", out_size=24)
    if status != STATUS_OK:
        return TestResult(
            name="GET_ID",
            cmd=CMD_PRODTEST_GET_ID,
            passed=False,
            status_code=status,
            detail=f"non-OK status 0x{status:08x}",
        )
    if len(resp) != 24:
        return TestResult(
            name="GET_ID",
            cmd=CMD_PRODTEST_GET_ID,
            passed=False,
            status_code=status,
            detail=f"response wrong length {len(resp)} (expected 24)",
            raw_response=resp,
        )
    uid = resp[0:12]
    fw_version = struct.unpack("<I", resp[12:16])[0]
    report.stm32_uid_hex = uid.hex()
    report.prodtest_fw_version = fw_version
    # Sanity: a fresh STM32 UID is never all-zero and never
    # all-ones (factory cookie check).
    if uid == b"\x00" * 12 or uid == b"\xff" * 12:
        return TestResult(
            name="GET_ID",
            cmd=CMD_PRODTEST_GET_ID,
            passed=False,
            status_code=status,
            detail=f"UID looks bogus: {uid.hex()}",
            raw_response=resp,
        )
    return TestResult(
        name="GET_ID",
        cmd=CMD_PRODTEST_GET_ID,
        passed=True,
        status_code=status,
        detail=f"uid={uid.hex()} fw_v{fw_version}",
        raw_response=resp,
    )


def test_display_pattern(tx: ProdtestTransport, pattern: int) -> TestResult:
    in_data = struct.pack("<I", pattern)
    status, resp = tx.send_cmd(CMD_PRODTEST_DISPLAY_PATTERN, in_data, out_size=0)
    passed = status == STATUS_OK
    return TestResult(
        name=f"DISPLAY_PATTERN({pattern})",
        cmd=CMD_PRODTEST_DISPLAY_PATTERN,
        passed=passed,
        status_code=status,
        detail=f"pattern={pattern}",
    )


def test_saes_selftest(tx: ProdtestTransport) -> TestResult:
    status, resp = tx.send_cmd(CMD_PRODTEST_SAES_SELFTEST, b"", out_size=8)
    if status != STATUS_OK:
        return TestResult(
            name="SAES_SELFTEST",
            cmd=CMD_PRODTEST_SAES_SELFTEST,
            passed=False,
            status_code=status,
            detail=f"non-OK status (likely saes-dhuk feature off)",
        )
    fingerprint = resp[:8].hex() if len(resp) >= 8 else ""
    # All-zero fingerprint = SAES not actually running. Pass requires
    # at least one nonzero bit.
    nonzero = any(b != 0 for b in resp[:8])
    return TestResult(
        name="SAES_SELFTEST",
        cmd=CMD_PRODTEST_SAES_SELFTEST,
        passed=nonzero,
        status_code=status,
        detail=f"fingerprint={fingerprint}",
        raw_response=resp,
    )


def test_bhk_selftest(tx: ProdtestTransport) -> TestResult:
    status, resp = tx.send_cmd(CMD_PRODTEST_BHK_SELFTEST, b"", out_size=8)
    if status != STATUS_OK:
        return TestResult(
            name="BHK_SELFTEST",
            cmd=CMD_PRODTEST_BHK_SELFTEST,
            passed=False,
            status_code=status,
            detail="non-OK status (likely bhk / saes-dhuk feature off)",
        )
    fingerprint = resp[:8].hex() if len(resp) >= 8 else ""
    nonzero = any(b != 0 for b in resp[:8])
    return TestResult(
        name="BHK_SELFTEST",
        cmd=CMD_PRODTEST_BHK_SELFTEST,
        passed=nonzero,
        status_code=status,
        detail=f"fingerprint={fingerprint}",
        raw_response=resp,
    )


def test_flash_rw(tx: ProdtestTransport) -> TestResult:
    # Pattern 0xDEADBEEF is the canonical factory test value.
    in_data = struct.pack("<I", 0xDEADBEEF)
    status, _ = tx.send_cmd(CMD_PRODTEST_FLASH_RW, in_data, out_size=0)
    passed = status == STATUS_OK
    return TestResult(
        name="FLASH_RW",
        cmd=CMD_PRODTEST_FLASH_RW,
        passed=passed,
        status_code=status,
        detail="(stub — flash test page helpers not yet wired)",
    )


def test_trng_sample(tx: ProdtestTransport, n: int = 256) -> TestResult:
    in_data = struct.pack("<I", n)
    status, resp = tx.send_cmd(CMD_PRODTEST_TRNG_SAMPLE, in_data, out_size=n)
    if status != STATUS_OK or len(resp) != n:
        return TestResult(
            name=f"TRNG_SAMPLE({n})",
            cmd=CMD_PRODTEST_TRNG_SAMPLE,
            passed=False,
            status_code=status,
            detail=f"status=0x{status:08x} got {len(resp)} bytes",
        )
    # Very-basic χ² placeholder: count zero bytes (uniform random
    # should have ~n/256 of any specific byte value). All-zero or
    # constant-value output fails.
    distinct = len(set(resp))
    passed = distinct >= 32  # at least 32 distinct byte values in 256 bytes
    return TestResult(
        name=f"TRNG_SAMPLE({n})",
        cmd=CMD_PRODTEST_TRNG_SAMPLE,
        passed=passed,
        status_code=status,
        detail=f"got {n} bytes, {distinct} distinct values",
        raw_response=resp,
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_all_tests(tx: ProdtestTransport, report: UnitReport) -> None:
    # Order matters: GET_ID first so the report has the UID for
    # traceability even if subsequent tests fail.
    report.results.append(test_get_id(tx, report))

    # Display test: run all 5 patterns, each held for 1 second so
    # the fixture's camera can frame each.
    for pattern in (
        PATTERN_WHITE,
        PATTERN_BLACK,
        PATTERN_HSTRIPES,
        PATTERN_VSTRIPES,
        PATTERN_CHECKER,
    ):
        report.results.append(test_display_pattern(tx, pattern))
        time.sleep(1.0)

    report.results.append(test_saes_selftest(tx))
    report.results.append(test_bhk_selftest(tx))
    report.results.append(test_flash_rw(tx))
    report.results.append(test_trng_sample(tx, 256))


def main() -> int:
    parser = argparse.ArgumentParser(description="PQSigner prodtest runner")
    parser.add_argument(
        "--vid",
        type=lambda v: int(v, 0),
        default=int(os.environ.get("PQ_USB_VID", USB_VID_DEFAULT)),
        help="USB vendor ID",
    )
    parser.add_argument(
        "--pid",
        type=lambda v: int(v, 0),
        default=int(os.environ.get("PQ_USB_PID", USB_PID_DEFAULT)),
        help="USB product ID",
    )
    parser.add_argument("--report", help="Path to write JSON report")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    tx = ProdtestTransport(args.vid, args.pid, verbose=args.verbose)
    report = UnitReport()

    try:
        tx.connect()
        run_all_tests(tx, report)
    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        return 2
    finally:
        tx.close()

    # Print per-test summary
    print()
    print("=" * 60)
    print(f"UID:        {report.stm32_uid_hex}")
    print(f"FW version: {report.prodtest_fw_version}")
    print("=" * 60)
    for r in report.results:
        marker = "✓" if r.passed else "✗"
        print(f"  {marker} {r.name:<24}  status=0x{r.status_code:08x}  {r.detail}")
    print("=" * 60)
    if report.all_passed:
        print("RESULT: ALL TESTS PASSED — chip is prodtest-clean")
    else:
        fails = sum(1 for r in report.results if not r.passed)
        print(f"RESULT: {fails} FAIL(S) — set this chip aside, do not flash factory_provisioning")
    print()

    if args.report:
        with open(args.report, "w") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
        print(f"Wrote JSON report to {args.report}")

    return 0 if report.all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
