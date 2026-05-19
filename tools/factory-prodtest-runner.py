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
CMD_PRODTEST_OPTIGA_HANDSHAKE = 106
CMD_PRODTEST_SE050_HANDSHAKE = 107
CMD_PRODTEST_USB_LOOPBACK = 108
CMD_PRODTEST_BUTTON_TEST = 109

# Per-CMD INS codes for the v2 APDU dispatcher. Mirrors
# `proto/src/lib.rs::INS_V2_PRODTEST_*`.
INS_FOR_CMD = {
    CMD_PRODTEST_GET_ID:            0x80,
    CMD_PRODTEST_DISPLAY_PATTERN:   0x81,
    CMD_PRODTEST_SAES_SELFTEST:     0x82,
    CMD_PRODTEST_BHK_SELFTEST:      0x83,
    CMD_PRODTEST_FLASH_RW:          0x84,
    CMD_PRODTEST_TRNG_SAMPLE:       0x85,
    CMD_PRODTEST_OPTIGA_HANDSHAKE:  0x86,
    CMD_PRODTEST_SE050_HANDSHAKE:   0x87,
    CMD_PRODTEST_USB_LOOPBACK:      0x88,
    CMD_PRODTEST_BUTTON_TEST:       0x89,
}

# APDU + HID framing constants. Mirror `proto/src/lib.rs::APDU_CLA_V2`
# and `shared/src/apdu_framing.rs`.
APDU_CLA_V2 = 0xF0
HID_REPORT_SIZE = 64
HID_TAG_APDU = 0x05
HID_FIRST_DATA = HID_REPORT_SIZE - 7  # 57 bytes after [chan(2)|tag(1)|seq(2)|len(2)]
HID_CONT_DATA = HID_REPORT_SIZE - 5   # 59 bytes after [chan(2)|tag(1)|seq(2)]

# ISO 7816-4 SW values mirrored from `proto/src/lib.rs::SW_*`.
SW_OK = 0x9000
SW_WRONG_LENGTH = 0x6700
SW_INS_NOT_SUPPORTED = 0x6D00
SW_CLA_NOT_SUPPORTED = 0x6E00
SW_INTERNAL_ERROR_WIRE = 0x6F00

# Step-status nibble decode for BUTTON_TEST. Upper = step, lower = error.
BUTTON_STEP_DECODE = {
    0x00: ("PASS", "all 3 steps OK"),
    0x11: ("FAIL", "step 1 (LEFT) timeout — no press in 10 s"),
    0x12: ("FAIL", "step 1 (LEFT) wrong button — operator pressed RIGHT or wires are swapped"),
    0x21: ("FAIL", "step 2 (RIGHT) timeout"),
    0x22: ("FAIL", "step 2 (RIGHT) wrong button — operator pressed LEFT or wires are swapped"),
    0x31: ("FAIL", "step 3 (BOTH) timeout — operator did not press both buttons together"),
}

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
    """USB-HID APDU-over-Ledger-framing transport.

    Frames CMD_PRODTEST_* calls as v2 APDUs:
        [CLA=0xF0][INS=0x8x][P1=0x00][P2=0x00][LC][data]
    where INS is selected by `INS_FOR_CMD[cmd]`. Frames the APDU into
    64-byte HID reports per `shared/src/apdu_framing.rs`:
        frame 0: [chan(2 BE)][tag=0x05][seq=0x0000][total_len(2 BE)][data ≤ 57 B]
        frame N: [chan(2 BE)][tag=0x05][seq(2 BE)][data ≤ 59 B]
    Channel ID is fixed at 0x0001; the firmware echoes whatever the
    host sends.

    Linux hidapi quirk: `device.write` requires a leading 0x00 report-
    ID byte even when the descriptor has none (the kernel hidraw layer
    inspects byte 0 as the report ID). `device.read` does NOT include
    that byte.
    """

    CHANNEL_ID = 0x0001
    READ_TIMEOUT_MS = 60_000  # operator-interactive BUTTON_TEST can take ~30 s

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

    # ----- APDU + HID framing helpers -----

    @staticmethod
    def _build_apdu(ins: int, in_data: bytes) -> bytes:
        if len(in_data) > 255:
            raise ValueError(f"APDU LC overflow: {len(in_data)} > 255")
        return bytes([APDU_CLA_V2, ins, 0x00, 0x00, len(in_data)]) + in_data

    def _frame_apdu(self, apdu: bytes) -> list[bytes]:
        """Fragment the APDU into 64-byte HID reports."""
        frames = []
        chan = self.CHANNEL_ID

        # First frame.
        first = bytearray(HID_REPORT_SIZE)
        first[0] = (chan >> 8) & 0xFF
        first[1] = chan & 0xFF
        first[2] = HID_TAG_APDU
        first[3] = 0x00
        first[4] = 0x00
        first[5] = (len(apdu) >> 8) & 0xFF
        first[6] = len(apdu) & 0xFF
        first_chunk = min(HID_FIRST_DATA, len(apdu))
        first[7 : 7 + first_chunk] = apdu[:first_chunk]
        frames.append(bytes(first))

        off = first_chunk
        seq = 1
        while off < len(apdu):
            f = bytearray(HID_REPORT_SIZE)
            f[0] = (chan >> 8) & 0xFF
            f[1] = chan & 0xFF
            f[2] = HID_TAG_APDU
            f[3] = (seq >> 8) & 0xFF
            f[4] = seq & 0xFF
            c = min(HID_CONT_DATA, len(apdu) - off)
            f[5 : 5 + c] = apdu[off : off + c]
            frames.append(bytes(f))
            off += c
            seq += 1
        return frames

    def _read_response(self) -> bytes:
        """Reassemble one APDU response from the HID stream."""
        buf = bytearray()
        expected = 0
        seq = 0
        while True:
            data = bytes(self._dev.read(HID_REPORT_SIZE, timeout_ms=self.READ_TIMEOUT_MS))
            if len(data) == 0:
                raise TimeoutError(f"HID read timeout after {self.READ_TIMEOUT_MS} ms")
            if len(data) < 3 or data[2] != HID_TAG_APDU:
                if self.verbose:
                    print(f"[hid] dropping non-APDU frame: tag=0x{data[2]:02x}")
                continue
            r_seq = (data[3] << 8) | data[4]
            if r_seq != seq:
                raise IOError(f"HID seq mismatch: expected {seq}, got {r_seq}")
            if seq == 0:
                expected = (data[5] << 8) | data[6]
                if self.verbose:
                    print(f"[hid] response apdu_len={expected}")
                payload_off = 7
                chunk = min(HID_FIRST_DATA, expected)
            else:
                payload_off = 5
                chunk = min(HID_CONT_DATA, expected - len(buf))
            buf.extend(data[payload_off : payload_off + chunk])
            seq += 1
            if len(buf) >= expected:
                break
        return bytes(buf[:expected])

    # ----- Public API -----

    def send_cmd(
        self, cmd: int, in_data: bytes = b"", out_size: int = 0
    ) -> tuple[int, bytes]:
        """Send one prodtest command, return (status_code, response_data).

        Status code is the ISO 7816-4 SW from the firmware:
          SW_OK (0x9000)             — command succeeded
          SW_INTERNAL_ERROR (0x6F00) — chip / driver failure (see response for diagnostic)
          SW_WRONG_LENGTH (0x6700)   — input length not accepted by firmware
        For backwards compat with the Phase A scaffold, `status == STATUS_OK`
        is checked downstream — that constant is mapped to SW_OK below.
        """
        if self._dev is None:
            return STATUS_INTERNAL_ERROR, b""
        ins = INS_FOR_CMD.get(cmd)
        if ins is None:
            return STATUS_INTERNAL_ERROR, b""

        apdu = self._build_apdu(ins, in_data)
        if self.verbose:
            print(
                f"[hid] send cmd={cmd} INS=0x{ins:02x} apdu_len={len(apdu)} "
                f"out_size={out_size}"
            )

        for frame in self._frame_apdu(apdu):
            # Linux hidapi: prepend report-ID byte 0x00.
            self._dev.write(b"\x00" + frame)

        resp = self._read_response()
        if len(resp) < 2:
            return STATUS_INTERNAL_ERROR, b""

        sw = (resp[-2] << 8) | resp[-1]
        data = bytes(resp[:-2])

        # Map wire SW back to the script's status namespace: SW_OK → 0,
        # everything else carries the wire SW unchanged so downstream
        # `status != STATUS_OK` checks see the SW for logs.
        status_code = STATUS_OK if sw == SW_OK else sw
        return status_code, data


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


def test_optiga_handshake(tx: ProdtestTransport) -> TestResult:
    status, resp = tx.send_cmd(CMD_PRODTEST_OPTIGA_HANDSHAKE, b"", out_size=16)
    if status != STATUS_OK or len(resp) != 16:
        return TestResult(
            name="OPTIGA_HANDSHAKE",
            cmd=CMD_PRODTEST_OPTIGA_HANDSHAKE,
            passed=False,
            status_code=status,
            detail=f"status=0x{status:08x} got {len(resp)} bytes",
        )
    # OPTIGA RNG output must be non-trivial: all-zero / all-0xFF
    # means the chip didn't actually run the GetRandom APDU (stuck
    # bus / shorted line) and the firmware filled with sentinel.
    if resp == b"\x00" * 16 or resp == b"\xff" * 16:
        return TestResult(
            name="OPTIGA_HANDSHAKE",
            cmd=CMD_PRODTEST_OPTIGA_HANDSHAKE,
            passed=False,
            status_code=status,
            detail=f"RNG looks bogus: {resp.hex()}",
            raw_response=resp,
        )
    return TestResult(
        name="OPTIGA_HANDSHAKE",
        cmd=CMD_PRODTEST_OPTIGA_HANDSHAKE,
        passed=True,
        status_code=status,
        detail=f"rng={resp.hex()}",
        raw_response=resp,
    )


def test_se050_handshake(tx: ProdtestTransport) -> TestResult:
    status, resp = tx.send_cmd(CMD_PRODTEST_SE050_HANDSHAKE, b"", out_size=16)
    if status != STATUS_OK or len(resp) != 16:
        return TestResult(
            name="SE050_HANDSHAKE",
            cmd=CMD_PRODTEST_SE050_HANDSHAKE,
            passed=False,
            status_code=status,
            detail=f"status=0x{status:08x} got {len(resp)} bytes",
        )
    if resp == b"\x00" * 16 or resp == b"\xff" * 16:
        return TestResult(
            name="SE050_HANDSHAKE",
            cmd=CMD_PRODTEST_SE050_HANDSHAKE,
            passed=False,
            status_code=status,
            detail=f"RNG looks bogus: {resp.hex()}",
            raw_response=resp,
        )
    return TestResult(
        name="SE050_HANDSHAKE",
        cmd=CMD_PRODTEST_SE050_HANDSHAKE,
        passed=True,
        status_code=status,
        detail=f"rng={resp.hex()}",
        raw_response=resp,
    )


def test_usb_loopback(tx: ProdtestTransport, n: int = 256) -> TestResult:
    # Pseudo-random but reproducible test pattern: incrementing
    # bytes XOR'd with the position-rotated key 0xA5. Catches off-by-
    # one + bit-flip + byte-substitution bugs.
    payload = bytes((i ^ 0xA5) & 0xFF for i in range(n))
    status, resp = tx.send_cmd(CMD_PRODTEST_USB_LOOPBACK, payload, out_size=n)
    if status != STATUS_OK or len(resp) != n:
        return TestResult(
            name=f"USB_LOOPBACK({n})",
            cmd=CMD_PRODTEST_USB_LOOPBACK,
            passed=False,
            status_code=status,
            detail=f"status=0x{status:08x} got {len(resp)} bytes",
        )
    if resp != payload:
        # Pin first mismatch offset for diagnostics.
        mismatch_i = next(
            (i for i in range(n) if resp[i] != payload[i]), -1
        )
        return TestResult(
            name=f"USB_LOOPBACK({n})",
            cmd=CMD_PRODTEST_USB_LOOPBACK,
            passed=False,
            status_code=status,
            detail=(
                f"byte mismatch at offset {mismatch_i}: "
                f"sent 0x{payload[mismatch_i]:02x} got 0x{resp[mismatch_i]:02x}"
            ),
            raw_response=resp,
        )
    return TestResult(
        name=f"USB_LOOPBACK({n})",
        cmd=CMD_PRODTEST_USB_LOOPBACK,
        passed=True,
        status_code=status,
        detail=f"{n} bytes round-tripped byte-identical",
    )


def test_button_test(tx: ProdtestTransport) -> TestResult:
    """Operator-interactive button test. Allow up to ~35 s of total
    USB wait time: 3 × 10 s per step + reaction-time buffer."""
    status, resp = tx.send_cmd(CMD_PRODTEST_BUTTON_TEST, b"", out_size=4)
    if len(resp) != 4:
        return TestResult(
            name="BUTTON_TEST",
            cmd=CMD_PRODTEST_BUTTON_TEST,
            passed=False,
            status_code=status,
            detail=f"status=0x{status:08x} got {len(resp)} bytes (expected 4)",
        )
    step_status = resp[0]
    label, hint = BUTTON_STEP_DECODE.get(
        step_status, ("FAIL", f"unknown step_status 0x{step_status:02x}")
    )
    return TestResult(
        name="BUTTON_TEST",
        cmd=CMD_PRODTEST_BUTTON_TEST,
        passed=(step_status == 0x00),
        status_code=status,
        detail=f"{label}: {hint}",
        raw_response=resp,
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
    # Phase C: communication tests.
    report.results.append(test_optiga_handshake(tx))
    report.results.append(test_se050_handshake(tx))
    report.results.append(test_usb_loopback(tx, 256))
    # Phase D: operator-interactive button test (last because the
    # operator must be present and pressing buttons; failures from
    # the prior automated tests are easier to recover from without
    # involving a human).
    report.results.append(test_button_test(tx))


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
