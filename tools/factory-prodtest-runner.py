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
  - On pass: record acceptance and set the unit aside; DO NOT chain an
    irreversible provisioning or lifecycle ceremony
  - On fail: set device aside, log the offending CMD_PRODTEST_* code

Exit zero is a reversible acceptance-test result only. It grants no authority
to program OTP, rotate SE credentials, lock E140, or change option bytes.

The supported profile executes all ten stable commands. Eight are required
acceptance checks. BHK_SELFTEST and FLASH_RW are explicit unsupported-
capability probes: their expected failure is recorded as non-passing
``SKIP_UNSUPPORTED``, while an unexpected success fails the profile.

Usage:
    tools/factory-prodtest-runner.py [--device /dev/hidrawN]
                                     [--report report.json]
                                     [--verbose]

The script exits 0 only when the reversible profile is accepted: every
required check passed and both unsupported probes returned their exact
non-authority result. This does not mean every command passed and grants no
follow-on provisioning authority. Exit 1 is a test/profile failure; exit 2 is
a runner or transport failure. When ``--report`` is supplied, failures still
produce an atomic JSON receipt whenever the destination is writable.

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
import select
import tempfile
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

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
CMD_PRODTEST_RGB_TEST = 110
CMD_PRODTEST_RGB_OSD = 111
CMD_PRODTEST_RNG_CONFIG = 112

# Shared wire contract. Mirrors
# `proto/src/lib.rs::PRODTEST_MAX_RESPONSE_DATA_LEN`.
PRODTEST_MAX_RESPONSE_DATA_LEN = 254
EXPECTED_PRODTEST_FW_VERSION = 5

# Acceptance-profile identity. Board-scoped and versioned, because the matrix
# below is not board-neutral: v2 REQUIRES the two AW21036 RGB commands, which
# exist only on `pq1`. Running this profile against an `iota2` unit is therefore
# expected to fail, and the failure is the correct answer rather than a bug —
# the RGB decoders say so explicitly when the firmware has no RGB driver.
#
# v1 -> v2 (2026-09-21): RGB_TEST and RGB_OSD promoted OPTIONAL -> REQUIRED, so
# LED acceptance is a machine gate rather than an operator's glance; profile id
# carries the board. Receipts from the two versions stay distinguishable.
PROFILE_ID = "pqsigner-prodtest-reversible-pq1-v2"
PROFILE_BOARD = "pq1"
PROFILE_REQUIRED = "required"
PROFILE_OPTIONAL = "optional"
PROFILE_UNSUPPORTED = "unsupported"
OUTCOME_PASS = "PASS"
OUTCOME_FAIL = "FAIL"
OUTCOME_SKIP_UNSUPPORTED = "SKIP_UNSUPPORTED"

# This matrix is emitted verbatim in every JSON receipt. The feature lists are
# the host's required build policy, not a device-attested feature manifest;
# firmware behavior is separately bound by EXPECTED_PRODTEST_FW_VERSION.
# Keep the lists synchronized with Makefile's PRODTEST_*_FEATURES variables.
COMMAND_POLICIES = {
    CMD_PRODTEST_GET_ID: ("GET_ID", PROFILE_REQUIRED),
    CMD_PRODTEST_DISPLAY_PATTERN: ("DISPLAY_PATTERN", PROFILE_REQUIRED),
    CMD_PRODTEST_SAES_SELFTEST: ("SAES_SELFTEST", PROFILE_REQUIRED),
    CMD_PRODTEST_BHK_SELFTEST: ("BHK_SELFTEST", PROFILE_UNSUPPORTED),
    CMD_PRODTEST_FLASH_RW: ("FLASH_RW", PROFILE_UNSUPPORTED),
    CMD_PRODTEST_TRNG_SAMPLE: ("TRNG_SAMPLE", PROFILE_REQUIRED),
    CMD_PRODTEST_OPTIGA_HANDSHAKE: ("OPTIGA_HANDSHAKE", PROFILE_REQUIRED),
    CMD_PRODTEST_SE050_HANDSHAKE: ("SE050_HANDSHAKE", PROFILE_REQUIRED),
    CMD_PRODTEST_USB_LOOPBACK: ("USB_LOOPBACK", PROFILE_REQUIRED),
    CMD_PRODTEST_BUTTON_TEST: ("BUTTON_TEST", PROFILE_REQUIRED),
    # Both RGB commands are `pq1`-only, which is why this profile is
    # board-scoped (see PROFILE_ID). RGB_TEST proves the drive path — the part
    # identifies itself and every register write ACKs; the colour itself is the
    # operator's half. RGB_OSD is the fully machine-checkable half: it names a
    # dead LED by channel, needs no camera, and cannot pass vacuously.
    CMD_PRODTEST_RGB_TEST: ("RGB_TEST", PROFILE_REQUIRED),
    CMD_PRODTEST_RGB_OSD: ("RGB_OSD", PROFILE_REQUIRED),
    # Board-independent: every STM32U585 unit must be in the ESV-certified TRNG
    # configuration, and must BE the certified silicon revision.
    CMD_PRODTEST_RNG_CONFIG: ("RNG_CONFIG", PROFILE_REQUIRED),
}


def profile_receipt() -> dict:
    """Return a new, JSON-safe copy of the acceptance-profile contract."""
    policy_classes = {
        PROFILE_REQUIRED: [
            cmd
            for cmd, (_, policy) in COMMAND_POLICIES.items()
            if policy == PROFILE_REQUIRED
        ],
        # Derived, not hardcoded: an earlier version pinned this to [] while the
        # other two classes were computed, so a receipt silently claimed there
        # were no optional commands while two were declared optional.
        PROFILE_OPTIONAL: [
            cmd
            for cmd, (_, policy) in COMMAND_POLICIES.items()
            if policy == PROFILE_OPTIONAL
        ],
        PROFILE_UNSUPPORTED: [
            cmd
            for cmd, (_, policy) in COMMAND_POLICIES.items()
            if policy == PROFILE_UNSUPPORTED
        ],
    }
    return {
        "id": PROFILE_ID,
        "board": PROFILE_BOARD,
        "feature_list_authority": "host_expected_not_device_attested",
        # `board-pq1` is listed because naming a board is mandatory on every
        # stm32u585 build: omitting it compiles the iota2 pin map with every
        # pq1 fence silently inert, which is how an earlier recipe put iota2
        # pins on pq1 silicon.
        "secure_features": ["prodtest", "dev-testkey", "saes-dhuk", "board-pq1"],
        "nonsecure_features": ["stm32u585", "usb", "prodtest"],
        "max_response_data_len": PRODTEST_MAX_RESPONSE_DATA_LEN,
        "expected_firmware_version": EXPECTED_PRODTEST_FW_VERSION,
        "policy_classes": policy_classes,
        "commands": [
            {"cmd": cmd, "name": name, "policy": policy}
            for cmd, (name, policy) in COMMAND_POLICIES.items()
        ],
    }

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
    CMD_PRODTEST_RGB_TEST:          0x8A,
    CMD_PRODTEST_RGB_OSD:           0x8B,
    CMD_PRODTEST_RNG_CONFIG:        0x8C,
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
    0x13: ("FAIL", "step 1 (LEFT) release timeout — button stuck/welded ON"),
    0x21: ("FAIL", "step 2 (RIGHT) timeout"),
    0x22: ("FAIL", "step 2 (RIGHT) wrong button — operator pressed LEFT or wires are swapped"),
    0x23: ("FAIL", "step 2 (RIGHT) release timeout — button stuck/welded ON"),
    0x31: ("FAIL", "step 3 (BOTH) timeout — operator did not press both buttons together"),
    0x33: ("FAIL", "step 3 (BOTH) release timeout — a button is stuck/welded ON"),
}

# Response status codes — mirror `proto/src/lib.rs::NscStatus`.
STATUS_OK = 0
STATUS_INVALID_POINTER = 4
STATUS_NOT_INITIALIZED = 5
STATUS_INTERNAL_ERROR = 0xFFFFFFFF  # catch-all for the dispatcher

# The device's own ids, from `nonsecure/src/usb/mod.rs`'s
# `UsbVidPid(0x1209, 0x7051)`. These were previously Ledger's 0x2C97:0x0006 —
# a stale default that made the runner unable to find any PQSigner unit, which
# a factory would hit on its first run. `test_usb_ids_match_the_firmware`
# derives the expected values from that source file so they cannot drift again.
# 0x1209 is pid.codes, the community VID; 0x7051 is our allocation.
USB_VID_DEFAULT = 0x1209
USB_PID_DEFAULT = 0x7051

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
    policy: str = ""
    outcome: str = ""

    def __post_init__(self) -> None:
        declared = COMMAND_POLICIES.get(self.cmd)
        if declared is None:
            raise ValueError(f"unknown prodtest command in result: {self.cmd}")
        if not self.policy:
            self.policy = declared[1]
        if self.policy != declared[1]:
            raise ValueError(
                f"policy mismatch for command {self.cmd}: "
                f"{self.policy!r} != {declared[1]!r}"
            )
        if not self.outcome:
            self.outcome = OUTCOME_PASS if self.passed else OUTCOME_FAIL
        if self.outcome == OUTCOME_SKIP_UNSUPPORTED and self.passed:
            raise ValueError("SKIP_UNSUPPORTED must remain visibly non-passing")


@dataclass
class UnitReport:
    stm32_uid_hex: str = ""
    prodtest_fw_version: int = 0
    results: list[TestResult] = field(default_factory=list)
    fatal_error: str = ""

    @property
    def all_passed(self) -> bool:
        """Legacy literal result: false when approved unsupported probes skip."""
        return bool(self.results) and all(r.passed for r in self.results)

    @property
    def required_checks_passed(self) -> bool:
        for cmd, (_, policy) in COMMAND_POLICIES.items():
            if policy != PROFILE_REQUIRED:
                continue
            matches = [r for r in self.results if r.cmd == cmd]
            if not matches or any(
                not r.passed or r.outcome != OUTCOME_PASS for r in matches
            ):
                return False
        return True

    @property
    def profile_accepted(self) -> bool:
        if self.fatal_error:
            return False
        if any(r.cmd not in COMMAND_POLICIES for r in self.results):
            return False
        if not self.required_checks_passed:
            return False
        for cmd, (_, policy) in COMMAND_POLICIES.items():
            if policy != PROFILE_UNSUPPORTED:
                continue
            matches = [r for r in self.results if r.cmd == cmd]
            if len(matches) != 1 or matches[0].passed:
                return False
            if matches[0].outcome != OUTCOME_SKIP_UNSUPPORTED:
                return False
        return True

    def to_dict(self) -> dict:
        d = asdict(self)
        for r in d["results"]:
            r["raw_response"] = r["raw_response"].hex() if r["raw_response"] else ""
        d["profile"] = profile_receipt()
        d["required_checks_passed"] = self.required_checks_passed
        d["all_results_passed"] = self.all_passed
        d["profile_accepted"] = self.profile_accepted
        return d


# ---------------------------------------------------------------------------
# USB HID transport (placeholder — needs bench wiring)
# ---------------------------------------------------------------------------


def _find_hidraw_node(vid: int, pid: int) -> str | None:
    """The `/dev/hidrawN` node for `vid:pid`, or None.

    Reads the ids out of sysfs rather than shelling out, so it works on a bare
    fixture image with no extra tooling.
    """
    for entry in sorted(Path("/sys/class/hidraw").glob("hidraw*")):
        try:
            uevent = (entry / "device/uevent").read_text()
        except OSError:
            continue
        # HID_ID looks like "3:0000109:00007051" — bus:vendor:product, hex.
        for line in uevent.splitlines():
            if not line.startswith("HID_ID="):
                continue
            parts = line.split("=", 1)[1].split(":")
            if len(parts) == 3:
                try:
                    if int(parts[1], 16) == vid and int(parts[2], 16) == pid:
                        return f"/dev/{entry.name}"
                except ValueError:
                    pass
    return None


class HidRawDevice:
    """Minimal hidapi-compatible wrapper over a `/dev/hidrawN` node.

    Implements only what `ProdtestTransport` calls — `write`, `read` with a
    millisecond timeout, and `close` — and matches hidapi's semantics: the
    caller supplies the leading report-ID byte on write, and read returns the
    report without it. A timeout returns empty, which is what the transport's
    own timeout check expects.
    """

    def __init__(self, path: str) -> None:
        self.fd = os.open(path, os.O_RDWR)
        self.path = path

    def write(self, data: bytes) -> int:
        return os.write(self.fd, data)

    def read(self, size: int, timeout_ms: int = 0) -> bytes:
        timeout_s = (timeout_ms / 1000.0) if timeout_ms else None
        ready, _, _ = select.select([self.fd], [], [], timeout_s)
        if not ready:
            return b""
        return os.read(self.fd, size)

    def close(self) -> None:
        os.close(self.fd)


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
            # Fall back to the kernel's hidraw. A factory fixture should not
            # need a pip install to talk to a USB HID device, and on Linux
            # hidraw is always present — so this is the preferred path there,
            # not a degraded one. `HidRawDevice` implements exactly the three
            # hidapi calls this class uses.
            node = _find_hidraw_node(self.vid, self.pid)
            if node is None:
                print(
                    "ERROR: hidapi not installed and no matching hidraw node "
                    f"for {self.vid:#06x}:{self.pid:#06x}. Either `pip install "
                    "hid` or check the device is connected and readable "
                    "(a udev rule may be needed).",
                    file=sys.stderr,
                )
                raise
            self._dev = HidRawDevice(node)
            if self.verbose:
                print(f"[hid] opened {node} via hidraw (hidapi not installed)")
            return
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
    if fw_version != EXPECTED_PRODTEST_FW_VERSION:
        return TestResult(
            name="GET_ID",
            cmd=CMD_PRODTEST_GET_ID,
            passed=False,
            status_code=status,
            detail=(
                f"firmware/profile mismatch: got v{fw_version}, "
                f"expected v{EXPECTED_PRODTEST_FW_VERSION}"
            ),
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
    if status != STATUS_OK or len(resp) != 8:
        return TestResult(
            name="SAES_SELFTEST",
            cmd=CMD_PRODTEST_SAES_SELFTEST,
            passed=False,
            status_code=status,
            detail=f"status=0x{status:08x} got {len(resp)} bytes (expected 8)",
            raw_response=resp,
        )
    fingerprint = resp.hex()
    # All-zero fingerprint = SAES not actually running. Pass requires
    # at least one nonzero bit.
    nonzero = any(b != 0 for b in resp[:8])
    return TestResult(
        name="SAES_SELFTEST",
        cmd=CMD_PRODTEST_SAES_SELFTEST,
        passed=nonzero,
        status_code=status,
        # NOT a unit identity. This is a DHUK-derived value, and DHUK is shared
        # across all parts at RDP-0 (per-device only from RDP0.5 up, RM0456
        # Table 21). Units are tested and shipped at RDP-0, so every unit on the
        # line prints the SAME fingerprint — measured identical on two dies. It
        # proves the SAES/DHUK path runs; it does not distinguish boards, and
        # reading it as a per-unit value would make every unit look cloned. Use
        # the STM32 UID from GET_ID for identity.
        detail=f"fingerprint={fingerprint} (shared at RDP-0, not a unit id)",
        raw_response=resp,
    )


def test_bhk_selftest(tx: ProdtestTransport) -> TestResult:
    status, resp = tx.send_cmd(CMD_PRODTEST_BHK_SELFTEST, b"", out_size=8)
    if status == SW_INTERNAL_ERROR_WIRE and resp == b"\x00" * 8:
        return TestResult(
            name="BHK_SELFTEST",
            cmd=CMD_PRODTEST_BHK_SELFTEST,
            passed=False,
            status_code=status,
            detail="unsupported by reversible profile (expected non-authority result)",
            raw_response=resp,
            outcome=OUTCOME_SKIP_UNSUPPORTED,
        )
    return TestResult(
        name="BHK_SELFTEST",
        cmd=CMD_PRODTEST_BHK_SELFTEST,
        passed=False,
        status_code=status,
        detail=(
            "profile drift: expected SW_INTERNAL_ERROR and eight zero "
            f"diagnostic bytes, got status=0x{status:08x} len={len(resp)}"
        ),
        raw_response=resp,
    )


def test_flash_rw(tx: ProdtestTransport) -> TestResult:
    # The stable request shape is exercised as a negative-capability check.
    # The reversible profile must not grant a writable test page.
    in_data = struct.pack("<I", 0xDEADBEEF)
    status, resp = tx.send_cmd(CMD_PRODTEST_FLASH_RW, in_data, out_size=0)
    if status == SW_INTERNAL_ERROR_WIRE and not resp:
        return TestResult(
            name="FLASH_RW",
            cmd=CMD_PRODTEST_FLASH_RW,
            passed=False,
            status_code=status,
            detail="unsupported by reversible profile (no flash-write authority)",
            outcome=OUTCOME_SKIP_UNSUPPORTED,
        )
    return TestResult(
        name="FLASH_RW",
        cmd=CMD_PRODTEST_FLASH_RW,
        passed=False,
        status_code=status,
        detail=(
            "profile drift: expected SW_INTERNAL_ERROR with no response data, "
            f"got status=0x{status:08x} len={len(resp)}"
        ),
        raw_response=resp,
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


def test_usb_loopback(
    tx: ProdtestTransport, n: int = PRODTEST_MAX_RESPONSE_DATA_LEN
) -> TestResult:
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
        passed=(status == STATUS_OK and step_status == 0x00),
        status_code=status,
        detail=f"{label}: {hint}",
        raw_response=resp,
    )


# RGB_TEST response layout — mirrors `proto/src/lib.rs::CMD_PRODTEST_RGB_TEST`.
RGB_OUT_LEN = 24
RGB_SCAN_LEN = 16
RGB_VER_EXPECTED = 0xA8
RGB_RESET_ID_EXPECTED = 0x18
RGB_ADDR = 0x34           # AW21036, AD strapped to GND
RGB_BROADCAST_ADDR = 0x1C  # answered by the AW21036 regardless of the strap
BACKLIGHT_ADDR = 0x36      # AW99703 on the same bus — the bus's positive control


def decode_rgb_scan(scan: bytes) -> list[int]:
    """7-bit addresses present in the bitmap (bit a%8 of byte a//8)."""
    return [a for a in range(128) if scan[a // 8] & (1 << (a % 8))]


def test_rgb_test(
    tx: ProdtestTransport,
    r: int = 0,
    g: int = 0,
    b: int = 0,
    gcc: int = 0,
    en: int = 1,
    label: str = "",
) -> TestResult:
    """Light the 9 RGB LEDs and interpret the driver's self-report.

    The detail string is written to localize a dark board: if the AW21036 did
    not answer but the AW99703 backlight at 0x36 did, the bus is fine and the
    fault is the part or its strap; if neither answered, the fault is the bus.
    """
    name = f"RGB_TEST({label or f'{r:02x}{g:02x}{b:02x}'})"
    in_data = bytes([r & 0xFF, g & 0xFF, b & 0xFF, gcc & 0xFF, 1 if en else 0, 0])
    status, resp = tx.send_cmd(CMD_PRODTEST_RGB_TEST, in_data, out_size=RGB_OUT_LEN)
    if len(resp) != RGB_OUT_LEN:
        return TestResult(
            name=name,
            cmd=CMD_PRODTEST_RGB_TEST,
            passed=False,
            status_code=status,
            detail=f"status=0x{status:08x} got {len(resp)} bytes (expected {RGB_OUT_LEN})",
        )
    seen = decode_rgb_scan(resp[:RGB_SCAN_LEN])
    ver, reset_id, acks_ok, acks_total, en_level, gcc_used = resp[16:22]
    parts = [
        f"ver=0x{ver:02x}",
        f"id=0x{reset_id:02x}",
        f"acks={acks_ok}/{acks_total}",
        f"en={en_level}",
        f"gcc=0x{gcc_used:02x}",
        "bus=[" + " ".join(f"0x{a:02x}" for a in seen) + "]",
    ]
    if ver != RGB_VER_EXPECTED:
        if acks_total == 0:
            parts.append(
                "HINT: firmware attempted no writes — this build has no RGB "
                "driver (wrong board, or built without board-pq1)"
            )
        elif BACKLIGHT_ADDR in seen and RGB_ADDR not in seen:
            parts.append("HINT: bus OK (backlight answered), AW21036 silent — part or AD strap")
        elif not seen:
            parts.append("HINT: nothing on the bus — I2C2 pins, pull-ups or rail")
        else:
            parts.append("HINT: part addressable but identity wrong — wrong chip or bad read")
    return TestResult(
        name=name,
        cmd=CMD_PRODTEST_RGB_TEST,
        passed=(status == STATUS_OK and ver == RGB_VER_EXPECTED and acks_ok == acks_total),
        status_code=status,
        detail=", ".join(parts),
        raw_response=resp,
    )


# RGB_OSD response layout — mirrors `proto/src/lib.rs::CMD_PRODTEST_RGB_OSD`.
RGB_OSD_OUT_LEN = 24
OSST_BYTES = 5
OSD_INCONCLUSIVE = "INCONCLUSIVE"


def decode_osst(bitmap: bytes, total_channels: int) -> set[int]:
    """1-based channel numbers flagged in an OSST bitmap.

    `LED(k)` is bit `(k-1) % 8` of byte `(k-1) // 8`.
    """
    return {
        k
        for k in range(1, total_channels + 1)
        if bitmap[(k - 1) // 8] & (1 << ((k - 1) % 8))
    }


def channel_label(k: int) -> str:
    """Name channel `k` as its RGB package and colour.

    The board wires LED1..LED27 as LED_R1, LED_G1, LED_B1, LED_R2, ... so the
    channel index identifies both which of the nine packages and which die.
    """
    return f"LED{(k - 1) // 3 + 1}-{'RGB'[(k - 1) % 3]}"


def test_rgb_osd(tx: ProdtestTransport, gcc: int = 0, en: int = 1) -> TestResult:
    """Per-channel open detection — the dead-LED test a fixture can gate on.

    Two things have to be established before any verdict is meaningful, and
    both come from the same board fact:

    1. **Which `OSDE` encoding is open detection.** The datasheet contradicts
       itself (prose says 10=open/11=short, the register table says the
       reverse), so firmware returns both bitmaps and we resolve it here.
    2. **That detection actually ran.** Channels LED28..36 have no LED
       attached, so they MUST read open. Whichever mode flags all of them is
       open detection; if neither does, the mechanism did not work and the
       verdict is INCONCLUSIVE.

    A certification gate that reports PASS when the measurement silently did
    nothing is worse than no gate, so INCONCLUSIVE never passes.
    """
    in_data = bytes([gcc & 0xFF, 1 if en else 0, 0, 0])
    status, resp = tx.send_cmd(CMD_PRODTEST_RGB_OSD, in_data, out_size=RGB_OSD_OUT_LEN)
    if len(resp) != RGB_OSD_OUT_LEN:
        return TestResult(
            name="RGB_OSD",
            cmd=CMD_PRODTEST_RGB_OSD,
            passed=False,
            status_code=status,
            detail=f"status=0x{status:08x} got {len(resp)} bytes (expected {RGB_OSD_OUT_LEN})",
        )

    mode_a = resp[0:OSST_BYTES]
    mode_b = resp[OSST_BYTES : 2 * OSST_BYTES]
    ver, acks_ok, acks_total, en_level, gcc_used, wired, total = resp[10:17]

    parts = [
        f"ver=0x{ver:02x}",
        f"acks={acks_ok}/{acks_total}",
        f"en={en_level}",
        f"gcc=0x{gcc_used:02x}",
        f"wired={wired}/{total}",
        f"a={mode_a.hex()}",
        f"b={mode_b.hex()}",
    ]

    if acks_total == 0:
        parts.append(
            "firmware attempted no writes — this build has no RGB driver "
            "(wrong board, or built without board-pq1)"
        )
        return TestResult(
            name="RGB_OSD",
            cmd=CMD_PRODTEST_RGB_OSD,
            passed=False,
            status_code=status,
            detail=", ".join(parts),
            raw_response=resp,
        )

    if not 0 < wired <= total or total > OSST_BYTES * 8:
        parts.append("channel counts from the device are not sane")
        return TestResult(
            name="RGB_OSD",
            cmd=CMD_PRODTEST_RGB_OSD,
            passed=False,
            status_code=status,
            detail=", ".join(parts),
            raw_response=resp,
        )

    flagged_a = decode_osst(mode_a, total)
    flagged_b = decode_osst(mode_b, total)
    unwired = set(range(wired + 1, total + 1))
    a_is_open = bool(unwired) and unwired <= flagged_a
    b_is_open = bool(unwired) and unwired <= flagged_b

    if a_is_open == b_is_open:
        # Neither mode flagged the physically-open control channels (detection
        # did not run), or both did (cannot tell the encodings apart).
        why = (
            "both modes flagged the unwired control channels — cannot identify "
            "the open-detect encoding"
            if a_is_open
            else f"neither mode flagged the unwired control channels {sorted(unwired)} "
            "— open detection did not run (check the ~1 mA bias and PWMDIS)"
        )
        parts.append(f"{OSD_INCONCLUSIVE}: {why}")
        return TestResult(
            name="RGB_OSD",
            cmd=CMD_PRODTEST_RGB_OSD,
            passed=False,
            status_code=status,
            detail=", ".join(parts),
            raw_response=resp,
        )

    open_mode = "a(OSDE=10)" if a_is_open else "b(OSDE=11)"
    flagged_open = flagged_a if a_is_open else flagged_b
    faulty = sorted(flagged_open & set(range(1, wired + 1)))
    parts.append(f"open-encoding={open_mode}")
    parts.append(
        "channels OK"
        if not faulty
        else "OPEN: " + " ".join(f"{channel_label(k)}(ch{k})" for k in faulty)
    )
    return TestResult(
        name="RGB_OSD",
        cmd=CMD_PRODTEST_RGB_OSD,
        passed=(status == STATUS_OK and not faulty),
        status_code=status,
        detail=", ".join(parts),
        raw_response=resp,
    )


# CMD_PRODTEST_RNG_CONFIG — NIST ESV certificate E11 (STM32U575x/U585x,
# validated 2022-12-16). Table 2 fixes the configuration; the certificate covers
# "revision B and Later" silicon, identified by 0x41 in the RNG version register.
RNG_CONFIG_LEN = 20
RNG_CR_EXPECTED = 0x80F00D04      # config + RNGEN (bit 2) + CONFIGLOCK (bit 31)
RNG_NSCR_EXPECTED = 0x00017CBB
RNG_HTCR_ALLOWED = (0x00006E9C, 0x0000A2B0)   # alpha = 2^-20 or 2^-30
RNG_VER_EXPECTED = 0x41
DEV_ID_U575_U585 = 0x482


def test_rng_config(tx: ProdtestTransport) -> TestResult:
    """Per-unit evidence that the TRNG is in the ESV-certified configuration.

    Neither half is visible from outside the device and both are per-unit
    facts: silicon revision varies by batch, and a configuration write can be
    silently ignored (RNG_HTCR and RNG_NSCR are only honoured while CONDRST=1,
    and are frozen entirely once CONFIGLOCK is set).
    """
    status, resp = tx.send_cmd(CMD_PRODTEST_RNG_CONFIG, b"", out_size=RNG_CONFIG_LEN)
    if len(resp) != RNG_CONFIG_LEN:
        return TestResult(
            name="RNG_CONFIG",
            cmd=CMD_PRODTEST_RNG_CONFIG,
            passed=False,
            status_code=status,
            detail=f"status=0x{status:08x} got {len(resp)} bytes (expected {RNG_CONFIG_LEN})",
        )
    cr, nscr, htcr, ver, idcode = struct.unpack("<5I", resp)
    dev_id, rev_id = idcode & 0xFFF, (idcode >> 16) & 0xFFFF
    parts, bad = [], []
    parts.append(f"CR=0x{cr:08x}")
    if cr != RNG_CR_EXPECTED:
        bad.append(f"CR 0x{cr:08x} != 0x{RNG_CR_EXPECTED:08x}"
                   + ("" if cr & (1 << 31) else " (CONFIGLOCK NOT set)"))
    parts.append(f"NSCR=0x{nscr:05x}")
    if nscr != RNG_NSCR_EXPECTED:
        bad.append(f"NSCR 0x{nscr:x} != 0x{RNG_NSCR_EXPECTED:x}")
    parts.append(f"HTCR=0x{htcr:04x}")
    if htcr not in RNG_HTCR_ALLOWED:
        bad.append(f"HTCR 0x{htcr:x} is not one of E11's permitted values")
    parts.append(f"VER=0x{ver:02x}")
    if ver != RNG_VER_EXPECTED:
        bad.append(f"RNG version 0x{ver:x} != 0x{RNG_VER_EXPECTED:x}"
                   " — E11 covers revision B and later only")
    parts.append(f"DEV_ID=0x{dev_id:03x} REV_ID=0x{rev_id:04x}")
    if dev_id != DEV_ID_U575_U585:
        bad.append(f"DEV_ID 0x{dev_id:03x} is not U575/U585 (0x482)")
    if bad:
        parts.append("NOT CERTIFIED-CONFIG: " + "; ".join(bad))
    return TestResult(
        name="RNG_CONFIG",
        cmd=CMD_PRODTEST_RNG_CONFIG,
        passed=(status == STATUS_OK and not bad),
        status_code=status,
        detail=", ".join(parts),
        raw_response=resp,
    )


def test_trng_sample(
    tx: ProdtestTransport, n: int = PRODTEST_MAX_RESPONSE_DATA_LEN
) -> TestResult:
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
    passed = distinct >= 32  # at least 32 distinct byte values in 254 bytes
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
    # traceability. Never send another command if the identity/version contract
    # is not exact: later INS values must not be interpreted under an unknown
    # firmware protocol.
    identity = test_get_id(tx, report)
    report.results.append(identity)
    if not identity.passed:
        return

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
    report.results.append(test_trng_sample(tx, PRODTEST_MAX_RESPONSE_DATA_LEN))
    # Phase C: communication tests.
    report.results.append(test_optiga_handshake(tx))
    report.results.append(test_se050_handshake(tx))
    report.results.append(test_usb_loopback(tx, PRODTEST_MAX_RESPONSE_DATA_LEN))
    # Phase D: operator-interactive button test (last because the
    # operator must be present and pressing buttons; failures from
    # the prior automated tests are easier to recover from without
    # involving a human).
    # RGB LEDs: a colour sweep the operator (or the fixture's camera) watches.
    # Held long enough to be seen, and left dark at the end so the next unit
    # starts from an unlit board.
    for r, g, b, label in (
        (0xFF, 0x00, 0x00, "red"),
        (0x00, 0xFF, 0x00, "green"),
        (0x00, 0x00, 0xFF, "blue"),
        (0xFF, 0xFF, 0xFF, "white"),
    ):
        report.results.append(test_rgb_test(tx, r, g, b, label=label))
        time.sleep(1.0)
    report.results.append(test_rgb_test(tx, 0, 0, 0, label="off"))
    # Machine-checkable dead-LED detection — names the failing channel, so it
    # does not depend on the operator noticing a wrong colour.
    report.results.append(test_rgb_osd(tx))
    report.results.append(test_rng_config(tx))
    report.results.append(test_button_test(tx))


def write_report_atomic(path: str, report: UnitReport) -> None:
    """Durably replace a report without exposing a partial JSON document."""
    target = Path(path)
    parent = target.parent if str(target.parent) else Path(".")
    fd, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(report.to_dict(), output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def print_summary(report: UnitReport) -> None:
    print()
    print("=" * 60)
    print(f"Profile:    {PROFILE_ID} (board {PROFILE_BOARD})")
    print(f"UID:        {report.stm32_uid_hex}")
    print(f"FW version: {report.prodtest_fw_version}")
    print("=" * 60)
    for result in report.results:
        marker = {
            OUTCOME_PASS: "✓",
            OUTCOME_FAIL: "✗",
            OUTCOME_SKIP_UNSUPPORTED: "-",
        }.get(result.outcome, "?")
        print(
            f"  {marker} {result.name:<24}  {result.outcome:<16} "
            f"status=0x{result.status_code:08x}  {result.detail}"
        )
    print("=" * 60)
    if report.fatal_error:
        print(f"RESULT: RUNNER ERROR — {report.fatal_error}")
    elif report.profile_accepted:
        print(
            "RESULT: REVERSIBLE PROFILE ACCEPTED — required checks passed; "
            "unsupported probes remained non-authoritative"
        )
    else:
        failures = sum(1 for r in report.results if r.outcome == OUTCOME_FAIL)
        print(f"RESULT: PROFILE REJECTED — {failures} executed check(s) failed")
    print()


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
        report.fatal_error = f"{type(e).__name__}: {e}"
        print(f"FATAL: {report.fatal_error}", file=sys.stderr)
    finally:
        try:
            tx.close()
        except Exception as e:
            if not report.fatal_error:
                report.fatal_error = f"close {type(e).__name__}: {e}"
                print(f"FATAL: {report.fatal_error}", file=sys.stderr)

    print_summary(report)

    if args.report:
        try:
            write_report_atomic(args.report, report)
            print(f"Wrote atomic JSON report to {args.report}")
        except Exception as e:
            print(f"FATAL: could not write report atomically: {e}", file=sys.stderr)
            return 2

    if report.fatal_error:
        return 2
    return 0 if report.profile_accepted else 1


if __name__ == "__main__":
    sys.exit(main())
