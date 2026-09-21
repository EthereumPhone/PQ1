#!/usr/bin/env python3
"""Focused, transport-mocked tests for the reversible prodtest runner."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RUNNER_PATH = Path(__file__).with_name("factory-prodtest-runner.py")
SPEC = importlib.util.spec_from_file_location("factory_prodtest_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


class FakeTransport:
    def __init__(self, overrides: dict[int, tuple[int, bytes]] | None = None) -> None:
        self.overrides = overrides or {}
        self.calls: list[tuple[int, bytes, int]] = []

    def send_cmd(
        self, cmd: int, in_data: bytes = b"", out_size: int = 0
    ) -> tuple[int, bytes]:
        self.calls.append((cmd, in_data, out_size))
        if cmd in self.overrides:
            return self.overrides[cmd]
        if cmd == runner.CMD_PRODTEST_GET_ID:
            return (
                runner.STATUS_OK,
                bytes(range(1, 13))
                + struct.pack("<I", runner.EXPECTED_PRODTEST_FW_VERSION)
                + b"\x00" * 8,
            )
        if cmd == runner.CMD_PRODTEST_DISPLAY_PATTERN:
            return runner.STATUS_OK, b""
        if cmd == runner.CMD_PRODTEST_SAES_SELFTEST:
            return runner.STATUS_OK, b"\x01\x02\x03\x04\x05\x06\x07\x08"
        if cmd == runner.CMD_PRODTEST_BHK_SELFTEST:
            return runner.SW_INTERNAL_ERROR_WIRE, b"\x00" * 8
        if cmd == runner.CMD_PRODTEST_FLASH_RW:
            return runner.SW_INTERNAL_ERROR_WIRE, b""
        if cmd == runner.CMD_PRODTEST_TRNG_SAMPLE:
            n = struct.unpack("<I", in_data)[0]
            return runner.STATUS_OK, bytes(i % 251 for i in range(n))
        if cmd == runner.CMD_PRODTEST_OPTIGA_HANDSHAKE:
            return runner.STATUS_OK, bytes(range(1, 17))
        if cmd == runner.CMD_PRODTEST_SE050_HANDSHAKE:
            return runner.STATUS_OK, bytes(range(17, 33))
        if cmd == runner.CMD_PRODTEST_USB_LOOPBACK:
            return runner.STATUS_OK, in_data
        if cmd == runner.CMD_PRODTEST_BUTTON_TEST:
            return runner.STATUS_OK, b"\x00\x00\x00\x00"
        if cmd == runner.CMD_PRODTEST_RGB_TEST:
            return runner.STATUS_OK, healthy_rgb_response()
        raise AssertionError(f"unexpected command {cmd}")


def rgb_response(
    present: tuple[int, ...] = (
        0x1C,
        0x34,
        0x36,
    ),
    ver: int = 0xA8,
    reset_id: int = 0x18,
    acks_ok: int = 58,
    acks_total: int = 58,
    en_level: int = 1,
    gcc: int = 0x28,
) -> bytes:
    """Build a CMD_PRODTEST_RGB_TEST response with a given bus population."""
    scan = bytearray(16)
    for addr in present:
        scan[addr // 8] |= 1 << (addr % 8)
    return bytes(scan) + bytes([ver, reset_id, acks_ok, acks_total, en_level, gcc, 0, 0])


def healthy_rgb_response() -> bytes:
    return rgb_response()


class ReversibleProfileTests(unittest.TestCase):
    def run_profile(self, tx: FakeTransport) -> object:
        report = runner.UnitReport()
        with mock.patch.object(runner.time, "sleep", return_value=None):
            runner.run_all_tests(tx, report)
        return report

    def test_profile_matrix_covers_exact_stable_command_set(self) -> None:
        self.assertEqual(set(runner.COMMAND_POLICIES), set(range(100, 111)))
        unsupported = {
            cmd
            for cmd, (_, policy) in runner.COMMAND_POLICIES.items()
            if policy == runner.PROFILE_UNSUPPORTED
        }
        self.assertEqual(
            unsupported,
            {
                runner.CMD_PRODTEST_BHK_SELFTEST,
                runner.CMD_PRODTEST_FLASH_RW,
            },
        )
        receipt = runner.profile_receipt()
        self.assertEqual(receipt["max_response_data_len"], 254)
        self.assertEqual(receipt["expected_firmware_version"], 4)
        self.assertEqual(
            receipt["feature_list_authority"],
            "host_expected_not_device_attested",
        )
        self.assertEqual(receipt["policy_classes"]["optional"], [])
        self.assertEqual(
            set(receipt["policy_classes"]),
            {"required", "optional", "unsupported"},
        )
        self.assertEqual(
            receipt["secure_features"], ["prodtest", "dev-testkey", "saes-dhuk"]
        )

    def test_safe_profile_accepts_required_passes_and_nonpassing_skips(self) -> None:
        tx = FakeTransport()
        report = self.run_profile(tx)

        self.assertTrue(report.required_checks_passed)
        self.assertTrue(report.profile_accepted)
        self.assertFalse(report.all_passed)
        skips = [
            result
            for result in report.results
            if result.outcome == runner.OUTCOME_SKIP_UNSUPPORTED
        ]
        self.assertEqual({result.cmd for result in skips}, {103, 104})
        self.assertTrue(all(not result.passed for result in skips))

        trng_call = next(call for call in tx.calls if call[0] == 105)
        self.assertEqual(struct.unpack("<I", trng_call[1])[0], 254)
        self.assertEqual(trng_call[2], 254)
        loopback_call = next(call for call in tx.calls if call[0] == 108)
        self.assertEqual(len(loopback_call[1]), 254)
        self.assertEqual(loopback_call[2], 254)

        encoded = report.to_dict()
        self.assertTrue(encoded["profile_accepted"])
        self.assertFalse(encoded["all_results_passed"])
        self.assertEqual(encoded["profile"]["id"], runner.PROFILE_ID)

    def test_unexpected_unsupported_success_is_profile_failure(self) -> None:
        tx = FakeTransport(
            {runner.CMD_PRODTEST_BHK_SELFTEST: (runner.STATUS_OK, b"\x55" * 8)}
        )
        report = self.run_profile(tx)
        bhk = next(result for result in report.results if result.cmd == 103)
        self.assertEqual(bhk.outcome, runner.OUTCOME_FAIL)
        self.assertFalse(bhk.passed)
        self.assertFalse(report.profile_accepted)

    def test_required_short_response_fails_profile(self) -> None:
        tx = FakeTransport(
            {runner.CMD_PRODTEST_SAES_SELFTEST: (runner.STATUS_OK, b"\x01" * 7)}
        )
        report = self.run_profile(tx)
        self.assertFalse(report.required_checks_passed)
        self.assertFalse(report.profile_accepted)

    def test_optiga_probe_failure_cannot_accept_profile(self) -> None:
        tx = FakeTransport(
            {
                runner.CMD_PRODTEST_OPTIGA_HANDSHAKE: (
                    runner.SW_INTERNAL_ERROR_WIRE,
                    b"",
                )
            }
        )
        report = self.run_profile(tx)
        probe = next(
            result
            for result in report.results
            if result.cmd == runner.CMD_PRODTEST_OPTIGA_HANDSHAKE
        )
        self.assertFalse(probe.passed)
        self.assertEqual(probe.outcome, runner.OUTCOME_FAIL)
        self.assertFalse(report.required_checks_passed)
        self.assertFalse(report.profile_accepted)

    def test_get_id_firmware_version_mismatch_fails_profile(self) -> None:
        stale_get_id = (
            bytes(range(1, 13)) + struct.pack("<I", 1) + b"\x00" * 8
        )
        tx = FakeTransport(
            {runner.CMD_PRODTEST_GET_ID: (runner.STATUS_OK, stale_get_id)}
        )
        report = self.run_profile(tx)
        get_id = next(result for result in report.results if result.cmd == 100)
        self.assertEqual(report.prodtest_fw_version, 1)
        self.assertIn(
            f"expected v{runner.EXPECTED_PRODTEST_FW_VERSION}", get_id.detail
        )
        self.assertEqual(
            tx.calls,
            [(runner.CMD_PRODTEST_GET_ID, b"", 24)],
        )
        self.assertFalse(report.profile_accepted)

    def test_apdu_builder_accepts_255_and_rejects_256(self) -> None:
        apdu = runner.ProdtestTransport._build_apdu(0x88, b"x" * 255)
        self.assertEqual(apdu[4], 255)
        with self.assertRaises(ValueError):
            runner.ProdtestTransport._build_apdu(0x88, b"x" * 256)

    def test_transport_failure_still_writes_atomic_non_green_receipt(self) -> None:
        class BrokenTransport:
            def __init__(self, _vid: int, _pid: int, verbose: bool = False) -> None:
                self.verbose = verbose

            def connect(self) -> None:
                raise TimeoutError("fixture unavailable")

            def close(self) -> None:
                pass

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "unit.json"
            argv = ["factory-prodtest-runner.py", "--report", str(report_path)]
            with (
                mock.patch.object(runner, "ProdtestTransport", BrokenTransport),
                mock.patch.object(sys, "argv", argv),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                rc = runner.main()

            self.assertEqual(rc, 2)
            receipt = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertFalse(receipt["profile_accepted"])
            self.assertFalse(receipt["all_results_passed"])
            self.assertIn("fixture unavailable", receipt["fatal_error"])
            self.assertEqual(receipt["profile"]["commands"][0]["cmd"], 100)
            self.assertEqual(list(Path(temp_dir).glob(".*.tmp")), [])




class RgbTestDecodeTests(unittest.TestCase):
    """The RGB response exists to localize a dark board, so the decode and the
    hint selection are tested directly — including the failure shapes, which is
    the half that actually gets read in the factory."""

    def test_scan_bitmap_round_trips_addresses(self) -> None:
        for present in ((), (0x08,), (0x34, 0x36), (0x1C, 0x34, 0x36, 0x77)):
            resp = rgb_response(present=present)
            self.assertEqual(
                runner.decode_rgb_scan(resp[: runner.RGB_SCAN_LEN]), sorted(present)
            )

    def test_healthy_response_passes_and_sends_six_byte_request(self) -> None:
        tx = FakeTransport()
        result = runner.test_rgb_test(tx, 0xFF, 0x00, 0x00, label="red")
        self.assertTrue(result.passed)
        self.assertIn("ver=0xa8", result.detail)
        cmd, in_data, out_size = tx.calls[0]
        self.assertEqual(cmd, runner.CMD_PRODTEST_RGB_TEST)
        self.assertEqual(out_size, runner.RGB_OUT_LEN)
        # [r, g, b, gcc, en, reserved] — en defaults to 1 (drive RGB_EN high).
        self.assertEqual(in_data, bytes([0xFF, 0x00, 0x00, 0x00, 0x01, 0x00]))

    def test_silent_part_on_live_bus_blames_the_part_not_the_bus(self) -> None:
        # Backlight ACKs, AW21036 does not: bus and pull-ups are proven good.
        resp = rgb_response(present=(0x36,), ver=0xFF, acks_ok=0)
        tx = FakeTransport({runner.CMD_PRODTEST_RGB_TEST: (runner.STATUS_OK, resp)})
        result = runner.test_rgb_test(tx)
        self.assertFalse(result.passed)
        self.assertIn("part or AD strap", result.detail)

    def test_dead_bus_blames_the_bus(self) -> None:
        resp = rgb_response(present=(), ver=0xFF, acks_ok=0)
        tx = FakeTransport({runner.CMD_PRODTEST_RGB_TEST: (runner.STATUS_OK, resp)})
        result = runner.test_rgb_test(tx)
        self.assertFalse(result.passed)
        self.assertIn("nothing on the bus", result.detail)

    def test_partial_acks_fail_even_with_a_healthy_identity(self) -> None:
        # The classic "chip is there, writes are dropping" shape: identity reads
        # fine but the register writes did not all land.
        resp = rgb_response(acks_ok=57, acks_total=58)
        tx = FakeTransport({runner.CMD_PRODTEST_RGB_TEST: (runner.STATUS_OK, resp)})
        result = runner.test_rgb_test(tx)
        self.assertFalse(result.passed)
        self.assertIn("acks=57/58", result.detail)

    def test_short_response_fails_without_indexing_past_the_end(self) -> None:
        tx = FakeTransport({runner.CMD_PRODTEST_RGB_TEST: (runner.STATUS_OK, b"\x00" * 8)})
        result = runner.test_rgb_test(tx)
        self.assertFalse(result.passed)
        self.assertIn("expected 24", result.detail)


if __name__ == "__main__":
    unittest.main()
