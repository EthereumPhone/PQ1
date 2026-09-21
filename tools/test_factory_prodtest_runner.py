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
# Python caches bytecode for this module in tools/__pycache__, and source
# invalidation is (mtime, size) only. A same-length edit inside one mtime tick —
# exactly what a negative control that flips one constant does — leaves a stale
# .pyc that Python cannot distinguish from the restored source, so the OLD
# constants keep being served. That produced a false hardware FAIL once
# (RGB_VER_EXPECTED 0xA8 read back as 0xA9 from cache while the file on disk
# said 0xA8). Writing no cache for this loader removes the failure mode.
sys.dont_write_bytecode = True
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
        if cmd == runner.CMD_PRODTEST_RGB_OSD:
            return runner.STATUS_OK, osd_response()
        raise AssertionError(f"unexpected command {cmd}")


def osd_bitmap(channels: tuple[int, ...]) -> bytes:
    """Pack 1-based channel numbers into a 5-byte OSST bitmap."""
    b = bytearray(runner.OSST_BYTES)
    for k in channels:
        b[(k - 1) // 8] |= 1 << ((k - 1) % 8)
    return bytes(b)


def osd_response(
    open_channels: tuple[int, ...] | None = None,
    short_channels: tuple[int, ...] = (),
    open_in_mode_a: bool = True,
    ver: int = 0xA8,
    acks_ok: int = 46,
    acks_total: int = 46,
    en_level: int = 1,
    gcc: int = 0x20,
    wired: int = 27,
    total: int = 36,
) -> bytes:
    """Build a CMD_PRODTEST_RGB_OSD response.

    `open_channels` defaults to the nine unwired channels, i.e. a healthy
    board: the physically-absent LEDs read open and nothing else does.
    """
    if open_channels is None:
        open_channels = tuple(range(wired + 1, total + 1))
    opens = osd_bitmap(open_channels)
    shorts = osd_bitmap(short_channels)
    mode_a, mode_b = (opens, shorts) if open_in_mode_a else (shorts, opens)
    return (
        mode_a
        + mode_b
        + bytes([ver, acks_ok, acks_total, en_level, gcc, wired, total])
        + bytes(7)
    )


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


def makefile_prodtest_features() -> list[str]:
    """`PRODTEST_SECURE_FEATURES` from the Makefile, board placeholder resolved.

    Naming a board is mandatory on every stm32u585 build, so `$(BOARD_FEATURE)`
    always resolves to a real feature; here it resolves to the profile's board.
    """
    makefile = (Path(__file__).resolve().parents[1] / "Makefile").read_text()
    for line in makefile.splitlines():
        if "PRODTEST_SECURE_FEATURES" in line and ":=" in line:
            rhs = line.split(":=", 1)[1].strip()
            return [
                f"board-{runner.PROFILE_BOARD}" if f == "$(BOARD_FEATURE)" else f
                for f in rhs.split(",")
            ]
    raise AssertionError("PRODTEST_SECURE_FEATURES not found in the Makefile")


class ReversibleProfileTests(unittest.TestCase):
    def run_profile(self, tx: FakeTransport) -> object:
        report = runner.UnitReport()
        with mock.patch.object(runner.time, "sleep", return_value=None):
            runner.run_all_tests(tx, report)
        return report

    def test_profile_matrix_covers_exact_stable_command_set(self) -> None:
        self.assertEqual(set(runner.COMMAND_POLICIES), set(range(100, 112)))
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
        # Derived from the Makefile rather than pinned as a literal: the
        # receipt states the build policy a manufacturer must reproduce, so the
        # two drifting apart is the failure worth preventing. (It had already
        # drifted — the list omitted the board feature, which the build has
        # always passed.)
        self.assertEqual(receipt["secure_features"], makefile_prodtest_features())

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




class RgbOsdDecodeTests(unittest.TestCase):
    """The OSD verdict is what a certification fixture would gate on, so the
    important cases are the ones where it must REFUSE to pass."""

    def osd(self, **kw) -> object:
        resp = osd_response(**kw)
        tx = FakeTransport({runner.CMD_PRODTEST_RGB_OSD: (runner.STATUS_OK, resp)})
        return runner.test_rgb_osd(tx)

    def test_bitmap_round_trips_channel_numbers(self) -> None:
        for chans in ((), (1,), (2, 5, 8), (28, 36), tuple(range(1, 37))):
            self.assertEqual(
                runner.decode_osst(osd_bitmap(chans), 36), set(chans)
            )

    def test_channel_label_maps_index_to_package_and_colour(self) -> None:
        # LED1..3 are the R/G/B dies of package 1, LED4..6 of package 2, ...
        self.assertEqual(runner.channel_label(1), "LED1-R")
        self.assertEqual(runner.channel_label(2), "LED1-G")
        self.assertEqual(runner.channel_label(3), "LED1-B")
        self.assertEqual(runner.channel_label(26), "LED9-G")
        self.assertEqual(runner.channel_label(27), "LED9-B")

    def test_healthy_board_passes_and_names_the_open_encoding(self) -> None:
        r = self.osd()
        self.assertTrue(r.passed)
        self.assertIn("open-encoding=a(OSDE=10)", r.detail)
        self.assertIn("channels OK", r.detail)

    def test_resolves_the_encoding_either_way_round(self) -> None:
        # The datasheet contradicts itself; the unwired control channels decide.
        r = self.osd(open_in_mode_a=False)
        self.assertTrue(r.passed)
        self.assertIn("open-encoding=b(OSDE=11)", r.detail)

    def test_dead_green_channel_fails_and_is_named(self) -> None:
        # Channel 26 = LED9's green die — the shape actually seen on the EVT
        # unit, where one LED rendered magenta instead of white.
        r = self.osd(open_channels=tuple(range(28, 37)) + (26,))
        self.assertFalse(r.passed)
        self.assertIn("LED9-G(ch26)", r.detail)

    def test_detection_that_did_not_run_is_INCONCLUSIVE_not_pass(self) -> None:
        # The critical anti-vacuity case: all-zero status. Nine channels are
        # physically open, so an empty bitmap cannot mean "all good".
        r = self.osd(open_channels=())
        self.assertFalse(r.passed)
        self.assertIn(runner.OSD_INCONCLUSIVE, r.detail)
        self.assertIn("did not run", r.detail)

    def test_ambiguous_encoding_is_INCONCLUSIVE(self) -> None:
        # Both modes flag the control channels → cannot tell them apart.
        unwired = tuple(range(28, 37))
        r = self.osd(open_channels=unwired, short_channels=unwired)
        self.assertFalse(r.passed)
        self.assertIn(runner.OSD_INCONCLUSIVE, r.detail)
        self.assertIn("cannot identify", r.detail)

    def test_insane_channel_counts_from_the_device_fail(self) -> None:
        # `open_channels=()` keeps the helper from packing channel numbers the
        # 5-byte bitmap cannot hold; the point here is the device's own counts.
        for wired, total in ((0, 36), (40, 36), (27, 64)):
            r = self.osd(wired=wired, total=total, open_channels=())
            self.assertFalse(r.passed, f"wired={wired} total={total}")
            self.assertIn("not sane", r.detail)

    def test_short_response_fails_without_indexing_past_the_end(self) -> None:
        tx = FakeTransport(
            {runner.CMD_PRODTEST_RGB_OSD: (runner.STATUS_OK, b"\x00" * 8)}
        )
        r = runner.test_rgb_osd(tx)
        self.assertFalse(r.passed)
        self.assertIn("expected 24", r.detail)




class ProfileV2Tests(unittest.TestCase):
    """v2 makes LED acceptance a machine gate, which changes what the profile
    means: it is now board-scoped, so the identity must say so and the two RGB
    commands must be required rather than advisory."""

    def test_profile_id_is_board_scoped_and_versioned(self) -> None:
        self.assertEqual(runner.PROFILE_BOARD, "pq1")
        self.assertIn(runner.PROFILE_BOARD, runner.PROFILE_ID)
        self.assertTrue(runner.PROFILE_ID.endswith("-v2"), runner.PROFILE_ID)
        # The receipt must carry the board, or a manufacturer cannot tell which
        # board a stored receipt was produced against.
        self.assertEqual(runner.profile_receipt()["board"], "pq1")

    def test_both_rgb_commands_are_required(self) -> None:
        for cmd in (runner.CMD_PRODTEST_RGB_TEST, runner.CMD_PRODTEST_RGB_OSD):
            self.assertEqual(
                runner.COMMAND_POLICIES[cmd][1], runner.PROFILE_REQUIRED
            )
        required = runner.profile_receipt()["policy_classes"][
            runner.PROFILE_REQUIRED
        ]
        self.assertIn(runner.CMD_PRODTEST_RGB_TEST, required)
        self.assertIn(runner.CMD_PRODTEST_RGB_OSD, required)

    def test_receipt_derives_every_policy_class_including_optional(self) -> None:
        # Regression: the optional list was hardcoded [] while the other two
        # classes were derived, so a receipt could claim no optional commands
        # while some were declared.
        #
        # v2 leaves NO command optional, which makes the obvious version of this
        # test vacuous — hardcoded [] and a derived [] are indistinguishable.
        # So inject an optional command and assert the receipt reports it. This
        # tests the derivation itself rather than today's matrix.
        receipt = runner.profile_receipt()["policy_classes"]
        for policy in (
            runner.PROFILE_REQUIRED,
            runner.PROFILE_OPTIONAL,
            runner.PROFILE_UNSUPPORTED,
        ):
            expected = sorted(
                cmd
                for cmd, (_, declared) in runner.COMMAND_POLICIES.items()
                if declared == policy
            )
            self.assertEqual(sorted(receipt[policy]), expected, policy)

        sentinel = 199
        self.assertNotIn(sentinel, runner.COMMAND_POLICIES)
        with mock.patch.dict(
            runner.COMMAND_POLICIES,
            {sentinel: ("SENTINEL", runner.PROFILE_OPTIONAL)},
        ):
            classes = runner.profile_receipt()["policy_classes"]
            self.assertIn(
                sentinel,
                classes[runner.PROFILE_OPTIONAL],
                "receipt does not report a declared optional command",
            )

    def test_a_required_rgb_failure_rejects_the_profile(self) -> None:
        # The point of promotion: a dead LED must now sink the unit's verdict.
        bad = osd_response(open_channels=tuple(range(28, 37)) + (26,))
        tx = FakeTransport({runner.CMD_PRODTEST_RGB_OSD: (runner.STATUS_OK, bad)})
        report = runner.UnitReport()
        with mock.patch.object(runner.time, "sleep", return_value=None):
            runner.run_all_tests(tx, report)
        self.assertFalse(report.required_checks_passed)
        self.assertFalse(report.profile_accepted)

    def test_board_without_an_rgb_driver_says_so(self) -> None:
        # The firmware stub on a non-pq1 build writes nothing, so the response
        # is all zeros. A real pq1 run always ATTEMPTS writes, which makes
        # acks_total == 0 an unambiguous "this build has no RGB driver" rather
        # than a misleading "check your I2C pull-ups".
        zeros = bytes(runner.RGB_OSD_OUT_LEN)
        tx = FakeTransport(
            {runner.CMD_PRODTEST_RGB_OSD: (runner.SW_INTERNAL_ERROR_WIRE, zeros)}
        )
        r = runner.test_rgb_osd(tx)
        self.assertFalse(r.passed)
        self.assertIn("no RGB driver", r.detail)

        zeros_rgb = bytes(runner.RGB_OUT_LEN)
        tx = FakeTransport(
            {runner.CMD_PRODTEST_RGB_TEST: (runner.SW_INTERNAL_ERROR_WIRE, zeros_rgb)}
        )
        r = runner.test_rgb_test(tx)
        self.assertFalse(r.passed)
        self.assertIn("no RGB driver", r.detail)


if __name__ == "__main__":
    unittest.main()
