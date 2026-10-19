#!/usr/bin/env python3
"""Unit tests for the SE050 probe report (no hardware).

    python3 -m unittest discover -s tools/se050_probe -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import report  # noqa: E402


def line(s: str) -> str:
    return f"[SPROBE] {s}"


def build_log(objects: list[str], extra: list[str] = (), done: str = "OK") -> str:
    out = [
        "=== SPROBE START ===",
        line("6B.1 applet v7.2.0 AppletConfig=0x3f9f SecureBox=0xffff"),
        line("6B.4 free-memory[persistent] = 32767 bytes (SATURATED at 0x7FFF: a floor, blind to leaks)"),
        line("6B.4 free-memory[transient-reset] = 796 bytes"),
        line("6B.3 ReadIDList page=0 listed=%d more=false" % len(objects)),
    ]
    out += [line(f"6B.3   id={o}") for o in objects]
    out += [
        line("6B.6 plain GetVersionExt SW=0x6982 data="),
        line("6B.6 plain Read(ENTROPY_OBJ) SW=0x6985 datalen=0"),
    ]
    out += [line(e) for e in extra]
    if done:
        out.append(f"=== SPROBE DONE {done} ===")
    return "\n".join(out) + "\n"


CLEAN = [
    "0x7fff0206 class=nxp-reserved type=err size=18",
    "0xf0000000 class=iot-trust-prov type=0100 size=549",
    "0x7b5e00a0 class=stress-carveout type=err size=err",
]


class Report(unittest.TestCase):
    def test_clean_die_passes(self) -> None:
        r = report.analyse(build_log(CLEAN))
        self.assertEqual(r["findings"], [])
        self.assertEqual(report.exit_code(r), 0)
        self.assertEqual(len(r["inventory"]), 3)

    def test_size_err_is_not_a_size(self) -> None:
        r = report.analyse(build_log(CLEAN))
        self.assertIn((0x7B5E00A0, "stress-carveout", None), r["inventory"])

    def test_stale_e2e_object_is_a_finding(self) -> None:
        r = report.analyse(build_log(CLEAN + ["0x7b0a0000 class=e2e-test type=err size=err"]))
        self.assertTrue(any("0x7b0a0000" in f for f in r["findings"]))
        self.assertEqual(report.exit_code(r), 1)

    def test_production_and_unexpected_are_findings(self) -> None:
        for obj in ("0x7b100001 class=PRODUCTION(v6) type=00 size=32",
                    "0x12345678 class=UNEXPECTED type=00 size=4"):
            with self.subTest(obj=obj):
                self.assertEqual(report.exit_code(report.analyse(build_log(CLEAN + [obj]))), 1)

    def test_firmware_finding_line_counts(self) -> None:
        r = report.analyse(build_log(CLEAN, ["6B.3 FINDING: page 0 listed 80 IDs but only 64 fit"]))
        self.assertEqual(report.exit_code(r), 1)

    def test_plain_entropy_read_with_data_is_a_finding(self) -> None:
        log = build_log(CLEAN).replace("SW=0x6985 datalen=0", "SW=0x9000 datalen=32")
        r = report.analyse(log)
        self.assertTrue(any("half_E" in f for f in r["findings"]))

    def test_saturated_free_memory_is_marked(self) -> None:
        r = report.analyse(build_log(CLEAN))
        self.assertEqual(r["saturated"], ["persistent"])
        self.assertIn("saturated", report.render("x.log", r))

    def test_offset_unit_entries_passes(self) -> None:
        r = report.analyse(build_log(CLEAN, ["6B.3b ReadIDList offset unit = ENTRIES (matches apdu::sweep paging)"]))
        self.assertEqual(len(r["paging"]), 1)
        self.assertEqual(report.exit_code(r), 0)

    def test_offset_unit_bytes_is_a_finding(self) -> None:
        r = report.analyse(build_log(
            CLEAN,
            ["6B.3b FINDING: ReadIDList offset unit is not entries (entries=0/2 bytes=2/2) — apdu::sweep paging is wrong"],
            done="FINDINGS"))
        self.assertEqual(report.exit_code(r), 1)
        self.assertIn("6B.3b", report.render("x.log", r))

    def test_free_memory_error_is_a_finding(self) -> None:
        r = report.analyse(build_log(CLEAN, ["6B.4 free-memory[transient-deselect] ERR Transport"], done="FINDINGS"))
        self.assertTrue(any("free-memory" in f for f in r["findings"]))
        self.assertEqual(report.exit_code(r), 1)

    def test_plain_matrix_transport_error_is_a_finding(self) -> None:
        r = report.analyse(build_log(CLEAN, ["6B.6 plain GetRandom ERR Transport"], done="FINDINGS"))
        self.assertTrue(any("unverified" in f for f in r["findings"]))
        self.assertEqual(report.exit_code(r), 1)

    def test_no_marker_is_inconclusive(self) -> None:
        self.assertEqual(report.exit_code(report.analyse(build_log(CLEAN, done=""))), 2)

    def test_abort_is_inconclusive(self) -> None:
        self.assertEqual(report.exit_code(report.analyse(build_log(CLEAN, done="") + "=== SPROBE ABORT ===\n")), 2)


if __name__ == "__main__":
    unittest.main()
