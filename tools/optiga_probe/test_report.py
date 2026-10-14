#!/usr/bin/env python3
"""Unit tests for the OPTIGA probe report (no hardware).

    python3 -m unittest discover -s tools/optiga_probe -v
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import expected as exp  # noqa: E402
import report  # noqa: E402
from optiga_meta import Ctx, eval_ac, parse_ac, parse_meta  # noqa: E402


def line(s: str) -> str:
    return f"[OPROBE] {s}"


FACTORY = exp.load_factory()


def meta(*tlvs: str) -> str:
    """Wrap tag-length-value hex strings in the 0x20 metadata root."""
    inner = bytes.fromhex("".join(tlvs))
    return (bytes([0x20, len(inner)]) + inner).hex()

# A chip as the pre-#116 dev firmware leaves it: paired, provisioned, no hw counter.
PROVISIONED = {
    0xE140: FACTORY[0xE140],
    0xF1D0: meta("c00101", "c4018c", "c50120", "d00100", "d101ff", "d30100", "e80131"),
    0xF1D1: meta("c00101", "c4018c", "c50140", "d00723f1d0fe20e140", "d10323f1d0", "d301ff"),
    0xE120: FACTORY[0xE120],
    0xE0E8: FACTORY[0xE0E8],
    0xE0C0: FACTORY[0xE0C0],
}


def build_log(meta: dict[int, str], extra: list[str], done: bool = True) -> str:
    out = [line("BEGIN mode=readonly ver=1 board=pq1 sweep=0"), line("UID hex=" + "cd" * 27)]
    for oid, hx in meta.items():
        out.append(line(f"META phase=R3 oid={oid:04X} name=X hex={hx}"))
    for oid, hx in meta.items():
        out.append(line(f"META phase=R9 oid={oid:04X} name=X hex={hx}"))
    out += [line(e) for e in extra]
    if done:
        out.append("=== OPROBE DONE ===")
    return "\n".join(out) + "\n"


class AcTests(unittest.TestCase):
    def test_parse_and_text(self):
        ac = parse_ac(bytes.fromhex("23f1d0fd20e140"))
        self.assertIsNone(ac.error)
        self.assertEqual(ac.text(), "Auto(F1D0) && Conf(E140)")
        self.assertEqual(parse_ac(bytes.fromhex("e1fc07")).text(), "LcsO<operational")

    def test_eval_precedence(self):
        # Auto(F1D0) || Conf(E140): plaintext without auth -> denied.
        ac = parse_ac(bytes.fromhex("23f1d0fe20e140"))
        self.assertFalse(eval_ac(ac, Ctx()))
        self.assertTrue(eval_ac(ac, Ctx(shielded=True)))
        # LcsO<op || Conf(E140) at creation -> allowed.
        ac = parse_ac(bytes.fromhex("e1fc07fe20e140"))
        self.assertTrue(eval_ac(ac, Ctx(lcso=0x01)))
        self.assertFalse(eval_ac(ac, Ctx(lcso=0x07)))
        # Auto && Conf: shield alone is not enough.
        ac = parse_ac(bytes.fromhex("23f1d0fd20e140"))
        self.assertFalse(eval_ac(ac, Ctx(shielded=True)))
        self.assertTrue(eval_ac(ac, Ctx(shielded=True, authorized=frozenset({0xF1D0}))))

    def test_bad_ac(self):
        self.assertIsNotNone(parse_ac(bytes.fromhex("23f1")).error)
        self.assertIsNotNone(parse_ac(bytes.fromhex("00fd")).error)
        self.assertIsNone(eval_ac(parse_ac(bytes.fromhex("40e120")), Ctx()))

    def test_meta_parse(self):
        m = parse_meta(bytes.fromhex(FACTORY[0xE140]))
        self.assertIsNone(m.error)
        self.assertEqual(m.lcso, 0x01)
        self.assertEqual(m.data_type, 0x22)
        self.assertIn("Change=[LcsO<operational || Conf(E140)]", m.describe())
        self.assertIsNotNone(parse_meta(bytes.fromhex("2005c001")).error)


class ReportTests(unittest.TestCase):
    def analyse(self, log: str):
        return report.analyse(report.parse_log(log))

    def rules(self, findings):
        return {f.rule for f in findings}

    def test_provisioned_pre116_chip(self):
        extra = [
            "READ phase=R4 oid=E140 name=PBS ch=plain class=secret res=ok len=64 fp=00112233",
            "READ phase=R4 oid=F1D1 name=X ch=plain class=secret res=deny sta=ff lec=07",
            "READ phase=R4 oid=F1D0 name=X ch=plain class=secret res=deny sta=ff lec=07",
            "PBS e140=read match=1 e140_fp=aa build_fp=aa build_prefix=8ca52e4bc284d822",
            "SEC phase=R2 val=0",
        ]
        F, s = self.analyse(build_log(PROVISIONED, extra))
        r = self.rules(F)
        self.assertIn("PBS_READABLE_PLAIN", r)
        self.assertIn("ISSUE116_WEAK_READ", r)
        self.assertIn("S1_AUTHREF_NOT_LOCKED", r)
        self.assertIn("S1_AUTHREF_CHANGE_ALW", r)
        self.assertIn("S3_NO_SILICON_LOCKOUT", r)
        self.assertIn("S2_TA_POOL_OPEN", r)
        self.assertIn("WALLET_OBJECT_WRITABLE", r)  # F1D0 Change=ALW
        self.assertNotIn("AC_NOT_ENFORCED", r)
        states = {o["oid"]: o["state"] for o in s["objects"]}
        self.assertIn("firmware: authref dev", states["F1D0"])
        self.assertIn("pre-#116", states["F1D1"])
        self.assertIn("factory", states["E140"])

    def test_ac_bypass_is_critical(self):
        extra = ["READ phase=R4 oid=F1D1 name=X ch=plain class=secret res=ok len=32 fp=dead"]
        F, _ = self.analyse(build_log(PROVISIONED, extra))
        crit = {f.rule for f in F if f.sev == "CRITICAL"}
        self.assertIn("AC_NOT_ENFORCED", crit)
        self.assertIn("SECRET_READABLE_PLAIN", crit)

    def test_firmware_findings_and_incomplete(self):
        log = build_log(PROVISIONED, ["FINDING id=META_CHANGED msg=F1D0 metadata differs"], done=False)
        F, _ = self.analyse(log)
        r = {(f.sev, f.rule) for f in F}
        self.assertIn(("CRITICAL", "FW_META_CHANGED"), r)
        self.assertIn(("HIGH", "INCOMPLETE"), r)

    def test_ccm_and_sweep(self):
        log = build_log(PROVISIONED, ["SWEEP oid=1234 meta=2003c00101"]) + (
            "[OPTIGA/shield] slave_seq=0x00000005\n[OPTIGA/shield] master_seq=0x00000002\n"
        )
        F, _ = self.analyse(log)
        r = self.rules(F)
        self.assertIn("UNDOCUMENTED_OID", r)
        self.assertIn("CCM_SEQ_OVERLAP", r)

    def test_main_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.log"
            p.write_text(build_log(PROVISIONED, []))
            self.assertEqual(report.main([str(p), "--out", d]), 1)
            p.write_text(build_log(PROVISIONED, [], done=False))
            self.assertEqual(report.main([str(p), "--out", d]), 2)
            clean = {0xE0C0: FACTORY[0xE0C0]}
            p.write_text(build_log(clean, []))
            self.assertEqual(report.main([str(p), "--out", d]), 0)


if __name__ == "__main__":
    unittest.main()
