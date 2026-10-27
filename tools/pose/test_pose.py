"""python3 -m unittest tools/pose/test_pose.py"""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pose  # noqa: E402

# Option bytes as EVT-3D21 reported them in the shipping profile (2026-10-27).
EVT_SHIP_OB = bytes.fromhex(
    "aa78ef937f0000087f00f90b7c00000cffff80ff807f807fffff80ffffff80ff"
    "ffff80ff807f807fffff80ffffff80ff00000000000000000000000000000000")


def ob_with(**words):
    """EVT_SHIP_OB with some 32-bit words replaced (by index)."""
    w = list(struct.unpack("<16I", EVT_SHIP_OB))
    for i, v in words.items():
        w[int(i[1:])] = v
    return struct.pack("<16I", *w)


class FakeDfu:
    """In-memory DfuSe device: flash must be erased before it is written, like
    the real one, and any address outside the alt's region is refused."""

    def __init__(self, xfer=1024):
        self.xfer = xfer
        self.mem = {0: (pose.FLASH_BASE, bytearray(b"\x00" * pose.FLASH_LEN)),
                    1: (pose.OB_BASE, bytearray(EVT_SHIP_OB)),
                    2: (pose.OTP_BASE, bytearray(b"\xff" * pose.OTP_LEN))}
        self.sram2 = bytearray(pose.CANARY_LEN)
        self.alt = 0
        self.ptr = 0
        self.state = pose.IDLE
        self.status = 0
        self.pending = None

    def set_alt(self, alt):
        self.alt = alt

    def _region(self, addr, n):
        if self.alt == 0 and pose.CANARY_ADDR <= addr and addr + n <= pose.CANARY_ADDR + pose.CANARY_LEN:
            return self.sram2, addr - pose.CANARY_ADDR, False
        base, buf = self.mem[self.alt]
        if not (base <= addr and addr + n <= base + len(buf)):
            return None
        return buf, addr - base, self.alt == 0

    def _fail(self, code):
        self.state, self.status = pose.ERROR, code

    def ctrl_out(self, req, value, data):
        if req == pose.ABORT:
            self.state = pose.IDLE
        elif req == pose.CLRSTATUS:
            self.state, self.status = pose.IDLE, 0
        elif req == pose.DNLOAD:
            self.pending = (value, bytes(data))
            self.state = pose.DNLOAD_SYNC

    def _execute(self, block, data):
        if block == 0:
            if data[0] == pose.CMD_SET_ADDRESS:
                self.ptr = int.from_bytes(data[1:5], "little")
                if self._region(self.ptr, 1) is None:
                    self._fail(0x0B)
            elif data == pose.erase_cmd():
                self.mem[0][1][:] = b"\xff" * pose.FLASH_LEN
            return
        addr = pose.block_address(self.ptr, block, self.xfer)
        region = self._region(addr, len(data))
        if region is None:
            return self._fail(0x08)
        buf, off, is_flash = region
        if is_flash and buf[off:off + len(data)] != b"\xff" * len(data):
            return self._fail(0x03)
        buf[off:off + len(data)] = data

    def ctrl_in(self, req, value, length):
        if req == pose.GETSTATUS:
            if self.pending is not None:
                block, data = self.pending
                self.pending = None
                self.state = pose.DNBUSY
                self._execute(block, data)
                if self.state != pose.ERROR:
                    return bytes([0, 0, 0, 0, pose.DNBUSY, 0])
            elif self.state == pose.DNBUSY:
                self.state = pose.DNLOAD_IDLE
            return bytes([self.status, 0, 0, 0, self.state, 0])
        if req == pose.UPLOAD:
            addr = pose.block_address(self.ptr, value, self.xfer)
            region = self._region(addr, length)
            if region is None:
                self._fail(0x08)
                return b""
            buf, off, _ = region
            self.state = pose.UPLOAD_IDLE
            return bytes(buf[off:off + length])
        raise AssertionError(req)

    def power_cycle(self):
        self.sram2[:] = b"\x5a" * pose.CANARY_LEN


class Parsing(unittest.TestCase):
    def test_layouts_from_evt(self):
        self.assertEqual(pose.parse_layout("@Internal Flash   /0x08000000/256*08Kg"),
                         ("Internal Flash", [(0x08000000, 256, 8192, "g")]))
        self.assertEqual(pose.parse_layout("@Option Bytes   /0x40022040/01*64 e"),
                         ("Option Bytes", [(0x40022040, 1, 64, "e")]))
        self.assertEqual(pose.parse_layout("@OTP Memory   /0x0BFA0000/01*512 e")[1],
                         [(0x0BFA0000, 1, 512, "e")])

    def test_multi_segment_layout(self):
        _, s = pose.parse_layout("@Flash /0x08000000/04*016Kg,01*064Kg")
        self.assertEqual(s, [(0x08000000, 4, 16384, "g"), (0x08010000, 1, 65536, "g")])

    def test_descriptors(self):
        dev = bytes([18, 1, 0, 2, 0, 0, 0, 64, 0x83, 4, 0x11, 0xDF, 0, 2, 1, 2, 3, 1])
        cfg = bytes([9, 2, 45, 0, 1, 1, 0, 0xC0, 50])
        intf = b"".join(bytes([9, 4, 0, alt, 0, 0xFE, 1, 2, 6 + alt]) for alt in range(3))
        func = bytes([9, 0x21, 11, 255, 0, 0, 4, 0x1A, 1])
        d = pose.parse_descriptors(dev + cfg + intf + func)
        self.assertEqual(d, {"serial_index": 3, "alts": {0: 6, 1: 7, 2: 8}, "xfer": 1024, "interface": 0})

    def test_status_and_commands(self):
        self.assertEqual(pose.parse_status(bytes([0, 0x19, 0, 0, 5, 0])), (0, 25, 5))
        self.assertEqual(pose.set_address_cmd(0x08000000), bytes([0x21, 0, 0, 0, 8]))
        self.assertEqual(pose.erase_cmd(), b"\x41")
        self.assertEqual(pose.erase_cmd(0x08002000), bytes([0x41, 0, 0x20, 0, 8]))
        self.assertEqual(pose.block_address(0x08000000, 2, 1024), 0x08000000)
        self.assertEqual(pose.block_address(0x08000000, 5, 1024), 0x08000C00)
        with self.assertRaises(ValueError):
            pose.block_address(0x08000000, 1, 1024)


class OptionBytes(unittest.TestCase):
    def test_evt_ship_profile_decodes(self):
        ob = pose.decode_ob(EVT_SHIP_OB)
        self.assertEqual((ob["RDP"], ob["TZEN"], ob["nSWBOOT0"], ob["nBOOT0"]), (0xAA, 1, 0, 0))
        self.assertEqual((ob["SECBOOTADD0"], ob["BOOT_LOCK"], ob["SRAM2_RST"]), (0x180000, 0, 1))
        self.assertEqual(ob["SECWM1"], {"pstrt": 0x7F, "pend": 0})
        self.assertEqual(pose.ship_profile_problems(ob), [])

    def test_profile_rejects_each_deviation(self):
        cases = {
            "RDP 1": ob_with(w0=0x93EF78BB),
            "boot from flash": ob_with(w0=0x9FEF78AA),
            "bank 1 secure": ob_with(w4=0xFF7F0000),
            "WRP on page 0": ob_with(w6=0xFF00FF00),
            "BOOT_LOCK": ob_with(w3=0x0C000001),
            "HDP": ob_with(w5=0x80000000 | 0xFF00FF00),
        }
        for name, blob in cases.items():
            with self.subTest(name):
                self.assertTrue(pose.ship_profile_problems(pose.decode_ob(blob)))


class Evaluate(unittest.TestCase):
    def setUp(self):
        self.r = bytes(range(256)) * (pose.FLASH_LEN // 256)
        self.ob = pose.decode_ob(EVT_SHIP_OB)
        self.otp = b"\xff" * 512

    def test_pass(self):
        res = pose.evaluate(self.r, self.r, self.ob, self.otp, self.otp, 12.0, 10, True, False)
        self.assertEqual(res["verdict"], "PASS")

    def test_one_page_differs(self):
        flash = bytearray(self.r)
        flash[77 * pose.PAGE + 5] ^= 1
        res = pose.evaluate(self.r, bytes(flash), self.ob, self.otp, self.otp)
        self.assertEqual((res["verdict"], res["mismatched_pages"]), ("FAIL", [77]))

    def test_short_readback(self):
        res = pose.evaluate(self.r, self.r[:-16], self.ob, self.otp, self.otp)
        self.assertEqual(res["verdict"], "FAIL")

    def test_otp_burned(self):
        otp = bytearray(self.otp)
        otp[200] = 0
        res = pose.evaluate(self.r, self.r, self.ob, bytes(otp), self.otp)
        self.assertEqual((res["verdict"], res["otp_differs_at"]), ("FAIL", [200]))

    def test_unplug_too_short_or_skipped(self):
        self.assertEqual(pose.evaluate(self.r, self.r, self.ob, self.otp, self.otp, 3.0, 10)["verdict"], "FAIL")
        self.assertEqual(pose.evaluate(self.r, self.r, self.ob, self.otp, self.otp,
                                       canary_retained=True)["verdict"], "FAIL")


class Unplug(unittest.TestCase):
    def test_bouncing_replug_counts_only_the_last_gap(self):
        # EVT-3D21 run 2 (kernel log): gone 19:12:19, back :23, gone :23.5, back :30
        gaps = pose.absences([(19.0, False), (23.0, True), (23.5, False), (30.0, True)])
        self.assertEqual(gaps, [(19.0, 23.0), (23.5, 30.0)])
        s = pose.unplug_summary(gaps)
        self.assertEqual((s["off_time_s"], s["first_gone_to_last_back_s"]), (6.5, 11.0))

    def test_still_gone(self):
        self.assertEqual(pose.absences([(1.0, False)]), [(1.0, None)])


class EndToEnd(unittest.TestCase):
    """The real Dfu client against the fake device."""

    def setUp(self):
        self.dev = FakeDfu()
        self.dfu = pose.Dfu(self.dev, 1024)
        self.ident = {"layouts": {0: "@Internal Flash   /0x08000000/256*08Kg",
                                  1: "@Option Bytes   /0x40022040/01*64 e",
                                  2: "@OTP Memory   /0x0BFA0000/01*512 e"}}
        self.r = bytes((i * 7 + i // 251) & 0xFF for i in range(pose.FLASH_LEN))

    def fill_and_read(self, tamper=None):
        self.dfu.mass_erase()
        self.dfu.write(pose.FLASH_BASE, self.r)
        canary = b"\xa5" * pose.CANARY_LEN
        self.dfu.write(pose.CANARY_ADDR, canary)
        self.dev.power_cycle()
        if tamper:
            tamper(self.dev)
        flash, ob, otp = pose.read_state(self.dfu, self.ident)
        sram2 = self.dfu.read(pose.CANARY_ADDR, pose.CANARY_LEN)
        return pose.evaluate(self.r, flash, pose.decode_ob(ob), otp, b"\xff" * 512,
                             canary_retained=sram2 == canary)

    def test_honest(self):
        self.assertEqual(self.fill_and_read()["verdict"], "PASS")

    def test_page_kept_by_malware(self):
        def keep(dev):
            dev.mem[0][1][3 * pose.PAGE:4 * pose.PAGE] = b"\xbb" * pose.PAGE
        res = self.fill_and_read(keep)
        self.assertEqual((res["verdict"], res["mismatched_pages"]), ("FAIL", [3]))

    def test_option_bytes_changed(self):
        def boot_flash(dev):
            dev.mem[1][1][:] = ob_with(w0=0x9FEF78AA)
        self.assertEqual(self.fill_and_read(boot_flash)["verdict"], "FAIL")

    def test_write_without_erase_is_refused(self):
        self.dfu.mass_erase()
        self.dfu.write(pose.FLASH_BASE, b"\x00" * 1024)
        with self.assertRaises(pose.DfuError):
            self.dfu.write(pose.FLASH_BASE, b"\x01" * 1024)

    def test_address_outside_alt_is_refused(self):
        with self.assertRaises(pose.DfuError):
            self.dfu.read(0x4003_6400, 16)

    def test_mismatched_pages_base(self):
        a, b = bytes(32), bytes(16) + b"\x01" * 16
        self.assertEqual(pose.mismatched_pages(a, b, 0x100000), [128])


if __name__ == "__main__":
    unittest.main()
