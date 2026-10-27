"""Unit tests for the pure parts of pose.py: python3 -m unittest tools/pose/test_pose.py"""

import random
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pose  # noqa: E402


class ReadChunks(unittest.TestCase):
    def test_covers_range_exactly_once(self):
        chunks = pose.read_chunks(0, pose.FLASH_LEN, random.Random(1))
        covered = bytearray(pose.FLASH_LEN)
        for off, count in chunks:
            n = min(count * pose.READ_DATA, pose.FLASH_LEN - off)
            for i in range(off, off + n):
                covered[i] += 1
        self.assertTrue(all(c == 1 for c in covered))

    def test_counts_bounded_and_order_shuffled(self):
        chunks = pose.read_chunks(0, pose.FLASH_LEN, random.Random(2))
        self.assertTrue(all(0 < c <= pose.MAX_REPORTS for _, c in chunks))
        self.assertNotEqual([o for o, _ in chunks], sorted(o for o, _ in chunks))


class Mismatch(unittest.TestCase):
    def test_reports_page(self):
        exp = bytes(4 * pose.PAGE)
        act = bytearray(exp)
        act[pose.PAGE * 2 + 100] ^= 1
        self.assertEqual(pose.mismatched_pages(exp, bytes(act), 0), [2])
        self.assertEqual(pose.mismatched_pages(exp, bytes(act), 3 * pose.PAGE), [5])

    def test_clean(self):
        self.assertEqual(pose.mismatched_pages(b"x" * 64, b"x" * 64, 0), [])


class Pad(unittest.TestCase):
    def test_pad(self):
        out = pose.pad_image(b"abc", b"0123456789", 8)
        self.assertEqual(out, b"abc01234")

    def test_too_big(self):
        with self.assertRaises(ValueError):
            pose.pad_image(b"x" * 9, b"", 8)


class Info(unittest.TestCase):
    def test_decode(self):
        blob = bytearray(640)
        words = [0] * 21
        words[0] = 0x80F0_00AA  # TZEN=1, RDP=0xAA
        words[3] = 0x0C00_007C
        words[16] = 2048
        struct.pack_into("<21I", blob, 0, *words)
        blob[128:128 + 512] = b"\x00" * 176 + b"\xff" * 336
        info = pose.decode_info(bytes(blob))
        self.assertEqual(info["RDP"], 0xAA)
        self.assertEqual(info["TZEN"], 1)
        self.assertEqual(info["FLASHSIZE_KB"], 2048)
        self.assertTrue(info["OTP_FREE_BLANK"])


if __name__ == "__main__":
    unittest.main()
