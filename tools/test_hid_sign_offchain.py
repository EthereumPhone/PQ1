#!/usr/bin/env python3
"""Pin the `CMD_SIGN_OFFCHAIN` EIP-712 payload layouts against `proto`.

WHY THIS EXISTS (#693). Off-chain kinds 2 (`EIP712_TYPED`) and 3
(`EIP712_TYPED_V3`) have never executed on pq1 silicon and have never been
checked by the deployed wallet. Kinds 0 and 1 were verified end-to-end on
2026-09-18; these two were not, and they take a different firmware path:
EIP-712 parse, ERC-7730 descriptor lookup and binding against the pinned
roots, nested/string display witnesses (V3), and `replay_safe_hash` with no
EIP-191.

Until a device run happens, the wire construction in `hid_sign_offchain.py` is
checked by nothing at all. These tests are not a substitute for that run —
they cannot tell you the firmware accepts the bytes — but they do stop the
client drifting from the documented layout while the silicon gap stays open,
and they make the eventual failure interpretable: if the device refuses, the
refusal is about the device, not about a malformed client buffer.

The caps and layout are read out of `proto/src/lib.rs` rather than restated,
so a bound changed on the firmware side turns these red.

Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tools/test_hid_sign_offchain.py
"""

from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True  # a stale .pyc once faked a hardware FAIL

TOOL = Path(__file__).with_name("hid_sign_offchain.py")
# The tool imports its siblings (`hid_sign`, `hid_smoke`) by bare name, so
# tools/ has to be importable however this file is invoked — `python3 -m
# unittest tools/...` runs from the repo root, not from tools/.
sys.path.insert(0, str(TOOL.parent))
SPEC = importlib.util.spec_from_file_location("hid_sign_offchain", TOOL)
assert SPEC is not None and SPEC.loader is not None
tool = importlib.util.module_from_spec(SPEC)
sys.modules["hid_sign_offchain"] = tool
SPEC.loader.exec_module(tool)

PROTO = Path(__file__).resolve().parents[1] / "proto" / "src" / "lib.rs"

DS = bytes(range(32))
PTH = bytes(range(32, 64))
TRAILER = b"\xab" * 40


def u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


class ProtoBoundsAreMirrored(unittest.TestCase):
    """The client's caps must be the device's caps."""

    def proto_const(self, name: str) -> int:
        m = re.search(rf"^pub const {name}: usize = ([0-9_]+);", PROTO.read_text(), re.M)
        self.assertIsNotNone(m, f"{name} not found in {PROTO} — the constant moved")
        return int(m.group(1).replace("_", ""))

    def test_encoded_data_cap_matches_proto(self) -> None:
        self.assertEqual(
            tool.MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN,
            self.proto_const("MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN"),
        )

    def test_nested_blob_cap_matches_proto(self) -> None:
        self.assertEqual(
            tool.MAX_OFFCHAIN_EIP712_NESTED_LEN,
            self.proto_const("MAX_OFFCHAIN_EIP712_NESTED_LEN"),
        )

    def test_kind_numbers_match_proto(self) -> None:
        src = PROTO.read_text()
        for name, want in [
            ("OFFCHAIN_KIND_RAW32", tool.OFFCHAIN_KIND_RAW32),
            ("OFFCHAIN_KIND_PERSONAL_SIGN", tool.OFFCHAIN_KIND_PERSONAL_SIGN),
            ("OFFCHAIN_KIND_EIP712_TYPED", tool.OFFCHAIN_KIND_EIP712_TYPED),
            ("OFFCHAIN_KIND_EIP712_TYPED_V3", tool.OFFCHAIN_KIND_EIP712_TYPED_V3),
        ]:
            m = re.search(rf"^pub const {name}: u8 = ([0-9]+);", src, re.M)
            self.assertIsNotNone(m, f"{name} not found in proto")
            self.assertEqual(int(m.group(1)), want, f"{name} disagrees with proto")


class Kind2Layout(unittest.TestCase):
    def test_exact_byte_layout(self) -> None:
        ed = b"\x11" * 96
        got = tool.build_eip712_payload(DS, PTH, ed, TRAILER)
        want = u16(1) + DS + PTH + u16(len(ed)) + ed + u16(len(TRAILER)) + TRAILER
        self.assertEqual(got, want)
        # 2 + 32 + 32 + 2 + 96 + 2 + 40
        self.assertEqual(len(got), 206)

    def test_no_nested_section_is_emitted(self) -> None:
        # The V3 witness section must be ABSENT, not empty: an extra `0x0000`
        # would shift the trailer and the device would read the wrong bytes.
        got = tool.build_eip712_payload(DS, PTH, b"", TRAILER)
        self.assertEqual(got[66:68], u16(0), "encoded_data_len")
        self.assertEqual(got[68:70], u16(len(TRAILER)), "trailer must follow immediately")


class Kind3Layout(unittest.TestCase):
    def test_exact_byte_layout(self) -> None:
        ed, nested = b"\x11" * 96, b"\x22" * 64
        got = tool.build_eip712_payload(DS, PTH, ed, TRAILER, nested)
        want = (
            u16(1) + DS + PTH
            + u16(len(ed)) + ed
            + u16(len(nested)) + nested
            + u16(len(TRAILER)) + TRAILER
        )
        self.assertEqual(got, want)

    def test_empty_witness_section_is_still_v3(self) -> None:
        # A descriptor that selects no witnesses is a MEANINGFUL V3 request.
        # `b""` must produce a present-but-empty section, distinguishable from
        # kind 2's absent one — otherwise the two kinds collide on the wire.
        v3 = tool.build_eip712_payload(DS, PTH, b"", TRAILER, b"")
        v2 = tool.build_eip712_payload(DS, PTH, b"", TRAILER)
        self.assertNotEqual(v3, v2, "empty V3 witness must not encode as kind 2")
        self.assertEqual(len(v3), len(v2) + 2, "exactly one extra length prefix")
        self.assertEqual(v3[68:70], u16(0), "witness section present and empty")

    def test_v3_is_a_strict_prefix_extension_of_v2(self) -> None:
        # Everything up to encoded_data is identical between the kinds; only
        # the inserted section differs. If that ever stops holding, one of the
        # two layouts has drifted.
        ed = b"\x33" * 32
        v2 = tool.build_eip712_payload(DS, PTH, ed, TRAILER)
        v3 = tool.build_eip712_payload(DS, PTH, ed, TRAILER, b"\x44" * 8)
        head = 2 + 32 + 32 + 2 + len(ed)
        self.assertEqual(v2[:head], v3[:head])


class RefusesMalformedInput(unittest.TestCase):
    """Client-side refusals: a bad buffer should fail here, not as a gateway
    refusal that reads like a firmware bug during a silicon bring-up."""

    def test_wrong_domain_separator_length(self) -> None:
        with self.assertRaisesRegex(ValueError, "domain_separator must be 32"):
            tool.build_eip712_payload(DS[:31], PTH, b"", TRAILER)

    def test_wrong_primary_type_hash_length(self) -> None:
        with self.assertRaisesRegex(ValueError, "primary_type_hash must be 32"):
            tool.build_eip712_payload(DS, PTH + b"\x00", b"", TRAILER)

    def test_encoded_data_over_cap(self) -> None:
        over = b"\x00" * (tool.MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN + 1)
        with self.assertRaisesRegex(ValueError, "device cap"):
            tool.build_eip712_payload(DS, PTH, over, TRAILER)

    def test_nested_blob_over_cap(self) -> None:
        over = b"\x00" * (tool.MAX_OFFCHAIN_EIP712_NESTED_LEN + 1)
        with self.assertRaisesRegex(ValueError, "device cap"):
            tool.build_eip712_payload(DS, PTH, b"", TRAILER, over)

    def test_missing_trailer_is_refused(self) -> None:
        # The ERC-7730 trailer is what binds typed data to an authenticated
        # descriptor. Without it there is nothing to render and the device
        # refuses — catching it here says so in one line.
        with self.assertRaisesRegex(ValueError, "trailer is required"):
            tool.build_eip712_payload(DS, PTH, b"", b"")

    def test_at_cap_is_accepted(self) -> None:
        # Boundary the other way: exactly at the cap must NOT be refused, or
        # the client would reject payloads the device accepts.
        ed = b"\x00" * tool.MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN
        nested = b"\x00" * tool.MAX_OFFCHAIN_EIP712_NESTED_LEN
        got = tool.build_eip712_payload(DS, PTH, ed, TRAILER, nested)
        self.assertEqual(len(got), 2 + 32 + 32 + 2 + len(ed) + 2 + len(nested) + 2 + len(TRAILER))


if __name__ == "__main__":
    unittest.main()
