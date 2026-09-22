#!/usr/bin/env python3
"""Exercise CMD_SIGN_OFFCHAIN (INS 0x62) over USB HID on a live pq1 board.

EIP-1271 / ERC-6492 off-chain signatures. The FIRMWARE, not this client,
applies the wallet's Solady PersonalSign replay-safe nesting to the hash; this
client only sends the dapp-level input:
  * --kind raw32:    32 opaque bytes H (what a dapp passes to isValidSignature)
  * --kind personal: a UTF-8 message; the firmware applies EIP-191, then nests

Two response layouts, chosen by --deployed / --counterfactual:
  * deployed        -> [count u64 BE][C10 sig 4008]        = 4016 B
  * counterfactual  -> [count u64 BE][ERC-6492 blob 8608]  = 8616 B (slot 0 only)

Writes the raw response and a JSON record (<out>.json) of the request and the
parsed response, for tools/fork_verify_offchain.py.

Wire (docs/companion/usb-protocol-v2.md §0x62, proto SIGN_OFFCHAIN_INPUT_*):
  header 17 B = account(1) | chain(8 BE) | slot(4 BE) | kind(1) | payload_len(2 BE) | flags(1)

Usage: ./hid_sign_offchain.py --chain 8453 (--deployed|--counterfactual)
                              (--raw32 HEX | --personal TEXT) [--out FILE]

For the typed kinds (2 / 3) the device also needs an authenticated ERC-7730
trailer proving against the firmware-pinned `ERC7730_DESCRIPTORS_ROOT`. Emit
one first, then pass `-` as the fixture and hand over the three pieces:

  python3 tools/companion-stub/erc7730_trailer.py \
      --db tools/companion-stub/erc7730_db.bin \
      --known-calls-bloom secure/data/erc7730-known-calls.bloom \
      --unverified-status-for-test tools/companion-stub/erc7730_status.bin \
      --chain 8453 --contract 0x000000000022d473030f116ddee9f6b43ac78ba3 \
      --context eip712 \
      --domain-separator 0x3b6f35e4... --primary-type-hash 0xaf1b0d30... \
      --out /tmp/permit2_base.trailer.bin

  ./hid_sign_offchain.py --chain 8453 --deployed --eip712 - \
      --trailer /tmp/permit2_base.trailer.bin \
      --domain-separator 0x3b6f35e4... --primary-type-hash 0xaf1b0d30...

(`--eip712-v3 -` for kind 3.) `--list` on the trailer tool shows every
descriptor; Permit2 is entry [241] on Base. The packed `--eip712 FIXTURE`
form — `domain_separator(32) || primary_type_hash(32) || trailer` in one
file — still works.

**THE CATALOGUE MUST MATCH THE IMAGE.** `secure/src/db_roots.rs` pins TWO
descriptor roots: production (`cfg(not(feature = "e2e-test"))`) and a separate
e2e one (`cfg(feature = "e2e-test")`). A trailer built from the production
catalogue is refused by an `e2e-test` image with a bare `SW=0x6f00` and no
diagnostic — the Merkle proof simply does not reach the pinned root. For an
`e2e-test` image use the `_e2e` artefacts throughout:

    --db tools/companion-stub/erc7730_db_e2e.bin
    --known-calls-bloom secure/data/erc7730-known-calls-e2e.bloom
    --unverified-status-for-test tools/companion-stub/erc7730_status_e2e.bin

That catalogue holds ONE EIP-712 descriptor: chain 11155111, contract
`0x…7730`, domain separator `0x65a0dc9a…`, type hash `0xe4832905…`, and this
tool's DEFAULT `--encoded-data` is its body. Also note most registry EIP-712
types are NESTED (all three Permit2 types are), so they cannot render from
`encoded_data` alone and need kind 3 with a real witness record.
"""
from __future__ import annotations

import argparse
import json
import sys

from hid_sign import (
    INS_GET_WALLET_ADDRESS,
    drain_response,
    send_chained,
    u16,
    u32,
    u64,
)
from hid_smoke import SW_OK, HidRaw, find_hidraw, send

INS_V2_SIGN_OFFCHAIN = 0x62
OFFCHAIN_KIND_RAW32 = 0
OFFCHAIN_KIND_PERSONAL_SIGN = 1
OFFCHAIN_KIND_EIP712_TYPED = 2
OFFCHAIN_KIND_EIP712_TYPED_V3 = 3
OFFCHAIN_FLAG_ACCOUNT_DEPLOYED = 0x01

# proto/src/lib.rs bounds. The device refuses a payload past these, so building
# one is a client bug worth catching here rather than as a gateway refusal.
MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN = 512
MAX_OFFCHAIN_EIP712_NESTED_LEN = 2048
C10_SIG_LEN = 4008
EIP6492_BLOB_LEN = 8608
EIP6492_MAGIC = bytes.fromhex("6492649264926492649264926492649264926492649264926492649264926492")


def parse_hash32(text: str, label: str) -> bytes:
    """Decode a 32-byte hex value, 0x-prefixed or not."""
    raw = bytes.fromhex(text.removeprefix("0x"))
    if len(raw) != 32:
        raise ValueError(f"{label} must be 32 bytes, got {len(raw)}")
    return raw


def build_eip712_payload(
    domain_separator: bytes,
    primary_type_hash: bytes,
    encoded_data: bytes,
    trailer: bytes,
    nested_blob: bytes | None = None,
) -> bytes:
    """Build a kind-2 or kind-3 `CMD_SIGN_OFFCHAIN` payload.

    Layouts, from `proto/src/lib.rs::MAX_OFFCHAIN_EIP712_TYPED{,_V3}_LEN`:

        kind 2  domainSep_present(2) | domainSeparator(32) | primaryTypeHash(32)
                | encoded_data_len(2) | encoded_data
                | trailer_len(2) | trailer

        kind 3  ... | encoded_data
                | nested_blob_len(2) | nested_blob          <- V3 only
                | trailer_len(2) | trailer

    `nested_blob is None` selects kind 2; any bytes value (including `b""`)
    selects kind 3, because an EMPTY witness section is a meaningful V3 request
    and must stay distinguishable from "no section at all".

    Pure so `tools/test_hid_sign_offchain.py` can pin the layout without a
    device — kinds 2 and 3 have never run on silicon (#693), so the wire
    construction is currently unverified by anything else.
    """
    if len(domain_separator) != 32:
        raise ValueError(f"domain_separator must be 32 B, got {len(domain_separator)}")
    if len(primary_type_hash) != 32:
        raise ValueError(f"primary_type_hash must be 32 B, got {len(primary_type_hash)}")
    if len(encoded_data) > MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN:
        raise ValueError(
            f"encoded_data is {len(encoded_data)} B, device cap is "
            f"{MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN}"
        )
    if not trailer:
        # The ERC-7730 trailer is what binds the typed data to an authenticated
        # descriptor. Without it the device has nothing to render and refuses.
        raise ValueError("an ERC-7730 trailer is required for kinds 2 and 3")
    out = u16(1) + domain_separator + primary_type_hash
    out += u16(len(encoded_data)) + encoded_data
    if nested_blob is not None:
        if len(nested_blob) > MAX_OFFCHAIN_EIP712_NESTED_LEN:
            raise ValueError(
                f"nested_blob is {len(nested_blob)} B, device cap is "
                f"{MAX_OFFCHAIN_EIP712_NESTED_LEN}"
            )
        out += u16(len(nested_blob)) + nested_blob
    out += u16(len(trailer)) + trailer
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", type=int, required=True)
    ap.add_argument("--slot", type=int, default=0)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--deployed", action="store_true")
    mode.add_argument("--counterfactual", action="store_true")
    kind = ap.add_mutually_exclusive_group(required=True)
    kind.add_argument("--raw32", help="32-byte hex hash H")
    kind.add_argument("--personal", help="UTF-8 message")
    kind.add_argument("--eip712", metavar="FIXTURE",
                      help="EIP-712 typed data (kind 2). FIXTURE is "
                           "[domain_separator(32) | primary_type_hash(32) | ERC-7730 trailer], "
                           "the layout build.rs emits from the catalogue")
    ap.add_argument("--trailer", default=None, metavar="FILE",
                    help="ERC-7730 trailer emitted by "
                         "tools/companion-stub/erc7730_trailer.py. Use with "
                         "--domain-separator/--primary-type-hash instead of "
                         "packing a --eip712 FIXTURE by hand.")
    ap.add_argument("--domain-separator", default=None, metavar="HEX32",
                    help="EIP-712 domain separator, for use with --trailer")
    ap.add_argument("--primary-type-hash", default=None, metavar="HEX32",
                    help="EIP-712 primary type hash, for use with --trailer")
    kind.add_argument("--eip712-v3", default=None, metavar="FIXTURE",
                      help="same fixture layout as --eip712, sent as kind 3 "
                           "(EIP712_TYPED_V3): inserts the descriptor-selected "
                           "display-witness section before the trailer")
    ap.add_argument("--encoded-data", default=None,
                    help="hex EIP-712 encodeData body for --eip712 (no type hash); default is the "
                         "e2e Delegation body abi.encode(0x42*20, 7, 2000000000)")
    ap.add_argument("--nested-blob", default=None,
                    help="hex display-witness stream for --eip712-v3 (default: "
                         "empty, i.e. a descriptor that selects no witnesses)")
    ap.add_argument("--out", default="offchain_response.bin")
    args = ap.parse_args()

    domain_separator = primary_type_hash = encoded_data = None
    if args.raw32 is not None:
        k = OFFCHAIN_KIND_RAW32
        payload = bytes.fromhex(args.raw32.removeprefix("0x"))
        if len(payload) != 32:
            print(f"!! --raw32 must be exactly 32 bytes, got {len(payload)}")
            return 2
    elif args.personal is not None:
        k = OFFCHAIN_KIND_PERSONAL_SIGN
        payload = args.personal.encode()
    else:
        # usb-protocol-v2.md §0x62 kind 2:
        #   [u16 BE = 1][domain_separator 32][primary_type_hash 32]
        #   [u16 BE encoded_data_len][encoded_data][u16 BE trailer_len][trailer]
        is_v3 = args.eip712_v3 is not None
        k = OFFCHAIN_KIND_EIP712_TYPED_V3 if is_v3 else OFFCHAIN_KIND_EIP712_TYPED
        src = args.eip712_v3 if is_v3 else args.eip712
        if src == "-":
            # Unpacked form: the three pieces the trailer tool already took as
            # arguments, so nobody has to concatenate 32+32+N bytes by hand.
            missing = [n for n, v in (("--trailer", args.trailer),
                                      ("--domain-separator", args.domain_separator),
                                      ("--primary-type-hash", args.primary_type_hash))
                       if v is None]
            if missing:
                print(f"!! `-` needs {', '.join(missing)}")
                return 2
            try:
                domain_separator = parse_hash32(args.domain_separator, "--domain-separator")
                primary_type_hash = parse_hash32(args.primary_type_hash, "--primary-type-hash")
            except ValueError as e:
                print(f"!! {e}")
                return 2
            trailer = open(args.trailer, "rb").read()
        else:
            fixture = open(src, "rb").read()
            if len(fixture) <= 64:
                print(f"!! fixture must carry a trailer, got {len(fixture)} B")
                return 2
            domain_separator, primary_type_hash, trailer = (
                fixture[:32], fixture[32:64], fixture[64:]
            )
        if args.encoded_data:
            encoded_data = bytes.fromhex(args.encoded_data.removeprefix("0x"))
        else:
            encoded_data = (bytes(12) + bytes([0x42] * 20)
                            + (7).to_bytes(32, "big")
                            + (2_000_000_000).to_bytes(32, "big"))
        nested = None
        if is_v3:
            nested = bytes.fromhex((args.nested_blob or "").removeprefix("0x"))
        try:
            payload = build_eip712_payload(
                domain_separator, primary_type_hash, encoded_data, trailer, nested
            )
        except ValueError as e:
            print(f"!! {e}")
            return 2
    flags = OFFCHAIN_FLAG_ACCOUNT_DEPLOYED if args.deployed else 0
    want_len = 8 + (C10_SIG_LEN if args.deployed else EIP6492_BLOB_LEN)

    req = (bytes([0]) + u64(args.chain) + u32(args.slot) + bytes([k])
           + u16(len(payload)) + bytes([flags]) + payload)
    assert len(req) == 17 + len(payload)

    node = find_hidraw()
    if node is None:
        print("!! no PQSigner hidraw node — board not enumerated")
        return 2
    hid = HidRaw(node, 12.0)
    try:
        sw, data = send(hid, INS_GET_WALLET_ADDRESS, u32(0))
        sw, data = drain_response(hid, sw, data)
        if sw != SW_OK or len(data) != 20:
            print(f"!! GET_WALLET_ADDRESS failed (SW=0x{sw:04x}, {len(data)} B)")
            return 1
        sender = data
        kind_name = {0: "raw32", 1: "personal", 2: "eip712", 3: "eip712-v3"}[k]
        print(f"==> wallet 0x{sender.hex()}  chain {args.chain}  slot {args.slot}  "
              f"kind {kind_name}  payload {len(payload)} B  "
              f"{'deployed' if args.deployed else 'counterfactual (ERC-6492)'}")
        hid.timeout_s = 45.0
        sw, resp = send_chained(hid, INS_V2_SIGN_OFFCHAIN, req)
    finally:
        hid.close()

    print(f"    SW=0x{sw:04x}  response={len(resp)} B (want {want_len})")
    with open(args.out, "wb") as fh:
        fh.write(resp)
    if sw != SW_OK or len(resp) != want_len:
        print("=== FAIL === device refused or returned an unexpected length")
        return 1

    count = int.from_bytes(resp[0:8], "big")
    body = resp[8:]
    rec = {
        "chain_id": args.chain,
        "slot": args.slot,
        "kind": kind_name,
        "payload": "0x" + payload.hex(),
        "message": args.personal,
        "accountDeployed": bool(args.deployed),
        "sender": "0x" + sender.hex(),
        "newLocalOffchainCount": count,
    }
    if k in (OFFCHAIN_KIND_EIP712_TYPED, OFFCHAIN_KIND_EIP712_TYPED_V3):
        # The verifier recomputes the dapp-level hash from these:
        # H = keccak256(0x1901 || domain_separator || keccak256(primary_type_hash || encoded_data))
        rec["domainSeparator"] = "0x" + domain_separator.hex()
        rec["primaryTypeHash"] = "0x" + primary_type_hash.hex()
        rec["encodedData"] = "0x" + encoded_data.hex()
    if args.deployed:
        rec["c10Sig"] = "0x" + body.hex()
        nonzero = sum(1 for b in body if b)
        print(f"    local_offchain_count={count}  sig nonzero {nonzero}/{C10_SIG_LEN}")
    else:
        magic_ok = body[-32:] == EIP6492_MAGIC
        print(f"    local_offchain_count={count}  ERC-6492 magic suffix {'OK' if magic_ok else 'MISSING'}")
        if not magic_ok:
            print("=== FAIL === counterfactual blob lacks the ERC-6492 magic suffix")
            return 1
        rec["erc6492Blob"] = "0x" + body.hex()
    with open(args.out + ".json", "w") as fh:
        json.dump(rec, fh, indent=1)
    print(f"    record -> {args.out}.json")
    print("=== PASS === structurally valid off-chain response (verify on a fork)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
