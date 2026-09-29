#!/usr/bin/env python3
"""Device-side refusal controls for EIP-712 typed signing (kind 2) on a live board.

The positive case is proven (fork_verify_offchain.py). Clear signing is equally
about what the device REFUSES: a descriptor that does not bind to this request
must not produce a signature. Each case below changes ONE thing from the
accepted request, so a refusal can only be explained by that change.

SW 0x9000 = signed. Anything else = refused (every refusal surfaces as the
generic 0x6f00 on the wire, so this proves THAT the device refused, not which
internal check fired).

Needs an `e2e-test` image (auto-confirm) whose pinned ERC-7730 root matches
tools/companion-stub/erc7730_db_e2e.bin, and slot 0 registered for the chain.

Usage: ./typed_offchain_controls.py
"""
import os, struct, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hid_sign import drain_response, send_chained, u16, u32, u64
from hid_smoke import SW_OK, HidRaw, find_hidraw, send

INS_SIGN_OFFCHAIN = 0x62
INS_GET_WALLET_ADDRESS = 0x60
CHAIN = 11155111
BLOB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "companion-stub", "erc7730_db_e2e.bin")


def catalogue_entry(chain, contract_hex):
    blob = open(BLOB, "rb").read()
    entry_cnt, ir_pool_off = struct.unpack_from("<II", blob, 12)
    proof_depth, proofs_off = struct.unpack_from("<II", blob, 24)
    c = bytes.fromhex(contract_hex)
    for i in range(entry_cnt):
        b = 32 + i * 72
        if struct.unpack_from("<Q", blob, b)[0] != chain or blob[b + 8:b + 28] != c:
            continue
        pth = blob[b + 28:b + 60]
        ir_off, ir_len = struct.unpack_from("<II", blob, b + 64)
        ir = blob[ir_pool_off + ir_off: ir_pool_off + ir_off + ir_len]
        stride = proof_depth * 32
        proof = blob[proofs_off + i * stride: proofs_off + (i + 1) * stride]
        trailer = (len(ir).to_bytes(2, "big") + ir + i.to_bytes(4, "big")
                   + proof_depth.to_bytes(4, "big") + proof)
        return ir[62:94], pth, trailer
    raise SystemExit(f"no catalogue entry for chain={chain} {contract_hex}")


TYPED_DS, TYPED_PTH, TYPED_TRAILER = catalogue_entry(CHAIN, "0000000000000000000000000000000000007730")
# A cryptographically VALID bundle for a different descriptor (WETH Sepolia,
# context kind 1 = contract/calldata, not EIP-712).
WETH_DS, WETH_PTH, WETH_TRAILER = catalogue_entry(CHAIN, "fff9976782d46cc05630d1f6ebab18b2324d6b14")
ENCODED = bytes(12) + bytes([0x42] * 20) + (7).to_bytes(32, "big") + (2_000_000_000).to_bytes(32, "big")


def payload(ds=TYPED_DS, pth=TYPED_PTH, enc=ENCODED, trailer=TYPED_TRAILER, ds_present=1):
    return (u16(ds_present) + ds + pth + u16(len(enc)) + enc + u16(len(trailer)) + trailer)


def request(chain=CHAIN, slot=0, deployed=True, pl=None):
    pl = payload() if pl is None else pl
    return (bytes([0]) + u64(chain) + u32(slot) + bytes([2]) + u16(len(pl))
            + bytes([1 if deployed else 0]) + pl)


def fire(label, req, expect_ok):
    node = find_hidraw()
    if node is None:
        print(f"  {label:<52} !! device absent")
        return False
    hid = HidRaw(node, 45.0)
    try:
        sw, _ = send_chained(hid, INS_SIGN_OFFCHAIN, req)
    except Exception as e:
        print(f"  {label:<52} EXCEPTION {type(e).__name__}")
        return False
    finally:
        hid.close()
    signed = sw == SW_OK
    ok = signed == expect_ok
    print(f"  {label:<52} SW=0x{sw:04x} {'signed' if signed else 'REFUSED':<8} "
          f"{'OK' if ok else '!! UNEXPECTED'}")
    time.sleep(1.5)
    return ok


def main():
    node = find_hidraw()
    hid = HidRaw(node, 12.0)
    try:
        sw, data = send(hid, INS_GET_WALLET_ADDRESS, u32(0))
        sw, data = drain_response(hid, sw, data)
        print(f"wallet 0x{data.hex()}  chain {CHAIN} slot 0 (deployed path)\n")
    finally:
        hid.close()

    results = []
    # Positive: the exact accepted request, deployed path (slot 0 is registered
    # locally after the counterfactual call). Anchors every refusal below.
    results.append(fire("POSITIVE: intact typed request", request(), True))
    # 1. One-bit domain separator change (e2e scenario 5p's differential).
    bad_ds = bytearray(TYPED_DS); bad_ds[0] ^= 0x01
    results.append(fire("domain separator: 1 bit flipped", request(pl=payload(ds=bytes(bad_ds))), False))
    # 2. One-bit primary type hash change.
    bad_pth = bytearray(TYPED_PTH); bad_pth[31] ^= 0x01
    results.append(fire("primary type hash: 1 bit flipped", request(pl=payload(pth=bytes(bad_pth))), False))
    # 3. Merkle proof corrupted: bundle verification must fail.
    bad_tr = bytearray(TYPED_TRAILER); bad_tr[-1] ^= 0x01
    results.append(fire("Merkle proof: last byte flipped", request(pl=payload(trailer=bytes(bad_tr))), False))
    # 4. Valid bundle for a DIFFERENT descriptor (WETH Sepolia, context kind 1).
    results.append(fire("valid bundle, wrong descriptor (WETH)",
                        request(pl=payload(ds=WETH_DS, pth=WETH_PTH, trailer=WETH_TRAILER)), False))
    # 5. Right descriptor, wrong chain in the request header.
    results.append(fire("chain mismatch (request says 8453)", request(chain=8453), False))
    # 6. No descriptor at all.
    results.append(fire("trailer absent (len 0)", request(pl=payload(trailer=b"")), False))
    # 7. Re-run the positive last: the device still signs, so the refusals
    #    above were not a wedged session.
    results.append(fire("POSITIVE again (session still healthy)", request(), True))

    print(f"\n{'=== PASS ===' if all(results) else '=== FAIL ==='} {sum(results)}/{len(results)} as expected")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
