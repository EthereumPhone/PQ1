#!/usr/bin/env python3
"""Verify a device-produced EIP-1271 / ERC-6492 signature on a LOCAL anvil fork.

Input: the JSON record tools/hid_sign_offchain.py writes (<out>.json).

What is checked, in order:
  1. localhost RPC, chain id == signed chain id.
  2. H, the hash a dapp passes to isValidSignature: the raw32 payload, or
     `cast hash-message` (EIP-191) of the personal_sign message.
  3. Counterfactual (ERC-6492), run as the spec's algorithm with every step
     visible, NOT via Solady's helper (which silently returns false when its
     reverting-verifier singleton is absent — a vacuous "rejected"):
       magic suffix; decode (factory, factoryCalldata, sigWrapper); factory is
       the firmware's; the wallet has no code; deploy via factoryCalldata on the
       FORK; the wallet now exists at the device's address.
     Deployed: sigWrapper = abi.encode(ownerIndex = slot+1, c10Sig).
  4. wallet.isValidSignature(H, sigWrapper) == 0x1626ba7e.
  5. Controls, each MUST NOT return the magic: one flipped signature bit; H
     with one flipped bit. On a Base-mainnet fork these REVERT rather than
     return 0xffffffff: after both nested workflows fail, Solady's
     `_erc1271IsValidSignatureViaRPC` (eth_call, gasprice 0) finds no Basefee
     contract there and hits its gas-burn `invalid()`. Where that contract
     exists (Ethereum mainnet, Base Sepolia) it instead validates the BARE hash
     — issue #691.
  6. The security invariant (CLAUDE.md "Off-chain output"): the firmware must
     sign the replay-safe NESTED hash, never H itself — a device that bare-signs
     a caller-chosen 32-byte value is a UserOp-forgery oracle. Against the
     wallet's own c10Verifier and slot key:
       verify(nested) == true   where nested is derived HERE, independently:
           keccak256(0x1901 || domainSeparator(eip712Domain()) ||
                     keccak256(abi.encode(keccak256("PersonalSign(bytes prefixed)"), H)))
       verify(H)      is NOT true (false, or the verifier's designed revert
                      on a broken +C constraint): not bare-signed
     The true case is the positive control that makes the negative mean
     something (a verify() call that always fails would also "pass" it).
     This is also what keeps the bare-hash RPC path above harmless for
     off-chain signatures: the device's signature does not verify over H.

REFUSES any non-localhost RPC.

Usage: fork_verify_offchain.py RECORD.json [--rpc http://127.0.0.1:8545]
"""
from __future__ import annotations

import argparse
import json
import sys

from fork_submit_userop import ANVIL_KEY, FACTORY, cast

MAGIC_1271 = "0x1626ba7e"
EIP6492_MAGIC = "6492" * 16
C10_SIG_LEN = 4008


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("record")
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    args = ap.parse_args()
    if not (args.rpc.startswith("http://127.0.0.1") or args.rpc.startswith("http://localhost")):
        print(f"!! refusing non-local RPC {args.rpc}")
        return 2
    R = ["--rpc-url", args.rpc]
    rec = json.load(open(args.record))
    wallet = rec["sender"].lower()
    owner_index = rec["slot"] + 1
    problems: list[str] = []

    def ok(label: str, cond: bool, detail: str = "") -> None:
        print(f"    {'OK  ' if cond else 'FAIL'}  {label}{('  ' + detail) if detail else ''}")
        if not cond:
            problems.append(label)

    def is_valid(h: str, wrapper: str) -> str:
        r = cast("call", wallet, "isValidSignature(bytes32,bytes)(bytes4)", h, wrapper, *R, check=False)
        return r.stdout.strip().lower() if r.returncode == 0 else f"revert({(r.stderr or '').strip()[-80:]})"

    def flip(hexstr: str, byte_index: int) -> str:
        b = bytearray(bytes.fromhex(hexstr[2:]))
        b[byte_index] ^= 0x01
        return "0x" + b.hex()

    print("==> 1. network")
    chain = int(cast("chain-id", *R).stdout.strip())
    ok("fork chain id == signed chain id", chain == rec["chain_id"], f"{chain}")
    if problems:
        return 1

    print("==> 2. the dapp-level hash H")
    k = lambda s: cast("keccak", s).stdout.strip()
    if rec["kind"] == "raw32":
        H = rec["payload"].lower()
    elif rec["kind"] == "personal":
        H = cast("hash-message", rec["message"]).stdout.strip().lower()
    else:
        # EIP-712: H = keccak(0x1901 || domainSeparator || structHash),
        # structHash = keccak(primaryTypeHash || encodeData). Derived here from
        # the request fields, independently of the firmware.
        struct_hash = k("0x" + rec["primaryTypeHash"][2:] + rec["encodedData"][2:])
        H = k("0x1901" + rec["domainSeparator"][2:] + struct_hash[2:]).lower()
        print(f"    domainSeparator = {rec['domainSeparator']}")
        print(f"    structHash      = {struct_hash}")
    print(f"    H = {H}  ({rec['kind']})")

    if rec["accountDeployed"]:
        print("==> 3. deployed wallet: wrap the raw sig")
        code = cast("code", wallet, *R).stdout.strip()
        ok("wallet is deployed", len(code) > 2, f"{(len(code) - 2) // 2} B")
        wrapper = cast("abi-encode", "f(uint256,bytes)", str(owner_index), rec["c10Sig"]).stdout.strip()
    else:
        print("==> 3. counterfactual: the ERC-6492 algorithm, step by step")
        blob = rec["erc6492Blob"]
        ok("blob ends with the ERC-6492 magic", blob[2:].lower().endswith(EIP6492_MAGIC))
        inner = "0x" + blob[2:-64]
        dec = cast("abi-decode", "f()(address,bytes,bytes)", inner).stdout.split()
        factory, factory_calldata, wrapper = dec[0].lower(), dec[1], dec[2]
        ok("blob factory == firmware PQ_SMART_WALLET_FACTORY", factory == FACTORY, factory)
        pre = cast("code", wallet, *R).stdout.strip()
        ok("wallet has no code yet (really counterfactual)", pre == "0x", f"{(len(pre) - 2) // 2} B")
        before = is_valid(H, wrapper)
        ok("isValidSignature is NOT answerable before deploy", before != MAGIC_1271, before)
        if problems:
            print(f"\n=== ABORT: {problems}")
            return 1
        tx = json.loads(cast("send", factory, factory_calldata, "--private-key", ANVIL_KEY,
                             "--gas-limit", "8000000", "--json", *R).stdout)
        ok("factory call from the blob succeeded (FORK only)", tx.get("status") in ("0x1", 1),
           f"gasUsed {int(tx.get('gasUsed', '0x0'), 16)}")
        post = cast("code", wallet, *R).stdout.strip()
        ok("wallet now deployed at the device's address", len(post) > 2, f"{(len(post) - 2) // 2} B")
    if problems:
        print(f"\n=== ABORT: {problems}")
        return 1

    # abi.encode(uint256, bytes): [ownerIndex][0x40][len][sig...][pad]
    wb = bytes.fromhex(wrapper[2:])
    ok("wrapper ownerIndex == slot+1", int.from_bytes(wb[0:32], "big") == owner_index,
       str(int.from_bytes(wb[0:32], "big")))
    inner_sig = "0x" + wb[96:96 + C10_SIG_LEN].hex()

    print("==> 4. EIP-1271")
    got = is_valid(H, wrapper)
    ok("isValidSignature(H, sig) == 0x1626ba7e", got == MAGIC_1271, got)

    print("==> 5. controls (each MUST NOT return the magic)")
    got = is_valid(H, flip(wrapper, 96 + 1000))
    ok("rejected: 1 bit flipped in the signature", got != MAGIC_1271, got)
    got = is_valid(flip(H, 31), wrapper)
    ok("rejected: H with 1 bit flipped", got != MAGIC_1271, got)

    print("==> 6. invariant: the device signed the NESTED hash, never H itself")
    owner = cast("call", wallet, "ownerAtIndex(uint256)(bytes)", str(owner_index), *R).stdout.strip()
    pk_seed, pk_root = "0x" + owner[2:66], "0x" + owner[66:130]
    verifier = cast("call", wallet, "c10Verifier()(address)", *R).stdout.strip()
    dom = cast("call", wallet, "eip712Domain()(bytes1,string,string,uint256,address,bytes32,uint256[])",
               *R).stdout.splitlines()
    name, version = json.loads(dom[1]), json.loads(dom[2])
    dom_chain, dom_addr = int(dom[3].split()[0]), dom[4].strip().lower()
    ok("eip712Domain = (PQSmartWallet, 1, chain, this)",
       (name, version, dom_chain, dom_addr) == ("PQSmartWallet", "1", rec["chain_id"], wallet),
       f"({name}, {version}, {dom_chain}, {dom_addr})")
    dom_typehash = k("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    dom_sep = k(cast("abi-encode", "f(bytes32,bytes32,bytes32,uint256,address)", dom_typehash,
                     k(name), k(version), str(dom_chain), dom_addr).stdout.strip())
    struct = k(cast("abi-encode", "f(bytes32,bytes32)", k("PersonalSign(bytes prefixed)"), H).stdout.strip())
    nested = k("0x1901" + dom_sep[2:] + struct[2:])
    print(f"    nested (derived here) = {nested}")

    def verify(msg: str) -> str:
        r = cast("call", verifier, "verify(bytes32,bytes32,bytes32,bytes)(bool)", pk_seed, pk_root, msg,
                 inner_sig, *R, check=False)
        return r.stdout.strip() if r.returncode == 0 else "revert"

    # "Not valid" has two designed forms: `false` (final root mismatch) or a
    # bare revert(0,0) when a +C structural constraint fails first
    # (SPHINCsC10Asm.sol: forced-zero FORS bits, line ~86; WOTS digit sum
    # != 205, line ~170) — which is what a signature checked against the wrong
    # message normally hits. The positive control above uses the same call,
    # key and signature and differs ONLY in the message, so a revert here is
    # the verifier saying no, not a broken call.
    v_nested, v_bare = verify(nested), verify(H)
    ok("c10Verifier.verify(nested) == true  (positive control)", v_nested == "true", v_nested)
    ok("c10Verifier.verify(H) is NOT true   (not bare-signed)", v_bare in ("false", "revert"), v_bare)

    print()
    if problems:
        print(f"=== FAIL === {problems}")
        return 1
    print("=== PASS === the deployed wallet accepts the device's off-chain signature, "
          "and it is bound to the nested hash only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
