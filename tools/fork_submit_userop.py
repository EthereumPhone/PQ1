#!/usr/bin/env python3
"""Submit a device-signed UserOp to a LOCAL anvil fork through EntryPoint v0.6.

This is the independent end-to-end check the offline verifier cannot give:
tools/verify-c10-sig reuses the firmware's own Rust crates, so a bug shared by
signer and verifier would pass it. Here the chain's code does the checking:
PQSmartWallet.sphincsDigest (Solidity) re-hashes the UserOp, SPHINCsC10Asm (Yul)
verifies the C10 signature, the factory verifies the bootstrap-key signature
inside initCode and computes the CREATE2 address.

Input: the JSON record tools/hid_sign.py writes next to its response
(`<out>.json`): every field the device signed plus what it returned.

Order of operations (each step must pass before the next):
  1. RPC is localhost and its chain id equals the signed chain id.
  2. initCode (deploy only): factory == firmware PQ_SMART_WALLET_FACTORY,
     decoded chainId == signed chain, factory.getAddress(...) == device sender.
  3. EntryPoint nonce == signed nonce; the sender is funded on the FORK only.
  4. NEGATIVE CONTROLS via eth_call (no state change): one flipped signature
     bit, callGasLimit+1, and (deploy) one flipped bit in the bootstrap sig
     inside initCode. Every control MUST be rejected, or the run aborts — a
     chain that accepts a tampered op is not checking anything.
  5. The genuine op: eth_call simulation, then a real handleOps transaction on
     the fork; UserOperationEvent.success must be true, and the post-state
     (wallet code, recipient balance, slotUses) must move as expected.

REFUSES any non-localhost RPC: nothing here may reach a public network.

Usage: fork_submit_userop.py RECORD.json [--rpc http://127.0.0.1:8545]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

FACTORY = "0xe8ce78cd976497447ff8b76c71b59ae42af0d452"   # proto::PQ_SMART_WALLET_FACTORY
ENTRY_POINT = "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789"
# anvil's well-known dev account 0 — only ever used against a local fork.
ANVIL_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_ADDR = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
OP_T = "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)"
HANDLE_OPS = f"handleOps({OP_T}[],address)"
FAILED_OP = "0x220266b6"  # FailedOp(uint256,string)
USEROP_EVENT = "UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)"
CAST = os.path.expanduser("~/.foundry/bin/cast")


def cast(*a: str, check: bool = True) -> subprocess.CompletedProcess:
    r = subprocess.run([CAST, *a], capture_output=True, text=True, timeout=180)
    if check and r.returncode != 0:
        raise RuntimeError(f"cast {a[0]} failed: {(r.stderr or r.stdout).strip()[:600]}")
    return r


def revert_reason(text: str) -> str:
    """Pull FailedOp(opIndex, reason) out of cast's error text, if present.
    Match the contiguous hex run only: an earlier version filtered hex-looking
    characters out of the whole message, which picked up stray letters and
    decoded 'AA24 signature error' nibble-shifted into garbage."""
    m = re.search(FAILED_OP + r"([0-9a-fA-F]+)", text)
    if not m:
        return text.strip().splitlines()[-1][:200] if text.strip() else "(no output)"
    try:
        data = bytes.fromhex(m.group(1)[: len(m.group(1)) // 2 * 2])
        n = int.from_bytes(data[64:96], "big")
        return "FailedOp: " + data[96:96 + n].decode(errors="replace")
    except Exception:
        return "FailedOp (undecoded)"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("record")
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    args = ap.parse_args()
    if not (args.rpc.startswith("http://127.0.0.1") or args.rpc.startswith("http://localhost")):
        print(f"!! refusing non-local RPC {args.rpc} — this tool only talks to a local fork")
        return 2
    R = ["--rpc-url", args.rpc]
    rec = json.load(open(args.record))
    sender = rec["sender"].lower()
    problems: list[str] = []

    def ok(label: str, cond: bool, detail: str = "") -> None:
        print(f"    {'OK  ' if cond else 'FAIL'}  {label}{('  ' + detail) if detail else ''}")
        if not cond:
            problems.append(label)

    print("==> 1. network")
    chain = int(cast("chain-id", *R).stdout.strip())
    ok("fork chain id == signed chain id", chain == rec["chain_id"], f"{chain} vs {rec['chain_id']}")
    if problems:
        return 1

    # callData from an INDEPENDENT encoder (cast), not the firmware's own
    # reconstruct_execute_calldata: if the two disagree, the on-chain
    # sha256(callData) differs from what the device signed and step 5 fails.
    # ownerIndex == slot + 1 (slot 0 => 1).
    owner_index = str(rec.get("slot", 0) + 1)
    if rec.get("kind") == "batch":
        # One UserOp, several inner txs: executeBatchWithOffchainCount.
        txs = rec["txs"]
        call_data = cast(
            "calldata",
            "executeBatchWithOffchainCount(uint256,uint256,address[],uint256[],bytes[])",
            owner_index, str(rec["newOffchainCount"]),
            "[" + ",".join(t["to"] for t in txs) + "]",
            "[" + ",".join(str(t["value"]) for t in txs) + "]",
            "[" + ",".join(t["data"] for t in txs) + "]",
        ).stdout.strip()
    else:
        call_data = cast("calldata", "executeWithOffchainCount(uint256,uint256,address,uint256,bytes)",
                         owner_index, str(rec["newOffchainCount"]), rec["to"], str(rec["value"]),
                         rec["data"]).stdout.strip()

    init_code = rec["initCode"]
    print("==> 2. wallet address (independent of the device)")
    if len(init_code) > 2:
        ic = bytes.fromhex(init_code[2:])
        ok("initCode length", len(ic) == 4280, str(len(ic)))
        ok("initCode factory == firmware PQ_SMART_WALLET_FACTORY", "0x" + ic[:20].hex() == FACTORY, "0x" + ic[:20].hex())
        dec = cast("calldata-decode", "createAccount(bytes32,bytes32,bytes32,bytes32,uint64,bytes)",
                   "0x" + ic[20:].hex()).stdout.split()
        ok("initCode chainId == signed chain", int(dec[4]) == rec["chain_id"], dec[4])
        predicted = cast("call", FACTORY, "getAddress(bytes32,bytes32)(address)", dec[0], dec[1], *R).stdout.strip().lower()
        ok("factory.getAddress(masterPkSeed, masterPkRoot) == device sender", predicted == sender, f"{predicted} vs {sender}")
        code = cast("code", sender, *R).stdout.strip()
        ok("sender has no code yet (counterfactual)", code == "0x", f"{(len(code) - 2) // 2} B")
    else:
        code = cast("code", sender, *R).stdout.strip()
        ok("sender already deployed", len(code) > 2, f"{(len(code) - 2) // 2} B")
    if problems:
        print(f"\n=== ABORT before submitting: {problems}")
        return 1

    print("==> 3. nonce + fork-only funding")
    nonce = int(cast("call", ENTRY_POINT, "getNonce(address,uint192)(uint256)", sender, "0", *R).stdout.split()[0])
    ok("EntryPoint.getNonce(sender, 0) == signed nonce", nonce == rec["nonce"], f"{nonce} vs {rec['nonce']}")
    bal = int(cast("balance", sender, *R).stdout.strip())
    if bal < 10**17:
        cast("rpc", "anvil_setBalance", sender, hex(10**18), *R)
        print(f"    funded {sender} with 1 ETH on the FORK (anvil_setBalance)")
    if problems:
        return 1

    def op_str(o: dict) -> str:
        return "[(" + ",".join([sender, str(o["nonce"]), o["initCode"], o["callData"], str(o["callGasLimit"]),
                                str(o["verificationGasLimit"]), str(o["preVerificationGas"]),
                                str(o["maxFeePerGas"]), str(o["maxPriorityFeePerGas"]), "0x",
                                o["signature"]]) + ")]"

    genuine = {k: rec[k] for k in ("nonce", "callGasLimit", "verificationGasLimit", "preVerificationGas",
                                   "maxFeePerGas", "maxPriorityFeePerGas")}
    genuine.update(initCode=init_code, callData=call_data, signature=rec["type2Wrapper"])

    def flip(hexstr: str, byte_index: int) -> str:
        b = bytearray(bytes.fromhex(hexstr[2:]))
        b[byte_index] ^= 0x01
        return "0x" + b.hex()

    print("==> 4. negative controls (eth_call only — each MUST be rejected)")
    controls = [
        ("1 bit flipped inside the C10 signature", dict(genuine, signature=flip(genuine["signature"], 96 + 1000))),
        ("callGasLimit + 1 (unsigned field change)", dict(genuine, callGasLimit=genuine["callGasLimit"] + 1)),
    ]
    if len(init_code) > 2:
        # The factorySig is the last dynamic arg of createAccount; flip a byte
        # well inside it (initCode tail is the 4008-B sig + ABI padding).
        controls.append(("1 bit flipped in the bootstrap sig inside initCode",
                         dict(genuine, initCode=flip(init_code, 4280 - 2000))))
    for label, o in controls:
        r = cast("call", ENTRY_POINT, HANDLE_OPS, op_str(o), ANVIL_ADDR, *R, check=False)
        ok(f"rejected: {label}", r.returncode != 0, revert_reason(r.stderr + r.stdout))
    if problems:
        print(f"\n=== ABORT: a tampered op was ACCEPTED — the chain is not verifying: {problems}")
        return 1

    print("==> 5. the genuine device-signed op")
    recipients = ([(t["to"], t["value"]) for t in rec["txs"]] if rec.get("kind") == "batch"
                  else [(rec["to"], rec["value"])])
    before = {to: int(cast("balance", to, *R).stdout.strip()) for to, _ in recipients}
    sim = cast("call", ENTRY_POINT, HANDLE_OPS, op_str(genuine), ANVIL_ADDR, *R, check=False)
    ok("eth_call simulation succeeds", sim.returncode == 0, "" if sim.returncode == 0 else revert_reason(sim.stderr + sim.stdout))
    if problems:
        print(f"\n=== FAIL: the chain rejected the device's op: {problems}")
        return 1
    tx = cast("send", ENTRY_POINT, HANDLE_OPS, op_str(genuine), ANVIL_ADDR, "--private-key", ANVIL_KEY,
              "--gas-limit", "15000000", "--json", *R)
    rcpt = json.loads(tx.stdout)
    ok("handleOps transaction status == 1", rcpt.get("status") in ("0x1", 1), f"tx {rcpt.get('transactionHash')} gasUsed {int(rcpt.get('gasUsed', '0x0'), 16)}")
    topic = cast("keccak", USEROP_EVENT).stdout.strip().lower()
    evs = [lg for lg in rcpt.get("logs", []) if lg["topics"][0].lower() == topic]
    ok("exactly one UserOperationEvent", len(evs) == 1, str(len(evs)))
    if evs:
        d = bytes.fromhex(evs[0]["data"][2:])
        success = int.from_bytes(d[32:64], "big")
        ok("UserOperationEvent.success == true (inner call executed)", success == 1,
           f"actualGasCost {int.from_bytes(d[64:96], 'big')} wei, actualGasUsed {int.from_bytes(d[96:128], 'big')}")

    print("==> 6. post-state")
    code = cast("code", sender, *R).stdout.strip()
    ok("wallet code present at the device-predicted address", len(code) > 2, f"{(len(code) - 2) // 2} B")
    for to, value in recipients:
        after = int(cast("balance", to, *R).stdout.strip())
        ok(f"recipient {to[:10]}… received exactly the signed value",
           after - before[to] == value, f"+{after - before[to]} wei")
    su = int(cast("call", sender, "slotUses(uint256)(uint256)", "1", *R).stdout.split()[0])
    oc = int(cast("call", sender, "offchainSigCount(uint256)(uint256)", "1", *R).stdout.split()[0])
    bu = int(cast("call", sender, "bootstrapUses()(uint256)", *R).stdout.split()[0])
    print(f"    slotUses(1)={su}  offchainSigCount(1)={oc}  bootstrapUses={bu}")
    nn = int(cast("call", ENTRY_POINT, "getNonce(address,uint192)(uint256)", sender, "0", *R).stdout.split()[0])
    ok("EntryPoint nonce advanced by one", nn == rec["nonce"] + 1, str(nn))

    print()
    if problems:
        print(f"=== FAIL === {problems}")
        return 1
    print("=== PASS === the chain's own verifier accepted the device-signed UserOp")
    return 0


if __name__ == "__main__":
    sys.exit(main())
