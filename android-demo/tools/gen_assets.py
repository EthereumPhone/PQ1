#!/usr/bin/env python3
"""Export the PQ1 Demo app's assets and test goldens from the Python demo tools.

Two outputs:

  app/src/main/assets/erc20/<chain>_<token>.bin
      ERC-20 Merkle proof bundles cut from tools/companion-stub/erc20_db.bin
      (the blob whose root the EVT firmware pins as ERC20_DB_ROOT). The app
      attaches them so the device names the token instead of showing
      "token unknown". Re-run this whenever erc20_db.bin is regenerated.

  app/src/test/resources/golden/<flow>.bin, frames_*.bin
      Request payloads built by tools/demo_px_flows.py (the walked-on-glass
      reference) for a fixed sender / nonce / validTo. The JVM test
      FlowGoldenTest rebuilds each one in Kotlin and requires byte equality,
      so the app sends exactly what the Python demos send.

Usage:
  android-demo/tools/gen_assets.py                  # tools dir: ui-px worktree if present
  android-demo/tools/gen_assets.py --tools ../tools # explicit
"""
from __future__ import annotations

import argparse
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(os.path.dirname(HERE), "app")
REPO_TOOLS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "tools")
UIPX_TOOLS = os.path.expanduser("~/Documents/PQ1/sphincs_rust-ui-px/tools")

# Fixed inputs shared with FlowGoldenTest.kt.
SENDER = bytes.fromhex("51" * 20)
VALID_TO = 1_800_000_000
NONCE = 3

PROOFS = [  # (chain, token) pairs the app's flows reference
    (8453, "833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),  # USDC (Base)
    (8453, "4200000000000000000000000000000000000006"),  # WETH (Base)
    (8453, "50c5725949A6F0c72E6C4a641F24049A917DB0Cb"),  # DAI (Base)
    (1, "C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),     # WETH (mainnet)
    (1, "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),     # USDC (mainnet)
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default=UIPX_TOOLS if os.path.isdir(UIPX_TOOLS) else REPO_TOOLS)
    args = ap.parse_args()
    tools = os.path.abspath(args.tools)
    sys.path[:0] = [tools, os.path.join(tools, "companion-stub"), REPO_TOOLS]  # bybit: repo tools only
    print(f"tools: {tools}")

    import demo_px_flows as d  # noqa: E402
    import demo_bybit_replay as by  # noqa: E402
    from hid_smoke import frame_apdu  # noqa: E402

    d.time = types.SimpleNamespace(time=lambda: VALID_TO - 3600)  # cow_order: validTo = now + 3600

    # ── ERC-20 proofs ──
    out = os.path.join(APP, "src", "main", "assets", "erc20")
    os.makedirs(out, exist_ok=True)
    for chain, token in PROOFS:
        b = d.erc20_proof(chain, bytes.fromhex(token))
        path = os.path.join(out, f"{chain}_{token.lower()}.bin")
        with open(path, "wb") as fh:
            fh.write(b)
        print(f"  proof {chain}:{token}  {len(b)} B")

    # ── goldens ──
    gold = os.path.join(APP, "src", "test", "resources", "golden")
    os.makedirs(gold, exist_ok=True)
    c = d.Ctx(SENDER, argparse.Namespace(slot=0, account=0), NONCE)

    def usdc(a: float) -> int:
        return round(a * 10**6)

    g: dict[str, bytes] = {}
    g["send"] = d.f_send(c).payload
    g["erc20"] = d.f_erc20(c).payload
    g["safe_usdc"] = d.safe_request(c, d.USDC_BASE, 0, d.erc20_call(d.TRANSFER, d.ALICE, usdc(250)),
                                    ["x"], erc20=d.erc20_proof(d.BASE, d.USDC_BASE)).payload
    g["safe_cow"] = d.f_safe_cow(c).payload
    g["safe_msend"] = d.f_safe_msend(c).payload
    g["cow"] = d.f_cow(c).payload

    canonical, raw, h = by.bybit_safe_tx()
    g["bybit"] = (d.userop_head(SENDER, d.MAINNET, 0, NONCE, d.addr(by.BYBIT_SAFE), 0,
                                d.APPROVE_HASH_SELECTOR + h)
                  + d.trailers(safe=canonical + d.u16(len(raw)) + raw))

    for name, payload in g.items():
        with open(os.path.join(gold, f"{name}.bin"), "wb") as fh:
            fh.write(payload)
        print(f"  golden {name:11s} {len(payload)} B")

    # HID framing of the first chained APDU of the safe_msend payload (P1=0x80,
    # LC=255) and of a short unchained one (GET_WALLET_ADDRESS, account 0).
    first = bytes([0xF0, 0x30, 0x80, 0x00, 255]) + g["safe_msend"][:255]
    with open(os.path.join(gold, "frames_chained_first.bin"), "wb") as fh:
        fh.write(b"".join(frame_apdu(first)))
    with open(os.path.join(gold, "frames_get_address.bin"), "wb") as fh:
        fh.write(b"".join(frame_apdu(bytes([0xF0, 0x60, 0x00, 0x00, 4, 0, 0, 0, 0]))))
    print("  golden frames")
    return 0


if __name__ == "__main__":
    sys.exit(main())
