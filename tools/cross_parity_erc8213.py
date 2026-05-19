#!/usr/bin/env python3
"""Cross-implementation parity check for ERC-8213 signature/calldata
fingerprints.

Phase 5 item 7 (handoff: `docs/handoff-erc7730-phase5.md`) reserved this
script for an independent `viem` + `safe-hash-rs` round-trip: regenerate
the per-Kind fingerprint hashes that the firmware's
`tx::display::erc8213.rs` formatters render, and assert byte-equality
against the firmware's pre-computed test vectors in
`pqsigner-tx-core::erc8213::tests::*`.

Implementation deferred — covering the same surface today via the
host-side Rust round-trip in `pqsigner-tx-core::erc8213::tests` which
catches wire-format drift but not cross-implementation drift (the
parity gate that Cyfrin / viem / safe-hash-rs would each add). Until
this script lands the firmware-side tests are the only parity check.

Stub exits 0 so other CI lanes that depend on this script don't break.
"""

import sys

print("TODO: integrate Cyfrin clearsig + viem + safe-hash-rs "
      "(Phase 5 item 7 — handoff: docs/handoff-erc7730-phase5.md)")
sys.exit(0)
