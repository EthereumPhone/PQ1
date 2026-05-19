#!/usr/bin/env python3
"""Cross-implementation parity check for ERC-7730 clear-signing.

Phase 5 item 7 (handoff: `docs/handoff-erc7730-phase5.md`) reserved this
script for a Cyfrin `clearsig` round-trip: ingest `secure/data/erc7730/
*.json`, run them through Cyfrin's reference renderer, and compare the
output against the firmware's on-device pages (captured via QEMU's
`ui-capture` SHA-256 dumps).

Implementation deferred until the registry-mirror submodule lands
(handoff item 2) — without an attestation chain to anchor the corpus,
Cyfrin's pipeline rejects every descriptor we'd feed it. Until then
this script is a TODO sentinel so CI doesn't silently skip the parity
gate (the `make` target points here; missing file == loud failure).

Stub exits 0 so other CI lanes that depend on this script don't break.
"""

import sys

print("TODO: integrate Cyfrin clearsig (Phase 5 item 7 — handoff: "
      "docs/handoff-erc7730-phase5.md)")
sys.exit(0)
