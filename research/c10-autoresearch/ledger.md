# Ledger — what is known before the loop starts (2026-11-12)

Baseline: master `0bf8153f2` on kit 0055002D, SRAM-resident, 160 MHz.

- `cached_sign` = 598,749,275 cycles (3.742 s). `keygen` = 92,638,607 (0.579 s). `total` = 996,530,250.

Digests per segment (host, exact, `hw-sha256-oneshot` path):

| segment | digests | cycles per digest |
|---|---:|---:|
| keygen | 177,151 | 523 |
| sign pass (m0) | 512,999 | 583 |
| sign pass (m1) | 522,487 | 583 |
| verify | 361 | about 694, including parsing |

Pass A and pass B differ by about 230 cycles, which comes from the different shuffle.

The negative control is a one-bit mutation of `truncate`. It fails both gates, but the mutated build still verifies against its own key. So the byte gate, not the verify, is what catches silent output drift.

## Already done on master (do not re-try)

- **C+D**: unrolled DIN feed and HR read-out (`unrolled-io`), worth −96 cycles per digest.
- **B+E**: inlined barriers and a one-call digest (`oneshot`, `inline-barriers`), about −30 cycles per digest.
- **A**: INIT-only restart (`init-restart`), −17 cycles per digest. `scrub()` runs on wipe.
- **S1**: `find_count` uses `digit_sum` without extracting the digits.
- **S2**: `chain_hash` builds its preimage once per chain.
- **Lever 2**: the slot master is derived once per session. This is a firmware-level change; the bench never runs PBKDF2.

## Measured dead

- **Lever 3**: reading 4 HR words instead of 8 showed no gain on silicon (cycles per digest were flat).

## Known but unlanded (track B: trades FI independence or adds cross-sign state)

- **In-sign reuse** (branch `perf/insign-auth-reuse`, `e55121a50`, unpushed): pass B reuses pass A's top-layer auth path. It skips 177,151 digests per signature, and was reviewed GO-with-conditions.
- **Top-layer tree cache**: layer 1 is the same 512-leaf tree in every sign.
  - It saves about 177k digests per pass, and was reviewed by Fable and Astra (GO with conditions).
  - Condition H1: keygen becomes the single trusted producer, so the first use needs an uncached cross-check.
- **PBKDF2 twice on a first sign**: already fixed by lever 2.

## Needs a flash-run board (cannot be measured on the kit)

- **ICACHE**: `rcc.rs` writes `ICACHE_CR = 1`, which sets EN and clears WAYSEL, so the cache runs 1-way (direct-mapped). The reset default is 2-way.
- **Flash prefetch**: `FLASH_ACR.PRFTEN` is not set; latency is 4 wait states.
