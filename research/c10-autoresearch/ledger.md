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

## Session 2026-11-12, after 15 experiments (evaluator versions)

- **v1** (`link_sram.ld`): code fetched over the S-bus from SRAM. Superseded.
- **v2** (`link_cbus.ld`): code on the SRAM1 C-bus alias 0x0E000000, data and peripherals on the S-bus. Every v1 win held, including HR0..3.
- **v3** (`link_flash.ld`, `experiment_flash.sh`): code in flash bank 1 at 0x0C000000, with ICACHE_CR = 1 (1-way) and FLASH_ACR at 4 WS, exactly as `rcc.rs`. This is the **primary evaluator** from 8bfb1de17 on. The owner allowed flashing the kit, but nothing permanent (no option bytes, OTP or SE). v3 is within about 2% of v2.

## Measured floors (kit, 160 MHz)

| what | cycles |
|---|---:|
| 96-byte digest, straight-line asm, from registers | 214 |
| 96-byte digest, fed from SRAM | 225 |
| HASH last block (DCAL to DCIS) | ~65 |
| BUSY after DCIS | ~9 |
| DIN or SR access | ~2.6 (the earlier "9 per word" was size-optimized loop overhead in the probe) |
| `chain16` loop | 242 per step, at the floor |
| per-call overhead before batching | ~320 |
| count-search try, in situ | ~295 |
| R-grind try | ~1,770 before 4b13db307, ~925 after |

**Host counts per pass for m0:**

| primitive | count |
|---|---:|
| chain steps | 308,826 |
| search tries | 69,934 (m1: 87,120) |
| FORS leaves | 26,624 |
| FORS nodes | 26,611 |
| PRF+chain calls | 44,118 |
| R-grind tries | about 4,000 (m1: about 175; expected value 2,048) |

**Composition of a pass at 8bfb1de17:**

| part | share |
|---|---:|
| chain steps (at the floor) | ~60% |
| search tries | ~16% |
| FORS | ~15% |
| PRFs | ~5% |
| other | ~4% |

## Open landing conditions found so far

- **0477a87c7** copies sk_seed into unwiped stack buffers (`wots_secret`/`fors_secret` one-shot), as Fable round 1 found. The hot paths now bypass it (prf_chain, fors_leaf, wots_chains16), but the plain functions still do it.
- **Signer logic in the HASH driver** (chain iteration, count search, FORS leaf, per-key chains) moves proof obligations from the extracted Rust into `hw/`. Every keep after fe9ed862b is [FV-major] to land.
- Every driver change is behind a secure-only feature, so FSBL bytes do not change. Exception: the opt-level 3 override for `pqsigner-hw` also reaches the FSBL's copy unless it is scoped.

## Levers outside the bench (firmware level)

- **H7**: three `rng_strong::fill` calls per sign are SE round trips, about 0.3 s per sign according to the source comment. Not measurable on this kit, which has no SEs.
- `tick-hook` (UI film) after every digest, and the F-17 one-second rate limiter. These are wall-time components outside the hash work.

## Milestone 2026-11-12, evening (kit 0055002D, v3/v3b flash harness)

| | cached sign (2 passes + verify) | keygen |
|---|---:|---:|
| master, 1-way (as shipped) | 546.3 M cycles, 3.41 s | 85.5 M, 0.53 s |
| head, output-identical | 236.7 M, 1.48 s (−57%) | 37.8 M, 0.24 s |
| head + top-layer cache (track B) | 164.5 M, 1.03 s (−70%) | 76.1 M, 0.48 s (includes fill and the confirm build) |

**Cold first sign** (keygen + sign): 3.95 s on master → 1.72 s at head → 1.50 s with the cache.

**Evidence at head**
- Golden bytes on the kit for every keep.
- Host differential against pristine master: 400 cases, 100 keys, `opt_rand` Some and None, for both the fast path and the cache. The branch negative control produced 133/133 mismatches.
- Kit differential: 32 cases, 8 keys, signatures hashed with software SHA on the device, all equal to master.
- Track-B controls refuse for the intended reason (digest, confirm, subtree), and the positive control signs. The 512-leaf sweep matches a full rebuild.

**Product levers measured with stubs**
- Per-digest UI tick: +7.2%. Batching it per key or subtree brings that to +0.5%; this needs `film_tick_hash_n` in the secure world.
- Driver at opt-level `z`: +12%. The fast paths need a secure-only crate at opt 3, which keeps the FSBL unchanged.
- 1-way vs 2-way ICACHE: 0.15% at head.

**Not measurable on the kit**
- Film drawing: about 8 ms per 32 ms while live, per the source.
- `rng_strong`: about 0.3 s per sign, per the source.

**Open for landing**
- F1: boot KATs and crosscheck hooks for every new driver entry.
- FV-major re-extraction: chain, search, FORS and PRF logic now live in `hw/`.
- The track-B FI trade: the top auth path is no longer double-computed.
- Cleanup of warnings and dead fallback paths.
