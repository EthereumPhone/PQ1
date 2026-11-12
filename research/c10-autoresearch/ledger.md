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

## Round 3 (2026-11-12, late): paths beyond the hash floor

| experiment | result | verdict |
|---|---|---|
| `-C target-cpu=cortex-m33 -C target-feature=-fpregs` | −0.7% sign, −1.2% keygen | kept; now the bench default |
| `FLASH_ACR.PRFTEN` | −0.02% | discarded (noise) |
| Hand-scheduled asm chain step | +3.3% (+3.9% with aligned loop heads) | discarded; the compiler loop is already at the instruction floor |
| HASH context restore as a midstate | full restore is 108 cycles with ldm/stm bursts at 2.5 cycles per word, about the cost of the block it saves | dead |
| Sparse context restore | 36 of 38 CSRs carry state after one block (state ×2 + FIFO) | dead |
| No BUSY wait before INIT | −3.7% sign, −4.5% keygen; kit differential 32/32; soak 12/12 | **undocumented**, filed as #1151 for ST confirmation |
| PBKDF2 (cold path) | 94.1 M → 51.8 M cycles (0.59 → 0.32 s, −45%), via a raw-compression loop plus a generated Thumb-2 SHA-512 (`sha512-m33`, 3.1 KB) | kept as research; filed as #1152 |

PBKDF2 notes:
- Compilers top out around 13.7 k cycles per block (gcc).
- The unrolled 28 KB form gave no gain because it thrashed the 8 KB ICACHE from flash.
- The U585 has no hardware SHA-512.

**Combined, kit, flash:**

| configuration | cached sign |
|---|---:|
| output-identical | 234.7 M (1.47 s) |
| + no-busy-wait | 226.0 M (1.41 s) |
| + top cache | 163.4 M (1.02 s) |
| + both | 157.8 M (0.99 s), **−71% vs master 3.41 s** |

**Filed for later decision:**
- #1148 top cache
- #1149 batched tick
- #1150 opt-3 crate
- #1151 BUSY wait
- #1152 PBKDF2
- #1153 wall time outside hashing: RNG draws, prewarm during review, speculative signing, the F-17 1 s floor

**Not kit-measurable** (SEs and UI): RNG draws, prewarm, speculative signing, the film drawing cost.

**Digest count is at the FI-design minimum** (Fable round 3 agrees). Remaining levers are owner decisions or product-side.

## Round 4 (in progress): new tools and probes

- **PC-sampling profiler** (`harness/run_profile.sh` + `prof_report.py`). OpenOCD reads DWT_PCSR back to back while the bench runs, giving 5.7 k samples per sign.
  - Split: `wots_chains16` 63%, `fors_subtree16` 14%, `search128` 11%, `hits_target` 6% (overlapped), `th_multi16` 2%, one-shot paths about 2%; about 98% of signing time is in the hash-driver routines.
  - Hottest PCs are the store after DCAL (the write stalls while block 1 loads) and the DCIS poll, i.e. engine-bound.
  - Grind: 25% of its samples are on one DIN store that stalls while block 1 loads.
- **GPDMA feed** (`probe_dma`).
  - The DMA writes DIN at about 2.3 cycles per word.
  - TCF is set before the HASH has taken the last words (NBWP = 16). DCAL must wait for NBWP == 8, or the digest is wrong.
  - A DMA-fed 96-byte digest costs 225 cycles against 214 for the CPU straight-line feed: no gain on its own.
- **Software SHA-256**: about 5.3 k cycles per block (`sha2`, opt 3). A hardware+software hybrid in the ~130-cycle idle windows would give about +2.5%: not worth it.
- **USB HID**: 64-byte reports at 1 ms, so about 59 B/ms of payload.
  - A Type-2 result (about 4.15 KB) takes about 70 ms after signing; a rotation output (about 12.6 KB) about 215 ms.
  - A bulk/WebUSB transport would take under 10 ms. This is product-side.
- **Floor arithmetic.** About 1.09 M blocks × 66 cycles ≈ 72 M of engine time per pass, plus about 22 M of block-1 feed that cannot overlap on a single-context engine. That is about 94 M against about 113–117 M now, so roughly 17% headroom. Of that, about 4 M is the BUSY wait (#1151); the rest is polling latency, read-out and per-digest control.

## Round 4 results (2026-11-12, night)

- **HRA alias read-out** (`read_hr4`, one ldm from `HASH+0x0C`): −0.7% sign, −1.1% keygen, byte-identical. **Kept and now the default.** The head on v3b is **233.1 M cycles (1.46 s)**.
- **One-block chain-step prototype** (`probe_1blk`; NOT the frozen format): 2-block 198 cycles against 1-block 119 cycles, −40%.
  - A "C10 v2" one-block tweakable hash would give about −36% per pass: a cached sign of about 0.95 s without the cache, about 0.68 s with it.
  - It breaks the frozen formats (on-chain verifier, addresses, KATs, FV), so it is a pre-launch decision. Draft issue: `issue-drafts/c10v2-one-block-tweakable-hash.md`.
- **Product latency floor** (Fable round 4, verified in source):
  - Under `ui-px`, `film_resolve` blocks until `film_t >= T7 + RESULT_HOLD_MS`, 8.65 s after `film_start`, whatever the hash speed.
  - The legacy LCD route spins 3,000,000 `nop`s after "Signed".
  - USB results are paged in 255-byte `GET_RESPONSE` chunks.
  - Draft issue: `issue-drafts/latency-floor-outside-signer.md`.
- **Dead or low:**
  - dropping the DCIS clear: it removes an FI tripwire, so not taken;
  - C-bus template loads: the bench stack is in SRAM3, which has no C-bus alias, and the value is low;
  - DMA, and software SHA in the idle windows.
- **The two issue drafts were not filed.** The permission classifier blocked creating them because the owner had not asked; they await the owner.

## Round 5 (2026-11-12, late): C10 v2 one-block format (#1155), owner go

- **Spec:** `c10v2-spec.md` DRAFT 0.1. Reviews by Fable and Astra are in flight.
- **Python reference:** `c10v2/c10v2_ref.py`, forked from the clean-room v1 signer.
  - Self-test: 8 one-bit flips across the signature, a wrong root and a wrong message are all rejected.
  - 6 KATs in `c10v2/kat-v2-draft01.{json,txt}`.
- **Rust v2:** `sphincs-c10` feature `v2` (`src/v2hash.rs`, plus hooks at the top of the eight `hash.rs` functions).
  - `wots`, `fors` and `hypertree` are untouched.
  - `compile_error!` against every fused v1-layout driver feature.
  - `tests/v2_kat.rs`: Rust matches Python on all 6 KATs (pk_root and every signature byte), verifies the Python signatures and rejects a near-miss.
  - The v1 suite is unchanged at 82/0.
- **v2 kit golden:** `golden-v2.bin`, written by `host_v2`, is byte-identical to the Python reference for the bench inputs (`opt_rand`, shuffled signer).

**Kit, harness v3b, generic oneshot driver path for both versions** (`experiment_v2.sh os|v2`, `bench_os` / `bench_v2`):

| | v1 | v2 | change |
|---|---:|---:|---:|
| `cached_sign` | 440.6 M (2.75 s) | 332.5 M (2.08 s) | −24.5% |
| `keygen` | 65.7 M | 62.0 M | −5.7% |

**Reading it (digest counts from `host_os` / `host_v2`):**

- **Keygen** is the clean comparison: it runs exactly 177,151 digests in both versions and has no grind. Cost per digest fell only from 371 to 350 cycles.
- On the oneshot path, about 250 cycles per call is software overhead (buffer build, extern call, init, feed, poll). Halving the blocks barely shows.
- **Sign** counts differ because grind luck depends on the digests (m0: 513 k digests for v1, 445 k for v2). So the −24.5% mixes format gain with luck.

**Conclusion:** the oneshot path cannot measure v2. The gain lives where per-digest overhead is minimal, i.e. the fused driver loops that ship (the probe measured 198 → 119 cycles per chain step). The next step is v2 fused entries (chain, PRF+chain, search, node, FORS leaf), compared against the v1 fused head.

**Estimate for the fused head**, by arithmetic from the unit costs and not measured:

- chain steps: 616 k per cached sign × about 83 cycles saved ≈ 51 M;
- grind search, 3 blocks → 1: about 20 M;
- FORS: about 13 M;
- PRF: about 7 M;
- T_43: about 1.5 M.

Total about −92 M of 233 M (−40%).

**Spec finding while implementing:** in v1 the last FORS tree's root-wrapper `F` reuses the tweak of that tree's leaf 0, `(FORS_TREE, ht_idx, kp=12, cp=0, ha=0)`. See `fors.rs` and `SPHINCsC10Asm.sol:127`. Both calls run in every sign. The inputs differ, but the tweak repeats, which the SM-TCR argument normally excludes. v2 should give the wrapper its own address.

### Round 5, continued: spec 0.2, fused v2 entries, luck-averaged measurement

**Reviews.** Astra and Fable: adopt with changes, no blocking concern; every A7 width fits every value C10 uses. Folded into spec **0.2**:

- `cp` byte-aligned in A7;
- WOTS_DIGEST is `S ‖ m ‖ count ‖ A7`;
- FORS_LAST gets type 9. Fixes v1's tweak reuse between FORS tree 12 leaf 0 and the last-slot wrapper (`hypertree.rs:255`, `SPHINCsC10Asm.sol:127`);
- T_k are tweak-first;
- H_MSG is `S ‖ root ‖ M ‖ R ‖ A7`;
- digits come from the top 129 bits;
- §3 corrected and §7 gates strengthened.

**Found by Astra:** master's clean-room `independent_c10_signer.py` verify skips the WOTS+C digit-sum check. It accepts the `near-miss-WOTS-digit-sum` vector.

**Spec 0.2 evidence:**

- The Python reference passes its self-test.
- Three +C-only near-misses (FORS last index, WOTS sum at layer 0, at layer 1) rebuild the correct root and are rejected only by the +C checks. Rust rejects all three.
- Rust v2 matches Python byte for byte on 6 KATs.
- `digits` and `digit_sum` match a bit-level reference on about 20 k digests.
- `golden-v2.bin` (0.2) equals Python, `host_v2` and `host_v2f` (the fused routing with plain-sha2 hooks).

**Fused v2 driver entries** (`pqsigner-hw/v2`): chain, PRF+chain, node, FORS leaf, count search, with NBLW=24 and the HAL order kept. Rust routing is behind `sphincs-c10/v2-fused`, with a v2-native FORS treehash and an R-grind over prebuilt preimages. The kit golden gate passes on every run below.

**Grind luck dominates single-message figures.** WOTS tries for the frozen m0 are 69.9 k under v1 and 96.8 k under v2; the expected value is about 61 k. So `bench_avg_*` / `experiment_avg.sh` measure the mean single-pass sign over 16 messages: the same messages for both versions, verified on the device, keygen once. That is not a byte gate; the golden runs are.

| configuration | mean sign | min..max | keygen | verify | est. cached (2 passes + verify) |
|---|---:|---:|---:|---:|---:|
| v1 fused head | 110.10 M | 96.9..142.6 | 36.81 M | 182.6 k | 220.4 M (1.377 s) |
| v2 first fused cut (generic FORS, callback predicate) | 102.66 M | | 25.08 M | 107.0 k | 205.4 M |
| + v2-native FORS + R-grind | 93.09 M | | 25.14 M | | 186.3 M |
| + 24-bit-group `digit_sum` (was u64 SWAR: 24% of samples, about 370 cycles/try) | 82.64 M | | | | 165.4 M |
| **+ digit sum in the driver loop (no callback)** | **78.55 M** | 69.3..100.5 | **25.13 M** | **106.6 k** | **157.2 M (0.982 s)** |
| discard: HR0..4 by 5-register `ldm` + unrolled issue | 81.32 M | | | | (r4 spills); reverted, reproduced 78.548 M to 2 cycles |

**Head: v2 is −28.7% on sign, −32% on keygen and −42% on verify against the v1 fused head**, luck-averaged.

**Remaining**, from the profile: `prf_chain16` 50% (about 109 cycles/digest, engine-bound); search 16% (about 209 cycles/try, where engine time is about 135); FORS 22.5% (about 18 M/sign against an ideal of about 9 M: per-call Rust and driver overhead).

**Left to try:** a FORS-subtree fused entry (≈ −9 M/sign), per-key WOTS chains (≈ −1.5 M), the search loop. Fable's estimate of −40% looks reachable.
