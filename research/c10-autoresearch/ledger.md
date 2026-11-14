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

### Round 5: on-chain v2 verifier (`SPHINCsC10v2Asm.sol`, spec 0.2)

`contracts/smart-wallet/src/verifiers/SPHINCsC10v2Asm.sol` sits next to v1 and is not deployed.

**Construction:**

- 16-byte packed preimages, each written in ascending address order with A7 last (`shl(200, a7)`), per Astra's overlap finding.
- Branchless left/right selection before the stores.
- The T_k buffer is tweak-first.
- WOTS digits from the top bits.

**`test/SPHINCsC10v2Asm.t.sol`, 5/5 pass:**

- every Python reference KAT is accepted (the same KATs Rust v2 reproduces byte for byte);
- the 3 +C-only near-misses are rejected;
- 12 one-bit flips across every signature region, a wrong root and a wrong message are rejected;
- v1 and v2 do not cross-verify.

**Mutation controls:**

- Deleting the WOTS+C digit-sum check fails the near-miss test (n1 accepted).
- Deleting the FORS+C last-index check fails it too (n0 accepted).
- Restored: 5/5.

**Gas, measured:** verify 180,812 (v1) → **164,218 (v2), −9.2%**. Runtime size 1,238 → 1,213 B.

- Every verify runs exactly 361 hashes for both versions, because the digit sum is fixed at 205.
- The saving is the precompile word count; STATICCALL's 100-gas base is unchanged.

**v1 regression after all v2 edits:**

- `cargo test -p sphincs-c10` 82/0.
- The host gate passes on the fused head and the oneshot path.
- The kit frozen evaluator passes, with `cached_sign` 233,078,515, identical to the round-4 head.

**Not done:** the FSBL image was not rebuilt. Every driver addition is `cfg(feature = "v2")`, which the FSBL never names.

### Round 5: A/B on the digit position (advisor: 0.2's top-bit digits had no measured benefit in the kept code)

Measurement feature `v2-lowdigits` (`sphincs-c10` and `pqsigner-hw`): v2 with v1's digit position, the low 129 bits, and the same in-driver SWAR. 16-message average:

| | top-bit (0.2) | low-bit |
|---|---:|---:|
| mean sign | 78.55 M | 79.35 M |
| keygen | 25.13 M | 24.99 M |

- Keygen involves no digits; it moves 0.6% from code layout alone.
- The sign difference (1%) is inside grind-luck noise (about 2.5% standard error per side).
- The only reason for top-bit digits was the 5-word HR read, which was discarded.

**Decision for draft 0.3:** revert to v1's digit position. The Lean-extracted `extract_digits` and the Yul digit loop stay unchanged.

**Spec 0.2 itself is unreviewed.** Astra and Fable reviewed 0.1, and 0.2 folds in their changes. Send 0.3 back to both before calling it the candidate.

### Round 5: draft 0.3 (2026-11-13)

**Change:** WOTS digits back to v1's position (low 129 bits) everywhere:
- Python `digits()`;
- Rust: the v2 hooks in `wots::extract_digits` and `wots::digit_sum` are deleted, so both functions are byte-identical to master's again (checked by function-body diff against `0bf8153f2`);
- `v2hash::digits`/`digit_sum` and their test removed;
- the driver's in-loop SWAR is now the low-bit one (`v2_digit_sum`, words 3..7);
- the Yul loop uses v1's shape, `shr(mul(i, 3), d)`;
- feature `v2-lowdigits`, its callback search entry `pqsigner_v2_search43` and `bench_avg_v2fl` are deleted.

**Evidence:**
- `c10v2_ref.py selftest` OK. KATs regenerated: `c10v2/kat-v2-draft03.{json,txt}`, `nearmiss-v2-draft03.txt`, the forge `c10v2_kat_vectors.json`. They come from `c10v2/kat_export.py`, which reproduces the committed 0.2 files exactly from `kat-v2-draft02.json`. `pk_root`s are unchanged (keygen has no digits); all 6 signatures change.
- Rust `v2_kat` 2/2; forge `SPHINCsC10v2AsmTest` 5/5.
- **Near-miss mutation controls redone on the 0.3 vectors**, in both Rust and Solidity. Deleting the WOTS sum check accepts exactly `wots0` and `wots1`; deleting the FORS+C check accepts exactly `fors`; unmutated, all three are rejected. Stale 0.2 vectors would still have been rejected, vacuously, by a root mismatch.
- `golden-v2.bin` rewritten. It equals `host_v2` (generic), `host_v2f` (fused routing on a plain-sha2 mirror) and Python. The kit fused build reproduces it (`experiment_v2.sh v2f`: ok, cached 150.28 M on m0).
- **Regression against the earlier low-digit A/B run:** the same 16 messages give mean sign 79,349,200 against 79,348,884, each message within about 10 k cycles. The refactor changed nothing but code placement.
- v1: suite 82/0; the kit frozen evaluator passes, `cached_sign` 233,078,551 (head 233,078,515).

| configuration (16-message mean) | mean sign | keygen | verify | est. cached |
|---|---:|---:|---:|---:|
| v1 fused head | 110.10 M | 36.81 M | 182.6 k | 220.4 M (1.377 s) |
| **v2 draft 0.3 head** | **79.35 M (−27.9%)** | **24.97 M (−32%)** | **105.6 k (−42%)** | **158.8 M (0.993 s)** |

**Gas at 0.3:** 163,186 against v1's 180,812 (−9.7%). The 0.2 figure, 164,218, used different vectors and digit shifts.

### Round 5: FORS-subtree fusion, gate 5 and the 0.3 reviews (2026-11-13)

**FORS-subtree entry** (`pqsigner_v2_fors_subtree16`, signer-only, output-identical):
- It returns the root of the aligned FORS subtree of height `h` (0..11) at leaf `j0`, by an in-driver stack treehash.
- `auth[h]` of leaf `L` is exactly the subtree of height `h` at `((L >> h) ^ 1) << h`. So `sign_fors_tree` is 11 driver calls and the last-slot tree is one (`h = 11`). The auth logic stays in Rust (`v2hash::fors_auth_fused` / `fors_root_fused`), with 13 fewer digests per tree than treehash plus rebuild.
- `v2_ha` patches `ha` into A7's second DIN word: `(x & 0x7F) << 17 | (x >> 7) << 8`.

**Evidence:**
- `host_v2f` reproduces the 0.3 golden with a recursive mirror that builds A7 as an integer, independent of the word patch. Control: corrupting the height-7 node index breaks it.
- Kit golden reproduced.
- 16-message mean: **saves 3.544–3.566 M on every message** (constant, as FORS work is), with keygen and verify unchanged. Mean sign 79.35 → 75.79 M (−4.5%).
- About half the ~9 M estimate. The profile shows the entry is now engine- and bus-bound: about 45% of its samples are in the DCIS poll and most of the rest stall on DIN stores (about 150 cycles/digest against about 110 for a bare chain step).

**Gate 5** (`bench_v2drv`, `experiment_drv.sh`):
- Every fused v2 entry against software SHA-256 on the kit, with a v1 digest (NBLW = 0, oneshot or streamed, length 0..200) between every v2 call.
- 1,878 checks, 0 failures; 835 v1 probes, all correct.
- Covered: subtree at every height 0..11 at the first, last and a random position; search with n = 0, first-try hit, last-of-six hit, exhaustion, and a start at `u32::MAX − 16`.
- Controls: the `guard` build halts through the fault hook on a misaligned `j0`. A corrupted `v2_ha` plus a corrupted SWAR fail exactly the subtree (26) and search (29) groups, and nothing else.

**Reviews of 0.3 (covering 0.2):** both "adopt with changes"; no format-level break, no field alias, no store-order bug.
- **Astra** (GPT-6, `codex exec`): the first run was cut off by OpenAI's content filter before its final answer; resumed with neutral wording.
  - Its checks: the low-bit SWAR exact on 100,258 digests; a Yul packed-store model matches the spec on 2,000 cases.
  - Findings:
    1. Release Rust `pack` only `debug_assert!`ed ranges (`ha = 2048` encodes as `cp = 1`). Fixed: `assert!`.
    2. The Rust verifier turns a WOTS digit-sum mismatch into a zero node and keeps climbing; Yul and Python reject. Inherited from v1, it diverges on constructed keys only. Filed for master as **#1159**.
  - Most important gate: 5, now met.
- **Fable 5.2:** emulated the Yul `mstore` sequence on all 9 vectors (each near-miss stops at its intended check).
  - The fused grind accepted on the driver SWAR alone. Fixed: Rust re-checks with master's `wots::digit_sum` and stops the sign on a disagreement.
  - Spec overclaims, fixed in the spec:
    - the 39-byte `"pk_seed"`/`"sk_seed" ‖ master` KDF inputs share v2's F/PRF length, so the separation there is the tag prefix;
    - FORS_LAST is v2-only (#1158 stays in the v1 firmware-signing path);
    - the FV stack pinned to v1 is a cost of adopting v2.
  - Near-miss controls are now committed as `nearmiss_controls.sh` (same results as the manual run).

**Head after the fixes** (16-message mean; kit golden-v2 reproduced; v1 kit evaluator 233,078,514; option bytes re-read, identical to the baseline):

| configuration | mean sign | keygen | verify | est. cached |
|---|---:|---:|---:|---:|
| v1 fused head | 110.10 M | 36.81 M | 182.6 k | 1.377 s |
| v2 0.3 | 79.35 M | 24.97 M | 105.6 k | 0.993 s |
| v2 0.3 + FORS subtree | 75.79 M | 25.00 M | 105.6 k | 0.948 s |
| **v2 0.3 + FORS subtree + review fixes** | **75.94 M (−31.0%)** | **25.27 M (−31.4%)** | **121.4 k (−34%)** | **0.950 s** |

The release `assert!` in `pack` costs about 0.3 M in keygen and about 16 k in verify, which runs `pack` per hash on the generic path. Kept: correctness over 0.2% of sign.

**Left:**
- The last FORS tree, about 0.9 M/pass; a spec §6 decision, see #1158.
- Per-key WOTS chains: `prf_chain16` is 65% of samples and engine-bound, so ≤ about 2%.
- The search collect reads 8 HR words where 5 suffice: about 0.5 M.
- Loop micro-tuning in the subtree entry: about 1 M.

**Control for the Rust re-check:** a `host_v2f` mirror that reports a false hit (count `start + 1` with the wrong sum) stops the sign at `wots.rs:125` ("v2 grind: driver digit sum disagrees"). Restored: GOLDEN OK. Note: the `e7dc446bd` message says keygen and verify are unchanged; that was measured before the `pack` asserts went into the same commit (see the table above).

## Round 6 (2026-11-13): more hypotheses on the v2 head

### H1: v2 plus the top-layer cache (track B, #1148), measured

- **Enabling it:** the round-5 `compile_error!` that excluded `top-cache` under `v2` is removed.
  - The cache code is hash-agnostic except the confirm build's chain rotation, which existed only on the v1 `hw-sha256-prfchain` path. Under v2 the "independent" second build silently replayed the first, so the generic/v2 path now computes the same chains in rotated order.
  - The host keygen-fault control injected only into the v1 chain hook, so under v2 it injected nothing and "SIGNED" vacuously. It now also injects into the v2 PRF+chain mirror.
- **Host evidence** (`host_v2f --features topcache`):
  - golden-v2 bytes with 3 cache hits;
  - signing digests per pass 486,372 → 314,632;
  - controls: a flipped node, a keygen fault and another key's cache are all REFUSED; the valid cache SIGNS;
  - sweep: all 512 leaves' cached auth paths equal a full rebuild.
- **Kit** (`experiment_v2b.sh`, `bench_v2fb`): golden-v2 bytes, 3 hits, cached sign (m0) **96.2 M = 0.601 s**. Keygen 49.9 M (0.31 s): fill plus the confirm build.
- **16-message mean** (`BENCH_FEATURES=topcache ./experiment_avg.sh v2f`): 16/16 cache hits.

| | mean sign | est. cached | vs master 3.41 s |
|---|---:|---:|---:|
| v1 fused head | 110.10 M | 1.377 s | −60% |
| v2 head | 75.94 M | 0.950 s | −72% |
| **v2 head + top cache** | **52.10 M** | **0.652 s** | **−81%** |

- **Saving:** 23.8 M on every message (constant: the top-layer build).
- **Projection check:** the round-4 projection was 0.68 s; m0 alone reads 0.60 s because its grinds are lucky.
- **Still track B:** the FI trade (the top auth path is not double-computed per sign) and the keygen-confirm design need the owner's decision on #1148.

### H2: per-key WOTS entry (`pqsigner_v2_wots_chains16`), keep (output-identical)

- **The entry:** one driver call computes a key's 43 chains (PRF, then `steps` steps each) straight into the T_43 preimage buffer (`v2hash::wots_pk_fused`, routed from `wots::keygen_pk` under `v2-fused`). `ci` is patched into A7's second DIN word as `ci << 2`.
- **Not used for:** signing chains, which keep the F-16 shuffle, or the cache's rotated confirm build, which stays a different computation on purpose.
- **Evidence:**
  - host golden-v2, plain and `topcache`; the mirror builds `ci` into A7 as an integer;
  - kit golden reproduced;
  - gate 5 extended with a `wots_chains16` group (40 whole keys, `steps` 7 or random 0..15): 1,969 checks, 0 failures, 876 v1 probes.
- **Note on digest counts:** the plain host count 486,372 → 486,216 per pass comes from the earlier FORS-subtree commit (12 auth trees × 13 digests), not from this change.

| 16-message mean | before | after | per message |
|---|---:|---:|---:|
| v2, sign | 75.94 M | **71.29 M (−6.1%)** | −4.62..−4.65 M |
| v2, keygen | 25.27 M | 22.66 M (−10%) | |
| v2 + top cache, sign | 52.10 M | **49.39 M (−5.2%)** | −2.68..−2.72 M |
| est. cached sign | 0.950 / 0.652 s | **0.892 / 0.618 s** | |

- **Size of the win:** about 3× the round-5 estimate (≈ −1.5 M). The per-chain Rust path (`set_chain_index` on a 32-byte ADRS, `a7_of` parsing it back, two `pack`s with release asserts, the call) cost about 100 cycles per chain, × 44 k chains per pass.
- **Against v1's fused head:** −35.2% (plain), −55.1% (with the cache).

### H3: PRF value in the last FORS slot (spec §6, #1158), measured, NOT adopted

- **The variant:** feature `v2-fors-last-prf` (measurement only). The slot carries `fors_secret(sk_seed, ht_idx, 12, 0)` instead of the root of a fully built tree 12. Deterministic per `ht_idx`, and the verifier is unchanged.
- **Kit:** all 16 variant signatures verify on the device.
- **Why the measured mean (−1.79 M) is not the saving:** the slot value enters the FORS public key, which every WOTS+C grind hashes, so the counts change. The per-message delta spreads from −14.9 to +17.3 M: grind luck, not a saving.
- **The deterministic saving** is one full FORS tree per pass: 6,142 digests, about 0.94 M from the subtree entry's measured per-tree cost, i.e. about 1.3% of the current pass.
- **Adoption needs:** the owner's decision plus a review against the FORS+C argument (spec §6), and new KATs and golden, since signature bytes change.

### H4: whole-key WOTS entry (`pqsigner_v2_wots_pk16`), keep (output-identical)

- **The entry:** H2's chains plus the T_43 compression in one call. The 712-byte preimage is a driver-side `MaybeUninit` buffer written in full (6 header words, then 43 × 4 chain words) and handed to the existing `oneshot16`, so it is never zero-filled. The Rust buffer is gone.
- **Evidence:**
  - host golden-v2 (plain and `topcache`), and cache controls unchanged (3 refuse, 1 signs, 512-leaf sweep);
  - kit golden and golden + cache (3 hits);
  - gate 5 with a `wots_pk16` group (40 keys against a software T_43): 2,061 checks, 0 failures.
- **16-message mean:** v2 71.29 → **70.86 M (−0.61%)**, 431–437 k on every message. With the cache 49.39 → **49.16 M**. Est. cached sign **0.887 s / 0.615 s**. Kit m0 with the cache: 0.570 s.
- **Size of the win:** about 0.6 of the ~0.7 M estimate; part of `memclr` was other buffers.

### H5: count-search collect reads only HR3..HR7, discard

- **The variant:** 5 HR words per try instead of 8; a hit recomputes its digest to read all eight.
- **Result:** gate 5 passes and the golden is reproduced, but signA_m0 went 67.16 → **69.00 M (+1.84 M)**. Reverted, and the restore reproduces 67.16 M.
- **Reading:** same direction as v1's lever 3 (fewer HR reads, no gain). The reshaped loop costs more than three skipped reads save.

### H6: NBLW written once per v2 entry, INIT-only per digest, keep (output-identical)

- **The change:** `v2_begin` wrote STR = NBLW before every INIT, the HAL order. INIT leaves STR alone, and every v2 digest's own DCAL write carries the same NBLW = 24. Now `v2_entry()` (wait idle, STR = 24) runs once at the start of each v2 entry; each digest inside does only the ready/stale-DCIS check and INIT. NBLW is still set before every data phase and with every DCAL.
- **Evidence:**
  - gate 5: 2,061/0, with all 917 interleaved v1 digests (NBLW = 0) correct, so the 24 → 0 → 24 transitions at entry boundaries hold;
  - kit golden, and golden + cache (3 hits, m0 cached 0.5625 s).
- **16-message mean:** v2 70.86 → **69.80 M (−1.50%)**; with the cache 49.16 → **48.47 M (−1.39%)**. Per message 0.88–1.35 M, larger with more grind tries (one STR write fewer per try).
- **Costs:** verify rises about 2 k (single-digest entries now pay the entry setup); keygen −1.7%.
- **Est. cached sign:** 0.873 s, or **0.607 s** with the cache.

### H7: R grind in the driver (`pqsigner_v2_grind_r`), keep (output-identical)

- **The entry:** the whole FORS+C R grind in one call. The nonce is patched into a driver-side copy of the PRF input (103 or 119 bytes, wiped with volatile writes before return). R is written into H_MSG's words 16..19, and the last FORS index is checked as `(HR3 >> 4) & 0x7FF`. Rust re-checks the result with `fors::read_bits_le`.
- **Evidence:**
  - host golden-v2, plain and `topcache` (the mirror is plain sha2);
  - kit golden, and golden + cache (3 hits, m0 cached **0.549 s**);
  - gate 5 with a `grind_r` group: the first hit found in software, plus a run stopped one try short that must report exhaustion. 2,089 checks, 0 failures, 930 v1 probes.
- **16-message mean:** v2 69.80 → **69.07 M (−1.05%)**; with the cache 48.47 → **47.71 M (−1.57%)**. Per message 0.05–2.1 M, since R-grind tries vary.
- **Est. cached sign:** 0.864 s, or **0.597 s** with the cache. Fable estimated about 0.7 M (`fable-hypotheses-5.md`, "not worth doing"); measured about 0.73 M mean.

Fable's round-6 list is in `fable-hypotheses-5.md`.

### Test zero and H8: register diet in the v2 loops, keep (output-identical)

**Test zero** (`bench_v2micro`, `experiment_micro.sh`; DWT cycles per digest per entry, in isolation, not a gate). Before H8:

| entry | cycles/digest |
|---|---:|
| `chain16`, 15 steps | 127.0 |
| `chain16`, 1 step (entry + digest) | 198.0 |
| `node16` | 175.0 |
| `wots_chains16` | 119.6 |
| `wots_pk16` | 123.2 |
| `fors_subtree16` h = 11 | 145.2 |
| `search43`, per try | 173.0 |

The chain loop sat about 16 cycles above the unit-cost floor (about 111). The disassembly showed seven stack reloads per step, interleaved with the DIN stores (Fable item 1), and a register pinned to the non-encodable timeout constant 10,000,001.

**H8:**
- The chain loop's variable is the second A7 word (`a1 += 1 << 12` up to an end word). This frees `start`, `step`, `steps` and `low24`.
- The v2-only polls (`v2_ready_sr`, `v2_wait_dcis`) count down from `1 << 24`, an encodable immediate, so no constant stays live. The shared v1/FSBL `wait_ready_sr` is untouched.

| entry | before | after |
|---|---:|---:|
| `chain16`, 15 steps | 127.0 | **116.2** |
| `wots_chains16` | 119.6 | 117.0 |
| `node16` | 175.0 | 169.0 |
| `fors_subtree16` | 145.2 | 142.4 |
| `search43` per try | 173.0 | 174.0 |

- **Evidence:** gate 5 2,089/0; the guard halts at stage 200; kit golden; golden + cache (3 hits, m0 cached 0.541 s).
- **16-message mean:** v2 69.07 → **67.96 M (−1.61%)**, 1.00–1.18 M on every message; with the cache 47.71 → **47.05 M (−1.38%)**.
- **Est. cached sign:** 0.850 s, or **0.589 s** with the cache. Against v1's fused head: −38.3% plain, −57.3% with the cache.

### H9: count search with an exact early reject, keep (output-identical)

- **The changes:** per try the loop now reads only HR3..HR7 and feeds the 8 fixed message words from memory in four-word groups (`feed_words`) instead of 8 stack reloads. It sums digits 0..31 first: digits 32..42 add at most 11 × 7 = 77, so `s4 + 77 < target` cannot hit and the rest of the sum is skipped. That is about 89% of tries at 205 (the 32-digit partial has mean 112 and sd 13). A hit (twice per pass) drops the try in flight and recomputes its digest to read all eight words.
- **Branching:** on public grind data only, as before.
- **Microbench:** 174 → **137 cycles per try** (measured with an unreachable target, so every try takes the early reject).
- **Evidence:**
  - gate 5 2,091/0. New cases search for the real target 205 over long runs against a software search, exercising the early reject on real digests.
  - kit golden; golden + cache (3 hits, m0 cached **0.521 s**).
- **16-message mean:** v2 67.96 → **65.59 M (−3.48%)**; with the cache 47.05 → **44.69 M (−5.02%)**. Per message 0.36–5.6 M, scaling with the message's grind tries.
- **Est. cached sign:** 0.821 s, or **0.559 s** with the cache. Against v1's fused head: −40.4% plain, −59.4% with the cache.
- **Why H5 failed and this works:** H5 also read 5 words but kept the full sum and the stack-fed issue. Neither the read count nor the sum alone was the limit; the sum plus 10 stack reloads exceeded the engine time.

### H10, H11: FORS subtree loop, discards

- **H10:** `S` fed from the caller's buffer as a grouped load instead of stack reloads: 142.4 → 142.2 cycles/digest, no change. Interleaved reloads are not what makes the subtree slow.
- **H11:** leaves processed in pairs (height-1 node straight from registers, closures for leaf and node): **142.4 → 151.1**, worse.
- Both reverted; the microbench is back at 142.4.
- The subtree's remaining excess over the chain loop (about 20 cycles/digest, about 1.6 M per pass) is per-leaf bookkeeping; not pursued further this round.

### Round 6 summary (2026-11-13)

| configuration (16-message mean) | sign | est. cached sign | vs v1 fused head |
|---|---:|---:|---:|
| v1 fused head | 110.10 M | 1.377 s | |
| v2 at the start of round 6 | 75.94 M | 0.950 s | −31.0% |
| **v2 head** | **65.59 M** | **0.821 s** | **−40.4%** |
| v2 + top cache at round start (H1) | 52.10 M | 0.652 s | −52.7% |
| **v2 head + top cache** | **44.69 M** | **0.559 s** | **−59.4%** |

- **Against master as shipped** (3.41 s cached): −76% plain, **−84% with the cache**.
- **Kept (output-identical):**
  - H2 per-key WOTS chains (−6.1%);
  - H4 whole-key entry (−0.6%);
  - H6 NBLW once per entry (−1.5%);
  - H7 R grind in the driver (−1.05%);
  - H8 register diet (−1.6%);
  - H9 search early reject (−3.5%).
- **Track B:** H1 (the top cache under v2).
- **Measured, not adopted:** H3, the last-slot PRF (about 0.94 M/pass deterministic; needs an owner decision).
- **Discards:** H5 (5-word collect alone), H10, H11.
- **Gate 5:** 2,091 checks, 0 failures, with every v2 entry including the new ones.
- **Regression at the end:** v1 suite 82/0; v1 kit 233,078,504; v1 track B unchanged (163.35 M, 3 hits); option bytes identical to the baseline.

**Format-level options from Fable (owner decisions, not tested):**
1. `target_sum` 205 → 200: about −5.8 M/pass and about +2.5–4.5k verify gas; reopens the proof constants.
2. Two WOTS/FORS secrets per PRF digest: about −4 M/pass; keys change, the verifier does not.
3. An 8 + 10 hypertree split with the top cache: about −11 M/pass; the cache becomes structural, and keygen doubles.

**Round 6 close-out controls (advisor):**
- **UI tick:** H9's inlined HR read had dropped the per-digest `pqsigner_hash_tick()` under `tick-hook`. Restored. With `--features tick` the search entry links three tick calls again. No bench enables the feature, so no measured number changes.
- **H9's accept predicate** (`c10v2/h9_predicate.py`):
  - transcribed against `sum((D >> 3i) & 7)` on 1,111,280 checks: 200k random digests, all 256 single-bit digests, 2,000 exact boundary digests (digits 0..31 sum to 128, digits 32..42 all 7), and 20k near-target digests, at 5 targets;
  - 0 mismatches. The 77 → 76 control gives exactly 2,000 mismatches, the boundary cases.
- **H7's Rust FORS+C re-check:** a `host_v2f` mirror that returns the first nonce whatever its index stops the sign at `v2hash.rs:313` ("driver FORS+C check disagrees"). Restored: GOLDEN OK.

## Format options: security check and measurements (2026-11-13)

Owner: "check that the 3 format changes do not impact security before committing. Run tests on them and do an analysis." The full write-up is in `format-options-security.md`. Each option sits behind its own off-by-default flag:
- `sphincs-c10`: `v2-ts200`, `v2-prf2`, `v2-split810`;
- `pqsigner-hw`: `v2-prf2`, `v2-split810`;
- Python: `c10v2_ref.py --variant`;
- Yul: `SPHINCsC10v2{Ts200,Split810,All3}Asm.sol`.

Draft 0.3 is byte-identical with every flag off.

| configuration | luck-free mean sign | with top cache | est. cached sign (with cache) |
|---|---:|---:|---:|
| 0.3 head | 64.52 M | 43.62 M | 0.546 s |
| ts200 | 58.54 M (−9.3%) | 37.64 M (−13.7%) | 0.471 s |
| prf2 | 61.93 M (−4.0%) | 41.93 M (−3.9%) | 0.525 s |
| split810 | 75.33 M (+16.7%) | 32.85 M (−24.7%) | 0.411 s |
| all three | 66.27 M | 25.65 M (−41.2%) | 0.321 s |

- **Luck-free means.**
  - `luck_fit.py` fits each configuration's 16 per-message kit cycles against that message's exact WOTS tries and R nonces, taken from the host (`c10-ar-host luck16`).
  - c_w = 140–143 cycles/try, c_r ≈ 496 cycles/nonce, residual SD ≤ 5k cycles.
  - Raw means are in the doc.
- **Security verdicts:**
  - **ts200:** no change for honest operation. A key whose WOTS key signs a second digest (fault, bug, or reuse across formats) keeps about 1.7 bits less margin: median 2^55.3 → 2^53.7.
  - **prf2:** no change under the PRF assumption, provided the sk_seed-keyed inputs stay block-prefix-free. They do: "R_grind" is not a producible A7. About 48 whole PRF outputs per key become public at the cap.
  - **split810:** no change to the bounds. The A7 widening checks out. It is conditional on #1148, because the cache becomes structural.
- **New finding: reusing a key across formats.** The same seed signing under two v2 variants is unsafe:
  - **0.3 + ts200:** median 2^53–2^55 per forgery try. Keys are unchanged, so the address does not move either.
  - **0.3 + prf2:** median 2^77; the even-index secrets are shared.
  - **0.3 + split810:** large overlap. Astra found it; I verified it. 0.3's `(kp, ci)` equals split810's `(2kp + ⌊ci/32⌋, 2ci mod 64)` byte for byte. 38% of split810's WOTS PRF addresses equal a 0.3 address, and FORS trees 0..6 equal split810's 0, 2, …, 12.
  - Rule: fix the variant before any v2 key signs, or bind the format identifier into key derivation or the tweaks.
- **Tests:**
  - **Reference and host:** Python selftest and cross-format checks per variant. Rust matches the Python KATs per variant and combined. Host fused routing, plain and with the cache, equals the generic golden.
  - **Cache controls under split810:** 3 refusals, 1 positive control, and a sweep of all 1,024 leaves.
  - **Kit:** goldens for all four configurations. Gate 5: 0.3 2,091/0, prf2 2,091/0, split810 2,098/0, prf2+split810 2,098/0.
  - `h9_predicate.py` at 200: 0 mismatches, and the control fires.
  - **Forge:** 19/19, plus 21 mutation controls.
- **Verify gas, measured in the callee:**

  | verifier | gas | delta vs 0.3 |
  |---|---:|---:|
  | 0.3 | 157,585 | |
  | ts200 | 160,735 | +3,150 |
  | split810 | 157,653 | +68 |
  | all three | 160,803 | +3,218 |

- **Review (GPT-6 Astra, read-only, independent):**
  - no format break in any isolated variant;
  - cross-variant reuse rated HIGH;
  - `variant_controls.sh` did not assert its results: fixed, every row now checks its expectation and the run passes;
  - `near-miss-gen` + split810 is now a `compile_error!`;
  - wording corrections folded into the doc: top keys double, the cache reuses only the stored nodes, HR residue now holds a sibling secret.
- **After the advisor's check:**
  - kit goldens with the cache for all four variant configurations, 3 hits each;
  - the FSBL image is byte-identical to the parent commit's;
  - `lean_extract` 79/0;
  - re-runs at the committed head pass.
  - `v2-fors-last-prf` belongs to the same reuse class as ts200: it keeps `pk_root` and changes the FORS pk.
- **Regression after the edits:**
  - v1: suite 82/0; kit 233,078,450; track B 163,351,100 (3 hits).
  - 0.3: golden passes plain and with the cache; mean 65,593,849 (65,593,725 before the edits); gate 5 2,091/0.
  - Option bytes identical to the baseline.

## Round 7 (2026-11-13): driver wave, output-identical only

The owner asked for a wave with new hypotheses, noting there is "still a bit of juice left in the hash driver", and asked that no security bound change. This wave therefore takes output-identical changes only: no format, parameter or preimage change. Fable's list is `fable-hypotheses-6.md`.

### Test zero: what the HASH peripheral actually costs [measured, `bench_v2micro` probes 8–11]

| quantity | cycles |
|---|---:|
| DIN store, back to back (unrolled asm) | **1.0** |
| SR load, HR load | **1.0** each |
| DCAL → DCIS (spin-threshold probe: 19 × 3-cycle spins, then one SR read) | ~60 |
| DCAL → DCIS seen by a tight poll | 69 |
| DCIS → BUSY clear | ~9 |
| INIT, 10 DIN, DCAL, DCIS, HR read + SR clear, BUSY clear (one tight step) | 96 |
| a 39-cycle gap between INIT and the first DIN | adds 38: INIT needs no settle time |

- **The bus is zero-wait.** Fable's model assumed 2.6 cycles per access, taken from the context-restore burst figure. At 1 cycle per access, the per-digest excess is serial CPU work between DCIS and the next DCAL, plus poll-phase lag, not bus cost.
- **The chain step:** the steady state is 111 cycles (per-call overhead fitted out), against a floor of about 96.

### H1: `v2-asm-chain`, keep (commit `a7d048304`)

**What changed.** A hand-scheduled chain loop in inline asm, shared by `chain16`, `prf_chain16` and `wots_chains16`:
- `S` stays in r8..r11, the HR read lands in r0..r3, and the CR value is pinned in `lr`;
- loop control runs inside the engine window;
- a timed spin precedes a single first DCIS poll, whose hit falls through;
- straight-line and counted slow polls sit out of line.

**Checks kept:** the same as the Rust loop. BUSY spin with a 2^24 guard, stale-DCIS tripwire, DCIS poll with a 2^24 guard, SR clear.

**Asm without the timed poll:** 116.3, no change. The compiler's critical path was the same length.

**Timed-spin sweep** (cycles per `chain16` digest):

| spin | 12 | 13 | 14 | 15 | 16 | 18 | 20 |
|---|---:|---:|---:|---:|---:|---:|---:|
| cycles | 108.0 | **103.3** | 107.1 | 110.8 | 114.5 | 122.0 | 129.5 |

Spin 13 gives a steady state of about 97 cycles, at the floor. One step early costs about 5 cycles; late costs the overshoot.

**Microbench:** `chain16` 116.2 → 103.3, `wots_chains16` 117.0 → 106.2, `wots_pk16` 120.5 → 109.8.

**16-message mean:** sign 65.59 → **61.81 M (−5.8%)**, keygen 21.58 → 19.69 M (−8.8%), est. cached sign 0.821 → 0.773 s.

**Evidence:**
- gate 5: 2,091/0;
- guard halt;
- a **new stale-DCIS control** (`bench_v2drv --features stale`): a digest left uncleared must make `chain16` fault. It fires on asm and on the Rust loop. The positive control (cleared) completes. A mutant asm with the stale check removed passes the stale digest through (stage 301, caught); restored, it faults.
- kit golden;
- golden + cache: 3 hits, m0 cached 0.497 s.

### H2: `v2-asm-search`, keep (commit `b3e488e25`)

**What changed.** A hand-scheduled count search:
- HR3..HR7 in one `ldm`, and `S‖m` via two `ldm`;
- the CR value in `lr`;
- the digit sum and exact early reject moved entirely into the next try's engine window;
- a timed first poll;
- hit handling stays in the existing Rust (drain the try in flight, recompute, collect 8 words).

**First attempt:** the same `g24` sum in asm was 134–138 per try. The sum overran the engine window: each spin iteration added directly to the time per try.

**Exact sum, re-derived:**
- ten whole 3-bit digits per word (w7, w6 >> 1, w5 >> 2, plus the two straddling digits);
- paired under A = 0o0707070707, folded to 12-bit fields, summed by one multiply by 0x01001001.

**A first version was wrong** and the microbench caught it. It multiplied by 0x01041041 over 6-bit fields; the next partial product lands at bit 30, inside the 7-bit result. It found hits after 45,148 tries instead of 249,343.

**The fold version:**
- was checked in Python against the reference digit sum on 300k vectors, including all-7 and patterned words, before the kit run;
- finds the same 249,343 tries.

**Microbench:** early reject 137 → 114 cycles per try; real target 205: 140 → 115.1.

**16-message mean:** sign 61.81 → **60.07 M (−2.8%)**.

**Evidence:**
- gate 5: 2,091/0, search group 0;
- a **stale-search control**, its positive control, and a mutant (the stale check removed: caught, stage 301), then restored;
- kit golden; golden + cache: m0 cached 0.482 s.

### Round 7 standing (v2 0.3 format, 16-message mean, kit at 160 MHz)

| | mean sign | est. cached sign | with top cache (m0, kit golden) |
|---|---:|---:|---:|
| start of round 7 | 65.59 M | 0.821 s | 0.521 s |
| **after H1 + H2** | **60.07 M (−8.4%)** | **0.752 s** | **0.482 s** |

- **v1 (deployed format):** unchanged. Kit golden 233,078,552.
- **FSBL:** `make fsbl BOARD=iota2` image byte-identical to the round's parent (every addition is behind `v2-asm-*`, which the FSBL never names).
- **Security:** output-identical, so the scheme and its bounds are unchanged; same FI checks. The asm is new review surface, and it replaces Rust that had no FV coverage either: the driver is not extracted.

### Not done, next

- **`fors_subtree16`:** 142.4 per digest against a ~100 floor, 79.8k digests per pass, ≤ ~3 M. The same treatment applies, but the tree bookkeeping makes it the largest asm piece.
- **v1:**
  - the timed-poll treatment for `chain_steps` (two-block messages, so only the poll lag and post-DCIS path move);
  - Fable's item 13, the `search128` digit sum and early reject in the driver. Not yet measured: v1's two-block try gives the predicate a ~130-cycle window, so the gain may be smaller than Fable's 3–5 M.
- **Group B** (owner decisions): dropping the per-digest SR clear; #1151's no-BUSY-wait. On the asm loops, BUSY clears within the post-DCIS work, so the latter is now worth less.
- **Bench-side tuning only:** the timed-spin constants (13, 1) are tuned on this kit at 160 MHz with ICACHE 2-way; a different clock or code placement needs a re-sweep. An early poll costs a few cycles, a late one the overshoot.

### Round 7 follow-up checks (after the advisor review)

**Attribution: is asm needed?** The two levers were tested in plain Rust, asm off:
- **Timed poll in the Rust chain loop:** spins 3–11 give 116–122 cycles per digest, no gain over 116.2. Rust cannot hold the phase; the chain needs the asm schedule.
- **Fold-multiply sum in the Rust search** (`v2-fold-sum`, kept off by default as a fallback): 137 → 126 per try. The asm gives 114, worth about 0.7 M per pass more.

**Product configuration (caveat).**
- Both asm paths compile out under `tick-hook` without `tick-batch`, the per-digest UI tick. A product build in that configuration silently runs the old loops.
- The −8.4% is a no-tick bench figure and reaches the product only with the batched tick (#1149) or a tick inside the asm loops.

**Rust fallback at head** (bench crates with both asm features off): gate 5 2,523/0; kit golden passes.

**Dense digit-sum sweep, added to gate 5** (group 6b):
- the driver search against software search over 96 tries, 6 random keys, 32 targets;
- targets 140..160: hits dense, the full-sum path;
- targets 180..200 even: both sides of the early reject.

Gate 5 is now 2,523/0. Mutant: the straddling-digit field `bfi r11, r2, #1, #2` changed to `#1, #1` gives **125 failures** (search group); restored, 0.

**Format variants at head (with the asm):**
- goldens plain and cached (3 hits each) pass for ts200, prf2, split810 and all three;
- gate 5: prf2 2,523/0, split810 2,530/0, prf2+split810 2,530/0.

**Search asm stack:** now pushes 6 words, so `sp` stays 8-byte aligned at the `bl` to the fault hook.

**Final head after the follow-ups:**
- The 6-word push and the follow-up edits moved the search's best timed spin from 1 to 2, costing about 2 cycles per try (114 → 116; real target 115.1 → 117.1). Aligning the loop head (`.p2align 2`) made no difference, so it is not used.
- **16-message mean:** sign **60.21 M (−8.2% vs 65.59 M at round start)**, keygen 19.69 M, verify 119.2k, est. cached sign 0.753 s (raw mean, not luck-corrected).
- **Gates:** gate 5 2,523/0; stale-search control fires; kit golden; golden + cache (3 hits, m0 0.4835 s single message).
- **The spin constants are phase-sensitive to code layout:** any edit near these loops needs a re-sweep.

### H3: `v2-asm-fors`, keep (commit `f075e48d1`)

**What changed.** The FORS subtree keeps its tree logic in Rust (leaf order, fold decisions, node stack), which now runs inside each digest's engine window. Three asm transitions (into PRF, F and H) do the critical path:
- wait for DCIS with straight-line polls, then a 2^24-guarded loop;
- read HR, clear SR;
- BUSY/stale check;
- INIT, feed the next message from staging (`ss` = S, a0, a1'; `ps` = sk_seed, p0, p1'), DCAL.

The staged `sk_seed` copy is wiped with volatile writes. prf2 keeps the Rust subtree.

**Results:**
- `fors_subtree16`: 142.4 → **111.9** cycles per digest;
- v2 mean sign 60.21 → **57.82 M (−4.0%)**.

**Evidence:**
- gate 5: 2,523/0;
- an L/R-swap mutant in the H transition gives 33 failures; restored, 0;
- guard and stale controls;
- goldens plain and cached;
- ts200, split810 and all-three goldens plain and cached;
- gate 5 for split810: 2,530/0.

### H4: `v1-asm-chain` (deployed format), keep (commit `c5fc39130`)

**Probe of a v1 two-block step** (96-byte message, NBLW = 0), timed from INIT:

| point | cycles |
|---|---:|
| 16 stores done | 26 |
| 17th store (block 1 starts) | 31 |
| 18th store | waits for block 1 |
| 24th store + DCAL | 88 |
| DCIS | 156 |

So the floor is about 160–168 cycles per step.

**What changed.** An asm loop for the WOTS-shaped (`Z`) chain:
- staged block-1 words;
- `lr` serves as the CR value, then as the zero register after INIT;
- loop control after the stalling store;
- a timed first poll.

The same checks as the Rust loop.

**The timed spin is context-dependent:**

| context | Rust | best asm | best spin |
|---|---:|---:|---:|
| standalone `chain16` | 206.9 | 180.9 | 18 |
| per-key `wots_chains16` (the signer's path) | 198.6 | 188.3 | 14 |

At 18 the per-key path was slightly *slower* than Rust, and v1's mean rose +0.56%. Tuned at 14 for the per-key path: v1 mean sign 110.10 → **106.49 M (−3.3%)**, keygen 36.81 → 35.02 M (−4.9%), golden cached sign 233.08 → 225.84 M (−3.1%).

**Evidence:**
- kit differential: 32/32 equal to pristine master;
- v1 golden;
- `stale-v1` control fires, its positive control completes;
- gate 5: 2,523/0;
- FSBL image byte-identical (`make fsbl BOARD=iota2`).

The asm's in-loop stale check (as in H3) cannot be reached by a control: the entry check fires first.

### Round 7 close (luck-corrected expected means, kit 160 MHz)

| configuration | round start | round end | est. cached sign start → end |
|---|---:|---:|---:|
| v2 0.3 | 64.52 M | **56.93 M (−11.8%)** | 0.808 → **0.712 s** |
| v2 0.3 + top cache | 43.62 M | **37.83 M (−13.3%)** | 0.546 → **0.474 s** |
| all three options + cache | 25.65 M | 24.50 M (−4.5%) | 0.321 → 0.307 s |
| v1, deployed (raw 16-message mean; keys unchanged) | 110.10 M | **106.49 M (−3.3%)** | 1.377 → 1.332 s |

- **All three options + cache:** no FORS gain, because prf2 keeps the Rust subtree. A prf2 transition is the next step there.

**Next:**
- prf2 FORS transitions;
- v1 PRF/FORS paths;
- v1 `search128`: three blocks per try (128 bytes + padding), so the predicate is likely hidden; profile first.
- `node16`/T_43 are small.
- **Product:** H1–H4 compile out under the per-digest tick (#1149).

### Round 7 fixes (after the advisor's second review)

- **H2 alignment bug, real.** The search asm loaded `S ‖ m` with `ldm` straight from the caller's byte pointer. LDM faults on an unaligned address, and the contract promises only "32 readable bytes".
  - Gate 5's dense sweep now passes `sm` at an odd address. Before the fix it **hard-faulted** (status 0xfa170003, stage 7).
  - The wrapper now copies `sm` (public data) into an aligned `[u32; 8]`. Gate 5 2,523/0 with the odd address.
- **H3 secret copy removed.** The PRF transition now reads `sk_seed` in place with single `ldr`s (unaligned-safe) and stages only `[p0, p1']`, so there is no copy of the secret to wipe on the fault path. `fors_subtree16`: 111.9 → 110.6.
- **Search spin re-swept** after the layout change: 1 (114.0 per try).
- **Re-gated:**
  - gate 5 for 0.3 and split810;
  - guard, stale, stale-search and stale-v1 controls;
  - v2 goldens, plain and cached; ts200, split810 and all-three goldens, plain and cached;
  - v1 golden 225,840,970.
- **Means (2-way):** v2 57.54 M; v1 106.49 M.
- **Shipped 1-way ICACHE** (`EXP_CFLAGS=`), asm on against off:

  | | asm off | asm on | change |
  |---|---:|---:|---:|
  | v2 | 65.61 M | 57.56 M | −12.3% |
  | v1 | 110.21 M | 106.58 M | −3.3% |

  The 2-way-tuned spins hold.
- **"0.337":** not found in any session transcript (only timestamps), log or #1155 comment. The closest reported figure is 0.321 s (≈ 0.32 s), for all three options plus the cache.

## Round 8 (2026-11-13): v1 (deployed format) driver wave, output-identical only

Constraint as round 7: no change to any security bound; keys and signatures byte-identical. All work is on v1, the deployed format; v2 is untouched (v2f mean 57.54 M at head, unchanged: no leak).

### Test zero: v1 per-entry costs and floors [`bench_v1micro`, `experiment_v1micro.sh`]

**Profile first** (PC sampling over the 16-message v1 bench, 106.49 M mean sign): `wots_chains16` 62.8%, `fors_subtree16` 15.9%, `search128` 8.5% + `hits_target` 4.3%, `oneshot` (mostly the R grind) 2.55%, `th_multi16` 2.1%, memcpy/memclr ~1.5%.

| entry (v1) | start of round | floor (INIT→DCIS + ~14) |
|---|---:|---:|
| keygen-shape key (43 × (PRF + 7 steps)) | 189.6 cyc/digest | ~161 per step |
| `chain16` × 15 | 185.8 /step | ~161 |
| `fors_subtree16` | 10,897 /call (231.9 /digest) | ~7,500 /call |
| `search128` | 300 /try (pred false 304, digit sum 299: the predicate is already hidden) | ~226 |
| R grind (two one-shots) | 423 + 422 + Rust per nonce | ~395 |
| raw INIT→DCIS, asm stores: 1 / 2 / 3 blocks | 82 / 147 / 212 | |

**Block-0 window probe** (`--features win`): ALU work placed between the 17th DIN store (block 0 starts) and the 18th is free up to **44–46 cycles** for 2- and 3-block messages (147 → 149 at 48, then 1:1). That window is where every round-8 change puts non-feed work.

### E1: `v1-asm-chain` reorder, keep (`8ef5b8a7e`)
`rev r1..r3`, the position add, the end reload and the DCAL constant moved into the block-0 window; r1..r3 enter byte-swapped. `chain16` × 15 185.8 → 178.7; keygen shape 189.6 → 186.7; v1 mean 106.49 → 105.95 M. Golden, kdiff 32/32, gate 5, stale-v1 + positive, FSBL identical; a dropped-`rev` mutant fails the golden.

### E2: `v1-asm-key`, keep (`4d9816b67`, fixes `41d61c303`, `c155c600e`)
Whole WOTS key of the keygen shape (no order/digits, WOTS zero words, steps > 0; ~1,024 keys/sign) in one asm loop: the 80-byte PRF (`sk_seed` single `ldr` in place, never copied) and the chain steps; the previous chain's output store and the next index in the PRF's block-0 window. Keygen shape 186.7 → ~171 cyc/digest; v1 mean 105.95 → 101.43 M, keygen 34.76 → 32.47 M.
- **Astra (defect, fixed):** with `out` overlapping `sk_seed` the asm stored chain i after chain i+1's PRF read `sk_seed`; the Rust loop stores first. Reproduced (`out == sk_seed`, n = 2). The asm path is now taken only for disjoint ranges; the aliased case is in the microbench check (8/8).
- **My bug, fixed:** inserting the guard's `let` between the `#[cfg]` and the `if` moved the attribute onto the `let`: the v2 crates stopped compiling and a `tick-hook` build would have called a compiled-out fn. Caught by the v2f leak check.
- **Evidence:** software-SHA key check (7 step counts, odd `sk_seed`/tail/seed_adrs/out, plus aliasing); stale control fires, positive completes; mutant A (Rust entry check removed): the asm PRF check still halts; mutant B (both removed): passes through; `rev(i)`-store mutant 7/7 keys wrong; golden, kdiff 32/32, FSBL identical.

### E3: `v1-asm-fors`, keep (`cd1186608`, fix `0fc20a171`)
The v2 H3 pattern on v1: asm transitions into PRF (1 block), leaf (2 blocks), node (3 blocks), tree logic in Rust in the engine windows, `rev`s and the DCAL constant after the 17th store, the PRF secret only in registers. Subtree 10,897 → 8,670 cyc/call (184.5 /digest); v1 mean 101.43 → 98.26 M.
- **Astra:** messages, digest ownership, tree control and ABI conform (its model: 1,006 starts). Fixed: `j0 + 16` is now computed before the first digest (Rust order; an overflowing `j0` panics before any digest in both).
- **Evidence:** software-SHA subtree check 4/4 at odd addresses; stale-fors control; L/R-swap mutant 4/4 wrong; golden, kdiff, FSBL identical.
- **Left:** ~1,170 cyc/call above the floor, ~620 of it block-0 loads (leaf/node feed 16 words from staging, ~20 load cycles each).

### E4: `v1-asm-search`, keep (`0feade4bd`, fixes `0fc20a171`, `23df79045` [FV])
`search128` in asm for the WOTS+C preimage shape (words 4..8 and 20..31 zero, checked in Rust): block 0 from an aligned staging copy (public data), HR3..HR7 in one `ldm`, the `d` words and block-1 loads in the block-0 window, and the signer's `pred` callback called by `blx` from the post-DCAL window (no signer change, no new digit-sum code). 300 → 246 cyc/try; v1 mean 98.28 → 95.97 M.
- **Astra:** flags, staging, callback ABI (callee-saved state, 8-byte stack at `blx` and in the pushed slow path) conform (708 modelled cases). Fixed: the `tick-batch` end-of-call count could overflow near n = 2^32 (now saturating); documented that the asm ticks once per call (the signer calls with ≤ 4,096 tries), not every 32 tries.
- **1-way ICACHE regression, found and fixed.** After E5 shifted the layout, the 1-way mean was 98.58 M against 93.30 M 2-way (max sign +18 M). The asm loop (3520..3816 mod 8 KB) and `hits_target` (3512..3788) sat on the same lines of the direct-mapped cache and evicted each other on every try. Both now live in one section, `.text.pq1_c10_search` (driver: `v1-asm-search`; signer: new `hw-sha256-search-colocate`, one `cfg_attr` in `wots.rs` [FV], layout only). Contiguous, 2,350 B < 8 KB, so they cannot alias in any link layout. 1-way 93.48 M, 2-way 93.37 M.
- **Evidence:** one-shot-reference search check 12/12 (odd address, n = 1/2/3, hit at start, no hit, `d[0..12]` zero); stale-search control; count mutant 4/12 cases wrong; golden, kdiff, FSBL identical.

### E5: `v1-grindr`, keep (`dea4f6e91`)
The v1 R grind (119/103-byte PRF + 160-byte `h_msg` per nonce) as one driver call, plain Rust: `sk_seed` read in place (the signer's 119-byte `sk_seed` copy is gone), tail words built once, nonce patched (NBLW 24 as the one-shot writes it), HR3 only per nonce (`HR3 & 0x7FF0 == 0` ⟺ `read_bits_le(D, 132, 11) == 0`), the hit re-checked by the signer's `read_bits_le`; the rand-holding buffers are wiped. ~508 cyc/nonce. v1 mean 95.18 → 93.30 M (−2.0%).
- **Evidence:** grind check 4/4 against the one-shot loop (rand and none, odd addresses); nonce-word mutant 4/4 caught; golden, kdiff, FSBL identical.
- **Gap:** the nonce's top byte (`(nonce >> 24) << 24`) is zero for every nonce below 2^24 (cap 10 M), so no test reaches it; it is correct by inspection only.
- **Astra (fixed, `f5944ec36`):** outputs and the stopping nonce conform (30,042 modelled cases, all 65,536 predicate-byte pairs).
  - The tail words were wiped through a shadow copy (`let mut tw = tw`).
  - A new **dead-stack residue scan** in the grind check (any 4-byte window of `rand` or `sk_seed` below `sp` after the call) showed more than that: the compiler had also spilled tail words (rand, message) into other slots. Fixing `tw` alone still left rand behind.
  - The body now runs in its own `#[inline(never)]` frame, and the entry zeroes the 1 KiB of dead stack below `sp` after it.
  - Residue 0 with the scrub; rand found in both rand cases with the scrub skipped (mutant). `sk_seed` was never found.
  - Also fixed: the `tick-batch` count over-reported by two on exhaustion.
  - 513 cyc/nonce. Mean, golden, kdiff and FSBL re-run: 2-way 93.37 M, 1-way 93.52 M.
- **Residue scan on the other v1 entries (`255d55d09`):** after the key loop, no `sk_seed` window and none of the first four chain starts (WOTS secrets, references computed before the call) in the dead stack; after the subtree, no `sk_seed` window. The scan's liveness is shown by the grind's no-scrub mutant. Not run on the round-7 v2 entries or the old Rust paths.

### Tuning (`f2e3db6dc`)
Spins tuned in the signer, not the microbench: key-loop step **13** (golden keygen 32.47 → 32.07 M; the microbench had ranked 14 first); search **1** (mean 95.18/95.37/95.56 M at 1/2/3). PRF and chain-end spins are flat (±0.3 cyc/digest).

### Probes and measure-only
- **BUSY slow path:** 0 PC samples in every out-of-line BUSY loop. BUSY has cleared by the SR read everywhere, so nothing to fix.
- **`no-busy-wait` (#1151)** on the new loops (BUSY bit dropped from the INIT masks under the feature, then reverted): v1 mean 93.30 → 93.08 M (**−0.24%**), golden passes. It is now worth almost nothing.
- **memcpy/memclr:** the new staging arrays cost ≈0.2 M/sign. The remaining ~1.5 M/sign is inside the inlined signer (64 call sites in the bench's LTO body). Not pursued: it is an [FV] area.

### Round 8 close (kit 160 MHz, 16-message means, keys/signatures unchanged)

| v1 (deployed) | round 7 end | round 8 end |
|---|---:|---:|
| mean sign, 2-way ICACHE | 106.49 M | **93.37 M (−12.3%)** |
| mean sign, 1-way (shipped) | 106.58 M | **93.52 M (−12.3%)** |
| golden keygen | 35.05 M | 32.07 M (−8.5%) |
| golden cached sign (2 passes + verify) | 225.84 M (1.412 s) | **197.67 M (1.235 s, −12.5%)** |
| est. cached sign from the mean | 1.332 s | **1.168 s** |

- **v2 0.3:** 57.54 M, unchanged (no v2 work).
- **Gates at head (`276677480`, after the 512 B scrub and the `wots.rs` line-count fix):**
  - v1: golden (cached 197.66 M), kdiff 32/32 (it includes `opt_rand = None` cases), and the microbench checks (key 8/8, subtree 4/4, search 12/12, grind 4/4 with residue 0).
  - v2: gate 5 2,523/0 and the v2 golden. The v2 stale controls were not re-run; the v2 crates name none of the round-8 features.
- **Astra on the post-review fixes (`dea4f6e91..276677480`):** the `tw` wipe, the exhaustion count, the overlap guard (whole `if` gated) and the colocation (one input section, 0x930 bytes, in this fat-LTO single-CGU build) conform. Two MEDIUMs:
  - **The scrub wrote below `sp` without allocating it.** That is outside AAPCS and bypasses MSPLIM. **Fixed:** the scrub now does `sub sp, #512`, zeroes, then `add sp`, so a shortfall faults on the stack limit. Microbench residue 0 and all checks, golden, kdiff and FSBL re-run.
  - **Open, predates the round:** a `hash_engine_fault` from inside the grind skips both the local wipes and the scrub. The secure hook zeroizes global state and resets, but not this frame.
  - Also noted: colocation by section name is not guaranteed across separate input objects (it holds only with LTO + one codegen unit). The overlap guard's `16 * n` and `sk_seed + 32` are plain arithmetic (valid buffers cannot overflow; overflow checks would panic).
- **Landing conditions found this round:**
  - `v1-asm-search` must ship with `hw-sha256-search-colocate`; without it the 1-way aliasing can come back.
  - The grind scrub size (512 B against a 376 B inner frame) and the stack headroom below that call must be re-checked in the product build.
  - The host gate never runs `grind_r_drv` or any v1 asm (software hooks), so the v1 evidence is kit-only.
  - `wots.rs` keeps its line count: the attribute shares the `fn` line.
- **FSBL** byte-identical after every `hash.rs` edit (`e34d6e8ecabb3109f8ca…`): every addition sits behind `v1-asm-key`, `v1-asm-fors`, `v1-asm-search` or `v1-grindr`, which the FSBL never names.
- **Product caveat (#1149):** under `tick-hook` without `tick-batch` all asm paths compile out, and the grind entry ticks per digest.

## Round 9 (2026-11-13): residue gate, then v1 driver work (output-identical only)

### Standing gate: dead-stack residue scan (`225f67e0f`, `gate_residue.sh`, shared `residue.rs`)

**Method.** For each driver entry that touches a secret:
1. compute the secrets first, in software;
2. build their patterns: every 4-byte window in memory order at every byte offset, and every aligned word byte-reversed (so a raw HR value spilled before its `rev` also matches); zero windows are skipped;
3. zero the dead stack;
4. call the entry;
5. scan 4 KiB below `sp`.

The scan and clear run inlined in the caller, and the patterns live in a static, so the scanner never scans its own frame.

**v1 suite** (`bench_v1micro`, 7 cases, part of `experiment_v1micro.sh`'s ok):
- key loop: `sk_seed`, all 43 chain starts, the intermediate values of 8 chains;
- sign-shape keys: the starts and every value below the digit;
- FORS subtree: `sk_seed` and the 16 leaf secrets;
- grind, with and without rand;
- `prf_chain16`;
- `chain16` from a secret.

**v2 suite** (`bench_v2drv --features residue`, 9 cases over the round-7 asm entries): `wots_chains16`, `wots_pk16`, `prf_chain16`, `fors_leaf16`, `fors_subtree16` at h = 4 and 7, `chain16`, `grind_r` at 119 and 103 B.

**Result:** no residue anywhere (v1 mask 0x0, v2 mask 0x0). No fix was needed in the round-7 v2 entries.

**The gate can fire** (leaky mutants; the correctness checks stay green throughout):
- v1 combined mutant → mask 0xd:
  - a raw (byte-reversed) key-loop chain start stored below `sp`;
  - a FORS leaf secret below `sp`;
  - the grind with its scrub skipped (rand found; the no-rand grind case stays clean, so `sk_seed` never spills).
- v2 mutant (the FORS PRF output stored below `sp` in `v2x_f`) → mask 0x30.

**Gaps:**
- No v1 grind and no v2 search secret (the search has no secret inputs).
- The fault path's frame is not scanned (it resets).

### E6: key-loop block-0 preload, keep (`e4a5b47d2`)

**What changed:**
- `c0..c2` load into r9..r11 in the previous digest's block-0 window, together with the end compare (the flags live to the `bne` after DCAL).
- The step then loads `c3/c8/c9/c10` with one `ldm`, and `c12/c13` with `ldrd`.
- The slow-path counters moved to dead registers: r0 before the HR read; `lr` in the BUSY path, with the CR value re-made.

**Discarded first variant:** single `ldr`s interleaved between DIN stores were slower at every spin (best keygen 32.38 M against 32.07 M). Loads mixed into a peripheral store sequence cost more than one grouped `ldm`.

**Spin** re-swept in the signer: 10.

**Results:**
- golden keygen 32.07 → **31.61 M**;
- cached sign 197.66 → 195.81 M;
- v1 mean 93.37 → **92.42 M** (2-way), 93.52 → 92.62 M (1-way).

**Evidence:** kdiff 32/32, residue gate, `c8`/`c9` swap mutant (7/8 keys wrong), FSBL identical.

**Astra:** no defects. It checked every path into INIT, flag survival, the slow-path lifetimes, and that the base-in-list `ldm` is defined (Arm ARM: only writeback makes it UNPREDICTABLE). 54 modelled cases.

### E7: FORS zero-word transitions, keep (`39cd967aa`)

**What changed:** for the FORS shape, `v1x_leaf_z`/`v1x_node_z` load only the 8/9 non-zero block-0 words (two grouped `ldm`) and store the zeros from a register. The zero words are pad16's zero half, the layer, the tree's high word, ci and the leaf height, checked in Rust (public).

**Results:**
- subtree on the FORS shape 8,672 → **8,396** cycles/call;
- golden cached sign 195.81 → 194.73 M;
- v1 mean 92.42 → **92.02 M** (2-way), 92.62 → 92.24 M (1-way).

**Evidence:**
- the subtree check now covers both shapes (4/4);
- residue gate, kdiff;
- `w11`/`w12` swap mutant: 2/4 subtrees wrong, exactly the FORS-shaped cases;
- FSBL identical.

**Astra:** no defects (symbolic DIN trace equal to the generic transitions).

### E8: in-driver digit sum, discard (patch kept: `discarded/r9-E8-search-sum.patch`, `511f5c75c`)

**What it was:** a WOTS entry with the round-7 v2 fold sum (same digit position) in the engine window. The signer reaches it through one `link_name` line in `wots.rs`, and the predicate only confirms a hit (a disagreement fails closed). It would retire the colocation attribute and its feature.

**Exact:** a dense gate-5-style sweep, 938/0. That is 6 keys × targets 0..301 over 96-try windows, plus windows starting at and just before each hit, against one-shot digests and the reference digit sum. The WOTS entry also equals the callback search on three real target-205 searches.

**Speed-negative:**
- microbench 247.0 against 246 cycles/try;
- v1 mean **92.20 M** (spin 6; 92.27 M at spin 2) against 92.02 M with the callback.

Under the keep rule it is a discard. It is the fallback if the colocation landing condition is rejected.

### E9: key loop as a `global_asm!` function using r6/r7, keep (`609fa4f31`)

**The r6/r7 judgement.** Pushing and popping r6/r7 inside an inline `asm!` would sidestep LLVM's reservation (r7 frame pointer, r6 base pointer). That is only sound if every exit restores them, and the diverging fault path does not. As a standalone AAPCS function in `global_asm!` they are ordinary callee-saved registers:
- prologue `push {r4-r11, lr}; sub sp, #4`, so `sp` is 8-aligned at the fault call;
- epilogue `add sp, #4; pop {r4-r11, pc}`;
- no Rust frame is live inside it, so LLVM's frame-pointer and base-pointer assumptions never apply.

**What changed:** the asm text is generated from `v1_key_asm`. The two extra registers carry `c3` and `c8`, so a step's block 0 loads 4 words with one `ldm` instead of 6.

**Bug caught by the key check:** the first build listed `ldm r8, {r8, r9, r10, r6}` expecting that order. `ldm` always fills ascending registers from ascending addresses, so 7/8 keys came out wrong.

**Spin** re-swept in the signer: 10.

**Results:**
- golden keygen 31.61 → **31.23 M**;
- cached sign 194.73 → **193.30 M**;
- v1 mean 92.02 → **91.15 M** (2-way), 92.24 → **91.31 M** (1-way).

**Evidence:** kdiff 32/32, residue gate, `c9`/`c10` swap mutant (7/8 wrong), stale controls (key, positive, fors, search). Mutant A (Rust entry check removed): the function's own PRF stale check halts. FSBL identical.

**Astra (after the round-9 report; reviewed source blob `8e5591c9`): no defects.**
- **ABI:** prologue and epilogue balance at the single return; `sp` is 8-aligned at the fault call; r4..r11 restored. Saving r6/r7 across this external call preserves LLVM's frame and base pointers (AAPCS32).
- **Directives:** the section/global/type/thumb_func/size directives give a global `STT_FUNC` with the Thumb bit; `hb_lo`/`hb_hi` give 0x520C040C; the private fault hook is valid as a `sym` operand.
- **DIN order and preloads:** the order is exact, the `ldm` fills ascending registers, both preload sites establish `st[0..5]`, and every path into INIT keeps them.
- **Equivalence:** a mechanical comparison against `v1_key_asm` found only the setup, return, block 0 and preload widths changed.

### Not done (ranked low: ~0.1–0.2 M each for new asm)
- search zero-word block 0;
- `th_multi16` with the next value's loads in the stall;
- grind asm transitions;
- v2 work.

### Round 9 close (kit 160 MHz, keys/signatures unchanged)

| v1 (deployed) | round 8 end | round 9 end |
|---|---:|---:|
| mean sign, 2-way | 93.37 M | **91.15 M (−2.4%)** |
| mean sign, 1-way (shipped) | 93.52 M | **91.31 M (−2.4%)** |
| golden keygen | 32.07 M | 31.23 M |
| golden cached sign | 197.66 M (1.235 s) | **193.30 M (1.208 s)** |
| cached sign estimated from the mean | 1.168 s | **1.141 s** |

**Since round 7:** v1 mean 106.49 → 91.15 M (−14.4%).

**v2:** gate 5 2,523/0, v2 golden, v2f mean 57.54 M (unchanged).

**FSBL** byte-identical throughout.

**No signer-crate edits this round**, so no new extraction drift. `check_extraction_freshness.py` still shows the same 22 drifted pins. The round-8 `fors.rs`/`wots.rs` edits sit under targets already drifted by rounds 1–7: `sign-release`, `sign-forest`, `fors-*`, `wots-*`, `xmss-*`, `verifier`.


> **UPDATE 2026-11-13 (re-run 2026-11-14, round 14).** The residue-clean claims of this round were made with a scanner blind to the top band: the residue scanner (`residue.rs`) used for it had a blind top band. `res_found` stopped at `a < sp − 4`, and at opt-level `z` its `read_volatile::<[u8; 4]>` and `<[u32]>::contains` were out-of-line calls whose own pushes overwrote the words just below sp before they were read. That is where a driver entry's prologue saves the caller's callee-saved registers. (`res_clear` also left the 64 bytes below sp uncleared, which could only add false positives.) Fixed in rounds 13–14: the clear runs up to sp, the scan runs through sp − 4 with inline-asm loads and a call-free pattern loop, each v2 case runs in its own frame with its patterns computed out of line, and every suite's control build must flag a frame-copy control and a key word written at sp − 4.
> - **Re-run under the fixed scanner:** v1 7/7 clean (key loop, sign-shape keys, FORS subtree, grind with and without rand, `prf_chain16`, `chain16`); v2 9/9 clean (`wots_chains16`, `wots_pk16`, `prf_chain16`, `fors_leaf16`, `fors_subtree16` h = 4 and 7, `chain16`, `grind_r` 119 and 103 bytes); the controls fire (v1 0x180, v2 0x600).
> - **Today's implementations pass the corrected scan.** That covers the gate's suites and E9's key loop, which is still current.
> - **The historical runs cannot be re-validated where the code has been superseded.** E6's and E7's paths gave way to E9 and E10 and are not built in today's configuration. Their "residue gate" evidence stands only as made, on the scanner with the blind band.
> - **Round 8's earlier scans** (the grind check; the v1 key loop and subtree, `255d55d09`) are likewise historical. The same entries as they are today pass.
> - **Changed:** the round-13 v2 hits that the fixed scanner first showed were harness artifacts, not driver residue. `prf_chain16` and `chain16` showed the bench caller's own r5/r6, saved by the entries' `push {r4, r5, r6, r7, lr}` (Astra, from the disassembly). `wots_pk16` showed the scanner's own last pattern from the previous case, which shares its table; with the case order swapped it moved to case 0.

## Round 10 (2026-11-13): global_asm FORS and search, product-shaped measurement, v1 closing note

### E10: FORS subtree as a `global_asm!` function, keep (`c33268ebf`, generator `gen_fors_ga.py`)

**Premise checked first.** A timing-only probe with every block-0 load deleted from the three FORS transitions (garbage digests) took the subtree from 8,396 to 7,756 cycles/call. Loads were about 640 of the ~894-cycle gap to the ~7,500 floor.

**What changed:** the whole FORS-shape subtree, tree logic included, is one AAPCS function (E9 pattern):
- leaf constants live in r5..r11, so a leaf loads only `be32(j)`;
- node words and `L[1..3]` load in the block-0 window;
- the PRF finds `sk_seed[0..7)` preloaded (registers only);
- pushes, index updates and constant reloads run in the engine windows.

**The residue gate caught a leak in the first build.** The Rust wrapper had just fed `sk_seed` for the first PRF. The function's prologue `push {r4-r11}` then spilled those register-held words to the stack. Fix: the asm issues the first PRF itself (the same idle/stale check, STR 0, INIT as `gather_init`), so the caller never holds `sk_seed`. Afterwards: residue 0.

**1-way ICACHE:** the gap to 2-way grew from 0.16 to 0.35 M. Putting the Rust wrapper in the function's section brought it back to 0.17 M.

**Results:**
- subtree 8,396 → **8,110** cycles/call;
- golden cached sign 193.30 → 192.41 M;
- v1 mean 91.15 → **90.68 M** (2-way), 91.31 → **90.85 M** (1-way).

**Evidence:**
- subtree check on both shapes (4/4, odd addresses), residue gate, kdiff 32/32;
- stale-fors: on this path that is now the asm's own first-INIT check;
- `h'`/`idx'` swap mutant 2/4;
- FSBL identical.

**Astra:** no defects. Its model matched 9,400 digest inputs and 200 roots against the generic heights-stack reference, including slow waits and unaligned seeds.

### E11: search as a `global_asm!` function, keep (`38be65e1d`, generator `gen_search_ga.py`)

**What changed.** For the WOTS digest address (words 9, 11, 13, 14, 15 zero, checked in Rust), block 0 is seven constant words. They stay in callee-saved r5..r11 across every try and the per-try `pred` call, so only word 16 is loaded before the 17th store. The digest words, block-1 words and the count go through the block-0 window, and the last-try test moves into the engine window (two wait loops). The function sits in `.text.pq1_c10_search` next to `search128` and `hits_target` (contiguous, 3.2 KB).

**Results:**
- 246 → **227** cycles/try (the floor is ~226);
- golden cached sign 192.41 → 190.35 M;
- v1 mean 90.68 → **89.97 M** (2-way), 90.85 → **90.18 M** (1-way).

**Evidence:**
- the search check now covers both address shapes (24/24, odd address, edges);
- kdiff, residue gate, stale-search;
- `a0`/`a2` swap mutant 5/24;
- FSBL identical.

**Astra:** no defects. It checked the DIN sequence, the context and frame, counts and flags for n = 1, 2, 3 and in general, the base-in-list `ldm` (defined: no writeback), the predicate ABI and alignment, and section placement. 906 model cases, every preimage and predicate argument checked against SHA-256.

### Product-shaped measurement (measurement only; bench crates only, no firmware image flashed)

**The tick in the product.** The secure world's `pqsigner_hash_tick` is `film_tick_hash()` (`secure/src/ui/px/lcd.rs`):
- with no film live, an atomic load and a return;
- with a film live, a counter load/add/store, and every `HASH_TICK_EVERY` = 64 digests a call to `film_tick_paced`. That draws a frame at a time-paced rate (about one 8 ms frame per 32 ms), independent of hashing speed, so it is not modelled.

There is no `pqsigner_hash_tick_n` in the secure world: the batched tick (#1149) is still only a research variant. `bench_avg_v1` got the same per-call stubs as `bench` (`3c70a5f10`).

| v1 16-message mean, head | 2-way | 1-way (shipped) |
|---|---:|---:|
| no tick (bench) | 89.97 M | 90.18 M |
| **batched tick** (`tick-batch`, the #1149 variant) | 90.16 M | 90.46 M |
| per-digest tick (`tick`, what `ui-px` builds today) | 120.09 M | 121.28 M |

- **With the batched tick, essentially all of the round 7–10 gain reaches the product:** the batching costs 0.2–0.3%.
- **With today's per-digest tick, none of the asm runs:** every round 7–10 asm path compiles out, and the sign costs about 120 M (golden-equivalent ~1.5 s). The R grind entry (E5, Rust) is the only round 7–10 change that survives.
- The round 7–10 work therefore reaches users only if #1149 (batched tick) lands. That is an owner decision.

### Closing note: v1 headroom (kit 160 MHz, head `38be65e1d`)

**Profile at head (1-way):** key loop 65.6%, FORS subtree 13.9%, search 6.5% plus `hits_target` 5.4% (hidden in the engine window), `th_multi16` 2.3%, grind 1.8%, the rest about 4.5% (Rust glue, memcpy/memclr, one-shots, verify).

| entry | now | engine floor (INIT→DCIS + ~14) | practical headroom per sign |
|---|---:|---:|---:|
| WOTS key loop | 167.0 cyc/digest | ~161 | **~0.7 M**: the remaining ~6 cycles are `ldm` c9/c10/c12/c13, `rev pos` and the zero register; all 14 registers are in use |
| FORS subtree | 8,110 cyc/call | ~7,500 | **~0.3–0.5 M**: PRF tail loads, node `h'`/`idx'`/`L[0]`, poll lag |
| search | 227 cyc/try | ~226 | ~0 (at the floor; the predicate is hidden) |
| R grind | 513 cyc/nonce | ~385 | ~0.3 M |
| `th_multi16` | 1,973 cyc/call | ~1,800 | ~0.2 M |

Total practical driver headroom: about **1.5–1.7 M (~1.8%)** of a 90 M sign. That is below the ~2% mark, so v1 driver work is closing.

**Hardware axes, measured (measure only):**

| axis | result | status |
|---|---|---|
| ICACHE 2-way against the shipped 1-way | −0.23% | product setting (`rcc.rs`): owner |
| `FLASH_ACR.PRFTEN` | −0.11% (2-way), −0.20% (1-way) | was noise in round 3, now visible; product setting: owner |
| code in SRAM (C-bus alias) against flash + ICACHE | golden 198.23 M against 190.35 M (+4%) | not a lever |
| flash wait states | 4 WS at 160 MHz is the device minimum for the range | changing it needs a clock or voltage change: out of scope |
| HASH clock | on AHB at 160 MHz, no separate prescaler | — |
| no-busy-wait (#1151) | −0.24% (round 8) | owner |

**Untried: none safe within the rules.** The remaining levers are owner decisions (#1149 batched tick, by far the largest: about 25% in the product; 2-way ICACHE; prefetch; #1151) or format work.

### E12 (v2): whole-key WOTS loop as a `global_asm!` function, keep (`193a18780`, generator `gen_v2key_ga.py`)

**What changed.** For the research format, steps 1..15 (not `v2-prf2`), the E2 and E9 patterns:
- each chain's PRF is issued from asm, with `sk_seed[0..7)` preloaded during the previous chain's last step (registers only);
- `sk_seed[7]` and `p0`, `p1 | c` load after INIT;
- the previous chain's output store, the next chain's index words and the `S` reload run in the PRF's engine window;
- the chain steps keep the `v2-asm-chain` schedule.

**Results:**
- `wots_chains16` 106.2 → **102.3** cycles/digest (now below the bare `chain16` at 103.3); `wots_pk16` 109.8 → 106.0;
- v2 mean 57.54 → **56.21 M** (2-way), 56.23 M (1-way);
- keygen 19.69 → 19.03 M;
- v2 golden cached sign 110.04 → 107.32 M (0.671 s).

**Evidence:**
- gate 5 2,523/0 (40 key cases with random steps, 40 public-key cases, v1 digests interleaved);
- residue gate (v2 cases 0/1);
- a new `stale-v2key` control fires. The Rust entry waits only for BUSY, so this is the loop's own first-PRF check;
- `p1|c` mutant: 77 gate-5 failures;
- FSBL identical.

**Astra (round 11): one defect, fixed in `5554efeba`.** It is round 8's E2 overlap class again. The asm stores chain k after chain k + 1's PRF has read `sk_seed`; the Rust loop stores first. Astra reproduced the difference with `out == sk_seed`.
- **Fix:** take the asm path only when the 688-byte `out` cannot overlap `sk_seed`.
- **New gate-5 case:** `out == sk_seed` against a sequential software reference. Gate 5 is now 2,525/0, and a no-guard mutant fails exactly that check.
- **Gate gap closed:** `bench_v2fb` (the cached goldens) had not named `v2-asm-key-ga`, so the cached goldens never ran E12. It does now: cached golden passes with 3 hits; plain golden passes; v2 mean 56.27 M.
- **Everything else conforms:** the context and frame, indices and end, DIN order and endianness, the output pointer, hardware sequencing, ABI and secrets.

### Round 10 close (kit 160 MHz, keys/signatures unchanged)

| | round 9 end | round 10 end |
|---|---:|---:|
| v1 mean sign, 2-way | 91.15 M | **89.97 M (−1.3%)** |
| v1 mean sign, 1-way (shipped) | 91.31 M | **90.18 M (−1.2%)** |
| v1 golden cached sign | 193.30 M (1.208 s) | **190.35 M (1.190 s)** |
| v1 cached sign estimated from the mean | 1.141 s | **1.126 s** |
| v2 0.3 mean sign | 57.54 M | **56.21 M (−2.3%)** |

- **Since the end of round 7:** v1 106.49 → 89.97 M (**−15.5%**).
- **Since the start of round 7:** v1 110.10 → 89.97 M (−18.3%).
- **Product:** this reaches users only with the batched tick (#1149); with today's per-digest tick, v1 is about 120 M.
- **No signer-crate edits** this round, so no new extraction drift.
- **FSBL** byte-identical throughout.


> **UPDATE 2026-11-13 (re-run 2026-11-14, round 14).** This round's residue claims (the leak caught in E10's first build, then fixed; E10–E12 "residue gate clean"; E12's v2 cases 0/1) were made with a scanner blind to the top band: the residue scanner (`residue.rs`) used for it had a blind top band. `res_found` stopped at `a < sp − 4`, and at opt-level `z` its `read_volatile::<[u8; 4]>` and `<[u32]>::contains` were out-of-line calls whose own pushes overwrote the words just below sp before they were read. That is where a driver entry's prologue saves the caller's callee-saved registers. (`res_clear` also left the 64 bytes below sp uncleared, which could only add false positives.) Fixed in rounds 13–14: the clear runs up to sp, the scan runs through sp − 4 with inline-asm loads and a call-free pattern loop, each v2 case runs in its own frame with its patterns computed out of line, and every suite's control build must flag a frame-copy control and a key word written at sp − 4.
> - **Re-run under the fixed scanner:** v1 7/7 and v2 9/9 clean; controls fire.
> - **E10 and E11 (both current) pass the corrected scan.**
> - **E12's 8-bit v2 key loop** was superseded by E14–E16 and is not built in today's configuration, so its "residue gate clean" stands only as made, on the scanner with the blind band.
> - **The leak caught in E10's first build was real and independently found:** it was in the observable band, at the prologue push of the asm function the Rust wrapper called. Its fix (the asm issues the first PRF) stands, and the fixed scanner finds today's entry clean.

## Round 11 (2026-11-13): v2 (research format): global_asm FORS, 32-bit DATATYPE, search

### E12 review, fixed first (`5554efeba`)
See round 10's E12 entry: the overlap guard, the aliased gate-5 case (2,525/0, mutant-checked), and `bench_v2fb` now running E12.

### E13: v2 FORS subtree as a `global_asm!` function, keep (`ff7cfe71a`, `gen_v2fors_ga.py`)

**What changed** (the E10 pattern on one-block digests, any height 0..11):
- `S` and `a0` live in r5..r9;
- F (leaf) loads nothing;
- H (node) preloads `L[0..3)` and loads `L[3]` and its A7 word after INIT;
- the PRF preloads `sk_seed[0..7)` (registers only);
- the asm issues the first PRF, so the caller never holds `sk_seed` words (the round-10 residue lesson).

**Results:** subtree 110.6 → **101.0** cycles/digest; v2 mean 56.27 → **55.48 M** (2-way), 55.59 M (1-way).

**Evidence:**
- gate 5 2,525/0 (every height at the first, last and a random position);
- residue gate (the v2 subtree at h = 4 and 7);
- the full golden matrix, plain and cached;
- a new `stale-v2fors` control fires. This is the function's own first-PRF check: the Rust entry only waits for BUSY;
- `L1`/`L2` swap mutant: 33 failures;
- FSBL identical.

**Astra:** no defects.

### DATATYPE 00 settled on the kit before use (`58d10c31b`)

The `nblw32` probe (`bench_v2micro`):
- DIN words are the big-endian value of four message bytes, the last partial word's bytes sit in its **top** bits, and NBLW = 8 × (len % 4) (the RM's "valid bits after internal data swapping");
- equal to software SHA-256 for every length 0..160 and 1,200 v2-shape messages (NBLW 0/8/16/24: 164/160/160/1,360 checks, 0 failures);
- a byte-data one-shot right after a 32-bit digest is correct;
- the tail-in-low-bytes mutant fails every partial-word case.

**No other path inherits the data type.** Every other digest path writes its own CR value (DATATYPE 10) at INIT. Astra listed every CR write in the driver (E14 review). Gate 5 also interleaves a v1 digest after every v2 call.

### E14: the v2 key loop with DATATYPE 00, keep (`c7f4163b9`, `gen_v2key_dt.py`)

**What changed:**
- digests read from HR feed the next message as they are: a chain step drops its four `rev`s;
- the constants are swapped once at entry; in big-endian form the chain position is bit 20 and the chain index is `ci << (lsb + 24)`;
- `sk_seed` words are swapped in the preload window, and the outputs are swapped back in the PRF window.

**Results:**
- `wots_chains16` 102.3 → **94.6** cycles/digest;
- v2 mean 55.48 → **52.71 M** (2-way), 52.83 M (1-way);
- keygen 19.02 → 17.64 M.

**Evidence:** gate 5, residue gate, the full golden matrix, `stale-v2key`, little-endian-position mutant (77 failures), FSBL identical.

**Astra:** no defects.

### E15: the v2 FORS subtree with DATATYPE 00, keep (`1f6eb91cc`, `gen_v2fors_dt.py`)

**What changed:** F and H take the digest in flight unswapped, and the node stack holds big-endian words; only the root is swapped back. In big-endian form, `ha(x)` is `(x & 0x7F) << 9 | (x >> 7) << 16` and the height is bit 20.

**Results:** subtree 101.0 → **97.7** cycles/digest; v2 mean 52.71 → **52.45 M** (2-way), 52.57 M (1-way).

**Evidence:** gate 5, residue gate, golden matrix, `stale-v2fors`, little-endian-height mutant, FSBL identical.

**Astra:** no defects (exhaustive over x and k; 85,912 modelled messages).

### E16: the 32-bit key loop keeps `a0` in r6 and the DCAL value in r7, keep (`ebbd9e66c`)

**What changed:** r6 and r7 are free in the function and carry `sk_seed` preloads only around the PRF. A chain step now loads nothing and builds no constant.

**Results:**
- `wots_chains16` 94.6 → **91.7** cycles/digest;
- v2 mean 52.45 → **51.43 M** (2-way), 51.56 M (1-way);
- keygen 17.13 M.

**Evidence:** gate 5, residue gate, golden matrix, `stale-v2key`, `a0`/`a1` swap mutant, FSBL identical.

**Astra:** no defects.

### E17: v2 count search with DATATYPE 00 as a `global_asm!` function, keep (`07d6f3aa9`, `gen_v2search_dt.py`)

**What changed:**
- `S ‖ m` words 0..6 stay in registers across tries; the digit sum uses them as scratch in the engine window and then reloads them;
- words 6..7 and the A7 words load with one `ldm` after INIT;
- the count goes out as its own value;
- the fold sum and exact early reject are verbatim;
- the last-try test runs in the engine window;
- no timed spin (swept 1/2/4/6 and none).

**Results:**
- 114.0 → **103.0** cycles/try (real target 115.1 → 105.1, the same 249,343 tries);
- v2 mean 51.43 → **50.70 M** (2-way), 50.82 M (1-way).

**Evidence:** gate 5 (all search groups, including the dense digit-sum sweep), the golden matrix, stale-search, `sm6`/`sm7` swap mutant (197 failures), FSBL identical.

**Also in this commit:**
- the comments in front of every `global_asm!` block are plain `//` (doc comments there gave "unused doc comment" warnings);
- three v2 entry functions get their doc comments back. The E12, E13 and E17 insertions had landed between each function and its doc.

**Astra:** no defects, GO. Checked: the frame and ABI; DIN bytes and reloads after every digit-sum path; the fold decisions against the reference; hit and exhaustion count pairs for ranges of 1, 2 and 3; DCIS/BUSY/stale guards at both INIT sites, with BUSY slow paths rebuilding CR=0x60004; and that the nine comment hunks are non-executable. 882 controlled model cases and 240 SHA-256 differential cases.

### Round 11 close (kit 160 MHz, keys/signatures unchanged)

| v2 0.3 | round 10 end | round 11 end |
|---|---:|---:|
| mean sign, 2-way | 56.21 M | **50.70 M (−9.8%)** |
| mean sign, 1-way | 56.23 M | **50.82 M** |
| keygen | 19.03 M | 17.13 M |
| golden cached sign (plain) | 107.32 M (0.671 s) | **96.86 M (0.605 s)** |
| golden cached sign with the top cache | 70.74 M | **63.98 M (0.400 s)** |

**v2 since round 7 start:** 65.59 → 50.70 M (−22.7%).

**v1:** unchanged (closed, 89.97 M); gate 5's v1 groups and the v1 residue suite still pass.

**Signer crate:** no edits under `sphincs-c10/src`, so no new extraction drift.

**FSBL:** byte-identical throughout.

### v2 headroom at head (kit 160 MHz)

| entry | now | ~floor | practical headroom per sign |
|---|---:|---:|---:|
| key loop | 91.7 /digest | ~90 | ~0.3 M (poll lag; all registers in use) |
| FORS subtree | 97.7 /digest | ~91 | ~0.3 M (H's CR re-make and two loads, PRF tail loads) |
| search | 103.0 /try | ~91 | ~0.3 M (the digit sum fills the window) |
| T_43 one-shot (`wots_pk16`) | ~2.5% of the run | | ~0.3 M (a dedicated feed) |
| grind | ~1.9% of the run | | ~0.2 M |

Total practical v2 headroom: about **1.4 M (~2.8%)** of a 50.7 M sign. It is close to the ~2% closing mark, and every remaining item is ≤ 0.3 M.

**Fable's check of the table above.** Fable read the generators; nothing was run. Digest counts come from the ledger deltas:
- The floors are too low. Search needs `ldm` ×4 plus `ldr` after INIT, 11 DIN words and 5 HR reads, so its floor is ~94, not ~91. The key loop is essentially at its floor; only the per-chain PRF tail and the ladders remain, ~0.1–0.2 M.
- FORS: H pays ~6 cycles before DCAL and the PRF ~8; about half of that is removable (~0.15–0.25 M).
- T_43 is under-estimated. It runs through the generic byte-mode `oneshot16` over 12 blocks, so a dedicated 32-bit feed is worth ~0.25–0.4 M. That needs a multi-block (712 B) DATATYPE 00 probe first; the round-11 probe covered ≤160 B.
- Missing row: ~1.6 M (3%) is unattributed (glue, `node16`, H_MSG, verify). There is no v2 profile at head.

Realistic headroom is **~0.9–1.3 M (1.8–2.6%)**, so v2 is not closed yet.

**Next, in order:**
1. a T_43 32-bit feed (with the multi-block probe);
2. the FORS PRF tail and a ladder spin (E16 pattern);
3. H's CR re-make;
4. key-loop PRF tail and spin;
5. search (depends on HR surviving INIT, which is unproven);
6. grind in asm (the highest risk: `sk_seed` in a wiped buffer, two-block messages);
7. `node16` (Rust `feed_words`, ~0.05 M).

A v2 profile at head is a precondition for the closing note.

### The "v1 entry right after a v2 one" control (`b28509e94`)

Gate 5's interleaved v1 probe had only been the byte-mode one-shot and the streaming API, not a v1 driver entry. Gate 5 now also runs a v1 entry after every call to the DATATYPE-00 functions (FORS subtree, search, key loop, pk16).

**What it runs:** one of the v1 global_asm entries, rotating between the whole-key loop, the FORS subtree and the count search, in the input shape that selects each asm path. Each is checked against software SHA-256 from the v1 spec.

**Results:**
- gate 5: **2,940/0**, with 412 v1-entry probes; the evaluator now requires at least one probe and no v1-entry failure;
- control: the v1 FORS asm writing CR with DATATYPE 00 fails 137 of 412, i.e. every FORS probe;
- control: the same change in the v1 key-loop and search asm fails 209 of 412: every key probe, plus every search probe whose tries hit (the n = 5 runs mostly miss on both sides);
- guard, `stale-v2fors`, `stale-v2key` and `stale-search` still fire.

**Re-run at head (`b28509e94`):**
- FSBL `e34d6e8ecabb3109f8ca` (identical);
- residue gate clean (v1 7 cases, v2 9 cases);
- v1 golden passes;
- v1 kit differential 32/32 with search edges 0x3F.

**Not done this round:** item 4b, the FORS-PRF loads. Fable estimates ~0.15 M. It is ranked second for the next batch, after the T_43 feed.


> **UPDATE 2026-11-13 (re-run 2026-11-14, round 14).** The residue-clean claims of E13–E16 (v2 FORS subtree h = 4 and 7; the dt32 key loop) were made with a scanner blind to the top band: the residue scanner (`residue.rs`) used for it had a blind top band. `res_found` stopped at `a < sp − 4`, and at opt-level `z` its `read_volatile::<[u8; 4]>` and `<[u32]>::contains` were out-of-line calls whose own pushes overwrote the words just below sp before they were read. That is where a driver entry's prologue saves the caller's callee-saved registers. (`res_clear` also left the 64 bytes below sp uncleared, which could only add false positives.) Fixed in rounds 13–14: the clear runs up to sp, the scan runs through sp − 4 with inline-asm loads and a call-free pattern loop, each v2 case runs in its own frame with its patterns computed out of line, and every suite's control build must flag a frame-copy control and a key word written at sp − 4.
> - **Re-run under the fixed scanner:** v2 9/9 clean, including `wots_chains16` and `wots_pk16` (the dt32 key loop of E14–E16) and `fors_subtree16` h = 4 and 7 (the dt32 FORS of E15); controls fire. So **E14, E15 and E16, which are current, pass.**
> - **E13's 8-bit FORS** was superseded by E15 and is not built today, so its claim stands only as made.
> - E17's search hashes only public data and is not in the suite.

## Round 12 (2026-11-13): v2 profile, T_43 feed, v2 closing note

### The round-11 landing fix (accepted, merged)
Three real driver breaks were found by master's secure source-shape tests and fixed in `0d045f658`:
- the FSBL fence was missing 26 research features;
- the crosscheck read 32 bytes from the 16-byte one-shot's output;
- the fused entries bypassed the crosscheck (now a `compile_error!`).

The four tests were rewritten for the new shape (`0f378e451`..`0ba427076`), with 56 planted violations. Astra: FIX, FIX, GO, GO. From round 12 on, every driver keep re-runs the secure suite and the FSBL footprint test and updates the pinned sequences, each with a planted violation.

### Profile at head (PC sampling, 16-sign mean bench, 2-way, before E18)

| function | share of the run |
|---|---:|
| `pq1_v2_key_loop` | 63.9% |
| `pq1_v2_fors_sub` | 15.1% |
| `pq1_v2_search_dt` | 14.1% |
| `oneshot16` (the T_43 compression, ~1,240 cyc/call) | 2.5% |
| grind | 1.8% |
| bench main | 0.55% |
| `node16` | 0.47% |
| memcpy | 0.43% |
| other (signer Rust, verify, wrappers) | ~1.1% |

Per sign, as share × the whole run (≈ 830 M) ÷ 16, so with 1/16 of keygen and the verify included:

| row | per sign |
|---|---:|
| key loop | 33.2 M |
| FORS | 7.85 M |
| search | 7.32 M |
| T_43 | 1.29 M |
| grind | 0.95 M |
| bench main (bench-only) | 0.29 M |
| `node16` | 0.24 M |
| memcpy | 0.22 M |
| the rest (signer Rust, wrappers, verify) | ~0.56 M |

The rows sum to ≈ 51.9 M: the 50.70 M sign plus ≈ 1.2 M of keygen and verify. The non-entry rows (bench main, `node16`, memcpy, the rest) come to **~1.3 M per sign**. That is round 11's separate "unattributed ~1.6 M" row; it is not T_43, which had its own row.

### E18: the T_43 compression as a `global_asm!` feed, keep (`9a3deab71`, `gen_v2t43.py`)

**What changed.** While a block is in the engine, the HASH takes only the next block's first word; the next store waits. So the feed time after each block is on the critical path: about 48 cycles per block in the generic one-shot.
- The new feed stores the trigger word, loads the next 12 words in the engine window, and stores them back to back. It then loads 3 more words plus the next trigger with one `ldm`.
- The ten middle blocks are unrolled: no register is free for a counter.
- DATATYPE 10, as before. The input is memory bytes, so DATATYPE 00 would only add a `rev` per word (tight Rust feeds measured 1,970 against 2,125 cycles).
- Same checks as `init`/`final`. Not built with `tick-hook`, so no new tick site.

**The 712-byte DATATYPE 00 probe came first (`bench_v2micro --features t43`):** every length 640..776 and 200 v2-shape messages, 474 checks, 0 failures; a byte one-shot after a 32-bit digest 6/6.

**Results:**
- `wots_pk16` 95.3 → **94.2** cycles/digest (T_43 ~1,242 → ~862 cycles);
- v2 mean 50.70 → **50.35 M** (2-way), 50.82 → **50.44 M** (1-way);
- keygen 17.13 → 16.95 M;
- golden cached sign 96.86 → 96.06 M; with the top cache 63.98 → 63.53 M.

**Evidence:**
- gate 5 2,940/0;
- the golden matrix, plain and cached (3 hits each);
- the residue gate is clean in the default build and with `prf2`, where the Rust key loop runs before the feed (v2 9 cases, v1 7);
- a new `stale-v2t43` control calls `pq1_v2_t43` with DCIS left set: it halts through the fault hook, and with `stale-positive` (DCIS cleared) the same call returns;
- the swapped-store mutant fails all 40 `wots_pk16` checks;
- FSBL identical;
- landing tests: research features 26 → 27 and `global_asm!` blocks 8 → 9, each with planted violations R1–R3 caught;
- full plant set: 54 caught by the test, 5 stopped by the host compile;
- secure suite 2,984/0; FSBL footprint ok.

**Astra:** GO, no findings (178 words counted exactly; guards, ABI, cfg and generator identity; tests not weaker).

### E19: FORS wait-ladder spins, discard
`gen_v2fors_dt.py` takes optional F, H and PRF spins; the defaults reproduce the checked-in asm. Swept in the 16-message mean (baseline 50.346 M):

| spin | F | H | PRF |
|---|---:|---:|---:|
| 4 | 50.400 M | 50.321 M | — |
| 6 | 50.348 M | — | — |
| 8 | 50.400 M | 50.480 M | 50.745 M |
| 11 | 50.427 M | 50.718 M | 50.983 M |
| 14 | 50.665 M | 50.956 M | 51.221 M |

F and H together at 4: 50.397 M. The windows are already full of work. The best result, H = 4, is −0.05% and phase-sensitive: below the bar.

### Not tried, with reasons
- **FORS PRF tail (~8 cycles): not attempted.** By my reading it is register-bound, on the unprobed assumption that HR must be read before INIT. HR must be read into r0..r3 before INIT, r5..r11 hold `sk_seed[0..7)`, and r12 and lr do the status work. Parking HR in the frame to free three registers costs about what it saves.
- **Key-loop PRF tail: not attempted.** Register-bound by Fable's round-11 reading. Its spin is tuned (13, round 11).

### Closing note: v2 headroom (kit 160 MHz, head `9a3deab71`)

| entry | now | engine floor | practical headroom per sign |
|---|---:|---:|---:|
| WOTS key loop | 91.7 cyc/digest | ~90 | ~0.1–0.2 M: per-chain PRF tail; all registers in use; spin tuned |
| FORS subtree | 97.7 cyc/digest | ~92 | ~0.05–0.1 M: spins measured at ≤0.05%; the PRF tail and H's CR re-make are register-bound |
| search | 103.0 cyc/try | ~94 | ~0.1 M, and only if HR survives INIT (unproven); the digit sum fills the window |
| T_43 | ~862 cyc/call | ~800 | ~0.06 M |
| grind | ~0.95 M/sign | | ~0.2 M: the highest risk (`sk_seed` in a wiped buffer, two-block messages) |
| `node16` | 169 cyc/call | ~120 | ~0.05 M |

Total practical driver headroom is about **0.55–0.75 M (1.1–1.5%)** of a 50.35 M sign. That is below the ~2% mark, so v2 driver work is closing.

**Hardware axes:** the same as v1, measure only. ICACHE 2-way against 1-way: −0.19% (50.35 against 50.44 M). Prefetch and no-busy-wait are owner settings.

**Outside the driver (signer-crate edits are off limits while the Lean re-proof merges):** the non-entry rows come to about 1.3 M per sign. Of that, bench main (0.29 M) is bench-only and `node16` (0.24 M) is a driver entry already in the table. The remaining ~0.8 M is memcpy (0.22 M), signer Rust and wrappers, and the verify (0.12 M). Their callers have not been attributed; a call-graph profile is the first step.

**Estimates:** the floors above are estimates, not measurements. The profile was taken before E18.

### Round 12 close (kit 160 MHz, keys/signatures unchanged)

| v2 0.3 | round 11 end | round 12 end |
|---|---:|---:|
| mean sign, 2-way | 50.70 M | **50.35 M (−0.7%)** |
| mean sign, 1-way | 50.82 M | **50.44 M** |
| keygen | 17.13 M | 16.95 M |
| golden cached sign (plain) | 96.86 M | **96.06 M (0.600 s)** |
| golden cached sign with the top cache | 63.98 M | **63.53 M (0.397 s)** |

**v2 since round 7 start:** 65.59 → 50.35 M (−23.2%).

**v1:** closed. No v1 path changed in round 12, and it was not re-measured after E18.

**Signer crate:** no edits. **FSBL:** identical.


> **UPDATE 2026-11-13 (re-run 2026-11-14, round 14).** E18's residue claims ("clean in the default build and with `prf2`") were made with a scanner blind to the top band: the residue scanner (`residue.rs`) used for it had a blind top band. `res_found` stopped at `a < sp − 4`, and at opt-level `z` its `read_volatile::<[u8; 4]>` and `<[u32]>::contains` were out-of-line calls whose own pushes overwrote the words just below sp before they were read. That is where a driver entry's prologue saves the caller's callee-saved registers. (`res_clear` also left the 64 bytes below sp uncleared, which could only add false positives.) Fixed in rounds 13–14: the clear runs up to sp, the scan runs through sp − 4 with inline-asm loads and a call-free pattern loop, each v2 case runs in its own frame with its patterns computed out of line, and every suite's control build must flag a frame-copy control and a key word written at sp − 4.
> - **Re-run under the fixed scanner:** default v2 9/9 clean, and `prf2` 9/9 clean (`prf2` controls 0x600). **E18, which is current, passes in both builds.**

## Round 13 (2026-11-13): signer-glue attribution profile (the product sign chain)

**Merge:** `origin/master` `e4a1127e7` (fast-forward). The gates were unchanged:
- v1 golden cached sign 190.35 M;
- kdiff 32/32;
- gate 5 2,940/0;
- v2 golden 96.06 M plain, 63.53 M cached.

### The bench (`29d51c511`)
`bench_chain` mirrors `c10_sign_verified_with_progress_inner` (secure/src/crypto.rs) step for step:
- the rate step and CFI bumps;
- OptRand and the two shuffle seeds with their zero checks and wipes;
- sign A, `wait_random`, sign B;
- `subtle` `ct_eq` of the two 4,008-byte signatures;
- `wait_random`, verify behind `check_true_into_sentinel`, the CFI check, the release copy.

It takes 13 DWT phase stamps per chain, averaged over 16 messages, and keygen once (the slot-cache miss).

**Product-shaped by default**, unlike the other bench crates:
- the secure image's one-shot driver only;
- `pqsigner-hw` at the root profile's `"z"`: the root has no opt-3 override for it, while every other bench crate builds it at 3;
- generic `thumbv8m.main` with no `target-cpu`, as the firmware;
- the shipped 1-way ICACHE.

**Stubbed** (not kit-measurable on 0055002D, which has no SEs):
- the three `rng_strong::fill` draws. The EVT measures ~0.3 s for the three together (crypto.rs comment, owner 2026-10-21), about 48 M cycles, each ending in tens of ms of FI-checked CPU work;
- the UI progress sink, `ChipWaitTicks` and `busy_poll`;
- the delay byte;
- `pre_sign`'s interval (outside the inner function);
- the film's time-paced frame draws (~8 ms frames while a film is live).

### DWT phases (cycles, mean of 16 chains)

| configuration | sign pass | chain | keygen (cache miss) |
|---|---:|---:|---:|
| **product today**: one-shot driver, per-digest tick | 242.1 M | **484.6 M (3.03 s)** | 77.6 M |
| product, no tick | 233.4 M | 467.3 M | 74.4 M |
| research driver, per-digest tick (asm compiles out) | 161.0 M | 322.3 M | 48.1 M |
| **#1149**: research driver, batched tick | 91.7 M | **183.7 M (1.148 s)** | 31.4 M |
| research driver, no tick | 91.4 M | 183.2 M | 31.4 M |

In every configuration, the FI chain outside the two signs and the verify costs (re-measured with complete accounting after Astra's review). The 13 phases are contiguous from the chain's first internal stamp through the caller's extraction of the result. Only the caller's own timing overhead, 325–364 cycles per chain, lies outside them:
- `ct_eq` 116 k;
- the release (the return copy and the drops on the way out) 30 k;
- the rest ~15 k (rate/CFI 2.7 k, OptRand 0.2 k, seeds 1.2 k, two delays ~3.9 k, verify gate 3.1 k, CFI check 3.3 k);
- **0.16 M in all (0.03% today, 0.09% with #1149)**.

The re-run chains are 485.8 M (product), 464.5 M (product + `oneshot-speed`, −4.4%) and 183.6 M (#1149). The bench's own code changed slightly, so these sit about 0.25% above the first runs.

The verify is 0.21–0.24 M. Progress callbacks: 185 per chain. Ticks: 979 k per chain today (one per digest), 8.2 k batched.

**Axes** (chain, product / #1149):

| axis | product | #1149 |
|---|---:|---:|
| driver at opt 3 | 445.4 M (−8.1%) | 180.7 M (−1.6%) |
| `target-cpu=cortex-m33` | 493.4 M (+1.8%) | 182.8 M (−0.5%) |
| 2-way ICACHE | 478.6 M (−1.2%) | 183.2 M (−0.3%) |

### PC-sampling attribution (`prof_classify.py`)

| bucket | product today: share | product: per chain | #1149: share | #1149: per chain |
|---|---:|---:|---:|---:|
| HASH driver (its outlined fragments assigned by caller) | 75.6% | ~366 M | 92.4% | ~170 M |
| signer Rust (`sign_with_shuffle` body 9.7%, `wots::keygen_pk` 6.5%) | 16.3% | ~79 M | 6.6%¹ | ~12 M |
| memcpy / memclr (signer buffer builds and copies) | 4.2% | ~20 M | 0.7% | ~1.2 M |
| UI tick (stub; DWT: 17.4 M / 0.5 M) | 3.9% | ~19 M | 0.1% | ~0.2 M |
| FI chain + bench glue (DWT) | 0.03% | 0.16 M | 0.09% | 0.16 M |
| **outside the driver** | **~24%** | **~118 M** | **~7.6%** | **~14 M** |

¹ `hits_target` (5.6%) runs as the search asm's callback inside the engine window, so it is mostly overlapped. About 4 M per chain is not overlapped.

**The sampling window holds about 2% keygen.** The categories exclude only `0xFFFFFFFF` (the halted core).
- `prof_report.py`'s "drop the most common PC as the halt" heuristic dropped the hottest driver PC (the DCIS poll in `oneshot16`, 22% of samples) here, because the window ended before the bench halted.
- The round-12 profile was not affected (its dropped PC was `0xFFFFFFFF`). Earlier ones should be read with this in mind.

### Levers, ranked by measured share

| # | lever | effect | owner? |
|---:|---|---|---|
| 1 | Land the rounds 7–12 research driver together with #1149's batched tick | chain 484.6 → 183.7 M (−62%) | **owner** |
| 2 | `oneshot-speed` (E20, below) | product chain −4.5% (golden −6.4%), +192 B | owner to enable |
| 3 | Driver at opt 3 via the root profile | −8.1% today, −1.6% after lever 1 | **owner** |
| 4 | Signer memcpy / per-hash Rust overhead | 4.2% + 16.3% today, ~0.7% after lever 1 | proposal (FV) |
| 5 | The UI tick | 3.6% today, ~0.3% batched | lever 1 |
| 6 | The SE draws (~0.3 s, ~48 M) and film frames (~8 ms per frame while live) | not kit-measurable | owner |
| 7 | 2-way ICACHE (−1.2% / −0.3%); `target-cpu` (worse or noise) | noise to small | owner |
| 8 | The FI chain (0.03–0.08%) | negligible | **not touched** |

1. **The research driver with #1149.** The two are inseparable: the asm paths compile out under the per-digest tick, which is why the driver alone only reaches 161 M. Owner decisions: secure flash (already over budget with `ui-px`), film cadence, and the tick-must-not-hash contract.
2. **`oneshot-speed`** helps only until lever 1 lands. Enabling it in the product is the owner's call: flash and a nightly feature.
3. **Driver at opt 3 through the root profile** moves the FSBL bytes, so it is the owner's call.
4. **Signer memcpy and per-hash Rust overhead.** The sources (Fable): `chain_buf`/`chain_value` by-value copies, the `th` buffer builds, `wots_secret`'s 80-byte build plus its volatile wipe. This is a `sphincs-c10` proposal only (FV-extracted).
5. **The UI tick.** Already covered by lever 1.
6. **The SE draws and film frames.** These are the largest wall-clock items after lever 1. The kit has no SEs, so neither can be measured here.
7. **2-way ICACHE and `target-cpu`.** Small or noise, and both are owner settings.
8. **The FI chain.** Nothing to gain, and it is off limits.

### E20: `oneshot-speed`, keep (`57f13afa3`; enabling it in the product is the owner's call)

**What changed.** `#[cfg_attr(feature = "oneshot-speed", optimize(speed))]` on the five streaming / one-shot entries (init, update, final, oneshot, oneshot16), with the crate gate `#![cfg_attr(feature = "oneshot-speed", feature(optimize_attribute))]` (nightly). The feature implies `oneshot`, is in `SECURE_IMAGE_ONLY`, and nothing in `fsbl/` or `secure/` names it.
- **With the feature off, nothing changes:** the FSBL is byte-identical, and the product-shaped `bench_chain` image built against the pre-E20 and the current driver is byte-identical (`01d8d41ef396…` both).
- **With it on:** attributes only, and no FI-chain code is touched. But the five entries' machine code (layout, timing, spills) changes, and that has not been FI-evaluated (Astra). Output identity is shown by the goldens and gate 5, not by construction.

**Results:**
- the MachineOutliner fragments and the slice-index helper are gone (re-profiled);
- product chain 484.6 → **462.8 M (−4.5%)**, keygen 77.6 → 72.1 M;
- v1 one-shot golden in product codegen (`bench_os`, driver at `z`, generic target): cached sign 494.2 → **462.7 M (−6.4%)**;
- text +192 B.

**Evidence:**
- `golden.bin` bytes equal, with and without the feature;
- gate 5 2,940/0 in product codegen both ways (1,125 one-shot and streaming probes against software SHA-256);
- a new residue mode in `bench_chain`: `oneshot16` on the `wots_secret` preimage, `oneshot` on a secret-PRF preimage, and streaming with the key in its own update. Clean with and without the feature; the positive control (`residue-control`) fires;
- FSBL identical (`e34d6e8ecabb3109f8ca`);
- landing tests: research features 27 → 28, and the attribute is pinned to exactly the five entries under the feature, with the crate gate behind it. Plants S1b, S2, S3, S4 and S5 are caught; S1 is stopped by the compile;
- full plant set: 57 caught by the tests, 6 stopped by the host compile;
- secure suite 2,984/0; FSBL footprint ok.

**Residue scanner: two defects found and fixed (Astra review plus an endpoint control).** `residue.rs` is shared by the standing gate since round 9.
- **The 64 bytes below sp were scanned but never cleared.** The bench's own `res_add` frame could read as a residue there: mask 0x7 at sp−60 in `bench_chain`. `res_clear` now clears up to sp; interrupts are masked and nothing below sp is live.
- **The words nearest sp were never truly observed.** The loop stopped at `a < sp − 4`. Worse, at opt-level `z` its `read_volatile::<[u8; 4]>` and `<[u32]>::contains` are out-of-line calls whose pushes overwrite the band being scanned before it is read.
  - A new endpoint control (a key word written at sp−4) did not fire until the loads became one inline-asm `ldr` (`res_ld`) and the pattern test a call-free loop. Both positive controls now fire (mask 0x18).
  - Rounds 9–12's gate therefore had a blind band of the top few words below sp. That is where a driver entry's prologue pushes the caller's callee-saved registers.

**With the fixed scanner:**
- the v1 suite is clean (7 cases);
- the product one-shot cases are clean, with and without `oneshot-speed`;
- **the v2 suite flags 0x44–0x46** (`prf_chain16` and `chain16`, and in one build `wots_pk16`). The hits sit at sp−16 and sp−12, which are the r5 and r6 slots of the entries' `push {r4, r5, r6, r7, lr}`. These are values the bench caller held in callee-saved registers, saved as AAPCS requires: the round-10 "caller-held secret spilled by the prologue" class, and codegen-sensitive.
  - **Astra confirmed it from the disassembly:** the bench's software pattern computation leaves its final word in r5 before `prf_chain16` and in r6 before `chain16`. The recomputed words (`0x3eebfed4`, `0xeacefe30`) match the logs. These are not driver spills.
  - The `wots_pk16` hit (one build only) has no diagnostic evidence yet.

Separating bench-held from driver-held values needs the v2 suite to compute its patterns outside the calling frame. Until then the v2 standing residue gate is red for that reason. E20 does not touch those entries.

For the product, the open question is whether the signer holds secrets in callee-saved registers across driver calls. That is signer codegen, so a proposal only.

> **UPDATE 2026-11-13 (re-run 2026-11-14, round 14).** "The v2 standing residue gate is red" (above) is **resolved: the hits were harness artifacts and the gate is green.**
> - The v2 suite now computes its patterns out of line and runs each case in its own frame.
> - `prf_chain16` and `chain16` were the bench caller's r5/r6 values.
> - `wots_pk16` was the scanner's own last-loaded pattern from the previous case (case 0's table is identical to case 1's), saved by the next entry's prologue. Swapping the order moved the hit to case 0, with the same word and the same pattern index 1583 of 1584.
> - No driver change was needed. The product's open question (does the signer hold secrets in callee-saved registers across driver calls) remains a signer-side proposal.

## Round 14 (2026-11-14): residue finding — isolate, diagnose, correct the record

**Isolation (`bench_v2drv`, residue mode).**
- The secrets live in statics, written by an out-of-line `res_setup`.
- Each case's patterns are computed by an out-of-line `res_pats`, so the calling frame never loads a secret byte.
- Each case's clear, driver call and scan run in an out-of-line `res_case` frame. A pattern the scan leaves in a callee-saved register is restored on return and cannot reach the next case's driver prologue.
- The caller passes only static addresses and public A7 words.

**Diagnosis of the round-13 hits.**

| entry | round-13 hit | under isolation | cause |
|---|---|---|---|
| `prf_chain16` | sp − 16 (`0x3eebfed4`) | clean | the bench's software pattern computation left its last word in r5; the entry's `push {r4, r5, r6, r7, lr}` saved it (Astra, disassembly) |
| `chain16` | sp − 12 (`0xeacefe30`) | clean | the same, r6 |
| `wots_pk16` | sp − 12 (`0x327590f0`, pattern 1583 of 1584) | clean | the previous case's scan left its last pattern (the same table) in r6; the entry's prologue saved it. With the order swapped, case 0 flags instead, with the same word and index |

**Per-entry verdict under the fixed scanner** (`gate_residue.sh`, extended: each suite's `residue-control` build must flag its two positive controls, a frame copy of the key and a key word at sp − 4, and nothing else):

| suite | entries | verdict | controls |
|---|---|---|---|
| v1 (`bench_v1micro`, 7) | key loop, sign-shape keys, FORS subtree, grind with and without rand, `prf_chain16`, `chain16` | **clean** | 0x180 (both fire) |
| v2 (`bench_v2drv`, 9) | `wots_chains16`, `wots_pk16`, `prf_chain16`, `fors_leaf16`, `fors_subtree16` h4 / h7, `chain16`, `grind_r` 119 / 103 | **clean** | 0x600 (both fire) |
| v2 with `prf2` | the same 9 | **clean** | 0x600 |
| product (`bench_chain`, 3) | `oneshot16` on the `wots_secret` preimage, `oneshot` on a secret-PRF preimage, streaming with the key in its own update | **clean** (round 13: also with `oneshot-speed`) | 0x18 (both fire) |

**No driver fix was needed**, so no goldens, kdiff, gate 5 or FSBL re-runs: no driver code changed this round. The rounds 9–12 records carry dated UPDATE notes:
- every entry as it is today passes the corrected scan;
- the superseded implementations (E6, E7, E12, E13) cannot be re-validated, so their claims stand only as made on the old scanner;
- E10's independently found wrapper spill and its fix stand;
- the only changed verdict is round 13's interim "v2 gate red".

**Coverage limit (Astra):** selected inputs and patterns within 4 KiB of dead stack. Not signer-held secrets, not arbitrary configurations, and not all leakage.

**Gate acceptance (Astra):** the v1 control build is now judged by a control-aware `experiment_v1micro.sh`. It must complete with every other correctness check passing, so a faulted control run fails the gate.

## Round 15 (2026-11-14): wall-clock items the kit cannot measure (source-only trace)

No code changes, no kit runs. Three read-only traces with file:line evidence; I verified their load-bearing citations. Fable then checked the synthesis. The SE driver figures are estimates from source unless marked measured.

### Where each item runs (cached Type-2 sign, pixel route)

In `secure/src/nsc/cmd_sign_userop.rs`, in order:
1. parse, trailers and pages, then the **confirm** (~2076–2101);
2. atlas re-hash (~2111), the entropy blob from its SRAM cache, page-123 reads and the cap check;
3. **`film_start` (~2356)**: the busy film starts here, *before* slot-key lookup and any cache-miss keygen;
4. `c10_sign_verified_with_progress` (~2821), which runs:
   - **`pre_sign`** (crypto.rs ~95);
   - the **three strong-RNG draws** under `ChipWaitTicks` (~241–328);
   - sign A, delay, sign B, compare, delay, verify, CFI;
5. two more verifies (~2855);
6. the page-123 commit: normally one 16-byte tally append (a quad-word program with a busy-flag spin) when the registered slot's reconciled count is unchanged; otherwise one more append first (`last_userop_count_set`, `hw/flash.rs` ~2866), with compaction when the page is full;
7. the output;
8. **`film_resolve(Signed)` (~3056)**, then return (~3072).

The batch handler draws once per batch and uses the same landing. Deploy and rotation commands sign twice, so they make 6 draws and call `pre_sign` twice.

### 1. The film floor: the largest wall-clock item, by far

`film_resolve` draws until the film is done (lcd.rs ~2300–2345). `pqsigner-ui-px/src/loading.rs`:
- `done` needs film time ≥ T7 + `RESULT_HOLD_MS` = 6,200 + 2,450 = **8,650 ms** (~352);
- an answer after T5 = 4,800 ms adds whole 850 ms turns (`wraps_for`, ~250).

So on the pixel route, **if the answer comes by T5 (`t_ready` ≤ 4.8 s), the host gets the result ≥ 8.65 s after `film_start`, however fast the sign is**, and in every case at least 3.85 s after the answer. The source does not establish that every cached sign finishes before T5, nor the exact host latency. The cost is arithmetic from constants (certain); on-glass timing has not been measured.

**Scope:**
- the pixel route only (`ui-px` is outside `make release`; the investor and EF images use it);
- an atlas failure returns at once;
- the film-less resolve is 400 + 2,450 = 2,850 ms (loading.rs ~408);
- other routes end in a 3,000,000-iteration nop loop (≥ ~19 ms at 160 MHz).

**Film CPU during the sign** (estimates from measured pieces):
- a frame starts every ~32 ms (two TE refreshes), or every 28 ms with no TE stamp;
- chip waits (`busy_poll`) draw back to back at 16 ms;
- per frame ~5 ms CPU on DMA images (EVT, 2026-10-22: 3.7 ms render plus ~1 ms band-buffer wait, since removed);
- so about 12–16% of wall time with DMA and TE stamps, ~60% with DMA but no stamps, and ~40% without DMA (arithmetic only; `PX_SHIP_FEATURES` lists no `ui-px-dma`, but the investor/EF release script does).

Whether a unit has TE stamps is decided by a runtime self-test, not by source.

### 2. The three strong-RNG draws (OptRand 16 B, two 32-B shuffle seeds)

**What they do.** Each `rng_strong::fill` does a platform TRNG fill, then one OPTIGA and one SE050 GetRandom per ≤ 32-B chunk (`rng_strong_fold.rs` ~760–766, `MAX_SOURCE_BLOCK` 32), XOR-combined (~1026–1031). That is one round trip per chip per fill, six per sign. That count holds on the successful, already-open-session path: the OPTIGA re-handshakes near nonce reuse, and both drivers retry once with session recovery on a failure (`optiga/mod.rs` ~358, `se050/mod.rs` ~1050).

**Per draw, from source:**

| | OPTIGA | SE050 |
|---|---|---|
| command APDU | 6 B | 10 B |
| protection | 19-B CCM-8 record (software AES) | 30-B SCP03 C-ENC + C-MAC (software AES/CMAC) |
| transport frames | 25 B out, 23 + N B back | 36 B out; a 48 / 64-B T=1 frame back (the 42 / 58-B protected response plus 6 B of T=1) |
| I2C transactions (minimum) | 8 | 4 |
| guard delays | 50 µs nominal (`optiga/i2c.rs` ~45) | — |

Each not-ready poll costs extra (`ifx_i2c.rs` ~359; `t1oi2c.rs` ~309). The bus runs at 400 kHz (`board/mod.rs`, TIMINGR `0x1090378F`).

**FI-checked CPU work:**
- ~94 random delays per fill outside the platform fill, each drawing its own length: ~0.01 ms on the raw-TRNG-word path, **0.37 ms if it falls back** to the hardened 1-byte fill (`fi.rs` ~41–74);
- the pooled delays inside the platform fill: 106 / 206 for 16 / 32 B, measured ~8 µs each.

**Estimate per sign (all three fills):**
- **baseline estimate ~25–35 ms, including guards and FI CPU work**: ~600 B ≈ 13.5 ms, OPTIGA guards 1.7–5 ms, FI ~9 ms;
- **plus ~100 ms if the delay fallback dominates** (94 × 0.37 ms × 3);
- **plus chip processing and poll waits, which the source does not determine.** `crypto.rs` ~313–315 records "tens of ms of FI-checked CPU work" per draw and ~54 ms pauses at each draw boundary (EVT, 2026-10-22).

**Where "0.3 s" comes from:** commit `48a20b25d` (owner, EVT, 2026-10-21): "303 ms @0, the longest pause of the run", from the film-gaps recorder. That is **the longest film gap, not a draw duration**, and it was measured *before* the 2026-10-22 fixes. Those fixes cover FI delays drawing their own length (0.37 ms × 86 per draw, `docs/ui/pixel-ui-pilot.md` ~143), the SE050's fixed 259-B reads, and `ChipWaitTicks` now drawing the film during chip waits. So the 0.3 s is **unconfirmed for today's image**.

### 3. `pre_sign` (`secure/src/sign_rate.rs` 239–258)

- SRAM only, no flash write: a 250-sign session cap, then `wait_for_min_interval` (F-17: `MIN_SIGN_INTERVAL_MS` = 1,000), then the tick is stamped.
- **Start to start:** it binds only when the previous sign started < 1 s ago. That happens to the second sign of a deploy or rotation command once a sign drops under ~1 s; #1149's 1.15 s leaves ~150 ms.
- The wait is `wfi` on the ~1 ms SysTick. Wall cost: max(0, 1,000 ms − time since the previous sign started).
- That a normal confirm dwell makes it zero is an inference, not a measured result.

**Defect found (fail-open, FI): flagged for the owner and security review, not fixed here.**
- In `wait_for_min_interval`'s error arm (~377–391), when the first voted read of `LAST_SIGN_MS` disagrees, the code waits for one clean voted read and then **returns without checking the interval**, contradicting its own "fail-CLOSED" comment.
- One fault on that read skips the 1 s floor.
- The 250 cap and the caller's postcondition (`crypto.rs` 94–98, which checks only the count) still hold.

### Levers: proposals only, none implemented

Ranked by end-to-end effect. A cached pixel sign answers before T5, so b–f save **0 ms** end-to-end in the common case.

| # | lever | effect | gate | invariants |
|---:|---|---|---|---|
| a | shorten the film: don't block the host on `RESULT_HOLD_MS` (the result frame stays on the glass); fewer `REVS` | up to −2.45 s and −2.55 s; the only lever that moves the common case | **owner (UX / designer)** | no crypto or FI invariant; trusted-UI review |
| f | thin film frames during hashing | pays only past T5 (cache miss, deploy, rotation), in 850 ms steps; frees 12–60% of CPU while signing | owner (UX; risks the 10-22 stutter fixes) | none |
| e | check the FI-delay raw-word path is not falling back | up to ~0.1 s per sign if it is | measurement, ungated: a performance diagnostic. The fallback still draws hardware randomness, so it does not by itself breach the carve-out | delay-length sourcing (hardware TRNG either way) |
| d | one draw per source per sign (raise `MAX_SOURCE_BLOCK`, one fill of 80 B) | 2 × 2 round trips and ~190 delays fewer | **security / FI review** | three-source composition kept; the three separately gated fills and their all-zero checks merge; pinned tests change; chip length limits unverified |
| b | draw OptRand + seeds during the confirm dwell | hides the draws behind the human | **security review** | freshness becomes "per confirmed request"; the draws leave their place after `CFI_STEP_RATE_LIMIT`; needs consume-once and zeroize-on-decline |
| c | overlap SE I/O with hashing | only seed B can overlap sign A | **security / FI review** | changes the CFI step order; needs secure-world concurrency |

None touches invariant #4, and none needs a software PRNG.

**What this means for #1149:** on the pixel UI a cached sign that answers by T5 returns in 8.65 s whether hashing takes 3.0 s or 1.15 s. #1149 pays on long signs (in 0.85 s steps), on the non-pixel route, and as headroom once the film is shortened. Shortening the film is the user-visible decision.

### EVT measurement plan (for the owner)

**Build:**
- the recorder build: `FEAT_S=dual-se,dev-testkey,ui-lcd,ui-px,ui-px-dma,dev-dfu,stm32u585,usb,board-pq1,stack-hwm,ui-px-film-gaps` (`docs/ui/pixel-ui-pilot.md` ~118). This is a `dev-testkey` bench profile; today's investor/EF images default to `devunit-die-keys` (`tools/devunit/release.sh` ~48);
- flash with `tools/evt-dev-flash.sh`; sign with `tools/hid_sign.py`;
- record the commit and the feature set;
- for the end-to-end figure, build again with **both** `ui-px-film-gaps` and `stack-hwm` off. The recorder costs time, and `stack-hwm` holds `film_resolve` until a press or 60 s (lcd.rs ~2348, ~2410).

**New instrumentation is needed.** The recorder's WHERE, SE050 and FI pages show only the three longest pauses, phases spanning frames are split, and other pauses are discarded (`film_gaps.rs` ~239, ~360, ~417). So the plan needs a small dev-only addition:
- per-fill, per-source duration totals;
- whole-sign deltas of the counters;
- phase timestamps (confirm, `film_start`, `pre_sign`, each fill, sign A/B, the verifies, commit, `t_ready`, `film_resolve` exit);
- elapsed time recorded host-side in `hid_sign.py` (~278 has none).

This is a code change for a later round, with the owner's go.

**Capture for N ≥ 30 signs** (min / median / max; the first sign after unlock reported separately from warm ones):
1. Each of the three fills as a duration, split by source: platform TRNG, OPTIGA, SE050. This comes from the new per-fill totals; the recorder's pages give only the three longest pauses.
2. Wire time against chip latency: OPTIGA not-ready poll counts and SE050 start-byte polls, or a logic-analyser trace of I2C1 / I2C4 (the LA1010 is on this host).
3. Deltas of `DELAY_RAW_DRAWS` and `DELAY_RAW_FALLBACKS` per sign (the "FI ms n slow" page): a fallback rate per draw.
4. `t_ready` against T5, any wraps, and the `film_resolve` wait. Whether TE stamps are present (GATE page).
5. Host request-to-response time (`hid_sign.py`) and USB time after return.
6. One deploy or rotation command, to see `pre_sign`'s wait on the second sign.

**The output must show:**
- a per-sign table: confirm→`film_start`, `film_start`→sign start, `pre_sign` wait, draws (per fill, per source), sign A, sign B, the verifies, commit, `t_ready`, the film wait, and the host total;
- the fallback rate;
- whether 0.3 s still holds.

## Round 16 (2026-11-14): format changes as candidates — v2 0.3 dossier, family search, split810

**Owner, 2026-11-14:** format changes may enter the final code if security is no weaker than stock C10 (v1: h=18 d=2 a=11 k=13 w=8 l=43 T=205, 4,008 B). A later refinement makes gate (S) a **reporting device**: each item is marked PASS, MINOR-LOSS or FAIL with its numbers, and the owner decides minor losses. SHA-256 stays.

Labels: **[computed]** = a script printed it (named); **[argued]** = reasoning; **[reviewed]** = Astra.

### 1. Dossier: v2 draft 0.3 (#1155, the one-block format) against stock C10

Computed items: `c10v2/dossier_v2_03.py`. It imports `bound_variants.py` (and runs its anchor) and `format_options_numerics.py`.

**(a) The proven bound: equal numbers, proof not yet ported. Mark: PASS on the numbers, NOT YET PROVEN for v2.**
- **Quantitative.lean floor**, min(k·a, n − qBits, n − 2·qBits), equal [computed]: slot cap 2^16 gives 96 bits for both; the P14 bootstrap across C chains gives 94 b at C = 2 and 88 b at C = 16 for both. The Grover convention (half of each) gives 48, 47 and 44. That convention is not a QROM theorem.
- **EasyCrypt-shape bound**, equal [computed]: v2 0.3 changes no constant (`consts()` is equal; the script asserts it).
  - qr = qs = 2^16: ordinary 2^-60.80, wrapper 2^-59.80.
  - Bootstrap C = 2: 2^-59.80 and 2^-58.80; C = 16: 2^-56.80 and 2^-55.78.
- **Not proven:** the EasyCrypt theorems are proved for v1's byte format (32-byte seed blocks, 32-byte ADRS, v1's FORS_LAST tweak sharing). For v2 the equal row is "if the proof ports with the same charge structure". The port means re-checking the byte-layout-dependent refined exclusions (`LeafGrindingCandidates.ec`, `NodeQueryDomain.ec`) against the A7 one-block encoding, plus v2's dedicated FORS_LAST type 9, which removes v1's tweak sharing. Until then (a) is a computation, not a theorem.

**(b) Hash assumption: the same assumption. Mark: PASS [argued].**
- **The model:** both formats are the "simple" SHA-256 tweakable hash, modelled as a random oracle (classical) or quantum random oracle (Hülsing–Kudinov, ePrint 2022/346). The project's EasyCrypt proof is an ideal-oracle byte game over SHA-256 in either format, so v2 adds no assumption.
- **What it needs instead is an injective encoding of logical inputs:**
  - A7 injectivity [computed, `format_options_checks.py` A];
  - v2 input lengths disjoint from v1's, except the shared R-grind PRF, which is the same function [spec §3, listed];
  - the 39-byte KDF inputs separated by a fixed 7-byte ASCII prefix against hash outputs, plus secret keying [argued, spec §3].
- **H_MSG with R last** relies on SHA-256 collision resistance in M. M is already an unrandomized SHA-256 digest of the signed object, so this is no new assumption [argued].
- **Outside the random-oracle model** the constructions differ: v1's first compression block is seed ‖ ADRS, v2 makes one compression from the fixed IV. The project analyses neither in the standard model.

**(c) Fault fallback and SCA margins. Mark: MINOR-LOSS (DPA exposure), with a costed fix.**
- **Fault fallback: equal [computed].** One WOTS key signing two sum-205 digests leaves a median per-try forgery of 2^-55.21 (1st percentile 2^-47.27). That depends on (l, w, T) only. The FI chain (double compute, compare, verify-before-release, shuffle, sentinels) is the same code [argued].
- **DPA exposure: higher [computed count, argued impact].** Per signing pass, these are the single compressions that take `sk_seed` together with attacker-known varying words:

  | | FORS PRF | WOTS PRF | total |
  |---|---:|---:|---:|
  | v1 | 24,576 (one 48-B block) | 0 | 24,576 |
  | v2 0.3 | 24,576 | 44,032 | 68,608 (×2.79, about 1.5 bits) |

  v1's WOTS PRF is 80 B. Its `sk_seed` block, `sk_seed ‖ "wots" ‖ layer ‖ 0^24`, is constant per layer; the varying fields meet only a per-layer secret chaining value in block 2. v2's WOTS PRF is one block, `sk_seed ‖ A7`.

  So an attacker gets the same `sk_seed` trace budget from about 2.8× fewer signing passes. This is an exposure count, not a measured DPA margin.
- **Fix [argued, cost estimated]:** keep the WOTS secret PRF in v1's two-block shape, with `sk_seed` in a block that is constant per layer. The PRF is signer-side key derivation; the verifier never computes it. It costs +44,032 compressions per pass, about +4 M cycles (≈ +8% of 50.35 M), and restores v1's exposure. FORS is unchanged: v1's FORS PRF is already one block.
- **HR residue:** both formats compute 32-byte PRF digests and use 16 bytes, so there is no change [argued].

**(d) Format identifier in key derivation. Mark: FAIL as implemented, with a simple fix.**
- v2 derives `(sk_seed, pk_seed)` with v1's tags (`domain/src/lib.rs`); nothing binds a format.
- Between v1 and v2 the preimages are length-disjoint, so their chains and secrets are independent under the PRF assumption [argued]. Between v2 *variants* they are not (format-options-security §4: 2^53–2^77).
- **Fix (proposal, not implemented):** under the v2 feature only, derive the v2 master with a format-bound tag (e.g. `"sphincs-c10v2-0.3"` / `"...-acct"`) so that any later v2 variant needs a new tag. Account-0 stock tags stay untouched in default builds. This means a new address per format, which invariant #6 accepts only if the format is fixed before the first v2 key signs.

**(e) Review and reproducibility.** Every number above comes from `dossier_v2_03.py`, `bound_variants.py`, `format_options_numerics.py` and `format_options_checks.py`. Astra review: pending (next entry).

**Dossier bottom line:**
- **Not yet airtight.** (a) is equal in numbers but not proven for v2's byte format, (c) has a ~1.5-bit DPA exposure increase, and (d) is missing.
- The (c) and (d) fixes are small and specified: two-block WOTS PRF (about +8% sign), and a format-bound KDF tag.
- (a) needs the EasyCrypt byte-model port. That is the real remaining cost of adopting v2.

### 4. split810 (#1164) and ts200 (#1165) against gate (S)

**split810: is the ×1.21 pure proof slack?** Mostly yes; the residual is negligible but real. Read-only analysis of the EasyCrypt sources; the numbers come from `bound_variants.py`'s formulas with memoized accounting; argued, not proved.
- **Where the ×1.21 comes from.** The model signer rebuilds every layer's subtree on every signature (`RawLayer.ec:19` calls `RawMerkle.build`, per layer per signature, `RawSigner.ec:17–19`; twice per wrapper signature). The cost lemmas put that call count into the theorem's right-hand side through the `ChainVariable…Cost`, `LeafTarget…Cost` and `WrapperWotsCandidateCost` families.
- **Why that is slack.** The adversary's budgets are only qr and qs, and the signer's call log keeps repeats (`DomainQueryCount.ec:1` says "including cached repeats"; `WrapperLayerMemo.ec:1–2`). Counting distinct calls gives a new right-hand side for the same game and the same scheme.
- **Charging each hypertree subtree once** (FORS and the per-layer remainder kept; the wrapper still pays FORS twice), at qr = qs = 2^16:

  | | ordinary | wrapper |
  |---|---:|---:|
  | v1 tight | 2^-63.51 (×0.153 of stock-as-proved) | 2^-62.52 (×0.152) |
  | split810 tight vs v1 tight | ×1.00022 (+0.0003 bits) | ×1.00019 |

- **The residual is real, not accounting.** split810's 512 extra top-layer WOTS keys are distinct nodes: 154,624 more distinct calls, and a WOTS universe ×1.00195.
- **Verdict on the gate:**
  - **today:** FAIL (×1.213; and not proved for (8, 10) at all);
  - **after a tightened proof:** MINOR-LOSS of 0.0003 bits against v1 tight. "Tight split810 vs stock as proved" (×0.153) is not apples to apples, because the same tightening gives v1 ×0.153.
- **Proof work (judgement; nothing in the repo calibrates it).** The EasyCrypt tree is 1,089 `.ec` files and 182k lines; 57 `*Cost*.ec` files in at least 7 parallel families re-prove the build charge.
  - **Tightening at (9, 9):** a ghost set of built (layer, tree) pairs, with every build query of a built tree already in the log and the oracle table (keygen seeds the top tree with `build`'s inputs, so a rebuild adds 0 distinct calls). Either count `size (undup …)` with `RawSigner` kept, or add a memoizing signer plus an equivalence hop. About 3–6 new modules (0.5–1.5k lines) and edits in 40–60 files: **~10–30 person-days**. `functional_merkle_build_queries` exists, but over the fixed-function backend and hard-coding 9 levels.
  - **Generalized heights** (needed for (8, 10) at all): 108 files hard-code the height (`%/512` ×135, `%%512` ×88, `kp < 512` ×34, `nseq 9` ×14, …): **~20–60 person-days**, separate.
  - **The v2 byte port** (dossier (a)): separate again.
- **Also tightens stock** by ×0.15 (2.7 bits), so it is worth doing for v1 alone if the proof is touched.

**ts200 (#1165).**
- **(a):** proven-bound total ×1.0000; the encoding term ×0.30 (better) at these caps [computed, format-options-security §8].
- **(c): fault fallback 1.6–1.7 bits weaker** [computed: two-digest median 2^-55.3 → 2^-53.7; 1st percentile 2^-47.3 → 2^-45.6]. **FAIL under the strict reading.** Reported, not adopted.
- **(d):** keys do not change. A seed that signed under 205 must never sign under 200, or every reused WOTS key becomes two-time (~2^53). ts200 therefore needs a format-bound KDF tag more than any other option.

### 1b. Astra's review of the dossier (amends §1; the original verdicts are kept above)

Astra: **NO-GO against the strict a–e gate.** It reran the script: 500 samples give 55.00 / 47.59 bits, and the default 2,000 give 55.21 / 47.27. The corrected verdicts:

| item | verdict | correction |
|---|---|---|
| **(a)** | **GAP, blocking** | Halving the floor is **not a quantum check**: Grover scaling applies to a specified search problem, not to classical probability bounds or honest birthday events, so those values are an unsupported heuristic. The Lean floor checks arithmetic over imported estimates (`Quantitative.lean:245`). The EasyCrypt numbers are advantage bounds at qr = 2^16, not security levels. Classical and quantum statements parameterized by hash queries and qs = C·2^16 are still needed; a classical byte-model port alone cannot close (a). |
| **(b)** | **Conditional PASS** in the whole-hash random-oracle model | The EasyCrypt oracle samples whole byte strings and has no compression-block semantics, so it does not exploit v1's seed ‖ ADRS block (its exclusions do depend on v1 offsets). Gaps: the 39-byte KDF overlap is probabilistic, not structural, and needs a composition bound or disjoint encodings; H_MSG with R last lets one inner collision in `Compress(IV, S ‖ root ‖ M)` survive every R, which full SHA-256 collision resistance covers but which does not preserve a weaker randomized-hashing argument. |
| **(c)** | **GAP, blocking** | Fault arithmetic: equal. **The DPA counts were wrong.** Corrected in `dossier_v2_03.py`, which now counts tree 12, v1's recomputed revealed FORS leaves and the signing PRFs, and separates the cache state. Without the top cache, v1 26,636 against v2 70,742 (×2.656, 1.41 b); with the warm top cache, 49,414 (×1.855, 0.89 b). These are exposure counts, not traces-to-key-recovery, so **the SCA comparison is UNKNOWN**, not MINOR-LOSS. The fix adds 44,118 compressions per pass without the cache (≈ +4 M, to be measured). Also: HASH cleanup covers HR **and CSR**, which the recorded dead-stack scan does not. |
| **(d)** | **FAIL** | **The proposed tag fix is insufficient.** Slot keys use their own slot-master and slot-seed derivations (`domain/src/lib.rs:482`, `:742`). The format identifier must be bound into **both** branches, account variants included, and must distinguish target sum, address layout, PRF variant and the last-FORS-slot construction. Even v1 and v2 still share `sk_seed`, `pk_seed` and the R-candidate PRF, which needs joint-format accounting. |
| **(e)** | **PARTIAL** | Numerics reproduced and source reviewed; no proof replay, no physical validation. |

### 2. The family search (`c10v2/family_bound.py`, `format_options_numerics.py search`, `family_search.tsv.gz`)

**Method.**
- `family_bound.py` generalizes the EasyCrypt-shape bound, signer cost, verify gas, calldata and A7 fit over (h, d, a, k, w, l, T, n).
- It reproduces `bound_variants.py` exactly: 108 term-by-term rational matches over six variants and six cap pairs.
- 2,331,729 valid sets were checked in 223 s: PASS 21,830, MINOR-LOSS 15,710, FAIL 2,294,189.
- **Marks:** loss = the maximum over the floor metrics (classical, the Grover convention, C = 1, 2, 16), the (c) fault margin and log2(set / stock) of the EasyCrypt totals and their coverage and FORS terms. PASS ≤ 0, MINOR-LOSS ≤ 1 bit, FAIL > 1.

**Calibration.**
- **Device cycles:** the stock model gives 51.18 M against 50.35 M measured (+1.65%). Using per-call units derived from the measured shares instead of the briefed ones reproduces 50.35 M by construction.
- **Gas:** interpreter overhead fitted at 93.04 per call, to match Track B's 100,600 callee-only; plus 64,104 calldata, so 164,704 for stock.

**Main result: stock is on the PASS frontier, and no PASS set beats it on all three objectives.** The only PASS set with a signature ≤ 4,008 B is stock itself, so every gain costs signature bytes. Selected PASS frontier rows:

| set | cached sign, M (brief / share units) | sig B | verify gas (callee + calldata) | (c) Δ bits | EC ratio | A7 |
|---|---:|---:|---:|---:|---:|---|
| stock / v2 0.3 | 102.6 / 100.9 | 4,008 | 164,704 | 0 | 1 | fits |
| **h18 d2 a11 k13 w4 l64 T124 ("w4")** | **75.3 / 71.9 (−27%)** | 4,680 (+672) | 160,182 (−2.7%) | +0.34 | 0.651 | **fits as-is** |
| h18 d2 a10 k16 w8 l43 T205 | 95.6 / 93.9 | 4,344 | 175,910 | 0 | 0.622 | fits |
| h18 d2 a9 k19 w4 l64 T124 | 63.9 / 60.5 | 5,256 | 179,407 | +0.34 | 0.222 | fits |
| h16 d2 a10 k22 w4 l64 T124 | 46.5 / 43.0 | 6,040 | 205,538 | +0.34 | 0.082 | fits |
| h18 d3 a11 k13 w8 l43 T205 | 54.8 / 53.9 | 4,700 | 203,166 | 0 | 0.311 | re-layout |
| h18 d3 a11 k13 w8 l46 T209 | 39.7 / 36.3 | 4,844 | 219,635 | −0.04 (MINOR) | 0.325 | re-layout |
| h20 d4 a8 k18 w8 l47 T211 | 20.7 / 17.2 | 5,824 | 276,087 | +0.23 | 0.156 | re-layout |
| h18 d3 a8 k24 w4 l65 T124 | 20.3 / 16.6 | 6,764 | 233,322 | +0.05 | 0.035 | re-layout |

**What the metrics cannot see (agent and Astra):**
- The Lean floor is min(k·a, 112, 96): it never moves once k·a ≥ 96.
- An EasyCrypt ratio below 1 mostly reflects a cheaper model signer (fewer node candidates), not more security.
- Cycles for d ≥ 3 and w = 4 extrapolate from one calibration point. The driver asm is specialized to l = 43, w = 8.
- The constants for d ≠ 2 (the WOTS universe) are labelled assumptions.
- d = 1 rows and anything needing more than 56 address bits are excluded.

**Re-proof cost (token counts).**
- **Lean:** `Params.lean` has 6 hits; 3 of 12 other Spec files.
- **EasyCrypt:** 266 of 1,089 split `.ec` files (1,188 hits for 43/205/512/2048), plus 95 files carrying derived literals (155135, 364892, 771, …).
- **Scope:** any change other than T restates the cost, universe and encoding lemmas.

### 3. Prototype: the w4 set (host Python only, this round)

- **What exists:** `c10v2_ref.py --variant w4` (w = 4, l = 64, T = 124; digits from the low 128 bits; 4,680 B; A7 unchanged). Self-test: 8 bit-flips, wrong root, wrong message and 3 +C near-misses rejected. Cross-format checks pass both ways. 6 KATs and 3 near-misses (`kat-v2-w4.*`). Draft 0.3 and the other variants are unchanged: their KATs regenerate identically to the pre-change reference.
- **Not done this round:**
  - Rust host behind a flag and kit timing. The kit was off limits during the coordinator's pre-push host run, and the fused driver entries are specialised to l = 43, w = 8 (key loop, digit-sum fold, T_43 feed).
  - Device cost is therefore the calibrated model only: 75.3 / 71.9 M cached, against 102.6 / 100.9.
- **w4 against gate (S):**
  - (a) PASS on the model's numbers, with the same scope caveats as §1b.
  - (b) as v2.
  - (c) fault margin +0.34 b, DPA as v2.
  - **(d): it derives the same `sk_seed`, and its WOTS PRF A7 for ci < 43 equals 0.3's**, so it shares WOTS secrets with 0.3 unless a format identifier is bound into both derivation branches.
  - The WOTS one-time term is w^l = 2^128 against stock's 2^129, which the EasyCrypt encoding term carries.
