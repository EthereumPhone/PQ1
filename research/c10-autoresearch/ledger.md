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
