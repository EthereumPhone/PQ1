# C10 signing speed — hypotheses, round 1

Advisor: Fable 5.2, 2026-11-12. Worktree `pq1-autoresearch-wt`, branch `research/c10-autoresearch`. Read-only pass; this file is the only thing I wrote.

**The loop was running while I worked.** I last read `results.tsv` at row `772f8f29d` (six keeps, cached sign 357.9 M cycles). Anything after that row is not reflected here, with one exception: just before handing back I saw row `56d334b94` (`th`/`th_pair` gather feed, −7.8 M, cached sign 350.1 M). It covers most of N4 below; I have not read that commit.

**Evidence labels.**
- "RM" = RM0456 Rev 7, page numbers as printed in the page footer.
- "Loop" = your `results.tsv`, `ledger.md` and the kept commits.
- "Disasm" = objdump of `out/exp.elf` (the `chain16` build) for the current driver, and of an older product ELF (`~/repos/pq1-gates-wt/…/sphincs-tz-secure`, Oct 31, driver at `opt-level = "z"`) for the pre-loop driver.
- Every saving I predict is an **estimate**. I built and ran nothing.

## Headline

1. **Six keeps have taken the cached sign from 598.7 M to 357.9 M cycles (−40%).** Four of them are hypotheses I reached independently before seeing your results; the table in section C gives your measured numbers beside my estimates.
2. **Tree building is now 63% of a cached sign.** Four 512-leaf builds at your measured 56.4 M each is 226 M of 358 M. The largest remaining output-identical lever is the per-leaf pipeline: fuse `wots_secret` into the chain call (N1).
3. **The top-layer cache is now worth about −113 M cycles, −32% of the current cached sign,** by your own keygen figure. It is the only large algorithmic lever left, and it is track B.
4. **Chain steps look about 70–100 cycles above the engine floor,** but that rests on an unmeasured number: how long the HASH takes for the last block of a 96-byte message. One timing run settles it (H0b).
5. **The kit may over-reward CPU-side savings.** Reading 4 HR words instead of 8 was flat on flash in October and −8.5% on the kit. Kit bias is one explanation; the other is that October's prototype differed. Linking the bench's code at the `0x0E00_0000` code-bus alias of the same RAM would separate them (H0e).
6. **One kept commit has a secret-handling problem:** `0477a87c7` copies `sk_seed` into a stack buffer for every PRF and does not wipe it. N1 removes the copy and should be faster.
7. **Reusing more of pass A in pass B is not available.** Count, layer-0 tree and FORS reuse each remove a check that verify-before-release cannot replace (H15, H16).

## Per-pass budget (computed from the code)

One `sign_with_shuffle` pass, expected values. Block counts follow SHA-256 padding of the preimage lengths in `hash.rs`.

| Phase | Digests | Blocks | Shapes |
|---|---:|---:|---|
| Hypertree layer build, x2 | 354,302 | 731,130 | per leaf: 43 `wots_secret` (80 B, 2 blk), 301 chain `th` (96 B, 2 blk), 1 `th_multi` (1,440 B, 23 blk); 511 `th_pair` (128 B, 3 blk) |
| FORS, 13 trees | ~80,000 | ~160,000 | per tree: 2,048 `fors_secret` (48 B, 1 blk), 2,048 `th`, 2,047 `th_pair` |
| WOTS+C count grind, x2 | ~61,400 | ~184,000 | `wots_digest` (128 B, 3 blk); exact 1/p = 30,698 trials per grind |
| R-grind | ~4,100 | ~10,200 | 2^11 iterations x (119-B PRF, 2 blk + 160-B `h_msg`, 3 blk), both streamed |
| WOTS sign + in-pass self-check, x2 | ~700 | ~1,500 | |
| **Pass total** | **~500,500** | **~1,087,000** | 2.17 blocks per digest |

Your ledger's exact counts for the frozen inputs are 512,999 and 522,487, so the model is within 4%.

**Where the 357.9 M goes now** (first line measured, the rest my split):

| Part | Cycles | Share | Basis |
|---|---:|---:|---|
| 4 layer builds | ~226 M | 63% | 4 x your `keygen_cyc` of 56.4 M |
| FORS, 2 passes | ~70–80 M | ~21% | 160k digests at an assumed ~450 |
| Count grind, R-grind, WOTS sign, verify | ~50–60 M | ~16% | remainder |

Inside one layer build (56.4 M): about 45 M is chain steps (154k at ~295 each), about 9 M is `wots_secret`, about 2 M is `th_multi` and `th_pair`. The 295 comes from subtracting assumed costs for the other three, so treat it as ±30.

---

## A. Literature and prior art

Read in the relevant part:

- **Saarinen, "Accelerating SLH-DSA by Two Orders of Magnitude with a Single Hash Unit" (SLotH), CRYPTO 2024 / NIST 5th PQC conference.** Read from the PDF. A general-purpose hash accelerator gives roughly 10x, but "due to message formatting overhead, this will still leave the core hash unit underutilized". SLotH gets about another 10x by moving padding, `PK.seed`/`ADRS` formatting and Winternitz chain iteration into hardware, leaving 1–2 cycles between hashes. Its SHA2-256 core is 64 cycles per compression, the same class as the U5's 66. Your `chain16` and `search128` commits are the software form of the same move, and the remaining step in that direction is N1.
  https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/accelerating-slh-dsa.pdf — artifact https://artifacts.iacr.org/crypto/2024/a7/

Abstract or search summary only — leads, not checked facts:

- Kudinov, Hülsing, Ronen, Yogev, "SPHINCS+C: Compressing SPHINCS+ With (Almost) No Cost", ePrint 2022/778. Source of WOTS+C and FORS+C. https://eprint.iacr.org/2022/778
- Kudelski Security, "Improving the SPHINCS post-quantum signature scheme, part 2" (2017). Treats the top Merkle tree as cacheable key material; prior art for the top-layer cache. https://research.kudelskisecurity.com/2017/09/28/improving-the-sphincs-post-quantum-signature-scheme-part-2/
- Karl, Schupp, Sigl, "The Impact of Hash Primitives and Communication Overhead for Hardware-Accelerated SPHINCS+", COSADE 2024, ePrint 2023/1767. Studies the CPU-to-accelerator transfer cost directly, for SHAKE and Ascon. https://eprint.iacr.org/2023/1767
- ePrint 2025/298: SPHINCS+ tuning for Cortex-M4 FIDO keys; the abstract gives no timings and no hardware hash. https://eprint.iacr.org/2025/298
- SPHINCSLET, ePrint 2025/621: FPGA design. https://eprint.iacr.org/2025/621
- SPHINCS- on the EVM, the C10 lineage. https://ethresear.ch/t/sphincs-minus-efficient-stateless-post-quantum-signature-verification-on-the-evm/25165
- Zephyr hash benchmark sample: a polling-vs-interrupt harness, no STM32U5 numbers. https://docs.zephyrproject.org/latest/samples/drivers/hash_bench/README.html

**Not found:** any published cycles-per-digest figure for the STM32 HASH peripheral on short messages, any SLH-DSA implementation driving one, or anything on overlapping CPU work with it. Expect to produce these numbers, not find them.

---

## B. What RM0456 says about the HASH engine

| Fact | Source |
|---|---|
| SHA2-256: **66 cycles per intermediate block** = 16 "FIFO load" + 50 computation | Table 486, p. 2025; feature list p. 2014 |
| Table note: "Add the time required to load the block into the processor" — the software feed is on top | p. 2025 |
| **The last block costs 1x to 2.5x** an intermediate block for a plain hash, depending on its length | p. 2026 |
| `HASH_DIN` plus a 16-word FIFO form a **17-word input buffer** | §51.4.4, p. 2016 |
| A block starts only when the **first word of the next block** is written, or on DCAL for the last | §51.4.5 step 3a, p. 2018; §51.6.2, pp. 2028–2029 |
| "When the HASH is busy, a write access to the HASH_DIN register **might stall the AHB bus** if the digest calculation ... is not complete" | §51.6.2 note, p. 2029 |
| DINIS = 16 locations free; cleared by a DIN write | §51.6.6, p. 2033 |
| NBLW and DCAL cannot be set in the same write | §51.6.3, p. 2030 |
| HR reads return zero until DCIS; INIT forces HR to its reset values | §51.6.4, p. 2030 |
| **DCIS is cleared by INIT** as well as by writing 0 | §51.6.6, p. 2033; Table 487, p. 2026 |
| INIT sets NBWE to 0x11 and clears NBWP; it leaves NBLW alone | §51.6.1, §51.6.6, pp. 2027, 2032 |
| Context swap: save and restore IMR, STR, CR and **CSR0–CSR37** (CSR38–53 for HMAC only); only with no block in flight; CSRs read as zero unless DINIS = 1 | §51.4.8, p. 2024; §51.6.7, p. 2033 |
| DMA: one request per block, bursts of four words | §51.4.9, p. 2025 |
| No error flags | §51.4.10, p. 2025 |
| The only clock is `hash_hclk`, the AHB clock | Table 484, p. 2016 |
| ES0499: no HASH erratum (text search of the PDF) | es0499 |

**Does DIN accept the next block while the engine works?** The RM implies yes without saying it. The buffer is 17 words, the block moves into the core during the 16-cycle load phase, DINIS means "16 locations free", and the stall note says "might". The likely behaviour: block n+1 can be written during block n's 50-cycle computation, and a write stalls only while the FIFO is still full. Worth measuring directly (H0c).

**Context save and restore.** A restore is 3 control writes, INIT and 38 CSR writes: about 42 bus writes. It replaces one block, which is 16 DIN writes and 66 cycles. At 2–3 cycles per write that spends roughly 85–125 cycles to save roughly 100–115. Break-even at best (H17).

**Floor for one `th` or chain step (96 B = 24 words, 2 blocks).**

| Component | Cycles | Overlaps the engine? |
|---|---:|---|
| INIT, DCAL, SR polls | ~6–10 | no |
| Feed words 1–16 | 32–48 at 2–3 cycles per word | no, the engine has nothing yet |
| Block 1, started by word 17 | 66 | words 17–24 go in here if the FIFO accepts them |
| Last block: 8 data words plus padding | 66–165 | CPU idle |
| Read HR0–3, byte-swap | 8–12 | no |
| **Total** | **~180–300** | |

The engine alone is 132–231, so the "~130" in the brief is the optimistic end, not a measurement. I expect a 96-byte message near the low end: the 2.5x case is most likely padding spilling into an extra block, as it must for 128-byte inputs. That puts the practical floor at about **200–230 cycles per chain step, against roughly 295 on the kit now.** If the last block turns out to cost 2x for this shape as well, the floor is ~270 and `chain16` is already there.

Current `chain16` step, from the disassembly of `out/exp.elf`: about 70 instructions, of which 16 are stack loads of the fixed words, 24 are DIN stores and 8 are other peripheral accesses. The loop body has no calls left.

**Whole-sign floor at today's digest count:** 2.17 M blocks x 66 = 143 M cycles if every block were intermediate, up to ~240 M at the worst last-block factor, plus ~55 M of feed and read-out that cannot overlap. So about **200–300 M cycles against your 358 M.** With the top-layer cache in both passes, about 130–200 M.

**Clock levers: none on the product.** `secure/src/hw/rcc.rs` never writes the AHB or APB prescalers, so HCLK = SYSCLK = 160 MHz, the device maximum, with VOS range 1 and the EPOD booster on. The HASH has no kernel clock of its own. For the kit I only skimmed `harness/clk.c` (PLL1 to 160 MHz from MSIS); I did not check its prescalers.

---

## C. Hypotheses

Constraint tags: **OI** output-identical; **FI** effect on pass independence or on an existing fault tripwire; **SD** secret-dependent timing or access; **RAM**; **FSBL** changes FSBL bytes; **FV** touches a Lean-extracted or line-cited file. `secure/src/hw_io_under_test/pure_tests.rs` pins exact source shapes of the driver, so every driver change also needs a test re-pin when it lands.

### Already run by the loop

| Hypothesis | Commit | Measured, cached sign | My estimate | Note |
|---|---|---:|---:|---|
| HASH driver crate at `opt-level = 3` | `8618b5db7` | −46.6 M (−7.8%) | −6 to −11% | A package override also recompiles the FSBL's copy. The driver-resident loops below make this matter less; landing needs a secure-only crate or module with its own override. |
| `wots_secret` / `fors_secret` through the one-shot | `0477a87c7` | −21.7 M (−3.9%) | −2 to −4% | **Leaves `sk_seed` on the stack.** See below. |
| One STR write when NBLW = 0; write-only DCIS clear | `66b89a54b` | −6.1 M (−1.2%) | ~−2% | Both tripwires intact: STR is still zeroed at init and DCIS is still cleared. |
| Read HR0–3 only for truncating hashes | `fe9ed862b` | −44.7 M (−8.5%) | none; I had dropped it on the October result | The diff is what it says: four fewer HR reads, swaps and stores, and a 16-byte output. Flat on flash in October, large on the kit. See H0e. |
| Fixed-shape chain loop in the driver (`chain16`) | `38fba6feb` | −72.7 M (−15.2%) | −8 to −20% for the fixed-shape idea | Stronger than what I proposed: the running value never leaves registers. |
| Count grind in the driver (`search128`) | `772f8f29d` | −49.0 M (−12.0%) | −1.5 to −3% for a plain fixed shape | I underestimated this one. I have not reviewed the overlap of the next trial with the `digit_sum` check; it must return the first hit in counter order to stay output-identical, which your byte gate checks for the frozen inputs only. |

**On `0477a87c7`.** The streamed version passed `sk_seed` by pointer. The contiguous version copies it into an 80- or 48-byte local about 70,000 times per pass and returns without wiping it, so the signing seed sits in dead stack below every caller. This is a landing condition, not a reason to discard the result. N1 removes the copy.

### Tier 0 — measurements that re-rank the rest

**H0. Characterise the engine, the driver and the evaluator.**
- (a) Per-step cost of `chain16` in isolation: time one 7-step call and divide.
- (b) **Last-block cost per shape:** DCAL-to-DCIS time for 48, 80, 96, 128 and 1,440 bytes, as a multiple of 66. This decides whether chain steps are at the floor.
- (c) **Stall test:** time 16 DIN writes with the engine idle, giving bus cycles per word; then 32 back to back. If the second 16 take about as long as the first, the FIFO refills during computation. If they take ~66 more, it stalls.
- (d) A `hash-probe` stage dump still has value for the non-chain shapes (`th_pair`, `th_multi`, the PRFs), which now go through `oneshot16`.
- (e) **Code-bus alias run.** The bench links at `0x3000_0400`, where instruction fetch shares the system bus with data. The same secure SRAM is aliased in the code region at `0x0E00_0000` (RM Figure 4, p. 142), where fetch uses the code bus as it does from flash. Link `.text` there and re-measure baseline and each keep. If the HR0–3 gain shrinks toward zero, that build is the better evaluator and the kept deltas need re-weighing. This changes `harness/link_sram.ld`, which is frozen, so it means a new baseline and is your call. I have not checked whether the bench's startup allows execution from that alias.

### Tier 1 — next experiments, output-identical

**N1. Fuse `wots_secret` into the chain call.** *(top of the queue)*
- Mechanism: per WOTS chain the signer still does, outside the driver: build the 80-byte PRF buffer (with the `sk_seed` copy), call `oneshot16`, copy the result out, build the 96-byte chain buffer (64-byte seed and address copy plus `set_chain_index`), call `chain16`, copy the result out. A driver entry that takes `sk_seed` by pointer and the fixed words once per leaf can feed the PRF straight from `sk_seed`, keep its 16-byte output in registers, and run the chain on it. 88,000 chains per cached sign plus 22,000 per keygen.
- Files: `hw/src/hash.rs` (new gated symbol), `sphincs-c10/src/hash.rs` and `wots.rs` (`keygen_pk`, `sign_with_shuffle`).
- Predicted: −150 to −250 cycles per chain, about **−13 to −22 M per cached sign (−4 to −6%)** and −3 to −5 M per keygen. Confidence: medium.
- Constraints: OI. SD none: the feed pattern is fixed. **Removes the unwiped `sk_seed` copy.** FI: per-digest tripwires as in `chain16`. The F-16 chain-order shuffle is unaffected (it permutes whole chains). FV: major, `keygen_pk` and `sign_with_shuffle` bodies.
- Experiment: implement for `keygen_pk` only and read `keygen_cyc`.

**N2. Tighten the `chain16` step.**
- Mechanism: three small things in the loop body. Hoist `STR = 0` out of the loop, since nothing inside the loop can make NBLW nonzero. Load the fixed words with load-multiple instead of 16 single loads. Check whether the entry SR read can be merged with the previous step's last DCIS poll.
- Predicted: −10 to −30 cycles per step on 616k steps, **−2 to −5%**. Confidence: low to medium; it depends on H0b. If the last block costs 2x there is nothing here.
- Constraints: OI. FI: hoisting `STR = 0` is neutral by the argument above; merging the SR read weakens the "DCIS still set at init" tripwire and I would leave that one alone. FSBL no.
- Experiment: do the hoist and the load-multiple together, one run.

**N3. FORS leaf in the driver.**
- Mechanism: each FORS leaf is `fors_secret` (48 B, 1 block) followed by `th` on its output (96 B). Same fusion as N1: PRF fed from `sk_seed` by pointer, output kept in registers, leaf hash on it. 53,000 leaves per cached sign.
- Predicted: −100 to −200 cycles per leaf, **−1.5 to −3%**. Confidence: medium.
- Constraints: OI. SD none. Also removes the `sk_seed` copy on this path. FV: `fors.rs` bodies (not in your Lean-extracted list, but check the line citations).

**N4. Fixed-shape `th_pair`.** *(largely done by `56d334b94`, −2.2% measured; what remains is the `pad16` temporaries, if that commit kept them)*
- Mechanism: 55,000 per cached sign, 128 B, three blocks. Today each builds two `pad16` temporaries and a zeroed 128-byte buffer, then goes through the general `oneshot16`. A fixed-shape entry taking the two 16-byte nodes feeds 16 fixed words, 4 + 4 node words and 8 zeros.
- Predicted: −100 to −150 cycles each, **−1.5 to −2.5%**. Confidence: medium.
- Constraints: OI. FV: `hash.rs` `th_pair` body or a helper at file end.

**H5. Word-align the remaining preimage buffers.** Only matters for shapes still fed from memory through `oneshot16`. Check `ptr & 3` at entry before doing anything; if buffers are already aligned, drop it.

**H11. `overflow-checks` and bounds checks.** The hottest loops have moved into the driver, so this is worth less than before. A per-package override in `bench/Cargo.toml` gives a ceiling in one run; if it is under 1%, drop it. Turning the checks off for `sphincs-c10` on the product would remove a fail-loud property from extracted code.

**Codegen levers you asked about, answered briefly.**
- *Inlining:* the `extern "C"` hook hides the constant length from the driver, and LTO did not inline it. Per-shape driver entries are the practical fix, and you are already doing that.
- *LTO and codegen units:* the bench already has `lto = true` and `codegen-units = 1`. No lever left.
- *Opt level:* done for the driver. `sphincs-c10` was already at 3.
- *Keygen batching:* there is one serial engine, so there is nothing to run in parallel. The only batching available is fusing consecutive dependent hashes into one driver call (N1), which removes per-call overhead but not engine time.

### Tier 2 — track B: cross-sign state

**H4. Top-layer tree cache.**
- Mechanism: layer 1, tree 0 is the same 512-leaf tree for every signature of a key. A cached pass skips 177,151 digests.
- Predicted: **−113 M cycles per cached sign (−32% of the current 358 M)** with both passes cached, using your measured 56.4 M per build. With only pass A cached and pass B reusing its auth path, as in the in-sign branch, the same total.
- RAM: all 1,022 nodes, 16.4 KB; leaves only, 8.2 KB plus 510 `th_pair` per pass; nodes at height 4, 512 B plus one 16-leaf rebuild (3% of the tree). The height-4 form keeps 97% of the gain for almost no RAM.
- Constraints: OI. **FI: the cache is a single trusted producer.** A wrong top auth path fails verify against `pk_root`, so a corrupted cache is caught. A keygen-time fault that moves `pk_root` together with a consistent cache is not. Keep the reviewed condition: cross-check against one uncached build at first use. Zeroize on lock. FV: new function beside the proven `sign_inner`; `hypertree.rs` is also EasyCrypt line-cited.

**H6. Fill the cache from keygen.** Keygen's `compute_subtree_root(layer 1, tree 0)` builds exactly this tree and keeps only the root, so a first sign builds it three times. Keeping the nodes saves one 56 M build per first sign of a key. Same FI condition as H4.

**H7. One strong-RNG draw per sign instead of three.** Not a hash lever, and the kit cannot see it. `c10_sign_verified_with_progress_inner` calls `rng_strong::fill` three times (16 + 32 + 32 bytes), each a round trip to both secure elements; the source comments put the three at ~0.3 s on the EVT. One 80-byte draw split three ways has the same distribution. Perhaps −0.2 s per sign, if the cost is per call and not per byte, which I did not check. Keep the three all-zero checks and CFI bumps.

### Tier 3 — needs a flash-run board

**H13. ICACHE associativity.** Already in your ledger. Two additions:
- A dev read-back exists: `secure/src/ui/px/film_gaps.rs::icache_ways` shows WAYSEL on the FRAME page. Whoever ran that on 2026-10-22 knows whether it is 1-way on silicon.
- ICACHE_CR has hit and miss monitors (HITMEN, MISSMEN). Counting misses across one sign says whether associativity matters before you change it. With the hot loops now a few hundred bytes inside the driver, I expect this to matter less than it would have a day ago.

**H14. Flash prefetch; hot code in RAM.** Bounded by H13's miss count. RAM-resident code is writable code in the secure world that the FSBL does not measure. I would not ship that for a few percent.

### Tier 4 — considered, not recommended

**H9. Overlap caller work with the last block.** `search128` already does this where it is possible, because trial n+1 does not depend on trial n. Chains cannot: the next input is this digest. For tree hashing the caller-side work is too small to matter.

**H15. Pass B reuses pass A's WOTS+C count.** Saves about 61k digests per sign. **Rejected on FI grounds.** The on-chain verifier accepts any count whose digit sum is 205. A fault that makes pass A miss the true first hit yields a valid signature with a different count. At layer 1 the signed value is the same every time that layer-0 tree is used, so a different count is a second WOTS signature under the same one-time key. Today pass B finds the count independently and the compare refuses. A pass B that only checks validity lets it through, and verify cannot catch it. (Reusing R would save ~4k digests and is not worth analysing.)

**H16. Pass B reuses the layer-0 tree or the FORS trees.** Would save about a quarter of the digests. **Rejected for the same reason, more strongly.** A faulted layer-0 tree or FORS root gives a self-consistent signature that verifies, with an upper one-time key signing a wrong value. This is the grafting case the double compute exists for. The top layer is different only because its result is checked against `pk_root`.

**H17. Midstate for the count grind through `HASH_CSRx`.** Cost model in section B: break-even at best, and it puts saved engine state under FI and zeroize review. `search128` has taken most of what was available here.

**H18. DMA feed.** One request per block and a setup cost above 24 DIN writes, while the CPU has nothing else to do. Could help only `th_multi`, 0.2% of digests.

**H19. Software SHA-256 in the engine's idle time.** A software compression is well over 1,000 cycles against idle windows of 100–200. A few percent at best, for a second hash implementation in the signing path.

**H20. Clock, prescaler, booster.** No lever; see section B.

**H21. Verify.** 361 digests, 0.04% of a sign.

### Suggested order

H0b and H0c (they say whether N2 is worth anything) → N1 on `keygen_pk`, then on signing → N3 → N4 → N2 → H0e before costing any of this for landing → H4 and H6 as track B variants.

Rough stack, estimates on estimates: N1 to N4 at mid-range take 358 M to about 315–330 M. The top-layer cache on top of that gives about 215–230 M, roughly 1.4 s at 160 MHz against 3.74 s at your baseline.

---

## D. Where the framing is optimistic or wrong

1. **"~130 engine cycles per `th`" is the best case.** The RM gives 66 for an intermediate block and 1–2.5x for the last, so 132–231. No measurement of the last-block time exists in the repo. Until H0b, whether `chain16` has 25% left or nothing is unknown.

2. **The engine is not the only floor.** The first 16 words of every digest are fed with the engine idle, and the read-out is serial. A perfect driver still sits ~50 cycles above engine time per two-block digest.

3. **The evaluator is precise, but it may be biased.** 150 cycles of spread in 10^9 means noise is not the problem. The HR0–3 result is the warning: flat on flash in October, −8.5% here. Two explanations fit. Either SRAM-resident code makes every load and store cost more than it does behind the ICACHE, so instruction-count savings are inflated; or October's prototype and driver (then at `z`) were different enough that the comparison is not like for like. H0e separates them. Until then, savings that remove engine wait or bus stalls are the safest to carry over, and savings that remove instructions are upper bounds.

4. **Kit and product baselines already differ.** 583 cycles per digest on the kit at master, against ~500 driver cycles on pq1 in October (the ~533 "total" I used earlier is my own derivation from 3.5 s and 1.05 M digests, not a recorded figure).

5. **Wall time on the product is not digests times cycles.** Three things the bench does not contain:
   - the three `rng_strong` draws, ~0.3 s per sign by the source's own comment;
   - under `ui-px`, the busy film: `pqsigner_hash_tick` runs after every digest (and now after every `chain16` step) and each frame's time "comes out of the work it plays over" (`ui/px/lcd.rs`);
   - the F-17 rate limiter, which busy-waits to keep at least 1 s between signs.
   As the hash work shrinks toward 1.5–2 s, these become a quarter or more of what a user waits for.

6. **Pass-to-pass reuse is spent.** The top layer is the only part whose result verify-before-release checks independently.

7. **Landing cost is growing faster than the cycle count is falling.** Three of the six keeps are tagged FV or FV-major, and N1 and N3 would add more. The driver now contains signer logic (chain iteration, the count search), which moves proof obligations out of the extracted Rust and into `hw/`, where the FSBL fence, the source-shape pins and the FI review all apply. That is a reasonable trade for −40%, but it should be costed as a rewrite of the driver-signer boundary, not as six small patches.

8. **Keygen and verify are not separate problems.** Keygen is one layer build and follows the sign one for one, as your `keygen_cyc` column shows. Verify is 0.04% of a sign.

## Not checked

- I built, ran and measured nothing.
- Results after row `772f8f29d`.
- The `search128` overlap logic; I read the caller in `wots.rs`, not the driver body.
- The last-block factor per shape and the DIN stall behaviour: read from RM wording, not observed.
- Whether execution from the `0x0E00_0000` alias works with the bench's startup code.
- The kit harness's bus prescalers.
- Whether `rng_strong::fill` cost scales per call or per byte.
- The ICACHE configuration on silicon; I read `rcc.rs` and the RM only.
- ePrint 2022/778, 2023/1767 and 2025/298 beyond abstracts; the Kudelski post beyond a search summary.
- The `codex` MCP server failed to connect this session, so no second-model review of this list was run.
