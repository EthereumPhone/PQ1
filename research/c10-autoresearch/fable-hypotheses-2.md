# C10 autoresearch — round 2: driver review, re-rank, track-B bench, evaluator

Advisor: Fable 5.2, 2026-11-12. Read-only. Code read with `git show 8bfb1de17:<path>` (driver, signer) and from `HEAD` `a277673ec` (harness, ledger). I built and ran nothing; every cycle figure below is yours or is arithmetic on yours.

## Summary

1. **No output-identity bug found** in the new driver code or in `fors_tree_fast` / `grind_r_fast` / the chunked `find_count`. I checked each preimage layout word by word against master.
2. **Eight review findings, none of them a signature-forgery path.** The two that matter most before landing: the new entry points have no boot known-answer test and bypass the software crosscheck (F1), and `oneshot16` overruns a 16-byte buffer in a feature combination the manifest allows (F2).
3. **Output-identical headroom is at most about 9%, and I expect 4–6% to be reachable; no single item exceeds 3%.** Unit floors put a pass at roughly 112 M cycles against 123 M now. This track is close to finished.
4. **The top-layer cache is worth about −30% of a warm sign** (246 M → ~172 M at `h_c = 4`). I recommend filling it in keygen, confirming it by a second independent build before first use, and dropping in-sign reuse, which adds under 1% once both passes use the cache.
5. **The largest gap between the bench and the product is probably `tick-hook`.** With `ui-px` there is an extern call inside `chain_steps` after every step. The call's own cost is certain; whether it also worsens the loop's register use is a hypothesis. The bench sees neither. A stub tick in the bench would measure both.

---

## 1. Driver review

### What I checked for output identity (all clean)

| Function | Checked against master | Result |
|---|---|---|
| `chain_steps<Z>` / `chain_core` | 24 words: 16 template words with word 14 = `pos` big-endian, 4 value words, 4 zeros. Z path substitutes literal zeros for words 4–7, 11, 15 only when all six are zero. | Identical for every input, not only WOTS addresses: the zero test is exact, not structural. |
| `chain16` | `steps = 0` writes the value back unchanged; position uses `start_pos + step`. | Identical. (Master's checked add becomes `wrapping_add`; unreachable.) |
| `prf_chain16`, `wots_chains16` | PRF = `sk_seed` ‖ "wots" ‖ layer ‖ tree as 32 bytes ‖ kp ‖ ci: tail word 11 = ci. Chain template word 13 = ci. Result stored at `out[16 i]` by chain number, not by processing step. `z` is computed before word 13 is patched, and word 13 is not in the zero set. | Identical; shuffle changes order only. |
| `fors_leaf16` | 12-word PRF, then template ‖ secret ‖ 4 zeros. | Identical. |
| `node16`, `fors_tree_fast` | Leaf: hash address at template bytes 60..64. Node: height at 56..60, index at 60..64, both rewritten on every use, so no stale field carries over. Left child is the popped sibling. Auth-path selection is the same predicate as `sign_fors_tree`. | Identical. |
| `search128` | Tries run in counter order; `pred` is evaluated on try `c` before `c` advances; the speculative `c + 1` is collected and discarded on a hit. Count word = `count` big-endian at bytes 124..128; words 28–30 read from the buffer (zeros). | Returns the first hit and its digest, as the sequential loop does. |
| `find_count` chunking | Chunk boundaries at multiples of 4,096; master reports after a failed try with `count % 4096 == 4095`. 10,000,000 cap preserved, then the same panic. | Same count; same progress points. |
| `grind_r_fast` | With and without `opt_rand` (119 / 103 bytes); nonce in the last 4 bytes of a zeroed 32-byte field; `h_msg` buffer has R in 64..80 and zeros in 80..96. | Identical. |
| `gather` 3x32 / 4x32, `final_body_n` | Straight word feeds; HR0–3 only. | Identical. |
| `tick-hook` | One call per finished digest in every new path, including the discarded speculative try, and always with the engine idle. | Matches master's count and placement. |

What this does not cover: I did not run a differential test. The byte gate covers two messages and one key. A host differential against the software path over random inputs (keys, messages, every target leaf, both `opt_rand` forms) is the missing evidence, and it is cheap because `host/` already has the software hooks.

### Findings, by severity

**F1. New entry points have no boot KAT and bypass the crosscheck (high for landing).**
- Master's rule was that every feed shape the signer uses is exercised at boot (`restart_self_test`, 23 lengths) and that `hw-sha256-crosscheck` compares every hardware digest with software during soaks. `chain16`, `search128`, the gather pair, `prf_chain16`, `fors_leaf16`, `node16` and `wots_chains16` are covered by neither.
- Why it matters: these functions now compute sign pass A, pass B **and** the on-device verify (`pk_from_sig` goes through `chain16`; tree hashing through the gather entries). A driver or silicon behaviour that is wrong but deterministic yields signatures that agree with each other and verify on the device, and a `pk_root` that is wrong at keygen. Only an external check catches it. On the kit that is your golden file; on the product it would be the chain.
- Fix: one boot vector per new entry (a short chain with known end value, one node, one leaf, a 3-try search with a known hit), and a crosscheck hook in each.

**F2. `oneshot16` writes 32 bytes into a 16-byte buffer without `unrolled-io` (high in that combination, not reachable in today's builds).**
- In `final_body_n`, only the `unrolled-io` read-out honours `W`. The rolled loop is `for i in 0..8` regardless. `hw/Cargo.toml` lets `oneshot` (and so `chain`, `gather`, …) be enabled without `unrolled-io`.
- The bench and the secure image enable both, so nothing is wrong today. The fix is one line: make the rolled loop `0..W`, or make `oneshot` imply `unrolled-io`.
- Same function, dev builds: `xcheck_digest(out)` compares 32 bytes at `out` even when `W = 4`, so the crosscheck would read past the buffer and report a false mismatch.

**F3. `tick-hook` inside `chain_steps` breaks the hoisted-STR assumption if the tick ever hashes (medium, latent).**
- `chain_steps` writes `STR = 0` once before the loop. The tick's documented contract (comment in `final_body_n`) is that it "may run a whole SHA-256 of its own". A tick digest whose length is not a multiple of 4 bytes leaves NBLW nonzero, and the next chain step would pad with it.
- I found no hash on the tick path I read (`film_tick_hash` → `film_tick_due` → `atlas_film_frame()`); I did not read every callee of the frame draw. The result if one did would be wrong digests in both passes at different points: a refused signature, not a bad one.
- Fix: under `tick-hook`, write `STR = 0` after the tick, or narrow the tick's contract in writing and pin it with a test.

**F4. One `sk_seed` stack copy is still live (medium).**
- `sign_fors_tree` still calls `fors_secret` for the revealed leaf, 12 times per pass, and that function (from `0477a87c7`) copies `sk_seed` into an unwiped 48-byte local. `wots_secret` has the same shape but is dead in the fast build.
- Master never copied `sk_seed`; it was streamed by pointer. So this is the one remaining regression in secret handling.
- Fix: route that call through a PRF-only driver entry that reads `sk_seed` in place, or wipe the buffer as `grind_r_fast` does.

**F5. "The secret stays in registers" is not something the code can promise (medium, documentation and evidence).**
- `wots_chains16` holds 16 template words, 12 tail words and 4 value words. They do not fit in registers, and under `tick-hook` an extern call sits between the PRF and its use, so the PRF output must be saved across the call. Spilled copies are not wiped.
- This is not worse than master, which kept every WOTS secret element, every intermediate chain value and each FORS leaf secret in ordinary stack arrays with no wipe. But the doc comments claim more than master did. Either drop the claim or back it with a disassembly check per build.

**F6. Single STR write when NBLW = 0 removes one layer of the stale-NBLW protection (low).**
- Master wrote NBLW twice per digest (at init and at final), so one skipped write could not leave a stale value in place. Now a skipped `STR = 0` at init is enough. Within a sign the stale value can only be 24, left by the 119-byte R-grind PRF; other users of the driver between signs could leave other values.
- Consequence: one wrong digest, which the double compute or verify-before-release refuses. I would accept this, and say so in the comment that currently presents the init write as the guard.

**F7. `REG.sr.write(!SR_DCIS)` writes ones to reserved bits (low).**
- The RM marks SR bits 31:21, 14 and 8:4 "must be kept at reset value". Writing `SR_DINIS` alone (`0x1`) clears DCIS, leaves DINIS as it is, and keeps the reserved bits zero. Same cost.

**F8. Small robustness items (low).**
- `chain_steps` writes `STR = 0` before its first `wait_ready_sr()`. Master waited for BUSY to clear first. Move the write after the wait; it costs nothing.
- `wots_chains16` trusts `order[k] < n` for an out-of-bounds write. The Rust wrapper asserts it, which is good, but the driver re-reads `order` from memory afterwards. A clamp or a fault call in the driver closes the gap for one compare per chain. `digits` entries are not range-checked; a bad one gives a wrong signature that verify refuses.
- `feed_words` silently drops a remainder when `n` is not a multiple of 4. Every caller passes 4, 8, 12, 16 or 28. Add a `const` assertion.
- `search128`: `start + n` and `c + 1` are checked additions inside an `extern "C"` function, so a contract violation aborts. Acceptable; document it.
- The new paths skip the `hash-counters` bumps, so that feature's counts are no longer the signer's. Your host counts use a different mechanism; say which one a future reader should trust.
- `chain_steps` is instantiated six times (two `Z` variants in each of three entry points). Check the secure span; the `ui-px` image is already over its slot.

### Where secrets sit

| Buffer | Holds | State at head | In master |
|---|---|---|---|
| `fors_secret` 48-byte local (`hash.rs`) | `sk_seed` copy | **Live, unwiped**, 12 per pass (F4) | No copy; streamed by pointer |
| `wots_secret` 80-byte local (`hash.rs`) | `sk_seed` copy | Unwiped, but dead in the fast build | No copy |
| `prf` in `grind_r_fast` | `sk_seed` copy | Wiped with volatile writes before both the return and the panic | No copy |
| `hm` in `grind_r_fast` | R candidates | Not wiped; R is PRF output and the accepted one is published | Equivalent values in locals |
| Driver frames (`wots_chains16`, `prf_chain16`, `fors_leaf16`) | WOTS secret elements, intermediate chain values, FORS leaf secrets, in registers and any spills | Not wiped (F5) | — |
| `sk_i`, the 96-byte chain buffer, FORS `secret` and its `pad16` copy | The same values | Mostly gone from the fast path | Ordinary stack arrays, never wiped |
| HASH engine (DIN, context registers) | Last block fed, including `sk_seed` for PRFs | Reset by `scrub()` on every secret wipe | Same |

So against master: one new live `sk_seed` copy (F4), and otherwise the same class of residue in different frames.

### FI tripwires, relative to master

| Master, per digest | Now | Assessment |
|---|---|---|
| Wait BUSY = 0, fault if DCIS still set | Kept in every new entry and every loop iteration | Unchanged |
| `STR = 0` before INIT | Per call in `chain_steps` (up to 7 digests); per digest elsewhere | See F3, F8 |
| NBLW written again at final | Dropped when NBLW = 0 | See F6 |
| DCIS cleared after read-out | Kept (write-only form) | See F7 |
| DCIS timeout → fault posture | Kept everywhere | Unchanged |
| Preimage rebuilt from `seed` / `adrs` per chain | Template loaded once per key (`wots_chains16`) or per tree (`fors_tree_fast`) | A corrupted template now spoils 43 chains or a whole tree consistently within one pass. The other pass loads its own copy, so the compare still catches it. In keygen, which is single-computed, it is the existing #1054 class, not a new one. |
| Independent shuffle per pass | Kept: `order` reaches the driver | Unchanged for signing. Tree leaves are built in fixed order in both passes, as in master. |

Net: nothing here weakens double-compute → compare → verify. What changed is the amount of work that shares one loaded template and one loop counter, which the second pass still covers.

---

## 2. Remaining output-identical headroom

A pass at head is about 123 M cycles. Using your measured floors:

| Part | Count per pass | Now | Floor | Gap per pass |
|---|---:|---:|---:|---:|
| Chain steps | 308,826 | 242 | 214–230 (the loop needs the BUSY wait and DCIS clear that the straight-line figure omits) | 3.7–8.6 M on paper; I count ~2 M as reachable |
| Search tries | 69,934 (m0) | ~295 | ~270 | ~1.7 M |
| FORS leaves | 26,624 | 451 | ~350 (1-block PRF + 96-byte hash) | ~2.7 M |
| FORS nodes | 26,611 | 355 | ~265 | ~2.4 M |
| WOTS PRFs | 44,118 | inside `wots_chains16` | ~215 | small |
| `th_multi` | 1,024 | not measured | ~1,700 | ~1 M (my estimate) |
| R-grind tries | 2,048 expected | ~925 | ~505 | ~0.9 M expected |

The gaps sum to about 10.7 M per pass with chains at 2 M, which is 8.7% of a pass and a floor near 112 M. That is a ceiling: it assumes every part reaches its floor. The 265, 270, 350 and 505 floors are my arithmetic from your 2.6-cycle access, 66-cycle block and ~65-cycle last block; they are not measured.

**Re-ranked, output-identical:**

| # | Item | Expected gain on a cached sign | Cost |
|---|---|---:|---|
| R1 | **Whole FORS tree in the driver**, or at least "two leaves and their parent" per call. Loads the templates once per tree as `wots_chains16` does per key. | −2 to −3% | Moves treehash and auth-path selection into `hw/`. High review cost for the full form; the leaf-pair form is modest. |
| R2 | **`th_multi` fed in place** at the end of `wots_chains16` for keygen (the 43 results are already there), instead of clearing and filling a 1,440-byte buffer per leaf. | −0.5 to −1% | Small. |
| R3 | **R-grind in the driver** with the two prebuilt preimages as templates. | −0.5 to −1% on average | Small, but note m0 has ~4,000 tries against an expectation of 2,048, so the bench will show double the true gain. |
| R4 | Search: read HR3–7 only, recompute the full digest once on the hit. | −0.5% | Small. Only bytes 15–31 feed `digit_sum` and `extract_digits`. |
| R5 | ICACHE 2-way (`-DICACHE_2WAY` is already in `clk.c`). | Unknown. v3 is slightly faster than v2, so that comparison does not bound residual misses. Read the miss monitor (`BENCH.user[7]`) over a short window first. | One run. The product's hot set is larger (film, FI wrappers), so the product may gain more than the bench shows. |
| R6 | Chain step below 242. | ≤ 1–2% | You report it at the floor; I agree. Stop. |

**Round-1 items:** N2 is done (`ca674dc97`). H5 (alignment) is dead: 214 from registers against 225 from SRAM bounds it at 11 cycles, and the hot words no longer come from memory. H11 (overflow checks) is dead: the hot loops are in the driver and carry one or two checked adds per digest. H13 became R5. N3 and N4 are done.

**What is larger than anything in this table, and not output-identical work:**
- the top-layer cache (section 3), about −30%;
- on the product, the tick call inside the hot loop (section 4);
- the three `rng_strong` draws, ~0.3 s by the source comment, now roughly a fifth of a 1.5 s sign.

---

## 3. Track-B bench for the top-layer cache

### Cache form

Store the nodes at one height `h_c` of layer 1, tree 0. A pass rebuilds the `2^h_c`-leaf subtree that contains the target leaf and hashes the stored nodes up to the root.

| Form | RAM | Rebuilt per pass | Cost per pass (at 75.4 k cycles per leaf, 355 per node) | Saved of 38.6 M |
|---|---:|---|---:|---:|
| All 1,022 nodes | 16,352 B | nothing | ~0 | 100% |
| Leaves (`h_c = 0`) | 8,192 B | 511 nodes | 0.18 M | 99.5% |
| `h_c = 3` | 1,024 B | 8 leaves + 63 nodes | 0.63 M | 98.4% |
| **`h_c = 4`** | **512 B** | 16 leaves + 31 nodes | 1.22 M | 96.8% |
| `h_c = 5` | 256 B | 32 leaves + 15 nodes | 2.4 M | 93.7% |

Recommendation: `h_c = 4` as the primary variant, `h_c = 0` as the comparison point. Add 32 bytes for an integrity digest and a few words for the key tag. The partial rebuild also gives a free check: the rebuilt subtree's root must equal the stored node it replaces.

Expected warm sign at `h_c = 4`: 246.2 − 2 × 38.6 + 2 × 1.25 ≈ **171.5 M cycles (1.07 s), −30%**.

### Fill and confirm

- **Fill in keygen.** `compute_subtree_root` already passes through every height-`h_c` node; keep them. Extra cost should be near zero, and the bench should show that.
- **Confirm before first use (the earlier review's H1).** The risk is a keygen fault that produces a wrong `pk_root` together with a cache that agrees with it. Master would catch this at the first sign, because the sign rebuilds the tree and verify then fails; a cache filled by the same faulted build would not. So the cache must not be trusted until a second, independent build has reproduced the same `2^(9−h_c)` nodes and the same root.
- **Where to put the second build.** Two options, and the bench should time both:
  - (a) *In keygen:* build twice, compare, then publish `pk_root` and mark the cache valid. Costs one extra 38.6 M (0.24 s) per keygen. It also double-computes `pk_root` before anything derived from it leaves the device, which is the open #1054 concern.
  - (b) *In the first sign:* pass A builds the top tree uncached and compares its nodes with the cache; pass B and later signs use the cache. No extra work over master on the first sign.
  I would take (a): it is simpler to state, and every sign is then warm.
- **Make the second build differ from the first.** Both builds otherwise run the same code in the same order, so a fault triggered by position hits both alike. The driver already accepts a chain `order`; give the confirm build a shuffled one. Fisher-Yates per leaf uses software SHA-256, so derive one permutation per build and rotate it per leaf, and measure the cost.
- **Bind and protect.** Tag the cache with the key identity (account, chain, slot) and `pk_root`, in the style of `FihSlotTag`. Store SHA-256 over tag ‖ nodes and re-check it in each pass before use (about 9 blocks, well under 0.1% of a pass). After hashing up, compare the root with `pk_root` in release builds; today that comparison is a `debug_assert`.
- **Zeroize.** Invalidate the tag first, then wipe the nodes, from `nsc::zeroize_sensitive_state` alongside the slot cache. The nodes are not secret in the way `sk_seed` is, but they are key-linked state with an integrity requirement, and the project rule is that caches are wiped on lock.
- **Scope.** One entry, for the slot key. The bootstrap key signs only on rotation; give it a separate number if you want it, not a second cache by default.

### What the bench must time

| Measurement | Sequence | Purpose |
|---|---|---|
| Fill cost | keygen with node capture, against plain keygen | Shows the fill is free |
| Confirm cost | option (a): second shuffled build + compare; option (b): pass A with compare | The price of H1 |
| Cold first sign | keygen (+ confirm) + two passes + verify, from an empty cache | The honest first-sign figure |
| Warm sign | integrity check ×2 + two cached passes + verify | The headline |
| Wipe | invalidate + zeroize | Should be negligible; prove it |
| RAM | static bytes, and stack high-water of the cached pass against the uncached one | Budget |

Report each for `h_c = 4` and `h_c = 0`. Run warm signs for both messages; their top-layer target leaves differ.

### Keeping the byte gate meaningful

- Signatures from the cold path, the warm path and the warm path after a wipe-and-refill must all equal `golden.bin`.
- **Prove the cache was used.** Record a cache-hit count in the results block and require exactly 2 per warm sign. On the host, require the digest count to drop by exactly 2 × (177,151 − rebuilt digests). A green byte gate on a build that silently fell back to the uncached path proves nothing.
- **Must-refuse controls**, each expected to produce no signature at all, not a different one:
  - one stored node flipped after the fill;
  - a cache filled from a keygen with one leaf deliberately wrong, with the matching wrong root (the H1 case): the confirm step must refuse;
  - a valid cache from another key under this key's tag.
- **Host sweep:** for all 512 target leaves, the cached auth path equals the uncached one. This covers the edge leaves (0, 511) and both sibling sides at every height, which two messages cannot.

### In-sign reuse on top of the cache

It adds almost nothing. Once both passes use the cache, the only top-layer work left per pass is the 1.25 M rebuild, so reuse would save about 0.7% of a warm sign while removing pass B's independent check on 144 bytes. On the cold first sign, option (b) already has pass A as the confirm build and pass B on the cache. Drop in-sign reuse from the plan if the cache goes ahead.

A residual to state plainly: with the cache, both passes read the same stored nodes, so the pass-to-pass compare no longer covers the top auth path. That path then rests on verify-before-release against `pk_root`, the integrity digest, the release-mode root check and the confirm build.

One thing the cache does not touch: the layer-1 WOTS signature (count search and chains over the layer-0 root) stays per pass and per message.

---

## 4. Evaluator: where v3 differs from the product

Ordered by how much I expect each to move the number.

1. **No `tick-hook`, and it sits inside the hottest loop.** With `ui-px`, `chain_steps` makes an extern call after every step. The certain part is the call and the callee's fast path (two atomic loads, an add, a store, a modulo). The uncertain part is codegen: only callee-saved registers survive a call, which may cost the loop some of what it keeps in registers; round 1's disassembly of `chain16` already showed most template words loaded from the stack without a tick, so this may be small. The 242-cycle step is a no-tick figure. My guess for the product is 15–40 cycles per digest, 6–16% of the hash work.
   - Measure it: add a bench variant with `tick-hook` and a stub that copies `film_tick_hash`'s no-film path.
   - Product lever, if the stub confirms it: have the driver call the tick once per chain or per key with a digest count. `HASH_TICK_EVERY = 64` was chosen for "~0.3 ms of signing at ~4.6 µs a digest"; a digest is now about 1.5 µs, so that constant is already three times finer than intended, and a per-chain tick (8 digests) would still be far inside it.
2. **Driver opt level.** The bench compiles `pqsigner-hw` at 3. The product compiles it at `z` unless the override lands, and that override reaches the FSBL's copy. Run the bench once with the driver at `z` to learn how much of the gain depends on it. If it is most of it, the fast paths need their own secure-only crate.
3. **m0 is not an average message.** `cached_sign` is two passes of m0: 69,934 search tries against an expectation of 61,397 (+14%), and ~4,000 R-grind tries against 2,048. Search and R-grind wins are overstated and chain wins understated by a few percent each. A normalised figure (your unit costs × expected counts: 308.8 k steps, 61.4 k tries, 26.6 k leaves, 26.6 k nodes, 2,048 R tries) would be more honest for landing estimates. m1 errs the other way on R-grind (~175).
4. **Image size and cache pressure.** The bench image is tens of KB with one hot set; the product is ~430–480 KB and, with `ui-px`, interleaves film code with the hash loop through the tick. A 1-way 8 KB ICACHE that is harmless in the bench may not be in the product. Your hit and miss monitors are 16-bit and saturate, as `clk.c` notes, so read them over a short window (one keygen-leaf, not a whole sign).
5. **No FI wrapper, no secure elements.** The three strong-RNG draws, the 4,008-byte constant-time compare, the CFI steps and the rate limiter are absent. Only the RNG draws are large.
6. **Interrupts masked.** The bench runs under `cpsid i`. The product takes timer, display-TE and USB interrupts during a sign. Small, but nonzero, and each one also disturbs the ICACHE.
7. **Silent signing.** The bench calls `sign_with_shuffle_silent`; the product passes a progress function called every 16 leaves and every 4,096 tries. Negligible cycles, but it is where the product's UI work enters.
8. **Things I checked and consider equivalent:** PLL source (MSIS in the bench, HSI16 in the product, both 160 MHz); flash bank 1 at the secure alias with 4 wait states; ICACHE_CR = 1; prefetch off in both; code on the C-bus, data on the S-bus.

---

## Not checked

- No build, run, disassembly of the head image, or differential test. The identity table is a source reading.
- Whether the PRF output is actually spilled in the current codegen (F5), and the code size of the six `chain_steps` copies.
- Whether a write to `HASH_STR` while BUSY is set has any effect (F8, first item); the RM does not say.
- The `tick-hook` cost in item 4.1 and the `th_multi` and derived floors in section 2 are estimates.
- `run_flash.sh` and `evaluate.py` beyond their headers; `merkle.rs` and `hypertree.rs` had no diff against master at `8bfb1de17`.
- The replay rows in `results.tsv` were still being written when I read it.
