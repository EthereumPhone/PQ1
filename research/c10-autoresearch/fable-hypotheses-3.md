# C10 autoresearch — round 3: paths not yet tried

Advisor: Fable 5.2, 2026-11-12. Read-only, at head `20b46a5e3`. I built and ran nothing. Cycle figures are yours (ledger milestone) or arithmetic on yours; every gain below is an estimate until the kit says otherwise. 1 M cycles = 6.25 ms at 160 MHz.

## Summary

1. **The digest count is at its minimum.** For the frozen format, two full independent passes and the reuse you have ruled out, I find nothing that removes a digest. Your 341k against 322k is the 16-leaf cache rebuild plus m0's above-average grind counts.
2. **One engine feature can still remove *blocks*: context restore as a midstate.** Done by the book (38 registers) it is break-even. Done sparsely (only the registers that differ from their post-INIT values) it could be worth about 5–7% of a pass. The second form is off-spec and needs the kit to tell you which registers matter. This is the first experiment I would run.
3. **An inline-asm chain step is the other kit experiment worth running:** 242 against your straight-line 214 is up to 5% of a pass.
4. **The rest of the wall time is no longer hashing.** On a warm sign with the cache (1.03 s), the three strong-RNG draws (~0.3 s by the source comment) are the largest single item left. On a cold sign, PBKDF2 (0.57–0.59 s by the source and your October probe) costs more than the keygen (0.24 s). Both can be moved out of the wait the user sees.
5. **Merging the three RNG draws into one does not help.** I recommended this in round 1 and it was wrong: the fold draws at most 32 bytes per secure-element round trip, so 16 + 32 + 32 bytes is three round trips either way.
6. **Speculative signing during review would hide the whole sign,** but it changes what "consent" gates: from computing the user's signature to releasing it. I set out the analysis in section 3; it is an owner decision with a high landing cost. Message-independent prewarm gets a large part of the benefit without that change.

## Ranking, cheapest first

| # | Idea | Expected gain | Kit can measure? | FI / FV / landing cost |
|---|---|---|---|---|
| 1 | Sparse context restore for count grind (public data) | −3 to −4% of a pass | Yes, today | Off-spec register use; needs a boot KAT with fallback. No secrets involved. |
| 2 | Inline-asm chain step | up to −5% of a pass | Yes | Asm in `hw/`; outside Lean; FI review of the asm. |
| 3 | `-C target-cpu=cortex-m33` | 0 to −1% | Yes, one run | Global flag: reaches the FSBL and the reproducible-build pins. |
| 4 | Faster SHA-512 for PBKDF2 | −0.15 to −0.3 s, first sign of a session | Yes (pure CPU) | Output-identical; `bip39` is linked by the FSBL. |
| 5 | RNG: two round trips instead of three (derive both shuffle seeds from one draw) | −0.1 s per sign | No (no SEs) | Touches the independence argument for the two shuffle seeds; small. |
| 6 | RNG pool drawn before the sign (after unlock or during review) | −0.3 s per sign as perceived | No | New pre-drawn secret state; single-use and zeroize rules. |
| 7 | Prewarm during review: slot keygen, cache fill and confirm | −0.24 to −0.5 s on a cold sign as perceived | Partly (compute yes, UI no) | Key use before consent, without a signature; needs a budget. |
| 8 | Sparse context restore for the WOTS PRF | −3% of a pass | Yes | As 1, plus a new secret-equivalent object (the midstate) to wipe. |
| 9 | Top-layer cache for the bootstrap key | −0.45 s per rotation | Yes | Same review as #1148, second instance. |
| 10 | Software SHA-256 in the CPU's idle windows | −2 to −3% of a pass | Yes (unit cost) | Second hash implementation, re-ordered work; high. |
| 11 | Speculative full sign during review | −1.0 to −1.5 s as perceived | No | Changes the consent model; UI re-architecture; highest. |
| — | DMA feed; PGO; full-spec context restore | none expected | Yes, to confirm | — |

---

## 1. HASH engine features not yet used

### Context restore as a midstate

**What the RM gives (§51.4.8, p. 2024; §51.6.7, p. 2033).**

Save, with data loaded by software:
1. Write block 1 (16 words) and the first word of block 2. Block 1 only starts when that 17th word arrives.
2. Wait for BUSY = 0, then DINIS = 1. The CSRs read as zero unless DINIS = 1.
3. Read `HASH_IMR`, `HASH_STR`, `HASH_CR`, and `HASH_CSR0`–`HASH_CSR37` (offset `0x0F8 + 4x`). CSR38–53 are for HMAC only.

Restore:
1. Write `HASH_IMR`, `HASH_STR`, `HASH_CR` with the saved values.
2. Set INIT in `HASH_CR`.
3. Write CSR0–CSR37.
4. Continue feeding from the 18th word.

That is 42 writes, or 41 if IMR is always zero and you skip it. Whether steps 1 and 2 can be one CR write is not stated; try it.

**Bursts.** The chapter says only that registers take 32-bit word accesses. Nothing forbids a load-multiple or store-multiple over consecutive CSR addresses; the "burst of four" language is about the DMA interface to DIN. A store-multiple is restartable if an interrupt lands in it, which is harmless here because the writes are idempotent.

**Where block 1 is constant.**

| Digest | Block 1 | 17th word | Usable? |
|---|---|---|---|
| Count-grind try (`wots_digest`, 128 B) | seed ‖ WOTS address | first 4 bytes of the message hash: constant per grind | Yes; public data |
| WOTS PRF (80 B) | `sk_seed` ‖ "wots" ‖ layer ‖ first 24 bytes of the 32-byte tree field (zeros) | high half of the tree index: constant per tree | Yes; the saved state is secret-equivalent |
| R-grind PRF (119 B) | `sk_seed` ‖ "R_grind" ‖ `opt_rand` ‖ 9 message bytes | message bytes: constant per sign | Yes; secret-equivalent; small volume |
| R-grind `h_msg` (160 B) | seed ‖ root | first 4 bytes of R: **varies** | No, unless the pending word can be overwritten in the context |
| Chain step, FORS leaf, nodes, `th_multi` | contains the address, which varies | — | No |

**Cost by the book.** A restore is about 42 writes. At your 2.6 cycles per access that is ~109 cycles; with load-multiple and store-multiple pairs perhaps ~95. It replaces 17 DIN writes (44) and one block (66), so 110. Expect 0–15 cycles of gain per digest: **break-even**.

**The experiment worth doing: sparse restore.** After INIT, with one block processed and one word pending, most of the 38 registers probably hold their post-INIT values: the 16-word FIFO is empty. What must differ is the eight state words, the length counter, the word count and the pending word. If only ~10–12 registers differ, writing just those costs ~30 cycles.
- On the kit: save the context for several messages and for the post-INIT state, and diff them. That tells you which CSRs carry state.
- Then test a restore that writes only those, against software SHA-256, across all three usable shapes and many inputs.
- Also test overwriting the CSR that holds the pending word. If that works, `h_msg` and any other shape with a constant block 1 become usable.

Estimated gain if ~12 writes suffice:

| Digest | Now | With sparse restore | Per pass |
|---|---:|---:|---:|
| Count-grind try | ~290 | ~230 (restore 30, 15 words 39, two blocks 131, read-out and control ~30) | 61k × 60 ≈ 3.7 M, **−3%** |
| WOTS PRF | ~215 | ~125 | 44k × 90 ≈ 4.0 M, **−3.4%** |
| R-grind PRF | part of ~925 | −90 | 2k × 90 ≈ 0.2 M |

This is the only idea in this document that reduces engine work: about 105k fewer blocks per pass. The percentages are against a 118 M pass without the top-layer cache. With #1148 the WOTS PRF count roughly halves (one layer build instead of two), while the pass shrinks to ~82 M, so the grind share rises to about −4.5% and the PRF share stays near −2.5%.

**Costs and risks.**
- Sparse restore is not what the RM describes. It rests on INIT resetting the unwritten registers, which you can observe but ST does not promise. A boot KAT that exercises the restore, with a fallback to the plain path on mismatch, bounds the risk to speed, not correctness.
- For the PRFs, the saved state lets anyone who reads it compute every WOTS secret of that tree. It is a new secret object: secure RAM, wiped with the rest, one per layer per pass. Start with the count grind, which has no such issue.
- FI: one saved context feeds ~30,000 tries. A corrupted context makes every try wrong in one pass; the other pass saves its own. Same class as the per-key templates you already have.

### DMA feed

I do not expect it to help, and it needs no kit time unless you want the number.
- GPDMA moves each word as a separate read and a separate write, with its own arbitration. I would be surprised if it beat 2.6 cycles per word; the CPU's load-multiple and store-multiple pair is near 2.25.
- Each message needs the channel reprogrammed (address, count, enable): several register writes, comparable to feeding 5–8 words directly.
- Its real benefit is freeing the CPU during the feed, and the CPU has nothing to do.
- It is also a second bus master in the secure world, which the `ui-px` notes treat as a review item of its own.
If measured, measure it on `th_multi` (1,440 bytes), the only shape long enough to amortise the setup, and that shape is ~1.5% of a pass.

### The rest of the chapter

- **HMAC mode, SHA-224, MD5, interrupts:** nothing usable.
- **DATATYPE:** byte swapping is free in hardware; pre-swapped words would not be faster.
- **Skipping the DCIS clear** (INIT clears it): −2.6 cycles per digest, ~0.7% of a pass, and it removes the stale-DCIS tripwire. Not worth it.
- **Design-level note, not actionable:** standard SLH-DSA-SHA2 pads `PK.seed` to a full 64-byte block so that block 1 is the same for every hash and a midstate removes it everywhere. C10's layout puts the address in block 1, which is why 60% of your work is two-block digests that cannot share a midstate. That is frozen; it belongs in the notes for any future parameter set.

---

## 2. System-level wall time in the product

All from source; none of it is visible on the kit.

### Strong-RNG draws

- `c10_sign_verified_with_progress_inner` calls `rng_strong::fill` three times: 16 bytes (`opt_rand`), 32 and 32 (the two shuffle seeds).
- Each call: platform TRNG fill, then `fold_se_sources`, which loops over chunks of at most 32 bytes (`source_chunk_len`, `MAX_SOURCE_BLOCK`) and draws each chunk from **both** OPTIGA and SE050. So three calls are three OPTIGA and three SE050 round trips, with FI double-checks and `wait_random` delays around each.
- The source comment in `crypto.rs` puts the three at ~0.3 s on the EVT. I have no per-call figure.
- **One 80-byte draw would still be three chunks**, so six round trips. Merging the calls saves only the per-call FI scaffolding. My round-1 H7 overstated this.

What would help:
- **Fewer bytes.** `ShuffleSeed::derive` already hashes the seed with a label. Drawing one 32-byte value and deriving the two pass seeds from it with distinct labels cuts the draws to two chunks: about −0.1 s, assuming the cost scales with round trips and not with the per-call FI delays, which I could not check. The FI argument for independent seeds is that the two passes must run in different orders; label-separated derivation gives that. The SCA argument (two misaligned traces) is also kept. This needs the owner's reading of the software-PRNG rule: shuffle order is a countermeasure parameter, not signature-reaching, so it sits near the existing carve-out, but it is not inside it as written.
- **I would not derive `opt_rand` this way.** It reaches the signature, and the rule for that is explicit.
- **Draw earlier.** A small pool in secure RAM (80 bytes), filled after unlock or while the user reads the review pages, and consumed at sign time. This removes the full ~0.3 s from the perceived sign. Conditions: single use enforced with an FI-checked consumed flag, wiped on lock with everything else, refilled only from `rng_strong`. A value reused through a fault would repeat a shuffle order, or repeat `opt_rand` for a different message, which still gives a different R because R is keyed on the message.
- **Overlapping the I2C work with pass A** would need a non-blocking SE driver or a poll from the hash tick. Only the second shuffle seed can be deferred that far. The pool gets more for less.

### F-17 rate limiter

- `pre_sign` busy-waits until 1,000 ms have passed since the previous sign **started**, and refuses after 250 signs per unlock.
- At 1.48 s per sign it never waits. With the cache at 1.03 s it is on the edge.
- Consequence: **one second per signature is now a floor for batches and rotations.** `cmd_sign_userop_batch.rs` calls `c10_sign_verified_with_progress` per signature, and that wrapper charges `pre_sign` each time, so a batch of N signatures takes at least N seconds whatever the hash speed. If batch time matters, the interval is the lever, and that is an SCA policy decision, not an engineering one.

### Slot-cache miss and bootstrap keygen

Cold costs, from your milestone and the October probe:

| Step | When | Cost |
|---|---|---:|
| BIP-39 PBKDF2 (2,048 × HMAC-SHA512, software) | once per session and account for the slot master (the session keeps it); a cold address or sender-binding derivation before the confirm runs its own (`nsc/seed_once.rs`) | 92 M cycles, 0.57 s (the figure in `seed_once.rs`) |
| Slot keygen | first sign per (account, chain, slot) | 0.24 s; 0.48 s with cache fill and confirm |
| Bootstrap keygen | first address, deploy or rotation per session | 0.24 s |
| Bootstrap sign (Type-1) | each rotation or deploy | 1.48 s; no top cache today |

- **PBKDF2 is now the largest cold item,** and a fully cold session can pay it twice (once before the confirm for the address, once after for the slot master). It is two SHA-512 compressions per iteration already (`bip39/src/full.rs` clones a keyed state). 92 M over 4,096 compressions is ~22k cycles each, which is slow for SHA-512 on an M33; the `bip39` crate is also compiled at `z`. A tuned SHA-512 and an opt-3 loop might give 1.3–2x. The kit can measure this exactly: it is pure CPU.
- The address stretch usually runs under `GET_WALLET_ADDRESS` before any sign. The slot-master stretch runs after the confirm on the first sign of a session, so that one is in the visible wait. Worth confirming with a companion trace.
- **A top cache for the bootstrap key** would take a rotation from 1.48 + 1.03 to about 1.03 + 1.03. Rotations are rare; low priority.

### Other non-hash work on the sign path

I read `nsc/cmd_sign_userop.rs` from the confirm onward.
- `read_entropy_blob` runs on every sign, but under `dual-se` it copies from a RAM cache; no SE traffic. `decrypt_entropy_blob` is one small AES-GCM. On a slot-cache hit the result is not used at all; skipping it would save little.
- Page-123 reads are done twice each for FI; the tally commit is one small flash program before release. Milliseconds at most, unless a compaction (page erase) lands on that sign.
- The atlas re-hash under `ui-px` is ~75 KB through the HASH engine: about 0.2 M cycles each time. Negligible.
- The film: your stub measured +7.2% for the per-digest tick, and the source puts drawing at ~8 ms per 32 ms while live. #1149 covers the tick; the drawing share is a UX choice.

So the non-hash list is short: RNG, PBKDF2, the film, and the 1-second interval.

---

## 3. Idle-time and review-time precompute

### What can be done before the message matters

| Work | Depends on | Earliest point | Hides |
|---|---|---|---|
| PBKDF2 → slot master and bootstrap seeds | seed and account index | end of unlock for account 0; otherwise when the request names the account | 0.57 s |
| RNG pool | nothing | after unlock; refill after each sign | ~0.3 s |
| Slot keygen, cache fill and confirm | (account, chain, slot), supplied with the request | when the request arrives, before or during review | 0.24–0.48 s |
| R-grind, FORS, layer 0, both passes | message and `opt_rand` | when the digest is fixed, before confirm | 1.03–1.48 s |

The first three produce no signature. The fourth does.

### Prewarm (rows 1–3)

- Nothing that authorises a transaction exists before consent. What changes is that slot-key derivation (22,000 PRFs over the slot's `sk_seed`) can be triggered by a sign request the user then declines.
- **This is not new in kind.** In an unlocked session a companion can already trigger secret-dependent work with no button press: `GET_INIT_CODE` has no confirmation and runs the slot-0 keygen, the bootstrap keygen and a bootstrap signature over the factory authorisation, and the sign handler derives the sender address (bootstrap keygen, with its own PBKDF2 when cold) before the dialog opens. Prewarm extends that to slot keys other than slot 0.
- `SLOT_CACHE` holds a single entry (`Option<CachedSlot>` in `nsc/state.rs`), so alternating two slots forces a keygen each time. A per-session cap on prewarm keygens is therefore needed; the cache alone does not bound repeats. The same is true of `GET_INIT_CODE` across chains today.
- Invariant 8 (stateless slot selection, SRAM cache only) is respected: nothing is stored beyond what the cache holds today.
- The inactivity timer must not be reset by prewarm. Only confirm-dialog button presses do that.
- Mechanics: run it after the first review page is painted. A 0.24–0.48 s computation with buttons unread is probably acceptable on page one; latching button edges from the progress callback removes even that.

### Speculative signing (row 4)

**What it buys.** The user needs several seconds to scroll to the last screen (the chord arms only then). A 1.0–1.5 s sign finishes well inside that. Perceived sign time goes to roughly the release checks.

**Consent.** Today: no signature over the user's transaction is computed before confirm. Proposed: none is *released* before confirm. The existing precedent is narrower than it looks: `GET_INIT_CODE` signs and releases without a confirmation, but only a fixed-form factory authorisation, never a user operation. CLAUDE.md states the clear-signing guarantee as "decoded and rendered … before the user presses confirm"; it does not say when computation may start. I read this as a change in the meaning of the confirm gate that the owner must decide, not something the existing text settles.

**What gets worse.**
- **A finished, valid signature exists in secure RAM before consent.** Today a fault that skips the confirm verdict still has to be followed by 1–1.5 s of signing, during which the FI chain and the CFI transcript run after the faulted point. With speculation, the confirm verdict becomes the last gate before release, and a secure-RAM read primitive during review yields a signature the user never approved.
- **Slot-key signing compute without a button press.** A hostile companion can make the device produce side-channel traces of full slot-key signatures by sending requests and never confirming. Today that is possible only for the bootstrap key through `GET_INIT_CODE`, under the rate limiter. The limiter exists to bound exactly this.

**Conditions I would require.**
- Charge F-17 (interval and session count) when speculation starts, not at release. A declined request costs a unit.
- Bind the speculative result to the exact request: the digest that was displayed, the slot, the nonce. Re-check that binding after confirm with the existing calldata-commitment pattern.
- Put the confirm outcome into the signing CFI transcript as its own step, checked twice, so release requires both the FI chain and the confirm receipt.
- Keep verify-before-release after confirm, not before, so one gate still runs post-consent.
- Zeroize the held signature on decline, timeout, lock, tamper, and on any page change that alters what is displayed.
- Do not commit the page-123 tally until release, as today. A declined speculative signature leaves no trace on chain or in flash. It does consume a random hypertree position, which is harmless for a stateless scheme.
- A weaker variant keeps more of today's property: speculate pass A only and run pass B, the compare and the verify after confirm. It halves the visible wait. Note that pass A's output is already a complete signature, so this does not remove the pre-consent artefact; it only keeps half the work behind the gate.

**How the signer and the UI would share the CPU.** The signer is a deep, non-resumable call. The practical shape is the one the film already uses: the signer runs as the main flow and the dialog is serviced from the tick and progress callbacks (button edges latched, pages repainted between digests). Consequences:
- the confirm dialogs, including scroll-to-end gating and their FI receipts, would have to run inside a callback from the hash driver;
- any dialog code that hashes (the atlas re-hash) would run with a digest loop suspended around it, which is the F3 hazard from round 2;
- dialog rendering stacks on top of the signer's stack.
That is a re-architecture of the trusted UI path, not a signer change.

**My view.** Prewarm plus the RNG pool takes a cold sign with the cache from about 2.4 s after the confirm (RNG 0.3, slot-master PBKDF2 0.57, keygen with confirm 0.48, sign 1.03) to about 1.03 s as perceived, with no change to what confirm means. Speculation takes it from 1.03 s to near zero at the cost above. I would do the first and put the second to the owner with this section.

---

## 4. Compiler and codegen

- **`-C target-cpu=cortex-m33`.** The hot loops are bounded by bus accesses and engine time, so scheduling and tuning changes have little to act on. Expect 0–1%. It is a global flag: it changes every crate including the FSBL, and the reproducible-build hashes. One bench run answers it.
- **Inline asm for the chain step.** Your figures: 242 per step in the Rust loop, 214 straight-line from registers, plus ~9 for BUSY. My hypothesis is that the four HR reads (about 10 cycles) already cover the BUSY tail, so the 9 is not additive and an asm loop might reach ~220. If the 9 is additive the floor is 223 and the gain halves. That would be ~20 cycles on 309k steps: 6 M, about 5% of a pass. This is the largest codegen item left. Cost: hand-written asm in the driver is invisible to the Lean extraction and needs its own FI read; the existing per-step tripwires should be kept in it.
- **PGO.** Not practical. Instrumented builds need the profiler runtime, which `thumbv8m.main-none-eabi` `no_std` does not have. A host-collected profile can in principle be applied to a cross build, but these loops are MMIO-bound with fixed trip counts; branch layout has nothing to improve.
- **Hot-code placement.** You measured 1-way against 2-way ICACHE at 0.15% in the bench. The product image is ten times larger and interleaves film code through the tick. Grouping the driver and `sphincs-c10` hot functions into one contiguous section under 8 KB makes the product behave like the bench. Only a product build can show whether it matters.
- **Loop alignment** to the 16-byte ICACHE line for the chain and search loops: plausible 0–1%; try it together with the asm step.

---

## 5. Algorithmic ideas inside the frozen format and the FI design

**I believe the digest count is at its minimum.** The reasoning, component by component:

| Component | Digests per pass | Why it cannot shrink |
|---|---:|---|
| FORS, 12 signed trees | ~73.7k | A Merkle auth path needs every leaf of its tree, and the forest is bound to the hypertree position, so nothing carries over between signs. |
| FORS, forced-zero tree | ~6.1k | Only its root is emitted, and a root needs all 2,048 leaves. |
| Layer-0 tree | 177,151 | One of 512 trees chosen by the message digest; all 512 leaves are needed for the auth path. Cross-sign caching hits one time in 512. |
| Count grind, two layers | ~61.4k expected | The first counter with digit sum 205 is part of the frozen bytes; each try is one digest and there is no early exit inside a hardware digest. |
| R-grind | ~4.1k expected | The first nonce with a zero last index is part of the frozen bytes. |
| WOTS signs, self-check | ~0.7k | Already negligible. |

Things I looked for and did not find:
- **Sharing between FORS trees, or between FORS and the hypertree:** every hash is domain-separated by its address; no value recurs.
- **Sharing between the two count grinds:** different addresses and messages.
- **Reordering.** The layer-0 tree does not depend on the FORS result, so the order FORS → tree could be swapped, and the count grind for layer 0 could run before the tree build. That changes when work happens, not how much. It would let the target leaf's chain values be captured during the build instead of recomputed (~250 digests per layer, 0.07%).
- **Early abort.** The R-grind check and the digit-sum check both need the finished digest.
- **Caching the layer-1 count per layer-0 tree.** Deterministic per key and tree, but hits one time in 512 without the position biasing you have rejected.

What remains is not about digest count:
- **Blocks, not digests:** the context-restore midstate in section 1 removes ~105k blocks per pass.
- **CPU idle time.** At 242 cycles per chain step the CPU is feeding or reading for roughly 90 and waiting for roughly 150. Over a pass that is ~45 M idle CPU cycles. A software SHA-256 on an M33 costs on the order of 1,500–2,500 cycles per block (measure it; I am not confident of the figure), so ~5,000 for a three-block node. Running public hashes there, for example the upper FORS nodes, in slices between DCIS polls could absorb perhaps 8,000 of the 26,600 nodes per pass: about 2.8 M cycles, 2–3%. It needs a resumable software compression, a reordering so that independent public work is available during chain phases, and a second hash implementation in the signing path. As a side effect it adds implementation diversity against a common-mode HASH fault. I rank it low for the complexity.

---

## 6. Literature

What I could establish this round; search summaries unless marked as read.

- **SLotH (Saarinen, CRYPTO 2024), read in round 1.** Its gains come from three things: address and padding formatting in hardware, chain iteration in hardware, and a `PK.seed` block that is constant so the core starts from a midstate. You have done the software form of the first two. The third is the context-restore idea in section 1, limited by C10's layout to the PRFs and grinds. https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/accelerating-slh-dsa.pdf
- **OpenTitan.** Verification only, in mask ROM; the first chips shipped SPHINCS+ with SHAKE-128s, and later work reports SHA-2 parameter sets verifying faster than RSA and ECDSA on the HMAC block, which takes about 80 cycles per block once its FIFO is full. Nothing on signing, and nothing you have not done. Posts: https://gopher-octagon-aya6.squarespace.com/blog/post-quantum-secure-boot-on-opentitan and https://gopher-octagon-aya6.squarespace.com/blog/future-of-pqc-on-opentitan ; block timing from https://arxiv.org/pdf/2402.10395
- **A hash-based-signature accelerator integrated into OpenTitan** (LMS, XMSS, SPHINCS+), Journal of Cryptographic Engineering 2024. Hardware co-design; not applicable to a fixed peripheral. https://link.springer.com/article/10.1007/s13389-024-00362-4
- **Precomputation schemes.** I found no offline/online split for standard SPHINCS+. SPHINCS-PE (ePrint 2026/1708) splits the hypertree into a precomputed upper part and an online lower part, which is your top-layer cache generalised, but it changes the signature format. v-ORS (ePrint 2021/1495) cuts hash calls by changing how FORS subsets are chosen; also a format change. https://eprint.iacr.org/2026/1708 , https://eprint.iacr.org/2021/1495
- **Infineon and NXP secure elements.** I found no public description of an SLH-DSA signing implementation on either vendor's secure elements, and I did not search their product documentation in depth. Treat this as not found, not as absent.

Nothing in the literature I reached suggests a technique for a fixed general-purpose SHA-256 peripheral beyond what is in sections 1 and 5.

---

## Corrections to my earlier rounds

- Round 2, R6: I agreed the chain step was at the floor and said to stop. With your 214 straight-line figure beside the 242 loop figure, there are 19–28 cycles unexplained, so I now rank an asm step second. Whether it is reachable depends on the BUSY-tail hypothesis in section 4.
- Round 1, H7: "one 80-byte draw instead of three" does not reduce secure-element round trips. See section 2.
- Round 1, H17 and round 2: I rated context restore as break-even. That holds for the full 38-register restore. I had not considered writing only the registers that differ from the post-INIT state.

## Not checked

- No build or measurement. The sparse-restore estimate assumes ~12 state-bearing registers; the real number is unknown until the kit diff.
- Per-call cost of `rng_strong::fill`; only the source comment's ~0.3 s for three.
- Whether PBKDF2 actually falls inside the sign path in normal companion use.
- The software SHA-256 and SHA-512 cycle figures for the M33 are from memory.
- GPDMA transfer timing; I reasoned from its structure and did not read that chapter.
- `cmd_sign_userop_batch.rs` beyond its `c10_sign_verified_with_progress` call sites, and the off-chain handler.
- Infineon and NXP material beyond one search.
