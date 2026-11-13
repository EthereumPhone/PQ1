# C10 v2 format options: security check and measurements (2026-11-13)

Research for #1155, not adopted. The owner asked for the three format-level options from `fable-hypotheses-5.md` (items 4–6) to be checked for security impact **before** they are committed to, with tests and an analysis. Each option is now implemented behind its own off-by-default flag. Draft 0.3's output is byte-identical with every flag off: its 6 KATs and 3 near-misses regenerate exactly, the 0.3 kit golden and gate 5 pass, and the v1 suite is 82/0.

Every claim below carries a label:
- **[computed]**: a script or test produced it; the file is named.
- **[argued]**: reasoning, not executed.
- **[measured]**: kit 0055002D at 160 MHz, harness v3b.
- **[reviewer]**: GPT-6 Astra's opinion (§7).

## Verdicts

| change | honest operation | conditions and new risks | speed, luck-free mean of 16 messages per pass | verifier | formal-verification cost |
|---|---|---|---|---|---|
| **ts200**: WOTS+C target sum 200 | **Proven-bound total unchanged** (§8): its only T-dependent term, accepted-encoding collisions, falls ×0.30 at the reference caps [computed]. The one-time forgery chance per try is 2^-129 for any T [computed] | The fault fallback is about 1.7 bits weaker. **Keys do not change**, so a seed that ever signed under 205 must never sign under 200: that reuses every WOTS key, and a forgery then costs about 2^53. | **−5.98 M (−9.3%)**; −13.7% with the top cache | +3,150 gas (+2.0%); on-device verify +1.1k cycles | Mechanical: 205 is a literal in the Lean Yul model; EasyCrypt keeps the sum parametric |
| **prf2**: two secrets per PRF digest | **No proven-bound constant changes** (§8) [computed]; in the ideal model the two halves are independent uniform secrets [argued], **provided** the sk_seed-keyed inputs stay block-prefix-free; they are today [computed] | Whole 32-byte PRF outputs now become public: about 48 per key at the 2^16 cap. Even-index secrets equal 0.3's, so a seed used under both loses most of its WOTS margin (median 2^77). | **−2.59 M (−4.0%)**; −3.9% with the cache; keygen −0.93 M (−4.3%) | none (keys change) | Key-generation code changes, so the extracted PRF specs and KAT pins change |
| **split810**: layer heights (8, 10) | **The proven bound loosens: ×1.21 (0.28 bits) at 2^16 signatures** (§8) [computed]. The bound charges every hash the model signer makes, and it rebuilds the whole 10-high top subtree per signature. Per-key WOTS use and the FORS few-time term are unchanged [computed + argued]; the top layer has 1,024 WOTS keys instead of 512 [reviewer] | A7 widened. **Conditional on #1148**: the cache becomes structural, since without it signing is +17% slower. Keygen doubles. | **−10.77 M (−24.7%)** with the cache; +10.8 M without | +68 gas | Structural: both formal models assume one height per layer (`h = h' * d`, `SubtreeH * D = H`) |
| all three | as above | as above | with the cache 25.65 M per pass, an estimated **0.32 s** cached sign | +3,218 gas | sum of the above |

"Luck-free" is explained in §5: each configuration's 16 per-message cycle counts are fitted against that message's exact grind work, computed on the host.

## 1. ts200: WOTS+C target sum 205 → 200

What T does, in one place: the signer grinds a 32-bit count until the 43 base-8 digits of `WOTS_DIGEST` sum to T. The verifier rejects any other sum, then walks every chain from digit d_i to 7.

- **One-time forgery is independent of T [computed + argued].**
  - A forger who holds the chains revealed at d needs a digest d′ with d′_i ≥ d_i for all i and Σd′ = T = Σd. That forces d′ = d.
  - `format_options_numerics.py` checks this rather than assuming it. For a sampled d at each T in {190, 195, 200, 205, 208, 210}, an exact integer DP finds exactly one vector, d itself.
  - So each forgery try succeeds with probability 8^−43 = 2^−129 for any T.
  - The address A7 sits in the digest, so each try targets one key and there is no multi-target gain.
- **Honest operation never gives one WOTS key two digests [argued].**
  - Each key signs a value that is deterministic per position: the FORS public key at its `ht_idx`, or the layer-0 root of its tree.
  - The count search is deterministic, so the same node gets the same digest.
  - That is the standard SPHINCS+ argument, and nothing in ts200 touches it.
- **What T does change [computed]:**
  - |S_T| = 2^114.09 → 2^115.83 valid digit vectors;
  - grind tries per WOTS signature 30,698 → 9,192, which reproduces Fable's arithmetic and the kit's 61.4k tries per sign at 205;
  - verifier chain steps per WOTS signature 96 → 101.
- **The fault fallback is weaker [computed].**
  - The case: a fault, a bug or cross-variant reuse (§4) makes one WOTS key sign two digests. The forger then holds every chain at min(d1, d2).
  - Per-try forgery probability, exact DP over 3,000 sampled pairs:

    | | T = 205 | T = 200 |
    |---|---:|---:|
    | two digests, median | 2^−55.3 | 2^−53.7 |
    | two digests, 1st percentile | 2^−47.3 | 2^−45.6 |
    | three digests, median | 2^−39.0 | 2^−37.0 |

  - Both are far below 128 bits, so the double-compute FI chain is what protects this case at either T. At 200, a forger who gets one faulted signature out needs about 3× less work.
  - The model assumes both digests are uniform on the sum-T vectors, which holds for a signer that re-grinds a wrong node. An arbitrary fault need not fit it [reviewer]; the numbers illustrate the margin and are not a bound.
- **FORS [computed]:** unaffected. Its term depends on h, k, a and q only (§3).
- **Verifier:**
  - Yul +3,150 gas, measured in the callee: 157,585 → 160,735, identical on all 6 KATs, which is 10 more one-block F calls at about 315 gas each.
  - On-device verify +1.1k cycles.
- **Formal artefacts [computed by grep]:**
  - EasyCrypt (`WOTS_TW_ES.ec:579–586`) defines `target_sum` from a witness and states that it "does NOT pin the deployed 205".
  - Lean carries 205 as a literal in `Spec/Params.lean:65` and in the Yul interpreter model (`C10Source.lean`, `C10Program.lean`, `Phases.lean`), so changing it is a constant change plus a proof re-run.
  - `Quantitative.lean`'s bounds depend on q and n only.

## 2. prf2: one PRF digest, two secrets

Definition:
- Secret 2j takes bytes 0..15 and secret 2j+1 takes bytes 16..31 of `SHA-256(sk_seed ‖ A7(index 2j))`.
- For WOTS the pair bit is the `ci` LSB; for FORS it is the `ha` LSB. WOTS chain 42 is unpaired and uses the first half only.
- The verifier is unchanged.

- **Soundness [argued]:**
  - The secrets must be pseudorandom and independent, given everything revealed.
  - Under the assumption the scheme already uses, that `SHA-256(sk_seed ‖ ·)` over these one-block inputs is a PRF, a 32-byte output is pseudorandom. Its halves are therefore independent, even when one or both are revealed.
- **The new exposure is real, so the side condition is load-bearing [computed].**
  - Today only 16 bytes of any PRF output ever leave the device. Under prf2 both halves of one output are revealed when:
    - both digits of a WOTS pair are 0: P = 1.5·10^−3 per pair at T = 205, so about 0.03 whole outputs per WOTS signature;
    - two signatures on one `ht_idx` reveal sibling FORS leaves: about 48 whole outputs per key at q = 2^16 (8,192 expected same-`ht_idx` pairs × 12 trees × 2^−11).
  - A whole SHA-256 output allows length extension, giving `SHA-256(sk_seed ‖ A7 ‖ pad ‖ x)` for any x. So no other sk_seed-keyed input may start with a padded PRF block.
- **Prefix-freeness holds [computed, `format_options_checks.py` B].** The only sk_seed-prefixed SHA-256 inputs are:
  - the 39-byte PRFs (one length, one block each);
  - the R-grind PRF, `sk_seed ‖ "R_grind" ‖ [opt_rand] ‖ M ‖ nonce` (103 or 119 bytes; `fors.rs:122`, `v2hash.rs` `grind_r_fused`).

  For the R-grind's first block to equal a padded PRF block, the bytes "R_grind" would have to be an A7 the scheme produces. Read as an A7 they decode to type 5 (WOTS_PRF), but they set the always-zero bit 16 and have cp = 6, so in both layouts no constructor emits them. The rest of the block would also have to equal the padding (`0x80 ‖ 0^16 ‖ 0x138`).

  **This turns a convention into a rule:** any future sk_seed-keyed input must keep that property. Adding one would need a new check.
- **Wiping [argued]:**
  - The driver wipes its 8-word copy with volatile writes. The generic Rust path wipes the input copy and the digest.
  - The HASH peripheral's HR0..HR7 already held the whole 32-byte PRF digest under 0.3 until the next operation; only the first half was used. So prf2 leaves nothing there that was not there before.
  - The new transient is the second half in a stack array until it is wiped.
  - **A caveat [reviewer, Astra].** A zero-step `pqsigner_v2_prf_chain16` call (a digit-0 signature chain) leaves the whole digest in HR0..HR7 until the next digest. Under 0.3 the unused half was meaningless. Under prf2 it is the sibling chain's secret. The HASH block is secure-only (TZSC), and the next operation overwrites it. Register and spill residue has not been checked on the target.
- **DPA [not claimed]:** prf2 halves the number of sk_seed-keyed compressions. That may help or hurt a side-channel attacker; it is unmeasured, and this analysis claims no benefit.
- **Pairing is unambiguous [computed]:**
  - the pair bit is the LSB of a field whose other bits are unchanged;
  - single-chain signing (`pqsigner_v2_prf_chain16`) and height-0 FORS subtrees starting on an odd leaf take the right half, as gate 5 checks on the kit against a software model with prf2 semantics: 2,091/0.

## 3. split810: layer heights (8, 10)

Definition:
- Layer 0: 256-leaf trees, `idx_leaf = ht_idx & 0xFF`, 1,024 trees.
- Layer 1: one 1,024-leaf tree.
- A7 `kp` widens to 10 bits (32..23), and `ci` moves into a former zero bit (22..17).
- Signature sections 820 + 852 bytes; total still 4,008.

- **Bounds [computed + argued]:**
  - **FORS:** the few-time term depends only on (h, k, a, q). It is 2^−130.6 per H_MSG query at q = 2^16 (`format_options_checks.py` D), for both splits. Astra's exact binomial check gives 130.568 bits, against 130.568 from the Poisson approximation.
  - **WOTS:** every key still signs exactly one deterministic node.
  - **Keys:** the top layer has 1,024 keys (was 512); the bottom layer is unchanged at 2^18; all are address-separated. Total WOTS keys go from 262,656 to 263,168. A term linear in the top-layer key count doubles (1 bit), and one linear in the total moves 0.003 bits. "Unchanged" is true for the FORS term and per-key use, not for every term [reviewer].
  - **Hash work:** the tweakable-hash and Merkle arguments are per-node, and the total height is unchanged.
- **The A7 layout stays injective [computed, `format_options_checks.py` A]:**
  - the fields are disjoint bit ranges in 56 bits, and every role's maximum fits its width, for both layouts;
  - all 109 boundary tuples round-trip;
  - the widened bit is exercised: the split810 KATs include leaf indices ≥ 512 at layer 1 (917, 615, 727).
  - **Every site where the layout lives is pinned by a test or control:**
    - **Python, Rust and the host mirror:** they agree byte for byte.
    - **Yul:** controls revert one site at a time (kp 24 in FORS or in the hypertree, ci 18, heights (9, 9)), and each revert alone rejects the variant's own KATs.
    - **Driver `V2_CI_LSB`:** gate 5 passes 2,098/0, with `kp` drawn over 10 bits.
  - **Hostile signatures [argued, Yul]:** the per-layer height `hl = 8 + 2·layer` comes from the loop counter, not from the signature, and every index is masked from the 18-bit `ht_idx`.
- **The top-layer cache becomes structural. This variant is conditional on #1148 [measured + argued]:**
  - Without the cache a pass builds the 1,024-leaf top tree, which makes signing 17% *slower* (75.33 M against 64.52 M).
  - With the cache, each signing pass takes the top auth path from 64 stored height-4 nodes (1 KB, up from 512 B), rebuilds the 16-leaf subtree under its leaf, and re-climbs to `pk_root`.
  - **What is computed once rather than twice:** the stored nodes, filled at keygen. The rebuild and the climb run in both passes, and so does the top WOTS signature [reviewer, checked in `bench_v2fb`].
  - **What the cache already guarantees:**
    - fill and confirm at keygen through two independent builds (rotated chain order);
    - a digest check on every use;
    - the rebuilt subtree must equal the stored node, and the climb must reach `pk_root`.
  - Host controls under split810: a flipped node, a keygen fault and another key's cache are each refused; a valid cache signs. The full 1,024-leaf sweep shows the cached path equals a full rebuild.
  - A corrupted cache gives a refusal or a verify-before-release failure, and cached nodes are public values. Whether that FI trade is acceptable is #1148's question; split810 only removes the option of declining it.
- **Costs:**
  - keygen doubles: 21.58 M → 43.17 M plain, and 45.58 M → 91.2 M with fill and confirm (0.29 s → 0.57 s for a first sign on a new slot);
  - verify +68 gas.

## 4. Cross-variant key reuse (found during this check)

Every v2 variant derives the same `(sk_seed, pk_seed)` from a seed. So one seed signing under two variants is a real risk, for example after a firmware change mid-life. The numbers are [computed] (`format_options_numerics.py cross`), as median per-try forgery work:

- **0.3 and ts200: 2^53–2^55.**
  - Keys, tweaks and signed nodes are all identical; only the count changes. So every WOTS key that signs under both targets becomes a two-time key.
  - A wallet's address would not even change, because `pk_root` is the same. This is the dangerous one.
- **0.3 and prf2: 2^77 (1st percentile 2^63).**
  - Even-index secrets equal 0.3's, because they come from the same PRF input. Even FORS leaves are shared as well.
- **0.3 and split810: large overlap.** This corrects my first draft, which said "only `kp = 0`, `ci = 0`"; Astra found it [reviewer, then computed].
  - Moving `kp` and `ci` down one bit maps 0.3's `(kp, ci)` onto split810's `(2kp + ⌊ci/32⌋, 2ci mod 64)` with identical A7 bytes, so identical secrets and chain tweaks.
  - 38% of split810's WOTS PRF addresses (67,584 of 176,128 over two trees) equal a 0.3 address.
  - FORS trees 0..6 of 0.3 are byte-identical to split810's trees 0, 2, …, 12 at every `ht_idx`.
- **0.3 and `v2-fors-last-prf` (spec §6, #1158): the same class as ts200.** The flag replaces the last FORS slot's value, so the FORS public key at every `ht_idx` changes while `pk_root` does not. Switching it on or off for a key that has already signed makes each used layer-0 WOTS key sign two different nodes: a two-time key at about 2^53–2^55 [argued from §1's numbers]. Any decision on §6 falls under the same rule.
- **Also shared:** the R-candidate stream `PRF(sk_seed, "R_grind", opt_rand, M, nonce)` is the same in every variant. Fresh `opt_rand` makes it differ per signature.

**Rule if any variant is adopted:**
- fix the variant before the first v2 key ever signs;
- better still, bind the format identifier into key derivation or into every tweak, so that two formats can never share a chain. Changed roots and verifiers that reject each other's signatures do **not** establish separation [reviewer].

v1 and v2 do not have this problem: their preimage lengths are disjoint (spec §3).

**What this means for the bootstrap key.** Bootstrap keys are immutable per wallet (invariant #6). So the target sum and layer split chosen when v2 is adopted are permanent for every wallet created under it, unless the format identifier is bound into derivation from the start; then a later change means new keys and new addresses.

## 5. Measurements [measured]

Method:
- 16 messages (`bench_avg_v2f`), one signing pass each, every signature verified on-device. Each configuration, plain and with the cache, is also gated byte for byte by its own kit golden against host goldens (`experiment_v2.sh` and `experiment_v2b.sh` with `GOLDEN`/`VARF`; 3 cache hits each). The host goldens come from the generic Rust path, which equals Python's KATs, and are re-checked through the fused routing and through the cache.
- Variants that change keys also change every message's grind luck. So `luck_fit.py` fits, per configuration, `cycles_i = det + c_w·wots_tries_i + c_r·r_nonces_i`, with exact per-message counts from the host (`c10-ar-host luck16`).
- **Fit quality:** c_w = 140–143 cycles per try (the microbenchmark gave 137) and c_r ≈ 496 cycles per nonce. Residual standard deviation is 1.3–5.0k cycles on signs of 25–92 M.
- **"Expected" below means** det + c_w·E[tries] + c_r·E[nonces]; the expected try counts are exact.

| configuration | raw mean | **expected mean** | keygen | Δ vs 0.3 | est. cached sign (2 passes + verify) |
|---|---:|---:|---:|---:|---:|
| 0.3 head | 65.59 M | **64.52 M** | 21.58 M | | 0.808 s |
| ts200 | 58.81 M | **58.54 M** | 21.58 M | −9.3% | 0.733 s |
| prf2 | 61.21 M | **61.93 M** | 20.65 M | −4.0% | 0.775 s |
| split810 | 75.98 M | **75.33 M** | 43.17 M | +16.7% | 0.942 s |
| all three | 66.18 M | **66.27 M** | 41.30 M | +2.7% | 0.829 s |
| 0.3 + top cache | 44.69 M | **43.62 M** | 45.58 M | | 0.546 s |
| ts200 + cache | 37.91 M | **37.64 M** | 45.58 M | −13.7% | 0.471 s |
| prf2 + cache | 41.22 M | **41.93 M** | 45.82 M | −3.9% | 0.525 s |
| split810 + cache | 33.51 M | **32.85 M** | 91.20 M | −24.7% | 0.411 s |
| all three + cache | 25.55 M | **25.65 M** | 91.65 M | −41.2% | **0.321 s** |

- **Against Fable's arithmetic:**
  - ts200 −5.98 M, against its −5.8 M;
  - prf2 −2.59 M, against its −4 M (a saved PRF digest is worth about 86 cycles, not a full digest);
  - split810 −10.77 M with the cache, against its −11 M.
- **The cached-sign estimate** is two passes plus the measured verify. It is a kit hashing figure: no UI tick, driver at opt-level 3. As before, the UI film sets the visible time under `ui-px`.

## 6. Tests run

| test | result |
|---|---|
| Python reference, per variant (`c10v2_ref.py --variant … selftest`, `cross`) | sign and verify. 8 bit-flips plus wrong-root and wrong-message cases rejected. 3 +C-only near-misses rebuild the root and are rejected only by +C. **Cross-format:** ts200 keeps keys and is rejected both ways; prf2 changes keys and is accepted both ways; split810 changes keys and is rejected both ways |
| 0.3 unchanged | KATs and near-misses regenerate byte-identical; `kat_export.py` now writes variant vectors to their own files |
| Rust generic path against Python KATs (`tests/v2_kat.rs`), per variant and combined | 2/2 each, byte-identical signatures |
| Fused routing against the generic golden (host mirror, `host_v2f`), plain and with cache | equal for ts200, prf2, split810 and all three; cache used 3 times each |
| Top-cache controls under split810 | 3 refusals and 1 positive control; the 1,024-leaf sweep equals a full rebuild |
| Kit golden (`experiment_v2.sh` with `GOLDEN`) | ok for ts200, prf2, split810 and all three |
| Kit golden with the top cache (`experiment_v2b.sh` with `GOLDEN`, `VARF`) | ok for ts200, prf2, split810 and all three, 3 cache hits each |
| Gate 5, driver against software SHA-256 on the kit | 0.3: 2,091/0 · prf2: 2,091/0 · split810: 2,098/0 · prf2 + split810: 2,098/0 |
| H9 early reject at target 200 (`h9_predicate.py`) | 0 mismatches in 1.33 M checks; the 76-slack control fires |
| Solidity (`SPHINCsC10v2Variants.t.sol`, 14 tests, plus the 0.3 suite's 5) | 19/19 |
| Solidity mutation controls (`variant_controls.sh`, 21 configurations) | each +C revert is load-bearing; the target constant is live; each split layout site is live; stacking all four split reverts makes split810 accept 0.3 KATs, so those edits are the complete difference. **Each row now asserts its expected result,** and the script exits non-zero on any mismatch (Astra: it used to only print); re-run PASS, and a wrong expectation is caught |
| `near-miss-gen` with `v2-split810` | `compile_error!`: the generator assumes uniform heights (Astra); not ported |
| Structural checks (`format_options_checks.py`) | A7 injectivity (both layouts), prefix-freeness, pair-reveal rates, FORS term |
| Margin numerics (`format_options_numerics.py`, `cross`) | as in §1 and §4 |
| v1 regression | `cargo test -p sphincs-c10` 82/0; `--cfg lean_extract` 79/0; kit golden 233,078,450 (233,078,504 before); track B 163,351,100 (3 hits) |
| Shared code with every flag off | the FSBL image (`make fsbl BOARD=iota2`) is byte-identical to the parent commit's. The split refactor touched `merkle.rs`, `hypertree.rs`, `params.rs` and `topcache.rs`, which the FSBL and the Aeneas extraction read |
| Re-run at the committed head | per-variant Rust KATs, forge 19/19, and both analysis scripts (numerics identical to the first run) |

## 7. Independent review: GPT-6 Astra

Astra had read-only access to the working tree and was given the questions, not these conclusions. Fable is not an independent leg here, because it proposed the options. Astra re-ran the numeric scripts, the Python verifier matrix and 70,144 address-patch checks. It did not run Forge or silicon.

- **Isolated variants:** no format break found for any of the three.
- **HIGH, cross-variant seed reuse:** the same finding as §4, with a stronger split810 result. That result I verified and adopted.
- **MEDIUM, controls printed without asserting:** fixed (§6).
- **MEDIUM, an empty revert could be out-of-gas:** covered. The mutation controls show each near-miss rejection comes from its +C revert, since deleting that revert makes exactly that near-miss accepted.
- **LOW, `near_miss.rs` assumes uniform heights:** guarded with a `compile_error!`.
- **LOW, `SIG_HT_LAYER` is misleading under split810:** comment added.

**Per-variant verdicts (Astra):**
- **ts200:** no loss in the honest one-time argument, and about 1.7 bits less margin in the modelled two-use case. Its own numbers: median 55.25 → 53.56, mean-probability 51.34 → 49.62.
- **prf2:** cryptographically plausible under the SHA-256 PRF / random-oracle assumption. No length-extension route found. Pair selection is consistent, including chain 42, shuffled single chains and odd height-0 subtrees. Hardware HR residue is not proven clean.
- **split810:** the layout and the active loops conform. Security is conditional on cache integrity and on seed separation.

**Where Astra thought this read was too optimistic** (all folded in above):
- changed keys are not separated keys;
- cross-format rejection is not resistance to combining signatures;
- sampled fault exponents are not universal bounds;
- source-level wipes are not complete residue evidence;
- the cache summary overstated what is computed once.

## 8. The proven bound, instantiated per variant [computed]

Added 2026-11-13 after the owner asked whether the changes alter C10's security bounds. §1–§3 checked specific attack terms. This section evaluates the bound the project has actually proved.

**What is proved.** The EasyCrypt artifact (`contracts/verification/easycrypt/c10-port`, `RAW-NUMERICAL-EUF.md`, `RAW-WRAPPER-EUF.md`) proves explicit numerical EUF bounds for C10 in a classical ideal-oracle byte game:
- `WotsPoolNumericalBound` for the ordinary game;
- `WrapperWotsPoolNumericalBound` for the FI wrapper (two signs and a verify), the shape the device runs.

Every constant in those formulas is a proved hash-call budget or a proved universe size.

**The script.** `c10v2/bound_variants.py` re-derives each constant from the parameters:
- the target sum gives the accepted-encoding count A;
- each layer's signing cost contains one subtree build, `303·2^h − 1` calls (`DomainLayerCost.ec`); the rest of the layer cost is affine in h, and the heights sum to 18 either way;
- keygen is one build of the top layer;
- the WOTS cut universe is `8 · 301 · (2^18 + 2^h_top)` (`WotsCoordinateUniverse.ec`);
- the FORS universe, the coverage term, verify's 771 calls and the accepted-call caps do not change.

**The anchor.** With v1's parameters, the script reproduces both project evaluators exactly, as rationals, term by term, at five cap pairs: `tools/wots_pool_examples.py` (ordinary and wrapper pool) and `tools/wrapper_nonnode_examples.py`. It asserts this before printing.

**Results at qr = qs = 2^16** (the project's reference caps):

| variant | ordinary bound | FI wrapper bound | terms that move |
|---|---:|---:|---|
| v1, and v2 0.3 | 4.972e-19 (2^-60.80) | 9.952e-19 (2^-59.80) | none: same constants |
| ts200 | ×1.0000 | ×1.0000 | encoding ×0.30 (better) |
| prf2 | ×1.0000 | ×1.0000 | none |
| split810 | **×1.213 (2^-60.52)** | **×1.213 (2^-59.52)** | WOTS ×1.215, FORS ×1.213, zero and prefix ×1.003 |
| all three | ×1.213 | ×1.213 | as split810, plus encoding ×0.30 |

- **ts200:** the encoding term is `min(Q²·p/2^130, n²/(2A))`. Moving T toward the mean raises A, which shrinks the second branch and grows the first. At these caps the second branch is active, so the term falls ×0.30; if the first branch were active it would rise ×3.34. Either way the term is about 10^-5 of the total. The FORS term dominates (91%).
- **split810:** the per-signature hash budget rises from 364,892 to 442,460, because the model signer rebuilds the top subtree on every signature and a 10-high subtree costs twice a 9-high one. This is proof accounting rather than a new attack: the top tree is the same fixed tree on every signature, so a proof that charged it once would tighten v1 as well. That is a proof change nobody has made, so as stated today the bound for split810 is 21% looser.
- **Range:** the bounds are informative only up to about 2^26 raw hash queries. Beyond that the coverage term exceeds 1 for every variant.

**What this does not establish:**
- The theorems are proved for v1's byte format: 32-byte seed blocks, width- and offset-based domain separation, and v1's FORS_LAST tweak sharing. For every v2 variant, 0.3 included, the table shows what the bound becomes *if* the proof ports with the same charge structure. It is not a proof about v2; porting the byte model to the one-block A7 encoding is the "re-run proofs" cost of adopting v2.
- prf2's "no constant changes" holds in the ideal model only. A port has to re-prove that the private table keeps its distribution when one oracle output supplies two secrets. Length extension lies outside the ideal model; §2 and `format_options_checks.py` B cover the real-SHA-256 condition.
- The fault-case margins (§1) and cross-format reuse (§4) are outside the bound: the theorem assumes one honest format and no faults.

## 9. Not done

- **Proofs and extraction:** no formal-verification work was re-run for any variant; §8 evaluates the proven formula with re-derived constants, which is not a proof about v2. With every flag off, the `lean_extract` test configuration passes 79/0. The Aeneas extraction itself was not regenerated after the shared-file refactor.
- The Yul variants have no per-primitive gate (the same gap as 0.3).
- prf2's DPA effect is unmeasured.
- The split810 FI trade is #1148's open decision.
- The cross-variant rule in §4 is a recommendation, not implemented.
- Register and HR residue under prf2 has not been checked on silicon.
