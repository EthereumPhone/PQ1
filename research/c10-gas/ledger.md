# C10 verifier gas ledger (Track B, #1155)

Method for every number: **callee-only** (`test/gas/C10GasBench.t.sol`: pre-encoded calldata,
raw `staticcall` after a warm-up; warm CALL 100 + verifier execution, excludes tx calldata and
caller encoding). Identical on every valid vector (361 SHA-256 calls each). "High-level" =
`gasleft()` around a Solidity `verify(...)` call, logged only for comparison with #1155.

## Baseline (0895dcc79, re-measured first-hand 2026-11-13)

| verifier | callee-only | high-level (this bench) | high-level elsewhere | runtime size |
|---|---:|---:|---:|---:|
| v1 `SPHINCsC10Asm` (deployed) | 175,205 | 176,174 | 180,761 (`SPHINCsC10Asm.t.sol` ceiling test); #1155 quoted 180,812 | 1,238 B |
| v2 `SPHINCsC10v2Asm` (0.3) | 157,585 | 158,554 | #1155 quoted 163,186 | 1,207 B |

The high-level figures differ between tests by the caller's memory state (JSON parsing grows the
caller's memory before the call), so only callee-only numbers are compared below.

Floor estimate (fixed by the format): 361 warm STATICCALLs to 0x02 (36,100) + precompile
execution (v2 30,912; v1 37,656) = 67,012 (v2) / 73,756 (v1). Interpreter overhead at baseline:
~90.6k (v2) / ~101.4k (v1), about 250 gas per hash call.

## Harness validation (before any optimization)

- Candidates == references (byte-identical); all gates green; ref v1 codehash == deployed pin
  `0x8fa670d5…`; ref v2 codehash pinned `0x07175f63…`.
- Recorder sanity: precompile calls inside reverted frames are recorded (near-misses: 1 / 148 /
  255 calls).
- Mutation controls (`mutation_controls.py all --runs 64`): 14/14 caught. `v2-count-31bit` and
  `v1-count-31bit` (count >= 2^31 hashed with the top bit cleared; such inputs are rejected
  either way) were caught by the trace comparison ("SHA-256 input #254 / #147 differs"), which a
  result-only differential cannot see.

## Experiments

Deploy profile (runs=999999, the production build; separate build dir): v1 164,847 / 1,889 B,
v2 148,387 / 1,804 B callee-only. Keeps are judged on both columns.

Phase profile (v2 ref, default profile, from the +C near-misses n0/n1/n2 and a valid KAT):
H_MSG + checks 1,042; FORS (146 hashes) + layer-0 digest + digit sum 69,055; layer-0 chains/T_43/
Merkle + layer-1 digest + sum 45,537; layer-1 rest + root compare 41,962. FORS overhead is about
40k over its 146 hashes (~275 gas per hash), the largest share.

Gas-starved precompile calls (relevant to every "write the output in place" change): a STATICCALL
to 0x02 fails only if the forwarded gas (all but 1/64 of what is left) is below the precompile
cost, at most 336 (v2 T_43) or 600 (v1 T_43). The frame then holds at most floor(g/64) <= 9 gas,
and every call site is followed by more than 9 gas of work before any RETURN/REVERT, so a failed
hash always ends in out-of-gas in both reference and candidate; stale memory never reaches a
result. Re-checked per call site after each restructure. The gas threshold between success and
out-of-gas moves, as with any optimization.

| # | experiment | verifier | callee-only before -> after (default) | deploy before -> after | size | gates | decision |
|---|---|---|---|---|---|---|---|
| E1 | SWAR digit sum: 43-iteration loop -> 3 masks + adds + 1 MUL (exactness argument + unit gate `C10DigitSum.t.sol`, 20k+5k fuzz + structured; text pin) | v2 | 157,585 -> 151,371 (**-6,214**) | 148,387 -> 142,173 (-6,214) | 1,207 -> 1,263 | gate.sh green; controls 15/15 caught + 1 stale (re-targeted) | keep |
| E1 | same SWAR digit sum, ported | v1 | 175,205 -> 168,991 (**-6,214**) | 164,847 -> 158,633 (-6,214) | 1,238 -> 1,294 | gate.sh green | keep (v1 source change: re-pins, see below) |
| E2 | in-place auth walks (H3): every FORS/Merkle node is written by the precompile (outsize 16) straight into its half of the next H preimage, chosen by the parent index bit; sibling by 16-byte `calldatacopy`; FORS roots straight into their T_13 slot; T_13 output lands on the layer-0 digest m16 field, T_43 output in the first Merkle slot, Merkle root on the next m16 (and is read back once for the root compare). Drops the xor swap, mload, N_MASK ands. | v2 | 151,371 -> 139,530 (**-11,841**) | 142,173 -> 136,965 (-5,208) | 1,263 -> 1,224 (deploy 1,860 -> 1,676) | gate.sh green (first attempt had the sibling slot at 0x30 instead of 0x20: caught at once, "SHA-256 call #2 differs: H FORS_TREE ... cp=1") | keep |
| E3 | in-place WOTS chains (H2): the chain value stays at 0x10 (seeded by a 16-byte `calldatacopy`), each step writes its output (outsize 16) over it; the A7 word is the loop variable, `+ 1<<212` per step (cp nibble, p < 7: no carry); end value copied to its T_43 slot by one mload/mstore | v2 | 139,530 -> 133,723 (**-5,807**) | 136,965 -> 131,419 (-5,546) | 1,224 -> 1,196 (deploy 1,676 -> 1,652) | gate.sh green | keep |
| E4 | unroll the FORS 11-level and hypertree 9-level walks (generated straight-line code; x = 16*index so the slot of the node at height k is `and(shr(k, x), 0x10)`; A7 = aw \| h<<212 \| (index>>h)<<201, constants folded; no loop-carried path index) | v2 | 133,723 -> 119,256 (**-14,467**) | 131,419 -> 115,410 (-16,009) | 1,196 -> 1,894 (deploy 1,652 -> 3,114) | gate.sh green | keep |

### Harness hardening after the Astra conformance review (2026-11-13, between E4 and E5)

Astra (GPT-6, read-only) on the harness: "a non-equivalent candidate can pass" — ranked holes:
(1) check-order combinations untested; (2) random garbage almost never passes FORS+C/WOTS+C, so
chain/T_43/Merkle code rarely runs on garbage; (3) mutation runner could report infra failures as
CAUGHT; (4) digit-sum text pin optional and order-insensitive; (5) ABI fuzz mostly immediate
rejects, no value calls; (6) per-primitive test asserted acceptance loosely; (7) recorder filter
by address only; (8) no deploy-profile equivalence. All eight addressed (commit bd3446ea1):
deep conditioned-garbage vectors (counts re-ground against the reference's own digest preimages;
every one must run all 361 hashes and return false), check-order cross test, value calls,
call-kind-aware recorder, exact accept/reject in the primitive gate, ordered mandatory text pin,
INFRA classification, every semantic gate also under the deploy profile with ref v1 anchored to
the deploy pin `0xfd55ec70…`. Still finite testing, not a proof; see open questions.

Fable round 2 (opcode counts from the E3 assembly): remaining FORS cost was loop control ~45,
stack shuffling ~60 (8+ live variables), A7 rebuild ~35, slot arithmetic ~35 per level; predicted
E4 at 11-14k (measured 14.5k / 16.0k deploy). Next: chain outer loop (~190/chain -> ~110),
bottom-tested chain inner loop (~1.7k), TB to 0x80 (~190), drop redundant N_MASK ands and the
per-layer `mstore(TB, pkSeed)`; v1: delete the 13/43-element copy loops (~5-6k), then port
E2/E3/E4 keeping the zero-low-half invariant (FMP byte at 0x5f, count at 0x60).

### What a v1 bytecode change breaks (enumerated after the E1 v1 keep, nothing edited)

Full `forge test` (minus test/gas): 180 passed, 2 failed, 32 skipped (fork/RPC). Failing:
`PinnedCodehashes.test_codehash_pinned_or_print` and `SPHINCsC10AsmTest.test_verifierBytecodeFrozen`
(both: runtime codehash `0x8fa670d5…` -> `0xb0f12ecc…` at E1). Also failing by design, outside forge:
`contracts/verification/scripts/check_c10_source_pin.py` (Lean `C10Source.lean` literal vs .sol
L37-230), `check_c10_transcription.py` (6 drifts vs the hand transcription `c10Program`),
`check_c10_transcription_ast.py`; behind them the Lean `parse_c10` / `execC10Asm_eq` proofs, the
Halmos/cross_validation pin (`SPHINCS_C10_ASM_CODEHASH`) and the deploy-profile pin
`0xfd55ec70…`. Downstream, the verifier is deployed by CREATE2 from its creation code
(`script/ProductionDeploy.sol`), and its address is a constructor argument of the wallet
implementation and the factory: a new verifier moves the factory address, `PROXY_INIT_CODE_HASH`
and every wallet address (firmware `proto` frozen constants, `proto/tests/negative_frozen_constants.rs`),
and the Base mainnet deployment would no longer be the reproducible build
(`DeployedBytecodeReproCheck`, skipped offline). Pre-launch this is allowed on the research branch
but is an owner decision (invariant #6 is about the same words giving the same address across
chains, which a coordinated redeploy preserves; it does change every address derived so far).
v2 is not pinned anywhere yet; its adoption already changes all of the above.

| # | experiment | verifier | callee-only before -> after (default) | deploy before -> after | size | gates | decision |
|---|---|---|---|---|---|---|---|
| E5a | chain outer loop: one 16-byte cursor for the signature value and the T_43 slot, digest shifted 3 per chain, chain A7 base +1<<218 per chain, **plus** Fable's bottom-tested inner loop (`if lt { for {} 1 {} { ...; if iszero(lt) { break } } }`) | v2 | 119,256 -> 121,442..122,372 (**+2.2..3.1k**, now digit-dependent) | 115,410 -> 120,581..121,601 | 1,894 -> 1,931 | green | **discard** (via-IR lays the rotated loop out worse; per-chain cost now depends on the number of zero-step chains) |
| E5a' | same outer-loop streamlining, inner loop left top-tested | v2 | 119,256 -> 118,073 (**-1,183**) | 115,410 -> 113,975 (-1,435) | 1,894 -> 1,894 | gate.sh green | keep |
| E5b | memory: T_k buffer 0x800 -> 0x80, 32-byte outputs 0x780 -> 0x60 (expansion 87 -> 27 words); drop three N_MASK ands whose low half the next ascending store overwrites (R, FORS secrets, FORS_LAST slot) and the per-layer `mstore(TB, pkSeed)` (S at TB is never overwritten) | v2 | 118,073 -> 117,568 (**-505**) | 113,975 -> 113,680 (-295) | 1,894 -> 1,848 (deploy 3,140 -> 3,022) | gate.sh green | keep |
| E6 | delete the 13- and 43-element copy loops: FORS roots and WOTS endpoints are written straight into a T_k buffer at 0x80 laid out as the preimage `seed \|\| adrs \|\| v_0..` and hashed in place (precompile output slot moved 0x600 -> 0x620) | v1 | 168,991 -> 161,521 (**-7,470**) | 158,633 -> 151,160 (-7,473) | 1,294 -> 1,239 | gate.sh green | keep |
| E7 | port E2+E3 (in place) to the 32-byte layout: 16-byte outputs into the top half of the value words at 0x40/0x60, siblings by 16-byte `calldatacopy`, chains in place at 0x40 with the ADRS word as loop variable (+1<<32), roots into T_13 slots, T_13 onto the digest node word, T_43 into the first Merkle word, root onto 0x40. Invariant: low halves 0x50..0x5F / 0x70..0x7F are zero; restored by `mstore(0x60, 0)` after H_msg (message) and after each WOTS digest (count) | v1 | 161,521 -> 139,852 (**-21,669**) | 151,160 -> 137,084 (-14,076) | 1,239 -> 1,219 | gate.sh green (first attempt) | keep |
| E8 | port E4: unroll the FORS 11-level and hypertree 9-level walks (x = 32*index, word = 0x40 + and(shr(k, x), 0x20); ADRS = base \| h<<32 \| index>>h) | v1 | 139,852 -> 125,269 (**-14,583**) | 137,084 -> 123,329 (-13,755) | 1,219 -> 2,068 (deploy 1,661 -> 2,478) | gate.sh green | keep |
| E9 | port E5a': chain outer loop with one 16-byte cursor (slot = TB + 0x40 + 2*cursor), digest shifted 3 per chain, ADRS base +1<<64 per chain (the old ci-insert mask was a no-op on these words) | v1 | 125,269 -> 123,829 (**-1,440**) | 123,329 -> 122,144 (-1,185) | 2,068 -> 2,067 | gate.sh green | keep |

## Batch 1 result (2026-11-13)

| verifier | callee-only (default) | deploy profile (production) | runtime size default / deploy |
|---|---:|---:|---:|
| v2 0.3 | 157,585 -> **117,568** (-40,017, -25.4%) | 148,387 -> **113,680** (-34,707, -23.4%) | 1,207 -> 1,848 / 1,804 -> 3,022 B |
| v1 (deployed format) | 175,205 -> **123,829** (-51,376, -29.3%) | 164,847 -> **122,144** (-42,703, -25.9%) | 1,238 -> 2,067 / 1,889 -> 2,453 B |

Floor (361 warm calls + precompile execution): v2 67,012, v1 73,756; remaining interpreter
overhead ~50.6k (v2) / ~50.1k (v1). After optimization v1 costs only ~6.3k (callee-only) more than
v2, against ~17.6k before: most of the old gap was interpreter overhead, not preimage length.

Final checks: `gate.sh 256` green (both profiles); fixed-seed high-count fuzz
(`FOUNDRY_FUZZ_RUNS=4000 FOUNDRY_FUZZ_SEED=0x1155c10`, all C10Equivalence fuzz tests: 4,000 runs
each of mutations / ABI encodings / raw calldata per version, deep 24 per version): all pass.

## Format-level ideas (proposals only, NOT adopted: each changes the format and a security bound)

- **Higher WOTS+C target sum (e.g. 210).** Verify chain steps per layer = 43*7 - target: 96 at
  205, 91 at 210, 86 at 215. Each step is ~230 gas after this batch (184 precompile + call, ~45
  interpreter), so 210 saves ~2.3k and 215 ~4.6k per verify. Costs: the signer grinds
  P(sum = t)^-1 digests per layer (205: 3.26e-5, 210: 8.54e-6 = 3.8x, 215: 1.95e-6 = 17x), and the
  number of valid digit vectors drops (log2: 114.1 -> 112.2 -> 110.0), which enters the WOTS+C
  bound; needs the `bound_variants.py` analysis and a review like ts200's (which went the other
  way, +3.15k verify gas). Not recommended without that analysis.
- The rest of the floor is the format: 361 hashes x (100 warm CALL + 60 + 12/word). Nothing in
  this batch touched it; only fewer or shorter hashes would.
Mutation controls on the final candidates (`mutation_controls.py all --runs 64`): 26/26 caught
(one, `v1-root-cmp`, was STALE after E7, re-targeted and caught alone with `--only`). Notable:
`v1-l1h8-sibling-32` (last sibling copied as 32 bytes, so ABI padding enters its low half) is
caught only by the trailing-junk tests; `v{1,2}-count-31bit` only by the trace comparison;
`v1-e7-zero-after-{hmsg,digest}` (the zero-low-half invariant) by 11 tests each, including the
per-primitive trace ("SHA-256 call #… differs").

### Closing checks (after the advisor's pre-handback review)

- Full `forge test` (minus test/gas) at HEAD `296a99260`: 180 passed, **2 failed**, 32 skipped —
  only the two v1 codehash pins (`PinnedCodehashes.test_codehash_pinned_or_print`,
  `SPHINCsC10AsmTest.test_verifierBytecodeFrozen`); final v1 runtime codehash `0xe7e8af11…`.
  The wallet-level suites (`PQSmartWalletRealSig`, `PQMultiOpBundle`, `ERC7562ValidationRules`,
  …) pass against the optimized v1.
- v2 consumers outside this track: `SPHINCsC10v2Asm.t.sol`, `SPHINCsC10v2Variants.t.sol` (pass;
  its "delta vs 0.3" lines now compare optimized 0.3 with the unoptimized ts200/split810/all3
  variants, so they are no longer like-for-like), and
  `research/c10-autoresearch/nearmiss_controls.sh`, which text-patches the v2 verifier's two +C
  check lines (both kept verbatim, still apply). No codehash pin. Stale line citations
  `SPHINCsC10Asm.sol:127` in `c10v2-spec.md` and the autoresearch ledger (the v1 FORS_LAST
  tweak reuse) now point elsewhere if v1 changes.
- v1 landing is a re-proof, not a re-pin: the Lean Yul model (`Interpreter/Yul.lean`) has only
  `sha256 (inOff inLen outOff)` with a fixed 32-byte output and no `calldatacopy`, so
  `parse_c10` / `execC10Asm_eq` cannot even parse the E7-E9 code without extending the
  interpreter; the Halmos/cross_validation discharge is invalidated too.
- Astra conformance review of the final snapshot (cumulative, not per keep): no divergence for
  successful precompile calls; checked every removed mask, 16-byte in-place output, the v1
  zero-low-half invariant (incl. the dispatcher's 0x80 byte at 0x5F), the unrolled levels, chain
  bounds, the SWAR sum and check order. One finding: at EVM call depth 1024 every STATICCALL
  fails without writing output, so the *attempted* (never executed) precompile inputs differ from
  the third call on (stale in-place values vs the reference's untouched output slot). Argued, not
  tested: the observable result is still identical — reference and candidate both read an
  all-zero H_MSG digest and an all-zero WOTS digest (their 32-byte output slots are never written
  and are zero there), so both revert empty at the layer-0 digit sum after the same length/key
  checks. Depth 1024 is unreachable in practice since EIP-150. Scope of the equivalence claim:
  identical (success, returndata) for all calldata at any depth with sufficient gas; identical
  SHA-256 input sequences whenever the precompile calls succeed; the out-of-gas threshold moves.
- Deep conditioned-garbage fuzz ran 24 runs per version (inline config overrides the env runs),
  plus 14 fixed cases each.

## Batch 2 (2026-11-13)

Phase profile at batch-1 HEAD (v2 cand): FORS + layer-0 digest 44,573 (floor 27,120: ~119/hash
overhead), layer 0 + layer-1 digest 36,296 (floor 19,940), layer 1 rest 35,870 (floor 19,756).
From the assembly: chain inner loop ~69 gas overhead per step (192 steps), chain outer loop
~150 per chain (86 chains).

| # | experiment | verifier | callee-only before -> after (default) | deploy before -> after | size (default / deploy) | gates | decision |
|---|---|---|---|---|---|---|---|
| B1 | chain inner loop two-step unroll (`while >= 2 left: 2 steps`, then odd step) | v2 | 117,568 -> 123,166..123,322 (**+5.6k**) | - | 1,848 -> 1,920 | bench only | **discard** (as with E5a: extra control flow inside the chain loop makes via-IR reshuffle the stack) |
| B2 | unroll the 43-chain OUTER loop: per chain one calldatacopy, a constant-offset inner loop, one slot store; generated by `gen_v2_chains.py` (block between markers, `--check` wired into gate.sh) | v2 | 117,568 -> 111,898 (**-5,670**) | 113,680 -> 107,740 (-5,940) | 1,848 -> 5,105 / 3,022 -> 10,201 | gate.sh green | keep (size: one-time deploy cost ~+1.4M gas at the deploy profile; under the 24,576 B limit) |
| B3 | port all keeps to the research variants: ts200 / split810 / all3 candidates are now **derived** from the optimized 0.3 verifier by `derive_v2_variants.py` (asserted text substitutions: target 200; kp<<23, ci<<17, chain block with ci shift 217, Merkle heights 1..8 + `if layer { 9, 10 }`, layer-dependent idxLeaf/sigOff); `--check` in gate.sh. New frozen refs `test/ref/RefSPHINCsC10v2{Ts200,Split810,All3}Asm.sol` and gate `test/gas/C10VariantEquivalence.t.sol` (KAT files, bit flips, keys x lengths, counts, trailing junk, deep conditioned garbage at the variant's target and layout, fuzz, ABI) | variants | ts200 160,735 -> **114,478**; split810 157,653 -> **112,156**; all3 160,803 -> **114,736** | ts200 151,387 -> 110,290; split810 148,460 -> 107,919; all3 151,460 -> 110,469 | ~5.1-5.2 kB / ~10.2-10.4 kB | gate.sh green (both profiles) | keep |

Per-variant deltas vs optimized 0.3 (callee-only, default): ts200 +2,580 (was +3,150 unoptimized),
split810 +258 (was +68), all3 +2,838 (was +3,218). `SPHINCsC10v2Variants.t.sol` compares like for
like again.
| B4 | chain steps as straight-line blocks of 4, 2, 1 keyed on the bits of 7 - digit = `not(d)` (Fable batch 2, idea 3), in the generated chain block; variants re-derived | v2 + variants | 0.3 111,898 -> 108,901..108,975 (**-2.9..3.0k**, now digit-dependent); ts200 114,478 -> 111,175..111,227; split810 112,156 -> 109,171..109,251; all3 114,736 -> 111,405..111,467 | 0.3 107,740 -> 104,154..104,267; ts200 110,290 -> 106,396..106,439; split810 107,919 -> 104,419..104,461; all3 110,469 -> 106,590..106,616 | 0.3 5,105 -> 10,990 / **10,201 -> 19,652** (split810 20,229; EIP-170 limit 24,576) | gate.sh green | keep, with a size flag: one-time deploy +~1.9M gas at the deploy profile, break-even after ~650 verifies; leaves ~4.3 kB under the limit, so no further code growth at the deploy profile |
| B5 | FORS/hypertree walks from two per-walk words (Fable batch 2, idea 1): `cpha` = 11 lanes of A7 bytes 5..6 (cp = h, ha = t >> h), `slots` = byte 2k+1 is the node slot at height k, each from one MUL + mask; A7 bytes 0..4 stored once per walk, per level only `mstore(0x35, shl(16(h-1), cpha))`; slot = `byte(2h+1, slots)`, sibling `0x30 - slot`. Generated by `gen_v2_walks.py`; exhaustive unit gate `C10Lanes.t.sol` (all 2,048 indices x every height); C10-LANES text pin; variants re-derived (split810: heights 1..8 + `if layer {9, 10}`) | v2 + variants | 0.3 108,901..108,975 -> **103,908..103,982** (-5.0k); ts200 -> 106,182..106,234; split810 -> 104,043..104,123; all3 -> 106,277..106,339 | 0.3 104,154..104,267 -> 100,766..100,879; ts200 -> 103,008..103,051; split810 -> 100,929..100,971; all3 -> 103,100..103,126 | 0.3 10,990 -> 11,016 / 19,652 -> **18,820** | gate.sh green | keep |

### What a user pays (B6, measurement only; `test/gas/C10WalletGasBench.t.sol`)

The wallet implementation's verifier address gets the reference or the candidate runtime code by
`vm.etch` (verifiers are stateless), so both run behind the identical wallet, calldata and
storage. Type-2 `validateUserOp` (slot key, ownerIndex 1; v1 with the Rust userOp vector, v2 with
the same userOp and a Python-reference v2 signature over the same `sphincsDigest`), and EIP-1271
`isValidSignature(bytes32, bytes)` (Solady nested EIP-712, PersonalSign) over a fixed hash with
Python-reference signatures over the wallet's nested hash (fixture
`test/gas/c10_wallet_bench_vectors.json`, `wallet_bench_sign.py`; the nested hash is read from
the recorded verifier call, not re-derived). Every measured call accepts. Gas = `gasleft()`
around the wallet call from the test (cold verifier address, as in a transaction); not included:
EntryPoint overhead and calldata, both unchanged.

| path | default ref -> cand | deploy profile ref -> cand |
|---|---|---|
| v1 `validateUserOp` | 224,690 -> 173,330 (**-51,360**) | 213,946 -> 171,254 (-42,692) |
| v2 `validateUserOp` | 206,367 -> 152,716 (**-53,651**) | 196,770 -> 149,208 (-47,562) |
| v1 `isValidSignature` | 194,906 -> 143,530 (-51,376) | 184,326 -> 141,623 (-42,703) |
| v2 `isValidSignature` | 177,286 -> 123,731 (-53,555) | 167,866 -> 120,349 (-47,517) |

The saving is the verifier's, one for one: verification gas of a Type-2 UserOp drops by ~43-48k
(deploy profile), i.e. ~22-24% of `validateUserOp`; the rest of the UserOp is unchanged.
| B7 | v1 mirror of B2 + B4 (cheap: the chain generator gains a v1 mode): 43 chains unrolled, steps in straight-line blocks of 4/2/1 keyed on `not(d)`, value word at 0x40, ADRS `wotsAdrs \\| i<<64 \\| p<<32` | v1 | 123,829 -> **115,785..115,914** (-7.9..8.0k) | 122,144 -> 112,318..112,413 (-9.7..9.8k) | 2,067 -> 11,955 / 2,453 -> 13,210 | gate.sh green | keep (v1 landing remains an owner decision; no pins/scripts/Lean touched) |

### Wallet-level numbers at the end of batch 2 (after B7), corrected for a warm verifier

The first B6 run etched the verifier code inside the measured test, which leaves the verifier
account warm (about -2.5k against a real transaction; checked: an etch-free control read 2.8k
more). The bench now etches in `setUp` (one test contract per verifier) and carries an etch-free
control contract, which agrees with the etched candidate to ~0.1k. The B6 rows above are
therefore ~2.5k low in absolute terms; their ref-to-candidate deltas are unaffected. Each figure is
ONE signature. (`PQSmartWalletRealSig`'s own bench reads ~2.1k higher than the control because it
SLOADs the `wallet` state variable inside its measured window.)

| path | default ref -> cand | deploy profile ref -> cand |
|---|---|---|
| v1 `validateUserOp` | 227,041 -> 167,731 (**-59,310**) | 216,288 -> 163,855 (-52,433) |
| v2 `validateUserOp` | 208,736 -> 155,091 (**-53,645**) | 199,143 -> 151,587 (-47,556) |
| v1 `isValidSignature` | 197,336 -> 138,015 (-59,321) | 186,768 -> 134,286 (-52,482) |
| v2 `isValidSignature` | 179,716 -> 126,161 (-53,555) | 170,308 -> 122,791 (-47,517) |

At the deploy profile a Type-2 UserOp's `validateUserOp` costs ~24% less gas than with the
reference verifier; the signature bytes (calldata) are unchanged.

### Gas is now digit-dependent: sample spread, not a bound

Since B4 the verifier cost depends on how many 4- and 2-blocks the chains take. The min..max
ranges in this ledger are spreads over the KATs (6 for v2, 4 for v1). `gas_bound.py` fits gas =
a + b n4 + c n2 to the per-vector gas (`C10GasBench.test_gas_per_vector`) and evaluates it over
every (n4, n2) reachable with the fixed step sum; the fits are NOT exact (and at the deploy
profile have implausible signs), so the extremes are estimates only: default v2 ~103.6k..104.4k,
v1 ~115.4k..116.5k; deploy v2 ~100.5k..101.2k, v1 ~112.0k..112.9k, i.e. within ~0.5k (~0.5%) of
the samples. A `verificationGasLimit` margin of a few thousand gas covers it; a rigorous bound
would need a per-block cost read from the bytecode.

### Size against gas, per step (deploy profile, v2 0.3)

| step | runtime size | callee gas |
|---|---:|---:|
| batch 1 end | 3,022 B | 113,680 |
| B2 unrolled chain loop | +7,179 B -> 10,201 | -5,940 |
| B4 4/2/1 blocks | +9,451 B -> 19,652 | -3,473..-3,586 |
| B5 cpha/slots walks | -832 B -> 18,820 | -3,388 |

B4 is the step to drop if deploy size matters (it buys the least gas per byte). split810/all3 sit
at 19,272 B; EIP-170 allows 24,576 B.

## Batch 2 result

| verifier | callee-only (default) | deploy profile | runtime size default / deploy |
|---|---:|---:|---:|
| v2 0.3 | 117,568 -> **103,908..103,982** (ref 157,585: -34%) | 113,680 -> **100,766..100,879** (ref 148,387: -32%) | 1,848 -> 11,016 / 3,022 -> 18,820 B |
| v2 ts200 | (unoptimized 160,735) -> 106,182..106,234 | 151,387 -> 103,008..103,051 | 11,016 / 18,820 B |
| v2 split810 | (157,653) -> 104,043..104,123 | 148,460 -> 100,929..100,971 | 11,466 / 19,272 B |
| v2 all3 | (160,803) -> 106,277..106,339 | 151,460 -> 103,100..103,126 | 11,466 / 19,272 B |
| v1 | 123,829 -> **115,785..115,914** (ref 175,205: -34%) | 122,144 -> **112,318..112,413** (ref 164,847: -32%) | 2,067 -> 11,955 / 2,453 -> 13,210 B |

Gas is now slightly digit-dependent (straight-line step blocks), hence the min..max ranges over
the KATs. Size: the deploy-profile v2 runtime is within 5.3 kB (split810 5.3 kB) of the EIP-170
limit of 24,576 B; further code growth at the deploy profile must be checked against it.

Astra conformance review of the cumulative batch-2 code (snapshot of v1, v2, split810 candidates
+ references + generators): no divergence when precompile calls succeed. It checked the generated
blocks against their generators, every chain index x digit (positions digit..6 in order, ADRS/A7
fields, no carries, split810 ci<<17), the cpha/slots words exhaustively (all 2,048 indices, all 11
heights), every H preimage byte through the walks (A7 bytes 0..4 survive; the 0x35 store spills
only to unused scratch up to 0x54), root slots, the split810 offsets (layers 2336/3156, counts
3024/3844, auth 3028/3848), check order and returndata; it reports 344 full controlled-digest
traces per pair compared byte by byte. Its only finding is the batch-1 depth-1024 case (attempted,
never executed precompile inputs differ from the third call on; both versions revert empty), which
it confirms was already present in the batch-1 candidates.

Fable end-of-batch-2 estimate of the remaining v2 overhead (deploy, ~33.8k): call args + pop ~7.6k
(irreducible), per-chain fixed cost ~12k, walk levels ~8.5k, chain step ADRS stores ~2.9k, FORS
per-tree setup ~2.3k, the rest ~1.2k; realistic batch-3 headroom ~3-4k for v2.

Batch-2 closing checks: mutation controls `all --runs 64` (now scoped per verifier to its
semantic suites, gas benches excluded) **36/36 caught**, incl. 4 on the derived variants
(ts200 target, split810 layer-1 levels and section offset, all3 ci position) and the pin-only
`v2-b5-lanes-pin` (an unused-bit change of the cpha constant, semantically equivalent, caught by
the C10-LANES text pin). Fixed-seed fuzz (`FOUNDRY_FUZZ_RUNS=4000 FOUNDRY_FUZZ_SEED=0x1155c10`) of
every non-deep fuzz test in C10Equivalence and the three C10VariantEquivalence suites: all pass
(deep: 24 per version; the variant suites' inline `runs = 16` is not applied to the inherited
test, so their deep fuzz ran 256 per gate run). B1/E5a show via-IR stack layout can reverse a
paper saving, so every idea is measured.

Ranked next hypotheses (Fable, end of batch 2; v2 headroom ~3-4k): (1) byte-wise chain ADRS
(`mstore8` of ci once per chain, of cp per step; the 1-block is always cp 6) ~1.5-2k and ~6-7 kB
smaller at the deploy profile; (2) block tests on `d` with `iszero` instead of `not(d)` ~0.75k;
(3) sibling slots as their own BYTE lanes in `slots` ~0.75k; (4) FORS loop strength reduction
~0.3k; (5) 12-tree FORS unroll ~0.6-1k for +4-5 kB (size-limit risk; only after (1)). v1: BYTE
slots for both destinations ~3k (top), byte-wise chain ADRS ~1.5k, `d` tests ~0.75k.
Full `forge test` (minus test/gas) at the end of batch 2: 180 passed, 2 failed, 32 skipped — the
same two v1 codehash pins only (v1 runtime codehash now `0x9ac7abc2…`); `SPHINCsC10v2Variants`,
`SPHINCsC10v2Asm.t.sol` and the wallet suites pass. No pin, source-pin or transcription script,
Lean file, factory or deployment constant was edited.

Coverage notes. Astra's batch-2 review read v1, v2 and split810; ts200 and all3 rest on the
derivation check (`derive_v2_variants.py --check`) and their own equivalence suites. The three
variant references are byte copies of the 0895dcc79 variants (diff = contract name only), with
no codehash anchor. The 12-tree FORS unroll was not attempted (Fable: -0.6..1k for +4-5 kB, a
size-limit risk). The depth-1024 argument still holds for the batch-2 code: the
`mstore(0x35, ...)` spill ends at 0x54, below the digest slot at 0x60, so reference and candidate
both read an all-zero digest and revert empty (argued, not tested).

Track A's `research/c10-autoresearch/variant_controls.sh` text-patches the variant verifiers. Its
`shl(17, i)` patches (row "ci shift 17->18" and the combined "(9,9) layout" row) no longer apply:
the chain index is now a per-chain constant `shl(217, N)` in the generated block, so those rows
would report "mutation did not apply". Its other patches (`shl(23, i))`, `shl(23, idxLeaf)`,
`let hl := add(8, shl(1, layer))`, the target-sum and FORS+C revert lines) still apply once. Not
edited here.

## Batch 3 (2026-11-13): deploy size is part of the objective

| # | experiment | verifier | callee-only before -> after (default) | deploy before -> after | size default / deploy | gates | decision |
|---|---|---|---|---|---|---|---|
| C1 | byte-wise chain A7 (Fable): `mstore(0x20, chainA)` once per layer; per chain `mstore8(0x24, ci<<2)` (split810: `or(kb, ci<<1)`, kb = kp bit 0 in byte 4); per step `mstore8(0x25, cp<<4)` with cp from position algebra (4-block at digit, 2-block at digit \\| 4, 1-block always 6); no `a` word | v2 + variants | 0.3 103,908..103,982 -> **101,296..101,466** (-2.5k); ts200 -> 103,554..103,624; split810 -> 102,041..102,133; all3 -> 104,161..104,217 | 0.3 100,766..100,879 -> 100,282..100,452 (-0.4k); ts200 -> 102,540..102,610; split810 -> 100,990..101,082; all3 -> 103,110..103,166 | 0.3 11,016 -> 9,979 / **18,820 -> 10,715** (split810 19,272 -> 11,298) | gate.sh green | keep (-8.1 kB deploy) |
| C2 | chain block tests `if iszero(and(d, bit))` instead of `if and(nd, bit)` with `nd := not(d)` (Fable) | v2 | 101,296..101,466 -> 102,058..102,228 (**+0.76k**) | 100,282..100,452 -> 101,044..101,214 (+0.76k) | 9,979 -> 10,151 / 10,715 -> 10,886 | bench only | **discard** (solc keeps the ISZERO and the stack layout gets worse) |
| C3 | sibling slots as their own bytes of `slots` (Fable): `slots = sbit + C - (sbit << 8)` puts 0x30 - slot in the even byte of each lane, so a level reads its sibling slot with one BYTE (exhaustive unit gate extended to the sibling bytes) | v2 + variants | 0.3 101,296..101,466 -> **101,126..101,296** (-170); ts200 -> 103,384..103,454; split810 -> 101,858..101,950; all3 -> 103,978..104,034 | 0.3 100,282..100,452 -> 100,022..100,192 (-260); ts200 -> 102,280..102,350; split810 -> 100,765..100,857; all3 -> 102,885..102,941 | 9,979 -> 10,063 / 10,715 -> 10,830 (+115 B) | gate.sh green | keep (small; ~2.3k gas per kB) |
| C4 | FORS loop strength reduction (Fable): running `dg` (digest >> 11 i), `base` (+1<<24 per tree), secret / auth-path / T_13-slot pointers; the loop ends on the slot pointer; split810 re-derived (kp step 1<<23) | v2 + variants | 0.3 101,126..101,296 -> **100,637..100,820** (-0.48k); ts200 -> 102,900..102,978; split810 -> 101,347..101,437; all3 -> 103,466..103,522 | 0.3 100,022..100,192 -> **99,509..99,680** (-0.51k); ts200 -> 101,766..101,836; split810 -> 100,254..100,344; all3 -> 102,373..102,429 | 10,063 -> 10,049 / 10,830 -> 10,816 | gate.sh green | keep |

### Track A's `variant_controls.sh`, re-targeted on this branch (item 2)

Every patch applies again to the mechanically derived variants and every row is as expected (22
rows, `PASS`, files restored): kp FORS `base := add(base, shl(23, 1))` -> 24; kp hypertree
`shl(23, idxLeaf)` -> 24 (unchanged); ci 17->18 now rewrites the 43 per-chain `mstore8(0x24,
or(kb, 2i))` sites (asserting 43); layer heights (8,10)->(9,9) now sets `hl := 9` and swaps the
generated split810 hypertree walk for the 0.3 one (via `gen_v2_walks.py`). The stacked row
still turns split810 into exactly the 0.3 verifier (accepts all 6 0.3 KATs). Merge note:
Track A's branch `research/c10-autoresearch` has no commit touching this script or the variant
verifiers since `0895dcc79`, so there is no textual conflict today; but the script now targets
the derived variants and imports `research/c10-gas/gen_v2_walks.py`, so taking it without this
branch's verifiers breaks it, and any later Track A edit to the script or the variants will
conflict with this branch.

### Size-vs-gas menu (v2 0.3; `build_options.py`, every option passes the v2 equivalence, per-primitive and lanes gates)

Options differ only in the generated chain block (walks as committed after C4). Gas over the 6
KATs; constant where the steps are a loop.

| option | callee gas default | callee gas deploy | runtime default | runtime deploy | gas per kB vs the next smaller |
|---|---:|---:|---:|---:|---|
| batch-1 end (E5b), reference point | 117,568 | 113,680 | 1,848 | 3,022 | — |
| `rolled`: one loop over the chains, byte-wise A7, step loop | 108,565 | 108,049 | 1,931 | **2,179** | — |
| **`no-blocks`: chains unrolled, byte-wise A7, step loop (HEAD after C5)** | **102,633** | **102,123** | 4,434 | **4,683** | -5.9k for +2.5 kB (2.4k/kB) |
| `last-step`: as no-blocks, last step straight-line | 102,349..102,418 | 101,839..101,908 | 5,789 | 6,038 | -0.25k for +1.4 kB (0.2k/kB) |
| `head` (C4): chains unrolled, straight-line 4/2/1 blocks | 100,637..100,820 | 99,509..99,680 | 10,049 | 10,816 | -2.6k for +6.1 kB (0.4k/kB) |
| batch-2 end (B5): blocks with full A7 words | 103,908..103,982 | 100,766..100,879 | 11,016 | 18,820 | dominated |
| reference | 157,585 | 148,387 | 1,207 | 1,804 | — |

The straight-line step blocks (B4) buy the least gas per byte (0.4k gas per kB; a lean rework,
`last-step`, does worse at 0.2k/kB). Following the batch-3 objective, C5 drops them from the
committed candidate; `head` stays one generator call away (`gen_v2_chains.block_bytes`) for an
owner who prefers -2.6k gas per verify over 6.1 kB of deploy bytecode (one-time ~1.2M gas).

| # | experiment | verifier | callee-only before -> after (default) | deploy before -> after | size default / deploy | gates | decision |
|---|---|---|---|---|---|---|---|
| C5 | drop B4: chain steps as a loop over the cp byte (`no-blocks`); variants re-derived | v2 + variants | 0.3 100,637..100,820 -> **102,633** (+1.9k, constant); ts200 -> 105,183; split810 -> 103,289; all3 -> 105,839 | 0.3 99,509..99,680 -> **102,123** (+2.5k); ts200 -> 104,673; split810 -> 102,781; all3 -> 105,331 | 10,049 -> **4,434** / 10,816 -> **4,683** (split810 4,843) | gate.sh green | keep (size objective; gas digit-independent again) |
