# C10 verifier gas ledger (Track B, #1155)

Method for every number: **callee-only** (`test/gas/C10GasBench.t.sol`: pre-encoded calldata,
raw `staticcall` after a warm-up; warm CALL 100 + verifier execution, excludes tx calldata and
caller encoding). Identical on every valid vector (361 SHA-256 calls each). "High-level" =
`gasleft()` around a Solidity `verify(...)` call, logged only for comparison with #1155.

> **Landing note (2026-11-14, branch `land/c10-v1-proof`).** This ledger is landed with the
> relational proof of the optimized v1. Some files it describes are **not on master**; they
> stay on `research/c10-gas` (`8abd78932`):
> - the GPL EntryPoint bytecode fixture `contracts/smart-wallet/test/gas/entrypoint_v06_runtime.json`
>   (its landing is an open decision);
> - what depends on it:
>   - the wallet-path profile: `test/gas/C10WalletPathProfile.t.sol`,
>     `test/gas/c10_wallet_path_vectors.json`, `research/c10-gas/wallet_path_sign.py`,
>     `path_breakdown.py`, `path_summary.py`;
>   - the Base fee model `test/gas/C10BaseFeeModel.t.sol` (it imports the profile) and
>     `test/gas/base_fee_snapshot.json`;
>   - the batch-5 wallet shadows `test/gas/shadow/*` and `research/c10-gas/gen_shadow_wallet.py`,
>     with their steps in `gate.sh` and their mutants in `mutation_controls.py` (both are master's
>     versions here).
>
> Sections naming these files refer to that branch.

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
| D1 | v1 mirror of B5/C3 slots (cheap): one MUL per walk gives the node word (0x40 / 0x60) and its sibling word as BYTE lanes; exhaustive unit gate (`test_v1_slots_exhaustive`) + C10-LANES-V1 text pin; ADRS words unchanged | v1 | 115,785..115,914 -> **113,399..113,528** (-2.4k) | 112,318..112,413 -> 109,737..109,817 (-2.6k) | 11,955 -> 12,314 / 13,210 -> 13,590 | gate.sh green | keep |
| D2 | v1 byte-wise ADRS (cheap mirror of C1): `mstore(0x20, wotsAdrs)` once per layer, per chain `mstore8(0x37, i)`, per step `mstore8(0x3B, p)`; and, as for v2 (C5), steps as a loop (v1's straight-line blocks also buy only ~0.46k gas per kB: the bytes+blocks option measures 109,232..109,304 deploy at 12,028 B) | v1 | 113,399..113,528 -> **113,847** (constant) | 109,737..109,817 -> **111,772** (+2.0k) | 12,314 -> **5,161** / 13,590 -> **6,601** | gate.sh green | keep (size objective) |

v1 options (deploy profile): bytes + loop (HEAD) 111,772 / 6,601 B; bytes + blocks 109,232..109,304
/ 12,028 B; full ADRS words + blocks (D1) 109,737..109,817 / 13,590 B; reference 164,847 / 1,889 B.

### Wallet-level numbers at the end of batch 3 (deploy profile, cold verifier, one signature each)

| path | reference -> candidate |
|---|---|
| v1 `validateUserOp` | 216,288 -> 163,213 (-53,075) |
| v2 `validateUserOp` | 199,143 -> 152,885 (-46,258) |
| v1 `isValidSignature` | 186,768 -> 133,693 (-53,075) |
| v2 `isValidSignature` | 170,308 -> 124,044 (-46,264) |

## Closing note: where the v2 verifier stands (track B)

At HEAD (`no-blocks` build, deploy profile) a v2 verify costs **102,123** gas callee-only with a
4,683-byte runtime (reference 148,387 / 1,804 B). By phase (deploy, from the +C near-misses):
dispatch + H_MSG + checks 801; FORS + layer-0 digest 39,085; layer 0 + layer-1 digest 31,343;
layer 1 + root compare 30,905.

| component | gas | share | reducible? |
|---|---:|---:|---|
| SHA-256 precompile execution (361 calls: 60 + 12 per word) | 30,912 | 30% | only by fewer or shorter hashes (format) |
| warm STATICCALL to 0x02 (361 x 100) | 36,100 | 35% | only by fewer hashes (format) or EVM repricing |
| interpreter: CALL argument pushes + POP (361 x ~20) | ~7,200 | 7% | no (the minimum any caller pays) |
| interpreter: WOTS step loop control (192 steps x ~35) | ~6,700 | 7% | ~2.6k of it with straight-line step blocks, at +6.1 kB (the `head` option) |
| interpreter: everything else (per-chain and per-level bookkeeping, A7/ADRS bytes, sibling copies, T_k headers, digests, SWAR, ABI) | ~21,200 | 21% | < 1k left without growing code (Fable's batch-2 estimate, mostly realized by C1-C4) |

The phase figures are measured; the split of the interpreter share into rows is an estimate
(opcode counts, partly from Fable's ranking made for the blocks build). No further
semantics-preserving saving was found at this size point: the remaining ideas were estimated at
about 1k or less, and the two loop-shape attempts that lost gas (E5a, B1) were measured on the
older word-wise chain loop, not re-measured on the byte-wise one. The remaining choices are
size-vs-gas (the menu above) rather than new optimizations. v1 is in the same position
(111,772 deploy / 6,601 B; bytes + blocks 109,232 at 12,028 B).

**Format-level levers (proposals only, none adopted; each changes keys, signatures and the
security argument):**

1. **Higher WOTS+C target sum** (205 -> 210 / 215): 10 / 20 fewer chain steps per verify,
   ~-2.5k / ~-5k gas at ~250 gas per step. Cost: the number of valid digit vectors drops from
   2^114.1 to 2^112.2 / 2^110.0 (the WOTS+C term of the bound), and the signer grinds 3.8x / 17x
   more digests per layer (device signing time). Needs the `bound_variants.py` analysis and a
   review like ts200's.
2. **Smaller FORS** (one tree fewer, or one level less in every tree): 12 hashes fewer, about
   -3.1k each way. Cost: lower few-time FORS security at the same number of signatures per
   hypertree leaf; needs re-parameterizing (k, a) and redoing the FORS+C / position-binding
   analysis, plus new KATs and signer.
3. **Lower hypertree** (h < 18): 2 hashes fewer per removed level (~-0.5k), but fewer signing
   positions per key, which weakens the multi-target margin (the P14 bootstrap caveat) and the
   65,536-use caps' basis. Poor gas per unit of security.
4. **No CALL per hash** (e.g. tweakable hashes on the KECCAK256 opcode, ~30 + 6 per word with no
   100-gas CALL): would cut most of the 67k floor, but contradicts the decided "SHA-256 inside the
   PQ stack" rule (the device signs with the STM32 SHA-256 peripheral; software Keccak would make
   signing several times slower) and replaces the scheme's hash assumption. Listed for
   completeness only; not recommended.
5. Outside our control: an EVM change that prices precompile calls below the 100-gas warm access
   (or a SHA-256 opcode) would remove most of the 36,100 CALL share without any format change.

This closes the semantics-preserving v2 work: further gas comes only from a size-vs-gas choice
from the menu, or from a format decision with its security review.

Astra conformance review of the cumulative batch-3 code (v1, v2, split810 vs references): no
mismatch when the precompile calls succeed. It checked the byte-wise chain A7/ADRS (what else
writes 0x20..0x3F between the per-layer store and each step; split810's kb = 128 * (idxLeaf & 1);
all 43 chains x positions 0..6; digit 7 makes no call), the v1 0x37/0x3B bytes, the walk words
exhaustively (2,048 indices x 11 heights, both versions, incl. the sibling bytes), the
strength-reduced FORS loop (12 iterations, same per-tree offsets and addresses), the v1
zero-low-half invariant, and the generators; it reports 25,992 ordered precompile inputs over
72 synthetic-digest executions plus 3 real-SHA executions, all matching. Its qualification is
again failed-call memory semantics: if ONE precompile call failed and execution continued, the
next preimage would differ (stale reference output slot vs in-place candidate). Unchanged
argument: a single failure needs a gas-starved call, after which at most 9 gas remain and
execution ends in out-of-gas; at call depth 1024 every call fails and both versions revert empty
at the layer-0 digit sum. Not demonstrated reachable; still argued, not tested.

Batch-3 closing checks: mutation controls `all --runs 64` **44/44 caught** (incl. C1 ci/digit,
C3 sibling lanes (pin + 11 tests), C4 dg/kp, D1 sibling, D2 ci, split810 kb, all3 ci). Full
`forge test` (minus test/gas): 180 passed, 2 failed (the two v1 codehash pins; v1 runtime
codehash now `0x8b475ebe…`), 32 skipped. Every keep passed gate.sh at both profiles.

Re-checks at HEAD before handback: `build_options.py` re-run for all four options at HEAD after
making the blocks generators self-contained (`block_bytes` and `block_v1_bytes_blocks` now emit
their own `let nd := not(d)`; C5/D2 had removed it from the preambles, so `head` would not have
compiled): every option reproduces exactly (head 99,509..99,680 / 10,816 B; no-blocks 102,123 /
4,683 B; last-step 101,839..101,908 / 6,038 B; rolled 108,049 / 2,179 B; all with the reduced v2
gate green). Gate coverage per option: `no-blocks` = HEAD (full gate both profiles + variants,
44/44 controls, Astra); `head` = commit 04dc81fea (full gate both profiles + variants; Astra did
not read the byte-wise blocks); `rolled` and `last-step`: reduced v2 gate only (default profile,
64 runs, no variants) — either needs the full gate if picked. `variant_controls.sh` re-run at
HEAD: all 22 rows as expected. Fixed-seed fuzz (4,000 runs, seed 0x1155c10, all non-deep fuzz
tests of C10Equivalence and the three variant suites): pass. Gas is digit-independent again for
both v2 and v1 at HEAD (the batch-2 `verificationGasLimit` spread question no longer applies to
the committed builds; it applies to the `head` option).

## Batch 4 (2026-11-13): the rest of the on-chain cost (measurement and proposals only; no src change)

Harness: `test/gas/C10WalletPathProfile.t.sol` runs one UserOp through the **real EntryPoint
v0.6** (mainnet runtime code fetched with eth_getCode, keccak == the pinned
`0xc93c806e…`, fixture `test/gas/entrypoint_v06_runtime.json`; its ReentrancyGuard slot set to
1 as read from mainnet), the real wallet behind its ERC-1967 proxy, and real C10 signatures over
each UserOp's own `sphincsDigest` (`wallet_path_sign.py`). Scenarios: Type-2 (slot key,
`executeWithOffchainCount` to an EOA) and Type-1 rotation (bootstrap key, `addOwnerBytes`), each
fresh (nonce 0) and steady (after one earlier Type-2 op, so nonce and `slotUses` are non-zero).
Phases: `path_breakdown.py` / `path_summary.py` take each frame's gas from the `-vvvv` trace of
the measured run and the storage / LOG cost from a separate recorded run (EIP-2929/2200 rules).

**Measurement trap found and avoided:** an active `vm.startStateDiffRecording()` lowered the
measured handleOps by ~18k gas (it pre-warms accounts and slots), so the measured run uses no
recording cheatcode and the access list comes from a second test; reading the wallet before the
call (even with `vm.cool`) also warmed the implementation, so the pre-state is asserted from
known values instead. The earlier wallet benches did not record during measurement and are
unaffected.

### Type-2 `validateUserOp` + execution through handleOps (deploy profile, steady state, v2 candidate)

| phase | gas | of which storage (rule) | LOG | rest (opcodes, memory, CALL access) |
|---|---:|---:|---:|---:|
| EntryPoint v0.6 logic (handleOps + innerHandleOp) | 41,876 | 15,600 | 3,649 | 22,627 |
| wallet proxy, validation (impl-slot read, DELEGATECALL, 4.5 kB calldata copy) | 5,731 | 2,100 | 0 | 3,631 |
| wallet validateUserOp logic | 23,472 | 13,500 | 1,500 | 8,472 |
| `sphincsDigest` SHA-256 precompile execution (4 calls) | 468 | | | 468 |
| verifier (C10 verify) | 102,007 | | | 102,007 |
| wallet execution (proxy + impl + target call) | 4,561 | 300 | 0 | 4,261 |
| **EntryPoint frame = execution gas of the transaction** | **178,115** | | | |

Wallet overhead outside the verifier: 34,232 (proxy 5,731 + validation logic 23,472 + digest
468 + execution 4,561). Inside the validation logic: storage 13,500 = the 64-byte owner key
stored as `bytes` (length slot + 2 data slots: 3 cold SLOADs, 6,300), `slotUses` (cold read
2,100 + warm 100 + SSTORE n->n+1 2,900) and `offchainSigCount` (2,100); the `SlotUsed` event
1,500; the rest 8,472 includes the cold CALL to the verifier (2,600), four warm precompile CALLs
(400), the UserOperation ABI decode, the 4,008-byte argument copy into memory for the verifier
call, and the transient-storage credit. Fresh wallet (first op): +17,100 in the EntryPoint (nonce
0->1) and +17,100 in the wallet (`slotUses` 0->1).

### EIP-1271 `isValidSignature(bytes32, bytes)` (v2 candidate, default profile; wallet bench trace)

Proxy self 5,587 (impl slot 2,100 + cold impl 2,600 + copy); wallet logic 13,179 (owner key
6,300 storage; cold verifier CALL 2,600; Solady nested EIP-712 hashing and ABI ~4.3k); verifier
102,517; caller pays its own cold CALL to the wallet (2,600) and calldata.

### Type-1 rotation (deploy profile, steady, v2 candidate): EntryPoint frame 285,182

Validation logic 37,253 (storage 28,500: bootstrap key 6,300; `bootstrapUses` 2,100 + 100 +
20,000 for the first rotation, 2,900 later), verifier 102,007, execution (`addOwnerBytes`)
97,933 with storage 93,600: `isOwner[owner]` read + 0->1 (22,200), `ownerAtIndex[i]` as `bytes`
(length + 2 data slots 0->non-zero, 66,300 + the cold read 2,100), `nextOwnerIndex` (2,100 +
2,900); `AddOwner` event 2,149.

### What a Type-2 transaction costs, end to end (L1, deploy profile, steady state, one-op bundle)

`handleOps` calldata 4,964 B (v2: 909 zero / 4,055 non-zero; the signature wrapper alone is
4,128 B: 137 zero / 3,991 non-zero). EIP-2028 pricing (4 / 16 per byte).

| component | v2 reference | v2 candidate | v1 reference | v1 candidate |
|---|---:|---:|---:|---:|
| transaction base | 21,000 | 21,000 | 21,000 | 21,000 |
| calldata: signature wrapper (4,128 B) | 64,404 | 64,404 | 64,380 | 64,380 |
| calldata: rest of handleOps (836 B) | 4,112 | 4,112 | 4,112 | 4,112 |
| verifier | 148,271 | **102,007** | 164,731 | **111,656** |
| wallet overhead (proxy, validation logic, digest, execution) | 34,232 | 34,232 | 34,232 | 34,232 |
| EntryPoint v0.6 (gross) | 41,876 | 41,876 | 41,876 | 41,876 |
| refund (EIP-3529: the EntryPoint's reentrancy guard 1->2->1) | -2,800 | -2,800 | -2,800 | -2,800 |
| **net transaction gas** | **311,095** | **264,831** | **327,531** | **274,456** |
| signature calldata share | 20.7% | 24.3% | 19.7% | 23.5% |
| verifier share | 47.7% | 38.5% | 50.3% | 40.7% |

Labels: "EntryPoint frame" (gross execution, 178,115 for v2 cand) is what the trace shows; a
direct transaction does not pay the harness's cold CALL into the EntryPoint (the test-measured
"handleOps call gas" is ~2.7k higher); the 2,800 refund is invisible to `gasleft()` and is
applied at the end of the transaction (cap 20%, not binding).

- **EIP-7623 floor:** tokens = zero + 4 x non-zero = 17,129 (v2), floor = 21,000 + 10 x tokens =
  192,290; it binds only if execution gas < 6 x tokens = 102,774. Execution here is 175k-238k
  (net), so standard pricing applies; a PQ1 UserOp's own execution (EntryPoint + wallet +
  verifier, >= ~145k even at the verifier floor) keeps it above the floor in any bundle of PQ1
  ops. At floor pricing the signature alone would cost 161,010.
- **What the user is charged** (EntryPoint accounting = gas measured by the EntryPoint +
  preVerificationGas): with the eth-infinitism v0.6 SDK formula (`calcPreVerificationGas`:
  calldata of `packUserOp(op,false)` at 4/16 + 21,000 + 18,300 + 4 x (length + 31) / 32, total
  rounded as the SDK's `Math.round` does) the bundler's preVerificationGas is 107,788 (v2) /
  107,764 (v1), and the charge is v2 ref 310,204, v2 cand 263,940, v1 ref 326,640, v1 cand
  273,565 gas (deploy profile), within ~0.4% of the net transaction gas above.
- **Caveat (Astra):** the fixtures are signed for chain id 31337 (Foundry); mainnet signatures
  differ byte for byte, which moves the zero/non-zero calldata counts by a few bytes (tens of
  gas) and nothing else (the verifier's work is digest-independent since C5). "Type-1 steady"
  follows a Type-2 op, so its `bootstrapUses` write is still the first one (0 -> 1, 20,000);
  later rotations pay 2,900 there.
- **Plainly:** on L1 the signature's calldata is the second-largest item. After the verifier
  work it is 63% of the verifier's cost and 24% of the transaction; it does not dominate at
  EIP-2028 pricing. On an L2 rollup, where execution gas is cheap and the 4 kB of
  incompressible signature bytes are paid as L1 data, the signature's size is likely the
  dominant cost: that is the strongest argument for a shorter-signature format, and it would
  need the L2's own data pricing to quantify.

### Wallet-side proposals (semantics-identical; NOT implemented)

Every one of these changes the wallet implementation (or its proxy), so it moves the
implementation address, the proxy init-code hash (the firmware's frozen `PROXY_INIT_CODE_HASH`
and factory constants) and therefore **every wallet address** (invariant #6 holds again after a
coordinated pre-launch redeploy, but every address derived so far changes, and the Base
deployment would be redone). Batching them into one landing pays that cost once.

| # | change | Type-2 saving | Type-1 saving | EIP-1271 saving | touches | landing risk |
|---|---|---:|---:|---:|---|---|
| W1 | immutable-implementation proxy (implementation address in the proxy's code, no ERC-1967 slot read; the wallet has no upgrade function — checked on the compiled ABI, whose only lifecycle function is `initialize(bytes,bytes)`, and every `execute*` path uses CALL and rejects `target == address(this)`, so the slot is never written after creation) | 2,200 | 2,200 | 2,100 | factory + proxy bytecode only; no wallet logic, no counters | low-medium: proxy-detection tooling (EIP-1967 slot) and the init-code-hash constants |
| W2 | owner key packed in one slot (`pkSeed16 \|\| pkRoot16`; both are 16-byte values with zero low halves, enforced at install), `ownerAtIndex` still returns the same 64 bytes | 4,200 | 48,400 (install 44,200 + load 4,200) | 4,200 | storage layout of PQMultiOwnable (ERC-7201 struct), `StorageSlotParity` and any storage model; not the counters | medium; **edge case**: today an unset index reads as empty `bytes` and the all-zero key (0, 0) passes the N-mask check and is installable; packed, both read as 0. Identical behaviour needs either a new install rule rejecting the all-zero key (a semantic change for that degenerate key only) or a presence check against `nextOwnerIndex` (owners are append-only, so index < nextOwnerIndex means set), which costs one more cold SLOAD and halves the Type-2 saving to 2,100 |
| W3 | verifier as an internal function of the implementation instead of an external CALL | ~3,400 (cold CALL 2,600 + argument copy) | ~3,400 | ~3,400 | architecture: verifier code and its equivalence gates move into the implementation; the factory's squat-defence check needs its own copy | medium-high |
| W4 | `slotUses[i]` and `offchainSigCount[i]` in one slot (two uint128; caps are 65,536) | 2,200 | 0 | 0 | **invariant #7** code paths (`_bumpSlotUses`, `_setOffchainSigCount`, combined cap) and their invariant tests/proofs | high (per gas saved) |

**UPDATE 2026-11-13 (batch 5 §2): W1 and W2 MEASURED** on test-only shadows, differential-checked
against the frozen wallet: W1 -2,198 / -2,198 / -2,099 (Type-2 / Type-1 / EIP-1271, as estimated);
W2 in its lazy form -4,780 / -49,497 / -4,770 (more than estimated: the `bytes` copy goes too),
with no semantic change at all (the zero-key edge resolved by reading nextOwnerIndex only when
the packed word is 0); the eager presence check as written above costs 2,060 more (deploy profile).

Ranked by gas saved per unit of landing risk: W1, W2, W3, W4. All four together: about -12k
per Type-2 transaction (~4.5% of 267,631) and about -54k per rotation. Not wallet-changeable:
the EntryPoint's 41,876 (frozen v0.6; amortized only by bundling several UserOps per
transaction), `sphincsDigest`'s four SHA-256s (part of the signed format), the `SlotUsed` /
`AddOwner` events (removing them changes the observable logs), the `isOwner` write on install
(needed for the `AlreadyOwner` rule).

### v1 landing scope in Lean and Halmos (estimate only; no Lean file edited)

HEAD v1 uses constructs the Lean Yul model (`Interpreter/Yul.lean`) does not have:

- `byte` (40 sites): a new `BinOp`;
- `mstore8` (86 sites): a new `Stmt`;
- `calldatacopy` (20 sites): a new `Stmt`;
- 16-byte SHA-256 outputs (66 of 69 `staticcall`s): `Stmt.sha256` has a fixed 32-byte output,
  so it needs an output length;
- `for` loops that start at a computed value (`for { let p := and(shr(3i, d), 7) } lt(p, 7)
  { p := add(p, 1) }`, 43 sites): `forRange` only models `v := 0 .. count`;
- the program shape: the assembly interior grows from 9,285 B / 198 lines to 32,213 B /
  538 lines (unrolled chains and walks, in-place memory, MUL/BYTE slot words, a SWAR digit sum).

| file (current size) | what changes |
|---|---|
| `Interpreter/Yul.lean` (397 lines) | AST + semantics for the five constructs above |
| `Interpreter/YulParse.lean` (479) | parse them |
| `Interpreter/C10Source.lean` (295) | regenerated literal (3.5x larger) |
| `Interpreter/C10Program.lean` (272) | new transcription (~3x larger) |
| `Interpreter/C10Parse.lean` (184; 10 theorems) | `parse_c10 := rfl` re-checked on the larger source (~3 s today; stack may need raising) and the elision bridge |
| `Interpreter/Memory.lean` (235; 15) | byte-granular write lemmas (mstore8, calldatacopy, 16-byte outputs, low-half-zero invariant) |
| `Interpreter/Sha256Bridge.lean` (462; 22) | the 16-byte-output bridge |
| `Interpreter/Phases.lean` (6,325; 202), `HypertreePhase.lean` (1,227; 18), `Climb.lean` + `ClimbLoop.lean` (161; 6), `EnvFrame.lean` (101; 4) | the phase-by-phase symbolic execution is written for the old loops; most of it is rewritten for unrolled walks, unrolled chains with byte-wise addresses, and the slot/lane words (the 2,048-index lane identity and the SWAR sum become `decide`/bit-vector lemmas) |
| `Interpreter/C10Refine.lean` (614; 24) | `execC10Asm_eq`'s statement is unchanged; its proof is re-done on top of the new phases |
| `Verifier/*.lean` (8 files, ~860 lines; 38 theorems) | unchanged (spec side) |
| Python gates `check_c10_source_pin.py`, `check_c10_transcription*.py` | re-anchored; the AST checker learns the new builtins |
| Halmos `test/halmos/HalmosVerifier.t.sol` (3 rules) | unchanged rules (the length and N-mask gates are the same code); re-run, pins updated |

(**Correction 2026-11-13, batch 5 §3:** the theorem counts in this table came from a loose grep
that also counted prose; the declaration counts are Phases 195, Sha256Bridge 19, Memory 14,
C10Parse 9, EnvFrame 3, 295 on the interpreter side in all.)

About 12 Lean files and most of the ~300 interpreter theorems (Phases.lean's 202 dominate); a
multi-week proof effort. A cheaper route, also an estimate: keep the existing refinement of the
reference v1 and prove a **relational** theorem that HEAD v1 and the reference make the same
SHA-256 input sequence and the same result on every input (what the forge equivalence gate tests),
still after extending the AST with the five constructs.

Astra review of the batch-4 harness (read-only): the single-UserOp measurement is "broadly
sound as gross execution gas". Fixed after the review: (1) the user-pays table now separates the
EntryPoint frame from the harness's incoming CALL and subtracts the 2,800 EIP-3529 refund of the
EntryPoint's reentrancy guard (net transaction gas); the EIP-7623 floor is 21,000 + 10 x tokens
= 192,290 (it still does not bind); (2) preVerificationGas now rounds like the SDK's
`Math.round` over the fractional `lengthInWord` (+4 gas: 107,788 / 107,764); (3) the trace
parser now matches value-transfer frames (`fallback{value: …}`); (4) caveats on chain id 31337
and on "Type-1 steady" still paying the first `bootstrapUses` write. It confirmed the storage
rules (first-access originals, cold surcharges, SSTORE cases), the setUp/test warm-state
separation, the phase boundaries and the frame reconciliation for these scenarios, and that the
deposit charge includes the fixed 120,000 preVerificationGas of the fixture (not receipt gas).

### Measured vs attributed, and other notes (batch 4)

- **Measured:** every frame's gas (traces of runs without recording cheatcodes), the handleOps
  totals, the calldata byte counts, the deposit charge. **By rule:** the storage and LOG columns
  (from the recorded access list). **Reasoning / estimates:** the contents of each "rest"
  column, W3's ~3,400, the EIP-1271 split beyond its two frames, and the per-proposal savings.
- The execution phase measured is a zero-value call to an empty address with an unchanged
  off-chain count, so its 4,561 is a floor for real calls.
- The fresh-wallet deltas (+17,100 in the EntryPoint for nonce 0->1, +17,100 in the wallet for
  `slotUses` 0->1) are from the fresh-scenario access list (by rule), consistent with the frame
  totals (fresh 213,289 vs steady 179,089 in the default-profile traces, difference 34,200).
- **The coordinator's "~50k outside the verifier":** the wallet bench measured a first-use
  `validateUserOp` called directly from the test (152,885 - 102,123 = 50,762), which includes the
  first-use `slotUses` 0->1 write (+17,100), the test's own cold CALL into the wallet (2,600) and
  the test-side ABI encoding of the 4 kB UserOp. In steady state through the EntryPoint the
  wallet's own validation overhead is 29,671 (proxy 5,731 + logic 23,472 + digest 468), and the
  wallet's total including execution is 34,232.
- **Network use:** the EntryPoint v0.6 runtime code and its ReentrancyGuard slot were read from a
  public Ethereum RPC (three `eth_getCode` / `eth_getStorageAt` calls, no project data sent); the
  code is checked against the pinned codehash in every run. The committed fixture
  `test/gas/entrypoint_v06_runtime.json` is the EntryPoint's bytecode (GPL-3.0 source): the owner
  may accept it as a test fixture or drop it (the harness then needs a fork or a source build).
- **Lean scope caveats:** the estimate is for the committed v1 build (step loop); the `head`-style
  blocks build would also need `not`. The theorem counts are grep counts of `theorem` / `lemma`.
  The claim that the three Halmos rules pass unchanged is by reading (same gate code at the top),
  not run.
- `gate.sh 256` re-run at HEAD with the batch-4 tests included (both profiles; the `_accesses` and handleOps tests now run under deploy too): green. `git diff 3d9636153..HEAD -- contracts/smart-wallet/src` is empty.

## Batch 5 (2026-11-13): Base, W1/W2 shadows, the relational route (still no src change)

### 1. What a steady-state Type-2 UserOp costs on Base (`test/gas/C10BaseFeeModel.t.sol`)

**Parameters** (public reads only, `test/gas/base_fee_snapshot.json`): Base mainnet block
56,985,750, timestamp 1794587525 (2026-11-13); L2 base fee 5,000,000 wei (0.005 gwei); GasPriceOracle
(v1.6.0, Fjord + Isthmus + Jovian active): `l1BaseFee` 483,774,684, `blobBaseFee` 28,531,418,
`baseFeeScalar` 2,269, `blobBaseFeeScalar` 1,055,762; L1Block operator fee scalar and constant 0
(no operator fee on Base). The requests were the getters above, the latest block, and
`getL1Fee` on a seeded synthetic payload (random bytes + zeros, no project data).

**Fjord L1 data fee**, local implementation with Solady `LibZip.flzCompress` (the routine the
GasPriceOracle uses): estimatedSize = max(100e6, -42,585,600 + 836,500 x fastLzSize),
fee = estimatedSize x (16 x baseFeeScalar x l1BaseFee + blobBaseFeeScalar x blobBaseFee) / 1e12.
Checked: it reproduces `GasPriceOracle.getL1Fee` on the synthetic payload exactly
(83,490,855,674 wei).

**The transaction:** a signed EIP-1559 transaction for chain id 8453 (vm.sign) carrying the real
steady-state `handleOps` calldata: 5,080 bytes, FastLZ 4,438 bytes (v2; v1 4,439).

- **The signature is incompressible:** the 4,128-byte signature wrapper alone compresses to
  4,165 bytes (FastLZ adds framing); the same transaction with those bytes zeroed compresses to
  337 bytes. 93.5% of today's L1 data fee is the signature.
- L2 execution fee = transaction gas (net, incl. the 16/byte calldata gas: 264,831 v2 cand,
  311,095 v2 ref, deploy profile, batch 4) x L2 base fee (priority fee taken as 0).

| scenario | variant | L2 execution fee | L1 data fee | total | L1 share |
|---|---|---:|---:|---:|---:|
| today | v2 ref | 1,555.5 gwei | 175.0 gwei | 1,730.5 gwei | 10% |
| today | **v2 cand** | **1,324.2 gwei** | **175.0 gwei** | **1,499.2 gwei** | 12% |
| blob fee at its floor (1 wei) | v2 cand | 1,324.2 | 64.5 | 1,388.6 | 5% |
| blob fee x10 | v2 cand | 1,324.2 | 1,169.9 | 2,494.0 | 47% |
| blob fee x100 | v2 cand | 1,324.2 | 11,118.8 | 12,442.9 | 89% |
| L1 base fee x10 | v2 cand | 1,324.2 | 755.1 | 2,079.2 | 36% |
| L2 base fee x10 (0.05 gwei) | v2 cand | 13,241.5 | 175.0 | 13,416.5 | 1% |

(v1 today: ref 1,812.7 gwei, cand 1,547.3 gwei, L1 share 10-11%.) The L1 data fee equals the
L2 execution fee at a blob base fee of 11.4x today's (v2 cand; 13.5x with the reference).

**Signature size vs verifier gas on Base** (signature = its 16/byte L2 calldata gas + its share
of the L1 data fee; verifier = its L2 gas x L2 base fee):

| scenario | signature | verifier, candidate | verifier, reference | signature : candidate verifier |
|---|---:|---:|---:|---:|
| today | 485.6 gwei | 510.0 gwei | 741.4 gwei | 0.95 |
| blob fee at floor | 382.3 | 510.0 | 741.4 | 0.75 |
| blob fee x10 | 1,415.6 | 510.0 | 741.4 | 2.78 |
| blob fee x100 | 10,715.7 | 510.0 | 741.4 | 21.01 |
| L1 base fee x10 | 1,027.8 | 510.0 | 741.4 | 2.02 |
| L2 base fee x10 | 3,383.8 | 5,100.4 | 7,413.6 | 0.66 |

**Answer:** at today's Base parameters a user pays mostly L2 execution (88%); the signature
and the optimized verifier cost about the same (486 vs 510 gwei), and the verifier work of this
track cut the per-op fee by 231 gwei (13%). The signature's size takes over as soon as blob fees
rise: at 10x today's blob base fee it already costs 2.8x the verifier, at 100x 21x. When the L2
base fee rises instead, verifier gas stays the larger term. So both levers matter on Base, and
which dominates is a function of the blob market, not a constant.

### 2. W1 and W2 as test-only shadows, with a wallet-level differential harness

**Files (all under `contracts/smart-wallet/test/gas/shadow/`, nothing in `src/`):**
`ShadowPQMultiOwnable.sol` (the owner store with one packed word per key: `pkSeed[0:16] ||
pkRoot[0:16]`, lossless because the N-mask install rule zeroes both low halves; same ERC-7201
location and field positions, only field +2's value type changes; a HAND-WRITTEN copy of
`src/PQMultiOwnable.sol`, checked only by the differential harness), `ShadowPQSmartWallet.sol` and
`ShadowPQSmartWalletFactoryW1.sol` (GENERATED from `src/PQSmartWallet.sol` and
`src/PQSmartWalletFactory.sol` by `research/c10-gas/gen_shadow_wallet.py`: a fixed list of exact
text replacements, each required to match once, `--check` in the gate), `DiffMocks.sol` (a toy
C10 verifier and a call target), `WalletDifferential.t.sol` (the harness), `WalletShadowGas.t.sol`
(the bench). The reference is always the frozen `src/` code.

The W2 options differ only in three hooks (`_present`, `_checkInstall`, `_lockOut`):

| option | presence rule | install rule | difference from the reference |
|---|---|---|---|
| W2a | `packed != 0` | reject (0, 0): `ZeroOwnerKey` | (i) installing the all-zero key reverts; (ii) the implementation's lock-out entry `ownerAtIndex(0)` reads empty instead of 64 zero bytes (the lock-out cannot store (0, 0); it sets the same nextOwnerIndex, isOwner and AddOwner), so a toy-signed bootstrap op sent to the implementation itself is refused before the verifier (with the real C10 verifier the reference refuses it too: no one has a signature for pkRoot 0) |
| W2b | `index < nextOwnerIndex` | none | none (owners are append-only: every index below nextOwnerIndex is installed, none above) |
| W2b-lazy | `packed != 0 \|\| index < nextOwnerIndex` | none | none; nextOwnerIndex is read only when the word is 0 (unset index or the all-zero key) |

W1 (`ShadowFactoryW1`): an ERC-1167 clone of the implementation, created with the reference's
already-deployed semantics (Solady `createDeterministicERC1967`: no revert on an existing account,
`msg.value` forwarded to it, `ETHTransferFailed` otherwise); `getAddress` predicts the ERC-1167
address. Its differences: the proxy's code (so every account address and the init-code hash)
and no ERC-1967 implementation slot (proxy-detection tooling).

**The harness** (`WalletDifferential.t.sol`): system A = frozen reference, system B = shadow, both
bound to the same toy verifier (accepts `sig[0:32] == keccak256(pkSeed, pkRoot, message)`; mode
bytes make it revert or return a non-bool) so the harness can sign for any key, including the
all-zero key. A run is a random sequence (32 steps from the fuzz seed) of factory deploys
(valid / bad factory signature, wrong chain id, redeploys with value), raw proxies + initialize
(arbitrary owner bytes: the all-zero key, half-zero keys, N-mask violations, bad lengths,
duplicates), Type-1 rotations, Type-2 ops (single and batch execute, off-chain count updates
incl. non-monotonic and combined-cap edges, self calls, reverting targets), EIP-1271 (nested
PersonalSign, ERC-6492 wrapper, the legacy bytes form, the safe caller, ERC-7739 detection,
garbage), cap edges near 65,536 (the same counter slots stored on both), and misc calls
(non-EntryPoint callers, execute without validation, re-initialize, ETH, callbacks, unknown
selectors); 14% of owner keys are fresh random keys, 30% of those with one random low-half bit
set; 25% of the EIP-1271 calls run at gas price 0. Compared per call: success, return/revert
data, events, account accesses (calls, staticcalls, delegatecalls, creates, extcode reads: kind,
callee, caller, value, data, reverted, depth, balance delta, nonces) and every storage WRITE
outside the owner-key slots and the ERC-1967 slot, after B's addresses and per-system hashes are
mapped to A's. The account addresses are derived independently (CREATE2 with salt
sha256(seed || root) over the ERC-1967 or, for W1, ERC-1167 init code), each factory's getAddress
must equal them, and every account's code must be its system's proxy template.
Compared after every step on the touched account, and on every account, both implementations and
both factories every 8 steps and at the end: the public getters (nextOwnerIndex, ownerCount,
ownerAtIndex / slotUses / offchainSigCount up to nextOwnerIndex + 1 capped at 40, and at 2^128,
2^256-1 and nextOwnerIndex + 64; isOwnerBytes for every pool and fresh key; bootstrapUses,
masterPk*, entryPoint, c10Verifier, eip712Domain, the three constants, ERC-7739 detection,
balances; getAddress / addSlot0Digest / implementation / balance for the factories; not swept:
`sphincsDigest`, checked where it is used). Not compared (by design, stated in the file): storage
READS and the owner-key slots (the layout change), proxy creation code (checked against the
template instead), the wallets' precompile inputs (they hold the account address packed; the
factories' are compared), the top-level input (built per system). All steps of a run are one
transaction (the transient validation credit persists across them, identically on both sides).
A directed sequence (fixed) installs the all-zero key as bootstrap and as slot key, signs Type-1,
Type-2 and EIP-1271 with it, rotates, and redeploys through the factory with value.

**Results** (`gate.sh 256` green after the review fixes: default and deploy profiles, 256 fuzz
runs x 32 steps per option, plus the directed sequence): W1, W2a, W2b, W2b-lazy and W1+W2b-lazy: **no divergence** (W2a: only its two
documented ones, asserted by `test_w2a_documented_divergences`, and the harness checks that every
all-zero install B sees reverts with exactly `ZeroOwnerKey(64 zero bytes)`). Anti-vacuity
(`test_coverage`, 32 fixed seeds): every behaviour class the claim depends on is reached (new / existing account, the
all-zero key installed and validated, Type-1 validated + owner added, Type-2 validated + executed
+ batch, off-chain count updated, validation refused at the cap, valid nested / 6492 / legacy
EIP-1271, and the reverts AlreadyOwner, InvalidOwnerBytesLength, InvalidNMaskLayout,
OffchainSigCountNotMonotonic, CombinedSlotCapExceeded, NotFromEntryPoint, AlreadyInitialized,
SelfCallForbidden, OwnerIndexMismatch, InvalidFactorySignature). Finding on the way: the safe
caller path is dead in the wallet (`_erc1271IsValidSignature` is overridden to the nested
workflow only), so a raw-hash signature from the canonical MulticallerWithSigner is refused by
both; the harness checks that rather than counting it as coverage.

**Mutation controls (the harness must separate these from the reference):**

| control | caught by (first divergence) |
|---|---|
| naive W2, "0 means unset", no install rule (`ShadowWalletNaiveZeroUnset`) | the implementation's `ownerAtIndex(0)` getter at step 0; with that check off, random sequences (`step 5 [type1] getter ownerAtIndex`) and the directed sequence |
| naive W2, "always present" | `ownerAtIndex(nextOwnerIndex)` getter at step 0 |
| naive SIGNING path, getter right (`ShadowWalletNaiveSigningPath`: the getter uses W2b-lazy's rule, validateUserOp / EIP-1271 use "0 means unset") | NOT by a getter (asserted): `directed t1 validateUserOp: return/revert data`; random sequences `step 25 [erc1271] 1271 nested (gas price 0): return/revert data` (seed 6) |
| naive W1, reverts on an existing account (`ShadowFactoryW1NaiveRedeploy`) | `createAccount ... with value: success flag` (directed); random sequences at the first redeploy |
| 11 source mutants (`mutation_controls.py w`, 32-64 runs): W2b-lazy loses its fallback; W2b off by one (`<=`); W2a stops rejecting (0, 0); validateUserOp / EIP-1271 skip the presence check; unpacking leaves root bits in pkSeed; packing drops a byte of pkRoot; W1 keeps msg.value on a redeploy; Astra's two escapes: W1 swaps the CREATE2 salt preimage, the validation credit kept in persistent storage; and a stray storage write after the verifier sub-call (`w-credit-extra-sstore`) | all 11 CAUGHT. First divergences: getters, the exact W2a ZeroOwnerKey check, the verifier call or result in validateUserOp / EIP-1271, the value transfer in createAccount, the storage writes of the persistent credit (`t2 execute: account accesses`), and the salt swap at setUp (`B.getAddress != CREATE2 spec`; the runner now counts a failing setUp as a catch; before that fix it reported this mutant as INFRA) |

So the naive W2 is caught by the getter sweep AND, separately, by the signing-path comparisons.

**Astra review of the harness** (read-only, commit 72168574b): B (separating the naive W2) and C
(shadows faithful; W1's existing-account path matches Solady's) confirmed, D sound for
execution-gas deltas (gross call gas, not transaction fees; "add ~102k for the real verifier" is
an approximation). A: "useful bounded differential testing, insufficient as a general
equivalence gate", with two concrete escapes and four smaller holes, all addressed at the next
commit:
1. (high) a shadow keeping the validation credit in persistent storage passed (one transaction
   per run; storage not compared). Fixed: storage WRITES are now compared outside the owner-key
   slots and the ERC-1967 slot; new mutant `w-credit-persistent`.
2. (high) a W1 factory with a swapped CREATE2 salt passed (the B -> A address map was learned
   from B's own getAddress). Fixed: addresses derived independently and asserted, the factories'
   precompile inputs compared, account code checked against the system's proxy template; new
   mutant `w-w1-salt-swap`.
3. (medium) owner keys came from a 10-key pool with two fixed N-mask violations. Fixed: fresh
   random keys and random single-bit violations, swept by isOwnerBytes; indices to 40 and far
   indices; the missing constants; factory balances.
4. (medium) gas price was always 1 gwei. Fixed: 25% of EIP-1271 calls at gas price 0. NOT
   covered: a valid TypedDataSign (ERC-7739 nested typed data) signature.
5. (medium) `w-w2blazy-naive`'s anchor matched twice after the signing-path control was added
   (the runner would have reported it STALE). Fixed (contract-scoped anchor).
6. (low) W2a's exception accepted any ZeroOwnerKey payload. Fixed: exact encoding required.
7. (found afterwards, self-check) storage writes a frame makes AFTER a sub-call returns are filed
   by Foundry under a `Resume` record, which the harness skipped: a stray `sstore` after the
   verifier call passed the directed test. Fixed: writes are collected from every record
   (Resume included) in record order; mutant `w-credit-extra-sstore` now caught at
   `t2 validateUserOp`. Shadow suites re-run at 256 runs on both profiles after the fix: green.
Also adopted: the "top-level input" tag applies to delegatecalls only. Framing corrections taken:
`ShadowPQMultiOwnable.sol` is hand-written (above); "no divergence" means within the generated
sequences, not a proof of equivalence.

**Measured savings** (`WalletShadowGas.t.sol`; real EntryPoint v0.6, steady state, cold, the toy
verifier for every system so the differences are the proposals' and the absolute numbers are
NOT real-C10 numbers; deploy profile, default profile within 0-60 gas of these):

| scenario | reference | W1 | W2a | W2b | **W2b-lazy** | **W1 + W2b-lazy** |
|---|---:|---:|---:|---:|---:|---:|
| Type-2 handleOps (steady) | 79,547 | -2,198 | -4,823 | -2,720 | **-4,780** | **-6,978** |
| Type-1 rotation handleOps | 186,614 | -2,198 | -49,524 | -49,437 | **-49,497** | **-51,695** |
| EIP-1271 isValidSignature | 22,221 | -2,099 | -4,813 | -2,710 | **-4,770** | **-6,869** |
| createAccount (2 owners) | 292,732 | -25,444 | -89,402 | -89,434 | **-89,434** | **-114,878** |

Against the batch-4 by-rule estimates (W1 2,200 / 2,200 / 2,100; W2 4,200 / 48,400 / 4,200;
W2 with an eager presence check 2,100): W1 matches; W2 saves ~580 more than its two cold SLOADs
because the 64-byte `bytes` copy to memory and its length check go too; the eager W2b pays its
extra cold SLOAD (2,060 gas over W2b-lazy, deploy profile; 2,113 default). W2b-lazy is within 43 gas of W2a while keeping the
reference's exact behaviour, so W2a buys nothing: **W2b-lazy is the W2 to land**. For scale:
W1 + W2b-lazy is -6,978 on a steady Type-2 transaction of 264,831 (v2 candidate, batch 4; 2.6%),
-51,695 per rotation, -114,878 per account deployment; on Base at today's parameters (item 1)
-35 gwei of a 1,499-gwei Type-2 op (2.3%).

**Landing implications (unchanged from batch 4, now with the shadows to start from):** both move
the implementation and (W1) the proxy init code, so every wallet address, the firmware's frozen
`PROXY_INIT_CODE_HASH`, the factory constants, `StorageSlotParity` (W2: field +2's value type),
`PinnedCodehashes` and the deployment would be redone in one coordinated pre-launch change;
invariant #6 holds again after it. W2 changes no counter path (invariant #7 untouched).
Not done: W3 and W4 (kept as written proposals, per the batch brief).

### 3. The v1 relational route in Lean: scope, one notch sharper (no Lean file edited)

**Counting rule (replaces the batch-4 counts).** A declaration is a line starting
`theorem`/`lemma` (optionally `private`, optionally after an `@[...]` attribute). Batch 4 used a
loose `\b(theorem|lemma)\b` grep that also counted prose in comments: **correction (2026-11-13)**
to the batch-4 table: `Phases.lean` 195 declarations (not 202), `Sha256Bridge.lean` 19 (not 22),
`Memory.lean` 14 (not 15), `C10Parse.lean` 9 (not 10), `EnvFrame.lean` 3 (not 4),
`HypertreePhase.lean` 18 (same), `C10Refine.lean` 24 (same). The interpreter side
(`Interpreter/*.lean`, 10,752 lines) holds 295 declarations; the spec side (`Verifier/*.lean`)
29, untouched by either route.

A regex heuristic on each declaration's STATEMENT (text before `:=`) splits the 295:

| class (heuristic) | decls | proof lines | what it is |
|---|---:|---:|---|
| fragment-bound: names one of the 14 REF program fragments (`hmsgFragment`, `forsClimbBody`, `forsTreeBody`, `forsLastTreeBody`, `forsCopyBody`, `forsPhaseFragment`, `wotsDigitHashFragment`, `wotsDigitSumBody`, `wotsChainStepBody`, `wotsChainBody`, `wotsBody`, `wotsContTail`, `htClimbBody`, `htLayerBody`) or `c10Program`/`execC10Asm` | 97 | 4,979 | the symbolic execution of REF, phase by phase, and its spec connection (the longest: `ht_layer_step` 510 lines, `execC10Asm_eq` 201, `verifyHypertree_refine` 184, `fors_tree_body` 178, `wots_pkfromsig` 167) |
| interpreter / memory (mentions exec, VM, memory, holds) but no fragment | 52 | 913 | generic `execList`/`execFor` lemmas, memory algebra, REF-layout segment lemmas |
| data / spec (neither) | 146 | 2,679 | encodings (`wordOf`, `beByte`, `pad16`, ADRS `make`), bit extraction, digit sums, SHA-256 bridge |

**The relational statement.** `execHead pkSeed pkRoot message sig = execC10Asm pkSeed pkRoot message sig`
for every input of the spec signature length (the domain of the existing `execC10Asm_eq`); then
HEAD's refinement is one `rw` with `execC10Asm_eq`. A stronger variant states equality of the
ordered SHA-256 preimages too, which is exactly the forge equivalence gate's oracle.

**Common to both routes (the relational route does not save it):**

- AST and semantics in `Yul.lean`: `BinOp.byte`, `Stmt.mstore8`, `Stmt.calldatacopy`, a 16-byte
  output SHA-256 statement, loops with a computed start. Checked: all five can be NEW
  constructors (or, for the loop, a parser desugaring into `letv base start; forRange j (7 - base)`
  with `p := base + j`), so `Stmt.sha256` and `forRange` keep their signatures. Only three
  existing places case-split on the AST and gain trivial cases: `eval`'s `BinOp` match
  (`Yul.lean`), `assignsVar` and `execStmt_env_frame` (`EnvFrame.lean`, 1 theorem). Memory.lean
  gains byte-granular write lemmas (mstore8, calldatacopy, 16-byte outputs; roughly 8-12 new).
- `YulParse.lean` (no theorems): parse the new builtins.
- A second Source/Program/Parse set for HEAD: a generated literal ~3.5x the size of
  `C10Source.lean` (32 kB of assembly vs 9 kB), its transcription, and the `parse = rfl` +
  elision bridge (9 declarations today; `rfl` time on the larger source is a risk).

**Full re-proof of HEAD against the spec:** rewrite the 97 fragment-bound declarations (4,979
proof lines) for HEAD's shape (unrolled walks and chains, in-place outputs, slot words, SWAR sum,
byte-wise ADRS), some of the 52 layout-bound ones, and add data lemmas for the new encodings
(the SWAR identity, the BYTE slot decode, mstore8 ADRS = `wordOf (make ...)`, the
low-half-zero invariant): about 120-150 declarations across ~8 existing files, plus
`execC10Asm_eq`'s proof re-done (statement unchanged). The 146 data/spec declarations are reused.

**Relational route:** none of the 295 existing declarations is rewritten (REF's proof stays the
spec anchor; the three AST case splits only gain cases). New work: a two-program simulation layer
(`execList` / `execFor` congruence under a memory coupling, loop unrolling `forRange n body =
body_0; ...; body_{n-1}`, a relational SHA-256 statement lemma: same preimage bytes, outputs
stored at related places), about 15-25 declarations; and per-fragment relational lemmas pairing
each REF fragment with HEAD's code for it. REF spends about 7 declarations per fragment (main
lemma plus none / frame / mem-low companions); at 4-7 per pair over the 14 fragments that is
about 60-100 declarations in 2-3 new files. Each is easier than its functional counterpart
because it never mentions the spec (no `forsAcc`, `wotsChainAcc`, `readBitsLe` connection): it
only shows both programs hash the same bytes in the same order and store the results at
coupled places.

A staged variant follows the eight v1 commits (E1 SWAR digit sum, E6 no T_k copy loops, E7
in-place walks and chains, E8 unrolled walks, E9 chain outer loop, B7 unrolled chains in 4/2/1
blocks, D1 slots word, D2 byte-wise ADRS step loop): eight translation-validation steps, each
local to 1-5 fragments (about 18 fragment-steps, 70-120 smaller declarations), at the price of
seven intermediate source literals (from git) with their own `parse = rfl`. E1, E8, D1 are
local rewrites (a bit-vector identity, loop unrolling, a finite index decode); E6 and E7 change
where values live, so their coupling invariant is the hard part in either variant.

**Plainly:** the relational route touches no existing proof, avoids re-proving the spec
connection (the long half of Phases.lean) and composes in one line, but it is not small: about
75-125 new declarations against about 120-150 rewritten/new ones for the full re-proof, the same
AST/parser and HEAD-literal prerequisites, and no existing two-program infrastructure (every
current proof is single-program symbolic execution). My estimate of effort is 50-70% of the
full re-proof; the counts above are the firmer part, the effort ratio is judgement.

## Batch 6 (2026-11-13): the Lean side of landing the optimized v1 (relational route, step 1)

Context: the owner replaces `src/verifiers/SPHINCsC10Asm.sol` on master with the optimized v1
(batches 1-3); until the Lean model accepts it, master's A3.1 transcription lint and the v1 pins
are red. This batch starts the relational route sized in batch 5 §3. No pin test, transcription
script or A3.1 gate was edited (that wiring waits for the complete relational theorem);
`contracts/verification/extracted` and the extraction registry were not touched.

**Lean setup.** `contracts/verification/lean` has no Lake packages (mathlib-free;
`lake-manifest.json` lists none); manifest and `lean-toolchain` (v4.22.0) are identical to the
main checkout's, whose `.lake/build` was copied in. Baseline `lake build` of the unchanged
project: green (36 s with the copied artifacts). After the change the whole project rebuilds
(every Interpreter module downstream of Yul.lean, 18 modules) green in 42 s, with the SAME
warnings, and `#print axioms` of `execC10Asm_eq`, `parse_c10`, `execC10Asm_eq_parsed_source`,
`execStmt_env_frame` is unchanged.

**1. The AST extension (conservative).** `Yul.lean`: `BinOp.byte` (EVM BYTE, index ≥ 32 → 0),
`Stmt.mstore8` (one byte, value mod 256), `Stmt.calldatacopy` (blob bytes, zero past the end, the
same convention as `calldataload`), `Stmt.sha256h` (STATICCALL 0x02 with out-size 16: the first 16
digest bytes), `Stmt.forFrom v start count body` (`count - start` iterations fixed at entry);
all APPENDED, new `eval`/`execStmt` arms only, three byte-granular helpers. `EnvFrame.lean`:
`assignsVar` and `execStmt_env_frame` gain the four arms (the only existing proof touched;
statement unchanged). `YulParse.lean`: the builtins and statement shapes; the for-loop init is
now parsed as an expression (a literal 0 gives `.forRange` exactly as before, any other literal
is still rejected, a computed start needs a LITERAL count and a body that does not assign the
loop variable, checked by a fuel-based `assignsIn` so the parse stays kernel-reducible);
`parseYulFuel` with `parseYul = parseYulFuel parseFuel` by `rfl`. `parse_c10` re-checks by `rfl`
against the extended parser. No `not` was needed: the committed v1 build uses
`add/mstore/and/mstore8/staticcall/shr/or/shl/calldataload/mload/lt/byte/calldatacopy/eq/mul/
iszero/revert/return/sub`.

**2. The HEAD literal.** `C10HeadSource.lean` (lines 37-570 of the optimized `.sol`, byte-exact,
32,184 bytes; **correction 2026-11-13, batch 7**: first written here as 32,213, the batch-4 size of a slightly different span; the `#guard` in the file says 32,184) and `C10HeadProgram.lean` (its AST, 32 top-level statements, 403 in all), both
generated by `research/c10-gas/gen_lean_head.py` (`--check`); the AST is printed by the same
parser (`research/c10-gas/lean/PrintHead.lean`). `parse_c10_head : parseYulFuel headFuel
c10HeadSource = some c10HeadProgram` by `rfl` (fuel 65,536; the default 16,384 is too small for
the larger source): kernel-checked in about 10 s, no axioms. What it does NOT give: an
independent transcription check (the reference has one: the hand transcription `c10Program`
vs `parse_c10`); it pins the literal to the source, so the relational proofs are about the
exact optimized source.

**3. Relational pilot E1 (`RelE1.lean`, generated by `research/c10-gas/gen_rel_e1.py`).**
- `swar_digitSum` (every `x : Nat`): the optimized v1's two-statement SWAR digit sum, evaluated
  as the interpreter does (add/mul mod 2^256), equals the reference's 43-term fold
  `Σ_{ii<43} (x >>> 3·ii) &&& 7`. The proof:
  - per-lane digit fields (`and_split`, `and_m7`, by testBit extensionality);
  - the three lane fields' bounds (`laneLow_lt`);
  - shifts and masks normalized to `x / c % 8`;
  - `swar_lanes`, over 43 digit variables, uses `omega` for the identities;
  - `lane_extract` reads lane 14 out of the product via an explicit split `A + 2^126·(Σ + 512·H)`, `A < 2^126`.
- `e1_digitSum_rel`: from two VMs that agree on `d`, the reference fragment (`let digitSum := 0` +
  the 43-iteration loop) and the optimized fragment (`let lanes`, `let digitSum`):
  - both fall through and keep memory;
  - they bind the SAME `digitSum`;
  - each changes no other variable than `digitSum` and its own scratch (`ii` / `lanes`).
  `ref_digitSum_pin` / `head_digitSum_pin` tie both fragments to statements 11-12 of the
  respective layer loops by `rfl`.
- Axioms: `swar_digitSum`, `e1_digitSum_rel`: [propext, Classical.choice, Quot.sound] (the same
  as `execC10Asm_eq`); the pins none. No `sorry`, no `native_decide`/`bv_decide`.
- Cost, measured: 16 theorems + 7 defs, 321 lines (85 of them the two generated arithmetic
  statements), 2.5 s to check. One trap on the way: a 43-variable `omega` bound inside
  `swar_lanes` ran past 20 minutes; bounding the three lane fields BEFORE the digit expansion
  (`laneLow_lt`) took it to 2 s.

**4. Sizing the rest with the pilot's numbers (replaces the batch-5 estimate where they differ).**

| | reference (`c10Program`) | optimized (`c10HeadProgram`) |
|---|---:|---:|
| statements, all nesting levels | 116 | 403 |
| mstore / mstore8 / calldatacopy | 31 / 0 / 0 | 131 / 86 / 20 |
| SHA-256 calls: 32-byte / 16-byte output | 9 / 0 | 2 / 67 |
| loops: forRange / forFrom | 9 / 0 | 2 / 43 |

E1 relates 2 of the 403 optimized statements to 2 of the 116 reference ones.
- **Env-only fragments: the two routes cost the same.** The cheapest proof went THROUGH the
  reference's existing spec-level lemma (`wots_digit_sum`): the optimized fragment is
  characterized against the same spec value (`digitSum (extractDigits d)`), and the relation
  follows. That is also what a full re-proof would do for this fragment.
- **Where the routes differ:** in the memory-coupled fragments, which E1 does not exercise.
  - E6 (no T_k copy loops) and E7 (in-place 16-byte outputs) move every node to a different
    address.
  - B7/E9/D2 (43 unrolled chains as `forFrom` step loops with byte-wise ADRS) and E8/D1 (unrolled
    FORS and Merkle walks with BYTE-selected slots) sit on top of that layout.
- **What remains, measured per fragment pair.** The pilot spent 8 declarations and about 130
  lines on one fragment pair's wrapper (2 fragment defs, 2 pins, 2 value defs, a memory lemma,
  the relational theorem), plus 12 declarations / about 160 lines on its closed-form identity.
  - Thirteen reference fragments remain.
  - Two more closed-form identities are certain: D1's slot decode and D2's byte-wise ADRS.
  - Total: at least 105 wrapper declarations (about 1,700 lines) + about 25 arithmetic ones (about
    320 lines), i.e. **at least 130 declarations / 2,000 lines before any memory coupling.** That
    is already above the batch-5 relational estimate (75-125), so that estimate was low.
  - The coupling invariant for E6/E7 is not measured. Neither is the kernel/elaboration time of
    relating the 43 chains and 67 in-place hashes (E1 took 2.5 s, but touches no memory).
- **What decides the route:** the coupling cost. The next pilot should be ONE WOTS chain:
  - the reference's `wotsChainStepBody` loop over a 32-byte padded value;
  - against the optimized `forFrom` step loop: `mstore8` cp byte, `sha256h` written in place at
    0x40.
  It exercises mstore8, sha256h, forFrom and the layout coupling together. Its cost times 43
  (made uniform by a parametric lemma over the generated template) and the walk analogues will
  give the real total.

## Batch 7 (2026-11-13): merge with master, the batch-6 review closed, the WOTS-chain pilot

**0. Merge.** `origin/master` (`e4a1127e7`: Track B at `3d9636153` with the optimized v1 in
`src/`, plus the FV re-extract/re-prove) merged into `research/c10-gas` without conflicts.
Master's only changes to the track's files were comment lines: slither annotations in the
split810/all3 variants and the matching replacement in `derive_v2_variants.py`.
- `gate.sh 256`: green. The GAS / SIZE lines are unchanged from before the merge:
  - default profile: v1 113,847 gas / 5,161 B, v2 102,633 / 4,434;
  - deploy profile: v1 111,772 / 6,601, v2 102,123 / 4,683; ts200 104,673, split810 102,781.
- `derive_v2_variants.py --check`: exit 0.
- `research/c10-autoresearch/variant_controls.sh`: PASS, and its restore check reports the
  variant files unchanged. The tree showed no `src/` changes before the next commit.

**1. The batch-6 Astra review, item by item** (its verdict: conservativity FAILED literally at the
parser boundary; old-fragment execution unchanged).
- **P2-1, closed.** `mstore8 := 1` and `calldatacopy := 1` parsed to `.setv` before the
  extension and to `none` after it. The two statement branches now fire only when the next token
  is `(` (`nextIsLParen`); everything else falls through to the old assignment branch.
  Regression `#guard`s added for `mstore8 := 1`, `calldatacopy := 1` and `let x := byte`.
- **P2-2, closed.**
  - The `.forFrom` branch now also requires its literal count to be `< 2^256`; `#guard`s check
    that `2^256` is rejected and `2^256 - 1` accepted.
  - The `forFrom` comment in `Yul.lean` now states the correspondence on explicit premises:
    word-valued inputs and literals (`eval … start < 2^256`, since the interpreter does not
    reduce every expression mod 2^256), a body that does not assign `v`, correct lexical scope,
    and equality on observable state only, as for `forRange`. The loop driver is unchanged.
- **The re-review** of the fix (Astra, uncommitted diff) found:
  - A: PASS. Old-fragment conservativity holds by branch analysis, corroborated by 607 targeted
    inputs, 466 old-accepted programs and 35,829 parser/fuel pairs with zero differences.
  - B: PASS. The `k < W` check guards only `.forFrom`.
  - C: the premise wording was fixed as above.
  - D: the `YulParse.lean` header still described only the 32-byte staticcall and zero-start
    loops; it now lists the extensions.
- **Recorded, not changed:**
  - The cross-revision guarantee rests on the branch analysis and the probes. `rfl` and the
    rebuild check the CURRENT definitions; there is no mechanized theorem "old parser accepts ⇒
    new parser gives the same result".
  - Generic `Stmt` theorems now quantify over a larger type; their restrictions to old programs
    are unchanged.
  - `parse_c10_head` pins the literal to the source. It is not an independent transcription
    check: a shared parser mistake would survive both generating and checking the literal.
  - All 20 `calldatacopy` reads fall inside the 4,008-byte signature, so trailing calldata
    cannot reach them: FORS `[224, 2336)`, Merkle `[3028, 3172)` and `[3864, 4008)`.
  - For the later whole-program theorem: execute the actual `c10HeadProgram` from the
    reference wrapper's inputs and initial memory; establish the zero-suffix invariants it
    relies on; compare verdicts and relevant state, covering rejecting inputs; and keep
    source/EVM correspondence separate from equality of the two Lean executions.

**2. The WOTS-chain pilot (`RelChain.lean`; spec-free, memory-coupled).**
Scoped with the advisor first. The criterion was that the pilot must not re-measure E1: no
`Spec.*` term, no reference spec lemma (`wots_chain_step` / `wots_chain_body` unused), and an
ARBITRARY hash oracle `sha`. All three hold.

How the two chains differ:
- **Reference** (`wotsChainBody`, loop var `i = c`): the chain value is the variable `val`. Each
  step writes the full ADRS word to `0x20` and `val` to `0x40`, hashes `[0,0x60)` into `0x600`
  and masks the result back into `val`. The endpoint is stored at `0x80 + 32c`.
- **Optimized** (`chainBlock c`): the value lives in memory at `0x40`. The ADRS word at `0x20`
  is patched byte-wise (ci at `0x37`, cp at `0x3B`), and each step hashes in place
  (`sha256h … 0x40`). The endpoint is stored at `0xC0 + 32c`.

The coupling `StepRel`: the same seed bytes; the optimized ADRS bytes are `wotsAdrs`'s apart from
bytes 23/27; HEAD's 32 bytes at `0x40` are the bytes of the reference's `val`, whose low half is
zero; frames.

Proven, in build order:
- `adrsOf_byte`: if `wotsAdrs` has zero bytes 23..26, the reference's per-step ADRS word is
  `wotsAdrs` with byte 23 = chain index and byte 27 = position, which is exactly the two
  `mstore8` patches. `wotsAdrs_zero_field` discharges the hypothesis for the
  `or(shl(224,layer), or(shl(160,idxTree), shl(96,idxLeaf)))` both programs build, with fields
  in range.
- `chain_step_rel`: one reference step and one optimized step hash the SAME 96 bytes and
  re-establish `StepRel`.
- `execFor_rel` (generic): two loops in lock-step, the second offset by `off`.
- `chain_block_rel`: the whole reference chain body against `chainBlock c`, for any `c < 43`.
  - Both fall through and store the same 32 bytes (`0x80+32c` vs `0xC0+32c`).
  - The low-memory coupling is re-established, the rest is framed, and every variable outside
    each side's scratch keeps its value (added after an advisor review).
  - So the hypotheses for chain `c+1` hold again. The 43-fold COMPOSITION itself is not proven.
- `head_chainBlocks_pin`: the optimized layer loop's statements 16..187 ARE
  `(List.range 43).flatMap chainBlock`, so one template covers all 43 chains.
  `ref_chainLoop_pin`: the reference's statement 15 is `forRange "i" 43 wotsChainBody`. Both by
  `rfl`.

Axioms, printed from the file for all 30 theorems: each is a subset of [propext,
Classical.choice, Quot.sound], the same set as `execC10Asm_eq`. The pins and `writeBytes_get`
use none. No `sorry`. The whole project builds green.

**Spec-free, checked by grep**: no spec function or spec lemma (`Spec.` appears only in the
docstring; the only spec import is the `ByteVec` type), no `c10Oracle`, an arbitrary `sha`.
Constructs a proof now exercises: `mstore8`, `sha256h`, `forFrom` (here) and the env-only SWAR
fragment (E1); `byte` and `calldatacopy` are not exercised by any proof yet.

**Measured cost**: 30 theorems + 7 defs, 592 lines, 1-4 s to check.
- One-time infrastructure, reusable by every later fragment: about 13 theorems / 100 lines
  (byte-granular write lemmas, slice congruence, small-byte and UInt8 lemmas, the lock-step
  loop lemma).
- Per fragment (the WOTS chain): about 17 theorems + 7 defs / 470 lines.
- Coverage: the chain template is 258 of the optimized program's 403 statements (43 x 6), and it
  replaces 10 reference statements.

What the pilot does NOT cover yet:
- composing the 43 blocks against the reference's `forRange "i" 43` (a generic loop-vs-unrolled
  lemma plus env frames for `d`/`wotsPtr`/`wotsAdrs`/`N_MASK`/`OUT`/`TB`);
- the one `mstore(0x20, wotsAdrs)` before chain 0.

**Like-for-like, the same fragment in the reference's own proof.** Phases.lean's chain-specific
declarations (matched by name: chain bodies, step loop, frames, ADRS and chain-hash bridges) come
to 38 declarations / 1,009 lines. Without the outer 43-iteration composition (4 declarations /
138 lines) that is 34 / about 870 lines for ONE chain against the spec. The relational pilot does
the same chain in 24 per-fragment declarations / about 470 lines, plus shared infrastructure of 13
/ about 100. So, per fragment, the relational route is about 55% of the reference's line count and
70% of its declarations. A spec re-proof of the optimized chain would need at least the
reference's 870 lines, plus the byte-wise ADRS and in-place-output work.

**Sizing with real numbers (replaces the batch-6 floor).**
- **Measured so far:**
  - E1 (env-only): 23 declarations / 321 lines.
  - The chain (memory-coupled): 24 per-fragment declarations / 470 lines, on 13 / 100 of shared
    infrastructure.
- **Remaining memory-coupled families:**
  - the FORS tree (leaf + 11-level walk with BYTE-selected slots, D1);
  - the FORS last tree and root compression;
  - the WOTS pk compression (E6: different buffer offset);
  - the Merkle walk (9 levels; one template, both layers);
  - the H_msg / digest / count prefix;
  - the layer-loop and top-level glue.
- **Rough total:** 6-7 more families at about the chain's cost, about 150-170 declarations /
  2,800-3,300 lines. Plus composition and glue (the loop-vs-unrolled lemmas, the layer loop, the
  top-level verdict), about 30-50 declarations / 600-900 lines. In all, about 180-220
  declarations / 3,500-4,200 lines.
- **Comparison:** this is of the same order as the reference's own fragment-bound proof (97
  declarations / 4,979 lines for a program 3.5x smaller than HEAD). It is not small.
- **What the route buys:** every new lemma is mechanical memory/byte reasoning with no spec
  bridging. The reference's spec proof is reused untouched. Check times have stayed at seconds.
- **The one family that may cost more than the chain:** the FORS and Merkle walks, where D1's
  BYTE slot decode needs a finite identity on top of the coupling.

**Review status.** Astra re-reviewed the parser fix: A (old-fragment conservativity) PASS, B (the
`k < W` placement) PASS. Its C and D doc findings (the `forFrom` premise text, the `YulParse`
header) were fixed AFTER that review and have not been re-read. `RelChain.lean` has had no
independent read of its statements yet.

**State at the end of batch 7.** `gate.sh 256` ran at the merge commit and was green with
GAS/SIZE unchanged. The later commits touch only Lean files and this ledger, and the whole Lean
project builds green. The generator checks (`gen_lean_head`, `gen_rel_e1`, `gen_shadow_wallet`,
`derive_v2_variants`) pass. The gas/size table did not move.

## Batch 8 (2026-11-13): RelChain reviewed, the WOTS phase composed, the Merkle-walk pilot

**1. Astra review of `RelChain.lean` (at `18972302d`).**
- **A: PASS.** No vacuous or contradictory hypotheses.
- **B: PASS.** Astra kernel-checked a stdin theorem deriving every hypothesis for chain `c+1`
  from `chain_block_rel`'s conclusions plus `i := c+1`.
- **C: PASS for the next chain, INCOMPLETE for later code.** Two facts were not exported:
  - the reference's seed bytes unchanged against block entry: only output-to-output seed
    equality was stated, but later optimized code reads a separate seed copy at `TB`;
  - the optimized zero padding at `0x50..0x60`, which later 128-byte Merkle hashes read.
- **D: PASS (non-vacuity).** A concrete coupled state satisfies `StepRel`; breaking one
  optimized ADRS byte or one seed byte breaks it; one executed step from the mutated states
  gives different value bytes.
- **E: the two batch-7 doc fixes are accurate.** But the `YulParse.lean` header still claimed
  to mirror the Python checker "exactly", while `check_c10_transcription_ast.py` rejects
  computed loop starts and 16-byte outputs.

Fixed:
- `StepRel` carries the reference's seed preservation.
- `chain_block_rel` exports it, and also the optimized padding at `0x64..0x80` (= `64 + k`,
  `16 ≤ k < 32`). The docstring now says exactly what is framed.
- The header now says the Python checker mirrors the pre-extension rules only.
- Astra's probe is committed as `RelChainControls.lean`: theorems `coupled`, `adrs_rejected`,
  `seed_rejected`, plus a `#guard` on the executed outputs `(true, false, false)`.

**2. The whole WOTS chain phase of one layer (`RelWots.lean`).**
- `execFor_vs_blocks` (generic, one-time): a loop against its unrolled blocks
  (`(List.range' c rem).flatMap blk`), from a per-iteration step lemma.
- `WotsInv`: the invariant between chains. It holds:
  - the variables both chain bodies read;
  - the seed coupling, the optimized ADRS bytes, and the reference's seed preservation;
  - the endpoints of the chains already done, equal byte for byte;
  - the optimized padding, once a chain has run.
- `wots_inv_step`: one chain preserves `WotsInv` and adds its endpoint (from `chain_block_rel`).
- `wots_layer_rel`: the reference's `forRange "i" 43 wotsChainBody` against the optimized
  `mstore(0x20, wotsAdrs)` + `chainBlock 0 … 42`. Both fall through, and all 43 endpoints are
  equal byte for byte (`0x80 + 32i` vs `0xC0 + 32i`). The seed stays coupled, the reference's
  seed is unchanged, and the optimized padding at `0x50..0x60` holds.
- So that the next phase can start from it, `wots_layer_rel` also exports what the phase leaves
  alone:
  - reference memory from `96` up, outside the endpoints `[0x80, 0x80+32·43)` and the hash
    output `[0x600, 0x620)`;
  - optimized memory from `96` up, outside `[0xC0, 0xC0+32·43)`;
  - every reference variable except the six the chain body assigns (`digit`, `steps`, `val`,
    `chainBase`, `step`, `i`), and every optimized variable except `p`.
- `head_wotsLayer_pin`: the optimized layer loop's statements 15..187 are exactly
  `mstore(0x20, wotsAdrs) :: (List.range 43).flatMap chainBlock`, by `rfl`. With
  `ref_chainLoop_pin` this fixes both sides in the two programs.
- Cost: 4 theorems + 1 def, 220 lines with the frames, under 1 s to check. The generic lemma is
  39 lines of it. The reference's own 43-chain composition in `Phases.lean` is 4 declarations /
  138 lines (batch 7). This step is 181 lines without the generic lemma (131%), 220 with it
  (159%). Chain plus composition, per fragment: about 650 relational lines against the
  reference's about 1,009 (64%).
- **Entry hypotheses of `wots_layer_rel`, not yet tied to the program:** `wotsPtr < 4096`;
  `wotsAdrs` bytes 23..26 zero; `d`, `wotsPtr`, `wotsAdrs` equal on both sides; the reference's
  `N_MASK` and `OUT = 0x600`; the optimized `N_MASK` and `TB = 0x80`; seed bytes `[0, 32)`
  equal. Discharging them is the layer-setup glue (the statements before each side's chain
  phase; `d` comes from the digit computation that E1 starts on).
- Axioms: `execFor_vs_blocks`, `wots_inv_step`, `wots_layer_rel`: [propext, Classical.choice,
  Quot.sound]; `head_wotsLayer_pin`: none.
- So the WOTS phase of a layer (the 173 optimized statements against the reference's chain loop)
  is ONE theorem.

**3. Merkle-walk pilot (`RelMerkle.lean`; the family expected to be hardest).**
How the two walks differ:
- **Reference** `forRange "h" 9 htClimbBody`: the node is the variable `merkleNode`. Each level
  loads the sibling with `calldataload`, writes the ADRS word, places node and sibling at
  `0x40 ^ s` / `0x60 ^ s`, hashes `[0,0x80)` into `0x600` and masks the result.
- **Optimized** `merkleBlk 0 … 8`: the node lives in a 32-byte slot chosen by the precomputed
  `slots` word. Each level copies the sibling's 16 bytes in with `calldatacopy`, writes the ADRS
  word, and hashes straight into the next level's node slot (the last level into `0x40`).

Proven:
- `slots_decode` (D1), for all 512 leaf indices × 9 levels by `decide` (3 s, axioms
  [propext]): byte `2j` of `slotsOf t` is the sibling slot `0x60 - 32·bit_j`, byte `2j+1` the
  node slot `0x40 + 32·bit_j`.
- `loadWord32_byte` / `beByte_calldataload` (one-time): `calldataload` byte-wise, matching
  `calldatacopy`.
- `merkle_slice_eq`: one level hashes the same 128 bytes on both sides. It covers both slot
  assignments, the sibling's high half from calldata, and the low halves zero.
- `ref_level_eq` / `head_level_eq`: each side's level, executed, covering both optimized block
  shapes.
- `merkle_step_rel`: `MInv h → MInv (h+1)`.
- `merkle_walk_rel`: both walks fall through, and the reference's final `merkleNode` has exactly
  the 32 bytes the optimized v1 leaves at `0x40`, the value both programs compare with the root.
  The level-9 coupling is exported too.
- Pins by `rfl`: the reference's statement 26 is `forRange "h" 9 htClimbBody`; the optimized
  layer loop's statements 198..224 are `(List.range 9).flatMap merkleBlk`.
- `merkle_walk_rel` also exports both env frames: the reference keeps every variable except the
  six `htClimbBody` assigns, the optimized blocks assign none.
- The walk's entry assumptions on the optimized slot word and ADRS base now come from the
  program:
  - pins by `rfl`: statements 190..192 are `slotsSetup` (`t`, `sbit`, `slots`), statement 197
    is `tbSetup` (`tb := and(treeAdrs, TM)`);
  - `slotsSetup_eval`: running them binds `slots = slotsOf idxLeaf` and leaves memory alone;
  - `tbSetup_eval`: likewise `tb = treeAdrs &&& TM`.
- **Still assumed at the walk's entry, not yet discharged:** the optimized `idxLeaf` and
  `treeAdrs` equal the reference's leaf index and tree ADRS; `merklePtr` points at the same
  auth path; and statements 193..196 (the pk compression between the two setups) keep
  `slots`, `treeAdrs` and the memory the walk reads. (`tb` is bound after them, at 197, right
  before the walk starts at 198.) That is the layer-glue step.

`byte` and `calldatacopy` are now exercised by a proof as well, so all five new constructs are.
Axioms, printed for all 20 theorems:
- none: the four pins, `byteAt_unfold`;
- [propext]: `slots_decode`, `bitOf_9`;
- [propext, Quot.sound]: `bitOf_le`, `xor64`, `xor96`, `sOf`;
- [propext, Classical.choice, Quot.sound]: the rest, including `slotsSetup_eval` and
  `tbSetup_eval`.
No `sorry`. The whole project builds. The file checks in about 5 s.

All 57 theorems of `RelChain`, `RelChainControls`, `RelWots` and `RelMerkle` were printed
together: 10 depend on no axioms, 14 on [propext], 13 on [propext, Quot.sound], 20 on
[propext, Classical.choice, Quot.sound]. Nothing else.

**Cost, like-for-like (corrected after checking imports).** `RelMerkle.lean` now has 20
theorems + 11 defs in 485 lines:
- about 2 theorems / 30 lines of one-time calldata infrastructure;
- about 23 declarations / 405 lines for the walk itself, with the env frames;
- 4 theorems + 2 defs / about 50 lines tying the slot word and ADRS base to the program. The
  reference needs no counterpart: it has no slot word.

The reference's proof of the same walk:
- HT-specific, in `HypertreePhase.lean` lines 33-323: `htStep`, `verifyAuthPath_eq_foldl`,
  `htAcc` (+2), `verifyAuthPath_eq_htAcc`, `htClimbBody`, `s_value`, `ht_climb_step` (116
  lines), `ht_climb`. 10 declarations / about 290 lines.
- Shared with the FORS climb, in `Phases.lean` (lines about 640-745, found by intersecting
  `Phases`/`Memory` declarations with the identifiers `ht_climb_step` uses): `climbSegs`,
  `climbMem_holdsSegs`, `climbMem_thPair`, `mstore32_comm`. 4 declarations / about 105 lines.
- `treeNode_Hadrs` (48 lines) is used only by the top-level refinement, not by the climb.
- `Climb.lean` and `ClimbLoop.lean` are **not** part of it: `HypertreePhase` imports only
  `Phases` and `EnvFrame`, and `Climb` is imported only by `ClimbLoop` and the root module. The
  batch-8 draft counted them ("about 17 declarations / 500 lines", "78%"), which was wrong.

So the reference walk is 290-395 lines, depending on whether the FORS-shared helpers are charged
to it, and the relational walk (405) costs **about 100-140%** of it, about 115-160% with the
slot tie-in. The chain was about 54% (470 vs 870). The D1 decode itself was cheap (one
`decide`). The cost is in the byte-level slot coupling: `MInv` has 16 conjuncts against the
reference's spec-level fold. In absolute lines the walk (about 405) is still close to the chain
(about 470).

**Caveat on "like-for-like".** The reference proves `program ↦ spec` (a refinement into
`verifyAuthPath`); these files prove `optimized ↦ reference program`. The comparison is of
effort for the same code region, not of the same theorem.

**Relational route, cumulative and remaining (measured families, then the model).**
- **Done:** E1 (321 lines), the WOTS chain phase (RelChain 607 + RelWots 220; controls 59), the
  Merkle walk with its slot tie-in (485). 1,692 lines in total.
- **Remaining:**
  - the FORS tree walk (11 levels, `C10-LANES` slot word over 2,048 leaf indices: another
    `decide`, larger);
  - the FORS leaf, last tree and root compression;
  - the H_msg / digest prefix, the WOTS digest/count hash, and the pk compression (E6);
  - the layer-loop and top-level verdict glue.
- **Estimate, in absolute lines per family** (the ratios compare different theorems, so they
  are not used to project):
  - FORS tree walk: about 400-500 (same shape as the measured Merkle walk, 405, plus a larger
    slot `decide`);
  - FORS leaf, last tree and root compression: about 300-500;
  - H_msg / digest prefix, WOTS digest/count hash, pk compression: about 600-900;
  - layer-setup and layer-loop glue (the entry hypotheses listed above) and the top-level
    verdict: about 700-900.
  - Total about 2,000-2,800 lines / 100-140 declarations, so the whole relational proof is about
    3,700-4,500 lines. These are estimates; only the 1,692 done lines are measured.

**Landing note (CI, found this batch; re-run and corrected at `ef984d040`).**
`make -C contracts/verification verify-fv-lints` (run by `lean-fv.yml`) FAILS on this branch
since batch 6: "AXIOM INVENTORY FAILURE: source inventory drift".
- Where it fails: `verify-build` passes. Then `lint_fv_invariants.sh` exits 1 at its line-96
  pre-check, `check_axiom_inventory.py lean`, before any of its five sub-lints run. So
  `test_axiom_inventory.py` and the planted-PATH control never run either. An earlier draft of
  this note said `lint_fv_invariants.sh` passed; it does not.
- Cause: `scripts/axiom_inventory_lean.json` pins the sha256 and the count of mentions of
  "axiom" for every Lean source that mentions the word. The drifted entries:
  - changed sha256, same counts: `SphincsCVerify.lean`, `Interpreter/Yul.lean`,
    `Interpreter/YulParse.lean`;
  - new, one mention each (in their headers): `C10HeadParse`, `RelE1`, `RelChain`, `RelWots`,
    `RelMerkle`.
- The source comparison fails first, so the elaborated-inventory comparison after it has not
  been run on this branch.
- Not re-pinned here (it is a pin). Landing any of the Lean commits needs that JSON
  regenerated, and then the rest of `verify-fv-lints` run for the first time.
- At `ef984d040`, `verify-audit` (no `sorry`) and `verify-ledger-consistency` both pass.

## Batch 9 (2026-11-14): `verify-fv-lints` run for real, review of the batch-8 fixes, the WOTS entry tied to the program, landing design note

**1. Axiom inventory re-pin (LOCAL ONLY, NEEDS OWNER SIGN-OFF).**
- `check_axiom_inventory.py` has no update mode ("an intentional edit … requires a reviewed
  re-pin"). The candidate was computed with its own census functions (`source_inventory`, and
  `elaborated_inventory` over `dump_axiom_inventory.lean`), and written with the file's own
  format (it round-trips byte-exactly through `json.dumps(indent=2)`).
- `bdfceafe9`, the diff, exactly as expected:
  - sha256 only, same mention counts: `SphincsCVerify.lean`, `Interpreter/Yul.lean`,
    `Interpreter/YulParse.lean`;
  - new, one mention each (headers): `C10HeadParse`, `RelE1`, `RelChain`, `RelWots`,
    `RelMerkle`.
  No other source entry changed. The elaborated inventory (27 environment axioms) is
  byte-identical. So nothing to report as a finding.
- `905c5deba` re-pins again after this batch's Lean edits: sha256 only for the root, `RelWots`
  and `RelMerkle` (docstrings), and a new `RelWotsEntry` entry. Elaborated still identical.
- With it, `make -C contracts/verification verify-fv-lints` exits 0 at `905c5deba`:
  - the inventory check (32 source modules, 27 environment axioms, both comparisons);
  - all five `lint_fv` sub-lints: escape-hatch (scans every `SphincsCVerify/**/*.lean`, so the
    new files are in scope), BreaksHash firewall, Gap-3 / theft_free closure, opaque guard,
    vacuous axiom;
  - `test_axiom_inventory.py` (6 tests) and the planted-PATH control.
  These had never run on the new files before.
- The other five `lean-fv.yml` steps also pass there: `verify-audit`,
  `verify-ledger-consistency` (plain make; CI wraps it in `run_authoritative_make.sh`),
  `verify-storage-mutators`, `verify-easycrypt-pins`, `verify-easycrypt-split-pins`.
- **Both re-pin commits need owner sign-off before they can reach master.** They are the only
  pin changes on this branch.

**2. Astra review of the batch-8 fixes** (`RelChainControls`, `RelWots`, `RelMerkle` at
`bdfceafe9`, neutral conformance wording).
- **A (statements vs names): PASS**, with documentation qualifications.
- **B (joint satisfiability): PASS.** Kernel-checked trivial witness for every `wots_layer_rel`
  hypothesis (zero memory, `d = wp = wa = 0`, the constants). Plus an executed probe of BOTH real
  programs with a constant oracle whose digest has digit sum 205: both prefixes fall through to
  the Merkle entry (`leaf = 0`, `merklePtr = 3028`) with every `MInv … 0` clause true. Real
  pointers: WOTS 2336 / 3172, Merkle 3028 / 3864, all below 4096. No hypothesis is unsatisfiable
  or unreachable.
- **C (frames vs what the next phase reads): PASS.** Every live read after the WOTS phase, after
  the Merkle walk (root comparison and next layer) is framed or related; the reference's excluded
  scratch is always rewritten before it is read.
- **D (controls): PASS** for what they claim, but they inspect only the ADRS and seed conjuncts.
- **E (pins, setup lemmas): PASS.** `slotsOf` is the interpreter's arithmetic.
- **F: INCOMPLETE for composition.** The frames preserve values; they do not make them EQUAL
  across programs. Counterexample to automatic composition: change only the optimized byte at
  `0x80` (its seed copy at `TB`); every WOTS hypothesis still holds, and the next compression
  reads it.

Fixed:
- Issue 1 (medium, composition): `RelWotsEntry.wots_phase_rel` (below) now exports the
  cross-program facts the next phase needs: the optimized seed copy at `[0x80, 0xA0)` equal to
  the seed (from an explicit layer-entry hypothesis, carried through the frames), the padding at
  `[0x50, 0x80)` zero, and `layer` / `idxTree` / `idxLeaf` / `countOff` / `sigBase` / `seed`
  equal across the two programs. **Still open:** the pk compression and Merkle setup establishing
  `MInv … 0`, the cross-layer invariant (node at `0x40`, seed copy at `TB`), and the shared root
  for the final comparison.
- Issue 2 (low, controls): `index_rejected` (chain-index byte 55) and `value_rejected` (value
  byte `0x40 + 5`); the probe oracle reads all four positions and the `#guard` rejects all four
  mutations.
- Issue 3 (low, docs): `RelMerkle`'s header now says `s` is bit 0 of the CURRENT `mIdx` (bit `h`
  of the leaf); `wots_layer_rel`'s docstring lists the pointer bound, the ADRS-zero bytes and the
  fixed `OUT` / `TB`.

**3. The WOTS entry hypotheses tied to the program (`RelWotsEntry.lean`, 488 lines).**
- Pins by `rfl`: both layer bodies' statements 0..14 (`refPre`, `headPre`: the shared 5-statement
  setup, each side's digit hash, digit sum, the gate, `wotsPtr`), and 0..15 / 0..187 with the
  chain phase (`refWotsPhase`, `headWotsPhase`).
- `setup5_eval`, `digit_hash_rel` (both hashes read the same 128 bytes; the optimized one has no
  store at `0x40`, so it needs its node bytes there to equal the reference's `currentNode`), and
  `tail_eval` (the gate).
- `wots_entry_rel`: from a coupled layer entry the two prefixes halt alike; when they fall
  through, EVERY entry hypothesis of `wots_layer_rel` holds. The digit sums agree by E1.
- `wots_phase_rel`: layer entry through the 43 chains, as one theorem.
- What is now assumed instead, at the layer entry (all layer-loop or prelude invariants):
  - equal `layer`, `idxTree`, `sigBase`, `sigOff`, `seed`;
  - the optimized node bytes at `0x40` equal the reference's `currentNode`, and its seed copy at
    `0x80` equals the seed;
  - bounds: `layer < 2^32`, `idxTree < 2^64`, `sigBase + sigOff < 4096`;
  - constants: `N_MASK`, the reference's `OUT = 0x600`, the optimized `OUT = 0x620` and
    `TB = 0x80`.
- Stated for `c10Oracle` and the real signature length, because E1 is. The other `Rel*` lemmas
  keep the arbitrary oracle.
- So step 4 MOVED the hypotheses out to the layer entry; it did not discharge them. Three are new
  in kind: the optimized node bytes at `0x40` equal `beByte currentNode`, the optimized seed copy
  at `0x80` equals the seed, and the optimized `OUT = 0x620`.
- **Executed probe of the new entry hypotheses** (`research/c10-gas/lean/EntryProbe.lean`, not
  part of the build). It runs BOTH real programs to the entry of layer 0 and of layer 1 (after a
  full layer-0 body). The common oracle is input-sensitive in digest bytes 0..13, the bytes node
  values keep, so the layer-1 node equality is a real differential check of layer 0. Its low bytes
  carry digit sum 205 so both gates pass, and byte 14 stays zero for the forced-zero FORS field
  (bits 132..142). Every `wots_phase_rel` hypothesis evaluates true at both layers, both prefixes
  fall through, the node is nonzero, and both controls (node with its top bit flipped; seed copy
  checked against the node) are false:

  ```
  layer 0: (true, true, [hlay, hl, hidx, hidx64, hsb, hso, hwp, hseed, hnode, htb, hRN, hROUT,
            hHN, hHTB, hHOUT, node_nonzero all true; ctrl_node_flipped false, ctrl_tb_vs_node false])
  layer 1: (same)
  ```

  It is executable evidence under one oracle, not a proof.
- Axioms: the four pins none; the other nine [propext, Classical.choice, Quot.sound]. Over all 72
  theorems of the five `Rel*` modules the union is {propext, Classical.choice, Quot.sound}. No
  `sorry`. Full `lake build` green.

**4. Cost, measured and remaining.**
- Done: 2,204 lines (E1 321, RelChain 607, controls 79, RelWots 223, RelWotsEntry 488, RelMerkle
  486).
- The WOTS-entry glue alone took 488 lines, which is more than the batch-8 glue bucket assumed
  per piece. Remaining, in absolute lines:
  - FORS tree walk: about 400-500;
  - FORS leaf, last tree, root: about 300-500;
  - H_msg / digest prefix and the WOTS pk compression (the digit hash is now done): about
    450-750;
  - remaining glue: pk compression into `MInv … 0`, the two-layer loop with its cross-layer
    invariant, the prelude, the root comparison and the top-level `execC10HeadAsm =
    execC10Asm`: about 600-900.
  - Total remaining about 1,750-2,650, so about 3,950-4,850 lines for the whole relational
    proof. Estimates; only the 2,204 are measured.

**5. Design note for the owner: how the relational proof would land on master.**

*Decision needed:* (i) keep the batch-6 in-place AST extension, or split it out; (ii) land HEAD
through `HEAD ≡ reference` (relational) or re-prove the spec on HEAD directly.

*Where master stands.* `src/verifiers/SPHINCsC10Asm.sol` on master is already the optimized v1
(`ef07c44cf`, `cdafc4e05`, `23b31bc95`). `c10Program` (`C10Program.lean`, `C10Source.lean`) is
still the transcription of the earlier verifier, the one deployed on Base (see "Two different
verifiers" below). So `make -C contracts/verification verify-transcription` (ci.yml and
`a31-transcription.yml`) is red on master; it fails here at its first check, on identical
inputs. A3.1 (`solidityVerifier_compiles_correctly`, `Bridge/Refinement.lean`) states
`deployed bytecode = execC10Asm`, which runs `c10Program`, and `execC10Asm_eq` (`C10Refine.lean`)
proves `execC10Asm` equal to `Spec.Signature.verify`. That still holds for the DEPLOYED verifier;
what it does not cover is the optimized v1 in `src/`, which is not deployed.

*How the relational route composes.*
1. Define `execC10HeadAsm`: `c10HeadProgram` under the same entry bindings as `execC10Asm`.
2. Prove `execC10HeadAsm_eq_ref : execC10HeadAsm pkSeed pkRoot message sig = execC10Asm pkSeed
   pkRoot message sig` for all inputs, under `c10Oracle`. This is the remaining relational work.
3. Restate A3.1 against `execC10HeadAsm`. The headline then composes as A3.1(HEAD) →
   `execC10HeadAsm_eq_ref` → `execC10Asm_eq` → spec. The existing ref→spec proof is reused
   unchanged: 8,166 program-specific lines (`Phases` 6,325, `HypertreePhase` 1,227, `C10Refine`
   614) plus 997 lines of shared infrastructure (`Memory`, `Sha256Bridge`, `C10Parse`,
   `EnvFrame`). `Climb` and `ClimbLoop` (161) are not on that path.
`c10Program` stays the reference, frozen against a byte-pinned copy of the earlier `.sol`. HEAD
gets its own transcription leg: `C10HeadSource` (byte-exact, regenerated by `gen_lean_head.py
--check`) and `C10HeadParse.parse_c10_head` (in-kernel parse by `rfl`).

*Gates and pins that would change (every one an owner-signed re-pin):*
- A3.1's statement, so `AXIOM_STATUS.json` (closures, `signature_pins`) and the elaborated axiom
  inventory (the axiom's `type_sha256`). `verify-ledger-consistency` checks these.
- `verify-transcription` / `verify-parse-transcription` retargeted. The Python checkers
  (`check_c10_transcription*.py`) reject the new constructs (`forFrom`, `sha256h`, `mstore8`,
  `calldatacopy`, `byte`), so either they are extended, or the in-kernel `parse_c10_head` becomes
  the HEAD transcription check and the Python checkers stay on the frozen reference copy.
  `check_c10_source_pin.py` gains the HEAD source pin.
- The bytecode-side A3.1 evidence must be re-run on the new bytecode once it is deployed: the KAT
  and bulk exes (`InterpMain.lean` runs `C10.execC10Asm`, so they need a HEAD variant), the Halmos
  input gates, and the codehash pins (`PINNED_CODEHASHES.md`, `PinnedCodehashes.t.sol`,
  `PinnedCodehashSelector.sol`, `DeployedBytecodeReproCheck.t.sol`).
- `verify-audit`'s headline list gains `execC10HeadAsm_eq_ref`; the source axiom inventory
  changes for the edited files (as in item 1).

*In-place vs separate AST extension.* Keep it in place. The extension adds constructors to the
shared `Stmt` and parser. It is conservative: two Astra reviews (batches 6 and 7) found the old
fragment's semantics unchanged; the whole reference proof rebuilds unchanged; the only edit to an
existing proof file is `EnvFrame.lean` gaining cases for the new constructors. A separate AST
would put the relational theorem across two interpreters plus a translation, which adds a layer
the relational lemmas do not need today.

*Recommendation: relational, not a direct spec re-proof on HEAD.*
- Cost, both as totals:
  - Relational: 2,204 lines done; bottom-up total about 3,950-4,850. Treat that as a FLOOR: the
    glue has already overrun once (the WOTS entry alone was 488 lines).
  - Applying the measured per-fragment ratios (54-140%) to the 8,166 program-specific reference
    lines instead gives about 4,400-11,400. That overstates fragments HEAD did not change, which
    relate by identical code. The two estimates bracket the cost; neither is measured.
  - A direct re-proof would redo the program side of those 8,166 lines against the byte-slot
    layout, plus spec bridges for the new constructs (`byte`, `calldatacopy`, 16-byte `sha256h`).
    Some of the 8,166 is spec-side folding that a re-proof would reuse; how much was not
    measured.
- Structure: one spec proof stays the anchor. The relational lemmas are oracle-agnostic except
  where E1 forces `c10Oracle`. Each later optimization re-proves only the fragments it changes,
  against the same reference.
- Risk: the relational proof is only as good as its glue. Every entry hypothesis must be
  discharged up to `execC10HeadAsm_eq_ref`, or the claim is vacuous. The remaining glue items
  are listed in item 2.
- **Two different verifiers (corrected in batch 10; the batch-9 draft conflated them):**
  - **Deployed on Base:** verifier `0x7Ab9Abd0…`, runtime codehash `0xfd55ec70…`
    (`deployments/base-mainnet.json`, status active). That is the earlier bytecode, and it is
    still the one `c10Program` transcribes and the A3.1 evidence covers. Checked by running
    under `FOUNDRY_PROFILE=deploy`: `C10Equivalence.test_reference_anchors` PASSES, i.e. the
    frozen copy `test/ref/RefSPHINCsC10Asm.sol` builds to `0xfd55ec70…`. Its lines 37-230 are
    byte-identical to `C10Source.lean`'s pinned text, which `c10Program` is parsed from. That text
    does not occur in `src/`.
  - **What master's `src/` builds:** the optimized v1, undeployed, unproven and unpinned; the
    owner accepted that state until the re-proof. Under the deploy profile it builds to runtime
    codehash `0x3cb7ea23…` at CREATE2 address `0x3edBE09d…`, so
    `DeployedBytecodeReproCheck.test_deployed_base_mainnet_bytecode_is_reproducible` and
    `PinnedCodehashes.test_codehash_pinned_or_print` FAIL on it: they pin the deployed set, and
    `src/` is no longer that.
  - The research gate's differential vectors (`gate.sh`, candidate against the frozen reference)
    are today's only check that the optimized v1 agrees with the deployed one.

## Batch 10 (2026-11-14): top-down skeleton, four of five phase obligations discharged

**0. Design-note correction.** The batch-9 note said nothing pins the deployed verifier. It
conflated two verifiers; restated in item 5 above ("Two different verifiers"), backed by running the
deploy-profile pins:
- the frozen reference `test/ref/RefSPHINCsC10Asm.sol` builds to the deployed `0xfd55ec70…`
  (`C10Equivalence.test_reference_anchors` PASS), and it contains `C10Source.lean`'s pinned text;
- `src/` (the optimized v1) builds to `0x3cb7ea23…`, so `DeployedBytecodeReproCheck` and
  `PinnedCodehashes` FAIL on it, as expected for an undeployed, unpinned build.
- Drift noticed, not edited (it is a test file outside this track's scope): the header of
  `contracts/smart-wallet/test/DeployedBytecodeReproCheck.t.sol` still says the freeze set is "NOT
  yet deployed on any chain", while `deployments/base-mainnet.json` records it as active.

**1. Astra review of the batch-9 work** (`RelWotsEntry`, the two new controls, the doc fixes,
`EntryProbe`; at `3e65dcdd3`).
- **A (statements vs names):** one minor overstatement. `wots_phase_rel` said "each side's
  constants hold" but does not export the optimized `OUT`. **Fixed:** the docstring now lists the
  exported constants.
- **B (pins):** PASS.
- **C (joint satisfiability):** PASS. Astra also ran `EntryProbe` with the real `c10Oracle` on KAT
  `valid-1` (nonzero seed): every hypothesis held at both layers, and both layer-1 WOTS phases
  fell through.
- **D (Astra's F question):** PASS. Every incoming value the next phase reads is EQUAL across the
  two programs, or a fixed constant (reference `OUT`, optimized `TB`). Nothing is merely preserved.
  The remaining items are values the next phase produces itself.
- **E (controls):** PASS. The guard's comparison gives `[true, false, false, false, false]`.
- **F:** PASS for the bounded claim. The specialisation to `c10Oracle` is disclosed.
- **Issue 2 (low):** `EntryProbe` printed but did not enforce. **Fixed:** `#guard`s, and a
  failing guard is checked to exit non-zero.

**2. The skeleton (`RelSkeleton.lean`, 578 lines).**
- **End theorem `head_verdict_eq`:** `execC10HeadAsm = execC10Asm` (the A3.1 function) for every
  key, message and signature under `c10Oracle`. It is proven from
  `PhaseObligations = O1 ∧ O2 ∧ O3 ∧ O4 ∧ O5`, each one named statement about one fragment
  between named coupling predicates.
- **The predicates:**
  - `HmsgExit`, `ForsExit`;
  - `LayerInv c`, the cross-layer invariant. It holds: the optimized node word at `0x40` equal to
    the reference's `currentNode` (masked, below `2^256`); the optimized seed copy at `TB`; equal
    `idxTree`, `seed`, `root`, `sigBase = 0`; `sigOff = 2336 + 836c`; the constants;
  - `WotsExit c`, `MidCarry c`.
- **Glue, proven once:**
  - the program and layer-body splits, as `rfl` pins;
  - the WOTS phase from `LayerInv` (`wots_exit`, through `wots_phase_rel` plus env frames and
    the setup values);
  - the Merkle walk (`merkle_walk_rel`), plus a `merkleNode < 2^256` bound (`walk_mn_lt`);
  - a halts-alike lock-step loop lemma (`execFor_rel'`), the two-layer loop (`loop_rel`), the
    prelude end (`preL_rel`), and the top level (`head_status_eq`).

**3. The phase obligations**, estimated against measured:

| obligation | fragment (ref / optimized) | estimate | status |
|---|---|---|---|
| obligation | fragment (ref / optimized) | size |
|---|---|---|
| O1 `HmsgObl` | statements 0..18 / 0..19 | **discharged**, `RelHmsg.lean` about 250 lines |
| O2 `ForsObl` | 19..24 / 20..25 | **open**; estimate 800-1,100 (unverified) |
| O3 `MidObl` | layer body 16..25 / 188..197 | **discharged**, `RelMid.lean` 374 lines |
| O4 `FinObl` | 27..28 / 225 | **discharged**, `fin_obl`, 37 lines |
| O5 `TailObl` | 29..31 / 29..31 | **discharged**, `tail_obl`, 23 lines |

(The sizes are measured; no estimates were recorded for O1, O3, O4 and O5 before they were
done, so the table makes no claim that estimates were met.)

- `head_verdict_eq_of_fors (hf : ForsObl)` is the end theorem with only FORS assumed (with
  `ForsObl` stated over the corrected `HmsgExit`; see item 4).
- All three batch-8/9 F gaps are now closed by proofs:
  - pk compression and Merkle setup into `MInv … 0` (O3);
  - the cross-layer invariant (O4 plus `LayerInv`);
  - the shared root (`LayerInv.root` carried through, O5).
- What O2 needs:
  - the 12 FORS trees (leaf hash plus 11 levels; reference nested loops against optimized
    unrolled levels with a `C10-LANES` slot word, decoded by `decide` over 2,048 indices × 11);
  - the last tree;
  - the root compression (reference copies 13 roots down by `0x40` then hashes `[0, 0x1E0)`;
    optimized hashes `[TB, TB + 0x1E0)` straight into `0x40`);
  - into `ForsExit`.
  The Merkle-walk, copy-loop and compression lemmas carry over in shape. Estimate 800-1,100 lines,
  unverified. One piece is measured: the FORS slot decode (`RelFors.fors_slots_decode`, the same
  `slotsOf` over 2,048 indices × 11 levels) checks by `decide` in about 18 s, axioms [propext].

**4. Evidence that the obligations are not vacuous** (`research/c10-gas/lean/PhaseProbe.lean`,
an executed probe, not a proof).
- **What it does:** runs both real programs along exactly the skeleton's splits, and evaluates
  every coupling predicate as a Bool at its cut point:
  - `HmsgExit`, `ForsExit`;
  - `LayerInv` at layers 0, 1, 2;
  - `WotsExit` at layers 0, 1;
  - `MInv … 0` plus `MidCarry` after the pk compression.
- **Two oracles:**
  - an input-sensitive mix oracle;
  - the real `c10Oracle` on KAT `valid-1`.
- **The `#guard`s:**
  - every predicate is true at every cut under both oracles;
  - both verdicts are equal, and `true` for the KAT;
  - a one-byte signature change makes both verdicts `false`.
- **Correction (found after the first draft of this section).** `ForsExit` holding on both
  executions shows the open obligation's CONCLUSION at reachable states. It says nothing about
  whether its HYPOTHESIS is strong enough, and it was not:
  - `ForsObl` quantifies over every state satisfying `HmsgExit`.
  - The optimized FORS writes each of its 13 roots as 16 bytes into a 32-byte slot at
    `0xC0 + 32i`, then hashes `[0x80, 0x260)`, so it relies on the slots' low halves being zero.
    `HmsgExit` said nothing about that memory.
  - So `ForsObl` as drafted was FALSE, and `head_verdict_eq_of_fors` would have been vacuous.
- **Found by a mutation sweep** (`PhaseProbe.sweep`). It flips one byte per 16-byte block of one
  side's post-H_msg memory over `[0, 0x640)`, keeps the mutants that still satisfy `HmsgExit`,
  runs FORS, and lists where `ForsExit` fails:
  - against the draft predicate: reference side `[]`; optimized side
    `[208, 240, …, 592]` = `0xD0 + 32i` for `i = 0..12`, exactly the root-slot low halves;
  - fixed (`78377e798`): `HmsgExit.zeroH` (optimized `[0xC0, 0x260)` is zero); `hmsg_rel` takes
    it as a hypothesis on the start state, which `vm0`'s zero memory meets; `hmsg_obl` is
    unchanged in statement;
  - with the fix the sweep returns `([], [])`, now a `#guard` in `PhaseProbe`.
- **Limits of the sweep.** It samples one byte per 16-byte block and one oracle, and covers O2
  only. O1, O3, O4 and O5 are proven, so they cannot have this defect; O2 is the only obligation
  still stated as a hypothesis.

**5. Axioms.** All theorems of `RelSkeleton`, `RelMid` and `RelHmsg` print only {propext,
Classical.choice, Quot.sound}, or none (the pins, `nmlit_eq`, `sigLen_eq`). No `sorry`. The full
`lake build` is green.

**6. Cost.**
- Measured: 3,396 lines in total (batch 10 added 1,192: skeleton 578, RelMid 374, RelHmsg 240).
- Remaining: O2 only, about 800-1,100. So the whole relational proof is about 4,200-4,500 lines.
- O1, O3, O4 and O5 came in at about 250, 374, 37 and 23 lines. The 800-1,100 for O2 is a
  guess by analogy with the Merkle walk, not a measurement.
- **Scope of the end theorem:** the interpreter model, i.e. `c10Oracle`, the real signature length,
  and `sig.offset = 0` (the interpreter's `sigOffset`, which is why `LayerInv` can fix
  `sigBase = 0`). That is exactly `execC10Asm`'s setting.
- **Not yet reviewed by Astra:** `RelSkeleton`, `RelMid`, `RelHmsg`, `RelFors`, `PhaseProbe`. The
  `zeroH` defect was found by the sweep after the batch-10 Astra run.

**7. Landing.** An axiom-inventory re-pin for this batch's Lean files follows as its own commit,
flagged LOCAL, NEEDS OWNER SIGN-OFF, like `bdfceafe9` and `905c5deba`.

## Batch 11 (2026-11-14): FORS discharged, HEAD ≡ reference with no obligation assumed

**0. Master merged.** `origin/master` (`158ef4b31`) merged as `4353d3b7b`, cleanly. It changed
only `hw/`, `secure/src/hw_io_under_test/pure_tests.rs` and `research/c10-autoresearch/**`. None
of these are on this branch's paths, so the cherry-pick answer is unchanged:
- the Lean side (`contracts/verification/lean/**`, `research/c10-gas/{gen_*.py, lean/, ledger.md}`)
  and the fixture side (`contracts/smart-wallet/test/gas/**`, the batch-4/5 research scripts)
  share only `research/c10-gas/ledger.md`, whose hunks would conflict;
- the axiom-inventory re-pins are separate commits on
  `contracts/verification/scripts/axiom_inventory_lean.json`, each needing owner sign-off.

**1. Astra review of the batch-10 work** (`RelSkeleton`, `RelMid`, `RelHmsg`, `RelFors`,
`PhaseProbe`, at `4353d3b7b`). `fors_obl`, `head_verdict_eq_full`, `execC10HeadAsm_eq` and the
new sweep engine came after it and are NOT reviewed.
- **A (scope): PASS.** Same entry bindings, zero initial memory, `c10Oracle`,
  `ByteVec Spec.SignatureLen`. No input restriction beyond `execC10Asm_eq`'s. `sigBase = 0`
  follows from the interpreter's `.sigOffset` semantics.
- **B (satisfiability / refutation of `ForsObl`): PASS, no refutation.** Astra kernel-checked an
  unusual `HmsgExit` witness (unrelated scratch memory, divergent stale bindings, oversized
  `dVal`); both FORS fragments fell through with equal node bytes under real SHA-256. Its source
  argument found no further memory or variable FORS reads without `HmsgExit` constraining it.
- **C (discharged obligations vs the skeleton's consumers): PASS.** All eight split pins are
  correct `rfl` equalities.
- **D (the probe): narrow FAIL.** A sweep failure under the substitute oracle is only a
  candidate counterexample, because the obligations are stated for `c10Oracle`. **Fixed:** every
  failing mutant is now replayed under `c10Oracle` from the same entry states, and labelled
  `confirmed` or `substitute-only`.
- **E: INCOMPLETE** at the time (O2 still assumed). Closed by item 3.

**2. Sweep strengthened** (`research/c10-gas/lean/PhaseProbe.lean`).
- **Modes** (`SWEEP` environment variable):
  - `block` (default): one byte per 16-byte block over `[0, 0x640)`, every phase;
  - `full`: every byte over every range FORS reads on either side, `[0, 0x260)` and
    `[0x600, 0x640)`, for the FORS phase;
  - `off`.
  `SWEEP_CHUNK` / `SWEEP_NCHUNKS` split the mutants for parallel runs.
- **Mutations:** each memory byte and each of 33 variables (+1), on one side at a time.
- **Two substitute oracles:** `mixSha`, plus a structurally different `mix2Sha`. Failures are
  replayed under `c10Oracle`.
- **Every phase, each against its own exit predicate:**
  - `fors` (`HmsgExit` → `ForsExit`);
  - `preL` (→ `LayerInv 0`);
  - `wots0` (→ `WotsExit 0`);
  - `mid0` (→ `MInv … 0` + `MidCarry`);
  - `walkFin0` (→ `LayerInv 1`);
  - `tail` (→ equal statuses).
- **Results, full mode** (22 parallel chunks; the first run took 759 s wall, before the
  `c10Oracle` replay was added; a second run with the replay also exited 0 on all 22 chunks, wall
  time not captured): no failing mutant in any phase under either oracle. Mutants kept (those
  still satisfying the entry predicate), per oracle:

  | phase | fors | preL | wots0 | mid0 | walkFin0 | tail |
  |---|---|---|---|---|---|---|
  | kept | 899 | 248 | 246 | 66 | 235 | 246 |

  Only `fors` is swept byte by byte; the other phases use block mode.
- **Negative control (the engine has to be able to fail).** A scratch copy with the `zeroH` row
  dropped from the probe's `HmsgExit` check (FORS phase only, block mode, 10 chunks, 221 s wall):
  - failing on the optimized side at exactly `208, 240, …, 592` = `0xD0 + 32i`, `i = 0..12`,
    under both oracles;
  - every one marked `(confirmed)` by the `c10Oracle` replay;
  - the five chunks holding failures exit 1.
  So the engine detects the known defect, and the replay classifies it correctly.
- **Runtimes:** `SWEEP=block` as one process: 2,193 s (about 37 min, with the full sweep and the
  lints running alongside), all 12 phase/oracle sweeps passing, no failing mutant. A default that
  slow is a trap, so the default is now `SWEEP=off` (about 35 s for the rest of the probe).
  `block` and `full` are opt-in and documented with these numbers in the probe header.
- **Limits:**
  - full-byte only for FORS;
  - the other phases at layer 0 only, one byte per block;
  - one signature, one entry pair per oracle;
  - substitute oracles, with replay only of failures.
  Since every obligation is now proven, the sweep is a regression check on the Bool encodings and
  the splits, not evidence for the theorem.

**3. O2 discharged (`RelFors.lean`, 1,029 lines; estimate was 800-1,100).**
- **The climb:**
  - `forsClimbBody` / `forsBlk` are the two climbs. `fors_ref_level_eq` / `fors_head_level_eq`
    are the executed levels, adapting the Merkle walk's; the slot decode is
    `fors_slots_decode`, 2,048 × 11 by `decide`.
  - `FInv` / `fors_step_rel` / `fors_climb_rel` relate 11 levels. The last level writes the
    optimized node into the root slot `0xC0 + 32i`, whose low half is zero by
    `HmsgExit.zeroH`.
- **One tree:** `tree_step` relates one tree under `TreeInv`. That invariant holds: roots so far
  equal (reference `0x80 + 32t`, optimized `0xC0 + 32t`), optimized future root slots' low
  halves zero, the seed copies, `[0x70, 0x80)` zero.
- **The 12-tree loop:** `fors_trees`, the 12-tree loop in lock step.
- **The rest:** `refLast_eval` / `headLast_eval` (the last tree); the root ADRS;
  `copy_loop13`; the two compressions hash the same 480 bytes.
- **`fors_obl : ForsObl`.**

**4. The end theorem, unconditional.**
- `RelFors.head_verdict_eq_full`: `execC10HeadAsm = execC10Asm` for every key, message and
  signature under `c10Oracle`, with **no** phase obligation assumed (O1-O5 all proven).
- `RelFors.execC10HeadAsm_eq`: composed with the reference's `execC10Asm_eq`, the optimized v1
  computes `nMaskedB pkSeed && nMaskedB pkRoot && verifyYulModel …`, the declarative spec
  modulo the same two N-mask guards.
- Axioms: {propext, Classical.choice, Quot.sound}. All 25 `RelFors` theorems print only these,
  [propext] (`fors_slots_decode`), or none (the pins).
- **Scope, unchanged:** the interpreter model (`c10Oracle`, the real signature length,
  `sig.offset = 0`) against the transcription `c10HeadProgram` of `src/`. It says nothing about
  the solc source→bytecode leg, which for the deployed verifier is A3.1 and for the optimized v1
  would be its restatement. See the batch-9 design note.

**5. Cost.** The relational proof is complete: 4,440 lines across the ten `Rel*` files,
including the controls. The batch-9 estimate was 3,950-4,850; the reference's program-specific
proof is 8,166 lines.

**6. Landing list** (for the landing batch; nothing here is done yet):
- Fix the drift in `contracts/smart-wallet/test/DeployedBytecodeReproCheck.t.sol`: its header
  says the freeze set is "NOT yet deployed on any chain", while `deployments/base-mainnet.json`
  records it as active.
- Owner sign-off on the axiom-inventory re-pins (`bdfceafe9`, `905c5deba`, `bd54dc29d`,
  `6297af758`, and this batch's), or one fresh re-pin by the census method at landing time.
- The A3.1 restatement, transcription retargeting and pin updates listed in the batch-9 design
  note, now that the Lean side needs no assumption beyond A3.1's own.
- Re-run on the landing commit: `gate.sh`, `verify-transcription` (expected red until
  retargeted), the six `lean-fv.yml` targets, and both probes.
- Gas gate: not re-run this batch. `git diff --name-only 0bfc5b93e HEAD -- contracts/smart-wallet
  research/c10-gas/gate.sh` is empty after the master merge, so the batch-8 gas/size table stands.
- The stale "still assumed" docstrings in `RelSkeleton`, `RelHmsg` and `RelMid` are fixed in this
  batch (with a matching re-pin), so they are not landing items.
