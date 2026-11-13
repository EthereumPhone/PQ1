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
