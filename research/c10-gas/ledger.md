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
