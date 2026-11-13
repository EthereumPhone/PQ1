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
