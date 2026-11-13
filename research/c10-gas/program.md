# C10 verifier gas: loop protocol (Track B, #1155)

Branch `research/c10-gas` (from `0895dcc79`), in its own worktree. Host only, local
commits only, never pushed.

## Goal

Lower the gas of the on-chain C10 verifiers without changing what they compute:

- `src/verifiers/SPHINCsC10v2Asm.sol`: v2 DRAFT 0.3, pre-launch candidate (primary target);
- `src/verifiers/SPHINCsC10Asm.sol`: v1, the deployed format.

## Hard rules

1. **Semantics-identical.** For every input: the same success flag, the same returndata (revert
   reasons included), and the same SHA-256 precompile inputs in the same order. No change to the
   signature format, parameters, tweaks or hashing. Format-level ideas are written up as
   proposals with a security note, never adopted.
2. Check order is part of the semantics: length revert, then key-mask `false`, then H_MSG and
   the FORS+C revert, then FORS, then per layer the WOTS+C revert, chains, Merkle; root compare.
3. Pins are not edited to make tests pass. A changed verifier moves its codehash (and through
   the wallet, CREATE2 addresses); the ledger lists which pins would need re-pinning at landing.
4. `git add <explicit paths>` only; no `-a`/`-A`; no push.

## Gates (all must be green for a keep)

`research/c10-gas/gate.sh` runs:

1. **Equivalence** `test/gas/C10Equivalence.t.sol`: frozen references in `test/ref/`
   (byte-identical copies of the two verifiers at `0895dcc79`, anchored by codehash: v1 to the
   deployed pin) against the candidates, comparing (success, returndata, SHA-256 input trace) on
   all KAT files and +C near-misses, the v1 vectors and 246-entry mutant corpus, bit-flip /
   length / key / count / splice sweeps, fuzzed mutations, non-canonical ABI encodings and raw
   calldata.
2. **Per-primitive** `test/gas/C10PrimitiveTrace.t.sol`: the candidate's SHA-256 inputs equal,
   call by call, the inputs the Python references hash (`v2_trace_export.py` from
   `c10v2_ref.py`; `v1_trace_export.py` from the clean-room `independent_c10_signer.py`). A
   divergence names the primitive and its address fields.
3. **Unit** properties for rewritten sub-computations (e.g. `test/gas/C10DigitSum.t.sol`), plus a
   text pin (`gate.sh`) that the verifier contains the exact snippet the unit test checks.
4. **Existing suites**: `test/SPHINCsC10*.t.sol`, `test/C10PrimitiveKat.t.sol`, minus the v1
   codehash freeze test (expected to fail when v1 changes; listed under re-pins).
5. **Mutation controls** `mutation_controls.py`: plant one bug at a time in the candidate; the
   gates must fail on every mutant (a STALE mutant must be re-targeted, not dropped). Includes
   trace-only mutants (count >= 2^31 hashed differently), which only the trace comparison
   catches.

## Measurement

`test/gas/C10GasBench.t.sol`, **callee-only**: pre-encoded calldata, raw `staticcall` after a
warm-up, so warm CALL (100) + verifier execution. Constant across valid vectors (361 SHA-256
calls). The HIGH-LEVEL number (Solidity call, includes caller-side encoding) is logged for
comparison with #1155's quoted figures, which were high-level.

## Loop

1. Pick the top-ranked hypothesis (advisor ranking in the ledger).
2. Implement it alone, on top of the last keep.
3. `gate.sh`; record gas before/after (callee-only), size, gates, in `ledger.md`.
4. Keep (commit, explicit paths) if gas drops, all gates are green and the code stays
   reviewable; else discard (`git checkout -- <file>`), with the reason in the ledger.
5. Every few keeps: rerun mutation controls; independent conformance review (Astra) of the
   diff against the reference.
