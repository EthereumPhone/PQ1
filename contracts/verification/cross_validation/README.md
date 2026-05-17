# Cross-validation: Lean spec ↔ Rust reference ↔ Solidity verifier

This directory wires the three independent implementations of
SPHINCS+C10 together so we can detect drift between:

  1. The **Lean 4 specification** in
     `../lean/SphincsCVerify/Spec/Signature.lean`.
  2. The **Rust reference** in `sphincs-c10/`.
  3. The **Solidity verifier** in
     `../../smart-wallet/src/verifiers/SPHINCsC10Asm.sol`.

## Why three implementations?

Defence in depth. Each implementation has a different failure mode:

| Implementation | Catches | Misses |
|---|---|---|
| Lean spec | Type-level layout errors, structural inconsistencies, theorem statements | Concrete-value bugs (opaque `sha256`) |
| Rust reference | Concrete-byte bugs, panics, side channels | Solidity-only bugs |
| Solidity verifier | EVM-specific bugs (storage layout, gas, calldata decoding) | Domain-tag drift, parameter drift |

All three must produce **the same boolean** for every test vector, or
something has drifted.

## How to run

```bash
# Step 1: regenerate test vectors from the Rust reference.
cd sphincs-c10
cargo test --release --test gen_test_vectors -- --nocapture > test_vectors.json

# Step 2: replay them in Solidity via Foundry.
cd ../contracts/smart-wallet
forge test --match-test test_test_vectors -vv

# Step 3: type-check the Lean spec API against the same vector shapes.
#         (Byte-level replay becomes available after Phase 7; see
#          ../docs/OPEN_PROOF_OBLIGATIONS.md for the plan.)
cd ../verification/lean
lake exe verify-test-vectors
```

Drift surfaces as either:

  * Foundry test failure (Rust ≠ Solidity).
  * Lean elaboration failure (spec ≠ what Rust/Solidity produce).
  * A diff in the printed `signatureLen`, `verifyingKeyLen`, or any
    other constant.

## Status

* **Rust ↔ Solidity differential testing**: already in place
  (`contracts/smart-wallet/test/SPHINCsC10Asm.t.sol`).
* **Rust ↔ Lean differential testing**: shape-only today. Byte-level
  replay inside Lean requires a kernel-computable SHA-256 spec
  (Phase 2) and the Lean test-vector executable (Phase 7); both are
  scoped in [`../docs/OPEN_PROOF_OBLIGATIONS.md`](../docs/OPEN_PROOF_OBLIGATIONS.md).
