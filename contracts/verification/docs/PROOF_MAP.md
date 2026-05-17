# Proof Map — PQSmartWallet Theft-Freedom

Theorem index for the SphincsCVerify project. Every entry is either
closed, axiomatic, or a `sorry` blocking the headline `theft_free`.

For the trust assumptions A1–A6 and the work plan, see
[`TRUST_ASSUMPTIONS.md`](TRUST_ASSUMPTIONS.md) and
[`OPEN_PROOF_OBLIGATIONS.md`](OPEN_PROOF_OBLIGATIONS.md).

## Headline

| Claim | Lean theorem | File | Status |
|---|---|---|---|
| **Theft-freedom** — every `balance(W)` decrement requires a SPHINCS+C10 sig valid under an installed owner key | `theft_free` | `Spec/Theorems.lean` | ✅ Closed (2026-05-17) — depends on exactly A1–A5 + Lean kernel built-ins |

## Verifier functional correctness

| Claim | Lean theorem | File | Status |
|---|---|---|---|
| Signature size is 4008 bytes | `signatureLen_eq_4008` | `Spec/Params.lean` | ✅ Closed |
| `(K-1) · A · N = 2112` | `k_minus_one_a_n_eq_2112` | `Spec/Params.lean` | ✅ Closed |
| Hypertree positions = 262,144 | `hypertreePositions_eq` | `Spec/Params.lean` | ✅ Closed |
| Cap < hypertree positions | `maxUses_lt_positions` | `Spec/Params.lean` | ✅ Closed |
| `W = 2^LogW` | `W_eq_two_pow_LogW` | `Spec/Params.lean` | ✅ Closed |
| Verifier deterministic | `verify_deterministic` | `Spec/Theorems.lean` | ✅ Closed |
| Rejects wrong length (type-level) | `verify_rejects_wrong_length` | `Spec/Theorems.lean` | ✅ Closed |
| Rejects nonzero last FORS index | `verify_rejects_nonzero_last_fors_idx` | `Spec/Theorems.lean` | ✅ Closed |
| `pkFromSig = none` on bad digit sum | `pkFromSig_returns_none_of_bad_digit_sum` | `Spec/Theorems.lean` | ✅ Closed |
| `verify = false` when hypertree returns `none` (structural form) | `verify_rejects_bad_digit_sum` | `Spec/Theorems.lean` | ✅ Closed (full per-layer chain still pending under `verify_signs`) |
| `readBitsLe` bounded | `readBitsLe_lt` | `Util/Bits.lean` | ✅ Closed |
| FORS indices bounded | `extractForsIndices_lt` | `Util/Bits.lean` | ✅ Closed |
| WOTS digits bounded | `extractDigits_lt` | `Util/Bits.lean` | ✅ Closed |
| `th` / `thPair` / `hMsg` size lemmas | `th_size`, `thPair_size`, `hMsg_size` | `Spec/Hash.lean` | ✅ Closed |
| Kernel-computable SHA-256 | `sha256` (def) | `Spec/Hash.lean` | ⏳ currently `opaque` |
| Tweakable-hash unfolds to SHA-256 | `th_unfolds_to_sha256` (+ siblings) | `Spec/Hash.lean` | ⏳ not stated |
| Reference signer complete | `Signer.sign` (def) | `Spec/Signer.lean` | ⏳ placeholder |
| `findCount` correctness | `findCount_correct` | `Spec/Signer.lean` | ⏳ not stated |
| Real `deserialise` | `Signature.deserialise` (def) | `Spec/Signature.lean` | ⏳ placeholder |
| `serialise/deserialise` round-trip | `serialise_deserialise_roundtrip` | `Spec/Signature.lean` | ⏳ not stated |
| Merkle round-trip | `merkle_roundtrip` | `Spec/Lemmas/MerkleRoundtrip.lean` | ⏳ not created |
| WOTS+C chain round-trip | `wots_chain_roundtrip` | `Spec/Lemmas/WotsRoundtrip.lean` | ⏳ not created |
| FORS+C round-trip | `fors_roundtrip` | `Spec/Lemmas/ForsRoundtrip.lean` | ⏳ not created |
| Chain-hash composition | `chainHash_compose` | `Spec/Lemmas/ChainHash.lean` | ⏳ not created |
| Sign/verify round-trip | `verify_signs` | `Spec/Theorems.lean` | ⏳ `sorry` |

## Verifier refinement (Lean spec ↔ Yul shape)

| Claim | Lean theorem | File | Status |
|---|---|---|---|
| Load R consistent | `load_R_consistent` | `Verifier/Equivalence.lean` | ⏳ `sorry` |
| FORS section consistent | `fors_section_consistent` | `Verifier/Equivalence.lean` | ⏳ stub |
| HT layer-0 consistent | `ht_layer0_consistent` | `Verifier/Equivalence.lean` | ⏳ stub |
| HT layer-1 consistent | `ht_layer1_consistent` | `Verifier/Equivalence.lean` | ⏳ stub |
| Refined ≡ Spec | `verifyRefined_eq_spec` | `Verifier/Equivalence.lean` | ⏳ `sorry` |
| Yul model ≡ Refined | `yul_eq_refined` | `Bridge/SolidityVerifier.lean` | ✅ Closed (`rfl`) |

## Wallet invariants

| Invariant | Lean theorem | File | Status |
|---|---|---|---|
| I-1 Non-bypass | `validateSignature_only_via_verify` | `Wallet/Invariants.lean` | ✅ Closed |
| I-2 Bootstrap monotonicity | `validateSignature_bootstrap_monotonic` | `Wallet/Invariants.lean` | ✅ Closed |
| I-2 Slot monotonicity | `validateSignature_slot_monotonic` | `Wallet/Invariants.lean` | ✅ Closed |
| I-3 No reset (structural) | `no_reset_path` + Storage no-decrease lemmas | `Wallet/Invariants.lean` | ✅ Closed |
| I-4 Bootstrap unremovable | `cannot_remove_bootstrap` / `bootstrap_unremovable` | `Wallet/Invariants.lean` / `Wallet/MultiOwnable.lean` | ✅ Closed |
| I-5 Combined cap (per-method + inductive) | `combinedCap_preserved_by_*`, `combinedCap_inductive` | `Wallet/Invariants.lean` | ✅ Closed |
| I-6 EIP-1271 forbids bootstrap | `eip1271_forbids_bootstrap` | `Wallet/Invariants.lean` (model in `Wallet/IsValidSignature.lean`) | ✅ Closed |
| I-7 CREATE2 chain-independent | `create2_address_chain_independent`, `create2_salt_definition` | `Wallet/Invariants.lean` | ✅ Closed (strengthened) |
| I-8 Squat defence | `factory_requires_bootstrap_sig` | `Wallet/Invariants.lean` | ✅ Closed |
| Bootstrap-bump monotonic | `bumpBootstrap_monotonic` | `Wallet/MultiOwnable.lean` | ✅ Closed |
| Slot-bump monotonic | `bumpSlot_monotonic` | `Wallet/MultiOwnable.lean` | ✅ Closed |

## Cryptographic axioms (named, with citations)

| Claim | Lean declaration | File | Status |
|---|---|---|---|
| SHA-256 SM-DT-TCR | `SM_DT_TCR_F` | `Crypto/Assumptions.lean` | 🔓 Axiom — Barbosa et al. ASIACRYPT 2024 |
| SHA-256 ITSR | `ITSR_F` | `Crypto/Assumptions.lean` | 🔓 Axiom — Barbosa et al. ASIACRYPT 2024 |
| `H_msg` random oracle | `hMsg_random_oracle` | `Crypto/Assumptions.lean` | 🔓 Axiom |
| EUF-CMA SPHINCS+C10 | `EUF_CMA_SPHINCSplusC` | `Crypto/EUFCMA.lean` | 🔓 Axiom — Hülsing PQC2022 + Barbosa et al. extension |
| Cannot forge without breaking SHA-256 | `cannot_forge_without_breaking_SHA256` | `Crypto/EUFCMA.lean` | ✅ Closed (deterministic-adversary form; consumes all four crypto axioms) |

## Bridge (TCB axioms + composite)

| Claim | Lean declaration | File | Status |
|---|---|---|---|
| solc 0.8.28 correct on wallet + verifier | `solidityVerifier_compiles_correctly` | `Bridge/Refinement.lean` | 🔓 Axiom |
| EVM bytecode obeys spec | `evm_bytecode_executes_correctly` | `Bridge/Refinement.lean` | 🔓 Axiom |
| Precompile 0x02 = FIPS 180-4 | `precompile_0x02_is_FIPS_180_4` | `Bridge/Refinement.lean` | 🔓 Axiom |
| EntryPoint v0.6 honest | `entrypoint_honest` | `Bridge/EntryPoint.lean` | 🔓 Axiom (added 2026-05-17) |
| Deployed verifier refines spec | `deployed_verifier_refines_spec` | `Bridge/Refinement.lean` | ✅ Trivial composite (work is in the axioms above) |

## File coverage

| File | Purpose |
|---|---|
| `Spec/Params.lean` | C10 parameters + arithmetic identities |
| `Spec/Bytes.lean` | ByteVec library |
| `Spec/Adrs.lean` | ADRS construction |
| `Spec/Hash.lean` | SHA-256 (opaque → def post-completion) + tweakable hashes |
| `Spec/Wots.lean` | WOTS+C sign/verify spec |
| `Spec/Fors.lean` | FORS+C with forced-zero last index |
| `Spec/Hypertree.lean` | D=2 hypertree |
| `Spec/Signature.lean` | Top-level verify + 4008-byte layout |
| `Spec/Signer.lean` | Reference signer |
| `Spec/Theorems.lean` | Functional-correctness theorems + `theft_free` |
| `Spec/Lemmas/*` | Round-trip sub-lemmas |
| `Spec/Sha256Impl.lean` | FIPS 180-4 SHA-256 (to be added) |
| `Verifier/Refined.lean` | Offset-indexed verifier (Yul shape) |
| `Verifier/Equivalence.lean` | Refined ≡ Spec |
| `Bridge/SolidityVerifier.lean` | Yul-level model |
| `Bridge/Refinement.lean` | Lean ↔ Solidity ↔ EVM bridge (A1, A3, A4) |
| `Bridge/EntryPoint.lean` | EntryPoint v0.6 contract (A2 — to be added) |
| `Crypto/Assumptions.lean` | SHA-256 cryptographic axioms |
| `Crypto/EUFCMA.lean` | EUF-CMA axiom + sub-lemma |
| `Wallet/Storage.lean` | Wallet state-transition model |
| `Wallet/MultiOwnable.lean` | Owner table + counter bumps |
| `Wallet/ValidateUserOp.lean` | `validateUserOp` model |
| `Wallet/Factory.lean` | Factory model (CREATE2 + squat defence) |
| `Wallet/Invariants.lean` | I-1 through I-8 |
| `Util/Bits.lean` | Bit-level operations |
| `Util/ByteVec.lean` | ByteVec helpers |

## How to verify

```bash
cd contracts/verification/lean
elan toolchain install $(cat lean-toolchain)
lake update
lake build
lake env lean --run scripts/check_no_sorry.lean
lake env lean --run scripts/dump_axioms.lean
```

A clean build means every closed theorem is checked by the Lean kernel.
The audit scripts surface remaining work and the axiom inventory.
