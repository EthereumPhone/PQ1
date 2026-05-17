# Proof Map — Verifier-Only Scope

A user-facing index of every theorem the SphincsCVerify project ships in
its current scope (the `SPHINCsC10Asm.sol` cryptographic verifier).

The wallet contracts (`PQSmartWallet`, `PQMultiOwnable`,
`PQSmartWalletFactory`) and the hardware-wallet firmware are out of
scope; the Lean files under `SphincsCVerify/Wallet/` are legacy and not
indexed here.

For the phased plan to close every pending theorem, see
[`OPEN_PROOF_OBLIGATIONS.md`](OPEN_PROOF_OBLIGATIONS.md).

## Functional correctness

| Claim | Lean theorem | File | Status | Phase |
|---|---|---|---|---|
| Signature size is 4008 bytes | `signatureLen_eq_4008` | `Spec/Params.lean` | ✅ Closed | — |
| `(K-1) * A * N = 2112` | `k_minus_one_a_n_eq_2112` | `Spec/Params.lean` | ✅ Closed | — |
| Hypertree positions = 262,144 | `hypertreePositions_eq` | `Spec/Params.lean` | ✅ Closed | — |
| Cap < hypertree positions | `maxUses_lt_positions` | `Spec/Params.lean` | ✅ Closed | — |
| Verifier deterministic | `verify_deterministic` | `Spec/Theorems.lean` | ✅ Closed | — |
| Verifier rejects wrong length (type-level) | `verify_rejects_wrong_length` | `Spec/Theorems.lean` | ✅ Closed | — |
| `th` returns 16 bytes | `th_size` | `Spec/Hash.lean` | ✅ Closed | — |
| `thPair` returns 16 bytes | `thPair_size` | `Spec/Hash.lean` | ✅ Closed | — |
| `hMsg` returns 32 bytes | `hMsg_size` | `Spec/Hash.lean` | ✅ Closed | — |
| `readBitsLe` bounded | `readBitsLe_lt` | `Util/Bits.lean` | ✅ Closed (Phase 1, 2026-05) | 1 |
| FORS indices bounded | `extractForsIndices_lt` | `Util/Bits.lean` | ✅ Closed (Phase 1) | 1 |
| WOTS digits bounded | `extractDigits_lt` | `Util/Bits.lean` | ✅ Closed (Phase 1) | 1 |
| Bit-extraction step bounded | `readBitsLe.stepValue_lt` (new in Phase 1) | `Util/Bits.lean` | ✅ Closed | 1 |
| `W = 2^LogW` | `W_eq_two_pow_LogW` (new in Phase 1) | `Spec/Params.lean` | ✅ Closed | 1 |
| Reject nonzero last FORS idx | `verify_rejects_nonzero_last_fors_idx` | `Spec/Theorems.lean` | ✅ Closed (Phase 1) | 1 |
| `pkFromSig` returns `none` on bad digit sum | `pkFromSig_returns_none_of_bad_digit_sum` (new in Phase 1) | `Spec/Theorems.lean` | ✅ Closed | 1 |
| `verify = false` when hypertree returns none | `verify_rejects_bad_digit_sum` (rewritten in Phase 1) | `Spec/Theorems.lean` | ✅ Closed (structural form; full per-layer chain is Phase 5) | 1 / 5 |
| Kernel-computable SHA-256 | `sha256` (def, not theorem) | `Spec/Hash.lean` | ⏳ currently `opaque` | 2 |
| `th` unfolds to SHA-256 | `th_unfolds_to_sha256` (+ siblings) | `Spec/Hash.lean` | ⏳ not stated | 2 |
| SHA-256 matches CAVS vectors | `Sha256TestVectors.*` | `Spec/Sha256TestVectors.lean` | ⏳ not created | 2 |
| Reference signer complete | `Signer.sign` (def) | `Spec/Signer.lean` | ⏳ placeholder | 3 |
| `findCount` correctness | `findCount_correct` | `Spec/Signer.lean` | ⏳ not stated | 3 |
| Real `deserialise` | `Signature.deserialise` (def) | `Spec/Signature.lean` | ⏳ placeholder | 4 |
| `serialise/deserialise` round-trip | `serialise_deserialise_roundtrip` | `Spec/Signature.lean` | ⏳ not stated | 4 |
| Merkle round-trip | `merkle_roundtrip` | `Spec/Lemmas/MerkleRoundtrip.lean` | ⏳ not created | 5 |
| WOTS+C chain round-trip | `wots_chain_roundtrip` | `Spec/Lemmas/WotsRoundtrip.lean` | ⏳ not created | 5 |
| FORS+C round-trip | `fors_roundtrip` | `Spec/Lemmas/ForsRoundtrip.lean` | ⏳ not created | 5 |
| Chain-hash composition | `chainHash_compose` | `Spec/Lemmas/ChainHash.lean` | ⏳ not created | 5 |
| Sign/verify round-trip | `verify_signs` | `Spec/Theorems.lean` | ⏳ `sorry` | 5 |
| Load R consistent | `load_R_consistent` | `Verifier/Equivalence.lean` | ⏳ `sorry` | 6 |
| FORS section consistent | `fors_section_consistent` | `Verifier/Equivalence.lean` | ⏳ stub | 6 |
| HT layer-0 consistent | `ht_layer0_consistent` | `Verifier/Equivalence.lean` | ⏳ stub | 6 |
| HT layer-1 consistent | `ht_layer1_consistent` | `Verifier/Equivalence.lean` | ⏳ stub | 6 |
| Refined ≡ Spec | `verifyRefined_eq_spec` | `Verifier/Equivalence.lean` | ⏳ `sorry` | 6 |
| Yul model ≡ Refined | `yul_eq_refined` | `Bridge/SolidityVerifier.lean` | ✅ Closed (`rfl`) | — |

## Cryptographic — `Crypto/` (named axioms with citations)

| Claim | Lean declaration | File | Status |
|---|---|---|---|
| SHA-256 SM-DT-TCR | `SM_DT_TCR_F` | `Crypto/Assumptions.lean` | 🔓 Axiom — Barbosa et al. ASIACRYPT 2024 |
| SHA-256 ITSR | `ITSR_F` | `Crypto/Assumptions.lean` | 🔓 Axiom — Barbosa et al. ASIACRYPT 2024 |
| `H_msg` random oracle | `hMsg_random_oracle` | `Crypto/Assumptions.lean` | 🔓 Axiom |
| EUF-CMA SPHINCS+C10 | `EUF_CMA_SPHINCSplusC` | `Crypto/EUFCMA.lean` | 🔓 Axiom — Hülsing PQC2022 + Barbosa et al. extension |
| Cannot forge without breaking SHA-256 | `cannot_forge_without_breaking_SHA256` | `Crypto/EUFCMA.lean` | ⏳ `sorry`; needs probability-game DSL (out of scope) |

## Bridge — `Bridge/` (TCB axioms + composite)

| Claim | Lean declaration | File | Status |
|---|---|---|---|
| solc 0.8.28 correct on verifier | `solidityVerifier_compiles_correctly` | `Bridge/Refinement.lean` | 🔓 Axiom |
| EVM bytecode obeys spec | `evm_bytecode_executes_correctly` | `Bridge/Refinement.lean` | 🔓 Axiom |
| Precompile 0x02 = FIPS 180-4 | `precompile_0x02_is_FIPS_180_4` | `Bridge/Refinement.lean` | 🔓 Axiom |
| Deployed verifier refines spec | `deployed_verifier_refines_spec` | `Bridge/Refinement.lean` | ✅ Trivial composite (work is in the three axioms above) |

## File coverage

| File | Purpose |
|---|---|
| `Spec/Params.lean` | C10 parameters + arithmetic identities |
| `Spec/Bytes.lean` | ByteVec library |
| `Spec/Adrs.lean` | ADRS construction |
| `Spec/Hash.lean` | SHA-256 (opaque pre-Phase 2; def post) + tweakable hashes |
| `Spec/Wots.lean` | WOTS+C sign/verify spec |
| `Spec/Fors.lean` | FORS+C spec (forced-zero last index) |
| `Spec/Hypertree.lean` | D=2 hypertree |
| `Spec/Signature.lean` | Top-level verify + serialise/deserialise |
| `Spec/Signer.lean` | Reference signer (stub pre-Phase 3) |
| `Spec/Theorems.lean` | Functional-correctness theorems |
| `Spec/Lemmas/*` | Round-trip sub-lemmas (created in Phase 5) |
| `Spec/Sha256Impl.lean` | FIPS 180-4 SHA-256 (created in Phase 2) |
| `Spec/Sha256TestVectors.lean` | CAVS-vector lemmas (created in Phase 2) |
| `Verifier/Refined.lean` | Offset-indexed verifier (Yul shape) |
| `Verifier/Equivalence.lean` | Refined ≡ Spec |
| `Bridge/SolidityVerifier.lean` | Yul-level model |
| `Bridge/Refinement.lean` | Lean ↔ Solidity ↔ EVM bridge (TCB axioms) |
| `Crypto/Assumptions.lean` | SHA-256 cryptographic axioms |
| `Crypto/EUFCMA.lean` | EUF-CMA axiom + sub-lemma |
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
The audit scripts surface the remaining work (each `sorry` and each
`axiom`).
