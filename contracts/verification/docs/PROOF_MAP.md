# Proof Map — What Is Proven, What Is Axiomatised, Where to Find It

A user-facing index of every theorem the SphincsCVerify project ships,
crossing referenced with the playbook in
`docs/how_to_math_proof_secureness.md`.

## Top-level claims and where they live

### Functional correctness — Stratum A

| Claim | Lean theorem | File | Status |
|---|---|---|---|
| Signature size is exactly 4008 bytes | `signatureLen_eq_4008` | `Spec/Params.lean` | ✅ Closed (`decide`) |
| `(K-1) * A * N = 2112` | `k_minus_one_a_n_eq_2112` | `Spec/Params.lean` | ✅ Closed (`decide`) |
| Hypertree positions = 262,144 | `hypertreePositions_eq` | `Spec/Params.lean` | ✅ Closed (`decide`) |
| Per-chain cap < hypertree positions | `maxUses_lt_positions` | `Spec/Params.lean` | ✅ Closed (`decide`) |
| Verifier is deterministic | `verify_deterministic` | `Spec/Theorems.lean` | ✅ Closed (`rfl`) |
| Verifier rejects wrong length (type-level) | `verify_rejects_wrong_length` | `Spec/Theorems.lean` | ✅ Closed |
| `th` returns 16 bytes | `th_size` | `Spec/Hash.lean` | ✅ Closed |
| `thPair` returns 16 bytes | `thPair_size` | `Spec/Hash.lean` | ✅ Closed |
| `hMsg` returns 32 bytes | `hMsg_size` | `Spec/Hash.lean` | ✅ Closed |
| Signing/verifying round-trip | `verify_signs` | `Spec/Theorems.lean` | ⏳ Section lemmas pending |
| Reject non-zero last FORS index | `verify_rejects_nonzero_last_fors_idx` | `Spec/Theorems.lean` | ⏳ Mechanical `simp` pending |
| Reject bad WOTS+C digit sum | `verify_rejects_bad_digit_sum` | `Spec/Theorems.lean` | ⏳ Statement to refine + simp |
| Refined ≡ Spec | `verifyRefined_eq_spec` | `Verifier/Equivalence.lean` | ⏳ 4 section lemmas pending |
| Yul model ≡ Refined | `yul_eq_refined` | `Bridge/SolidityVerifier.lean` | ✅ Closed (`rfl`) |

### Cryptographic security — Stratum A continued

| Claim | Lean declaration | File | Status |
|---|---|---|---|
| SHA-256 SM-DT-TCR | `SM_DT_TCR_F` | `Crypto/Assumptions.lean` | 🔓 Axiom (cited from Barbosa et al. 2024) |
| SHA-256 ITSR | `ITSR_F` | `Crypto/Assumptions.lean` | 🔓 Axiom (cited) |
| `H_msg` is a random oracle | `hMsg_random_oracle` | `Crypto/Assumptions.lean` | 🔓 Axiom (cited) |
| EUF-CMA for SPHINCS+C10 | `EUF_CMA_SPHINCSplusC` | `Crypto/EUFCMA.lean` | 🔓 Axiom (cited) |

### Wallet invariants — Stratum B

| Claim | Lean theorem | File | Status |
|---|---|---|---|
| `bumpBootstrap` monotonic | `bumpBootstrap_monotonic` | `Wallet/MultiOwnable.lean` | ✅ Closed |
| `bumpBootstrap` capped | `bumpBootstrap_capped` | `Wallet/MultiOwnable.lean` | ✅ Closed |
| `bumpSlot` monotonic | `bumpSlot_monotonic` | `Wallet/MultiOwnable.lean` | ✅ Closed |
| `bumpSlot` no cross-effect | `bumpSlot_no_cross_effect` | `Wallet/MultiOwnable.lean` | ✅ Closed |
| `setOffchain` monotonic | `setOffchain_monotonic` | `Wallet/MultiOwnable.lean` | ✅ Closed |
| Combined-cap invariant | `combined_cap_invariant` | `Wallet/MultiOwnable.lean` | ✅ Closed |
| Bootstrap unremovable | `bootstrap_unremovable` | `Wallet/MultiOwnable.lean` | ✅ Closed |
| Cap preserved by `bumpSlot` | `combinedCap_preserved_by_bumpSlot` | `Wallet/Invariants.lean` | ✅ Closed |
| Cap preserved by `setOffchain` | `combinedCap_preserved_by_setOffchain` | `Wallet/Invariants.lean` | ✅ Closed |
| CREATE2 address chain-independent | `create2_address_chain_independent` | `Wallet/Invariants.lean` | ✅ Closed (`rfl`) |
| Cannot remove bootstrap | `cannot_remove_bootstrap` | `Wallet/Invariants.lean` | ✅ Closed |
| Non-bypass | `validateSignature_only_via_verify` | `Wallet/Invariants.lean` | ⏳ Awaits `decodeWrappedSig` |
| Bootstrap monotonicity (validateUserOp) | `validateSignature_bootstrap_monotonic` | `Wallet/Invariants.lean` | ⏳ Mechanical |
| Slot monotonicity (validateUserOp) | `validateSignature_slot_monotonic` | `Wallet/Invariants.lean` | ⏳ Mechanical |

### Bridge to deployed bytecode — Stratum C

| Claim | Lean declaration | File | Status |
|---|---|---|---|
| solc 0.8.28 correctness on the verifier | `solidityVerifier_compiles_correctly` | `Bridge/Refinement.lean` | 🔓 Axiom (Verity-style work to discharge) |
| EVM bytecode obeys EVM spec | `evm_bytecode_executes_correctly` | `Bridge/Refinement.lean` | 🔓 Axiom (universal Ethereum) |
| Precompile 0x02 is FIPS 180-4 | `precompile_0x02_is_FIPS_180_4` | `Bridge/Refinement.lean` | 🔓 Axiom (consensus client) |
| Deployed verifier refines Lean spec | `deployed_verifier_refines_spec` | `Bridge/Refinement.lean` | ✅ Closed (the trivial composite; substance is in the three axioms above) |

## Coverage matrix

Playbook section → file containing the realisation:

| Playbook | File |
|---|---|
| § 4.2 Step 1 — Parameters | `Spec/Params.lean` |
| § 4.2 Step 2 — SHA-256 modelling | `Spec/Hash.lean` |
| § 4.2 Step 3 — ADRS, WOTS+C, FORS+C, hypertree, verifier | `Spec/{Adrs,Wots,Fors,Hypertree,Signature}.lean` |
| § 4.2 Step 4 — Functional correctness | `Spec/Theorems.lean` |
| § 4.2 Step 5 — Cryptographic soundness | `Crypto/{Assumptions,EUFCMA}.lean` |
| § 4.3 — AA scaffolding | `Wallet/{Storage,MultiOwnable,ValidateUserOp,Factory,Invariants}.lean` |
| § 4.4 Recipe C1 — Bridge to deployed bytecode | `Bridge/{SolidityVerifier,Refinement}.lean` |
| § 5.1 Track 1 step 1 — Lean reference verifier | `SphincsCVerify/Spec/*` |
| § 5.1 Track 1 step 2 — AA scaffolding via Verity | Modelled in `Wallet/`; full Verity rewrite deferred |
| § 5.1 Track 1 step 3 — Bridge proof | `Verifier/Equivalence.lean` + `Bridge/Refinement.lean` |
| § 5.4 Trust report | `docs/TRUST_ASSUMPTIONS.md` |

## How to verify the project

```bash
cd contracts/verification/lean
elan toolchain install $(cat lean-toolchain)
lake update
lake build                               # Type-checks every module.
lake env lean --run scripts/check_no_sorry.lean   # Audit `sorry` count.
lake env lean --run scripts/dump_axioms.lean      # Print every axiom used by headline theorems.
```

A clean build → every closed theorem is checked by the Lean kernel. The
audit scripts surface the remaining work (each `sorry` and each
`axiom`).
