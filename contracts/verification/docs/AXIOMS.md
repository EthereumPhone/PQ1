# Axioms — PQSmartWallet Theft-Freedom Proof

Machine-checkable inventory of every `axiom` declaration the headline
theorem `theft_free` depends on. Regenerate with:

```bash
cd contracts/verification/lean
lake env lean --run scripts/dump_axioms.lean
```

If a new `axiom` appears that is not on this list, CI fails.

The mapping to the six lettered assumptions in
[`TRUST_ASSUMPTIONS.md`](TRUST_ASSUMPTIONS.md):

| Trust assumption | Lean axiom(s) |
|---|---|
| A1 (SHA-256 precompile) | `Bridge.precompile_0x02_is_FIPS_180_4` |
| A2 (EntryPoint v0.6 unhackable) | `Bridge.entrypoint_honest` (to be added) |
| A3 (solc 0.8.28 compiles correctly) | `Bridge.solidityVerifier_compiles_correctly` (generalised) |
| A4 (EVM executes per spec) | `Bridge.evm_bytecode_executes_correctly` |
| A5 (SPHINCS+C10 EUF-CMA) | `Crypto.EUF_CMA_SPHINCSplusC` + `Crypto.SM_DT_TCR_F` + `Crypto.ITSR_F` + `Crypto.hMsg_random_oracle` |
| A6 (Lean kernel correctness) | Lean built-ins: `propext`, `Classical.choice`, `Quot.sound` |

---

## A. Cryptographic axioms — `Crypto/`

### `Crypto.SM_DT_TCR_F`

* **File**: `SphincsCVerify/Crypto/Assumptions.lean`
* **Statement**: SPHINCS+ chain-step tweakable hash
  `F(seed, ADRS, x) = sha256(seed ‖ ADRS ‖ x)[0..16]` is single-function
  multi-target distinct-tweak target-collision resistant.
* **Citation**: Barbosa/Dupressoir/Hülsing/Meijers/Strub ASIACRYPT 2024
  (ePrint 2024/910) §§ 4-5, Theorem 1.

### `Crypto.ITSR_F`

* **File**: `SphincsCVerify/Crypto/Assumptions.lean`
* **Statement**: Interleaved Target Subset Resilience holds for the
  FORS roots compression hash.
* **Citation**: Barbosa et al. ASIACRYPT 2024 § 6, Theorem 2.

### `Crypto.hMsg_random_oracle`

* **File**: `SphincsCVerify/Crypto/Assumptions.lean`
* **Statement**: `H_msg` is modelled as a random oracle.
* **Citation**: Barbosa et al. ASIACRYPT 2024 § 7.

### `Crypto.EUF_CMA_SPHINCSplusC`

* **File**: `SphincsCVerify/Crypto/EUFCMA.lean`
* **Statement**: SPHINCS+C10 forgery probability is bounded by
  `ε(A) + Q · 2^-128` for any PPT `A` making `Q` signing queries.
* **Citation**: Hülsing PQC2022 (WOTS+C / FORS+C variant) +
  Barbosa et al. ASIACRYPT 2024 extension.

## B. EVM / compilation / EntryPoint TCB axioms — `Bridge/`

### `Bridge.solidityVerifier_compiles_correctly`

* **File**: `SphincsCVerify/Bridge/Refinement.lean`
* **Statement**: `solc 0.8.28` compiles `PQSmartWallet.sol`,
  `PQMultiOwnable.sol`, `PQSmartWalletFactory.sol`, and
  `verifiers/SPHINCsC10Asm.sol` to EVM bytecode that faithfully
  implements the Yul/Solidity-source semantics modelled in
  `SphincsCVerify/Wallet/` and `SphincsCVerify/Bridge/SolidityVerifier.lean`.
* **Mitigation**: Foundry pins `solc 0.8.28`; differential tests
  against the Rust reference.

### `Bridge.evm_bytecode_executes_correctly`

* **File**: `SphincsCVerify/Bridge/Refinement.lean`
* **Statement**: EVM bytecode executes per the official EVM
  specification (Cancun or as configured per chain).

### `Bridge.precompile_0x02_is_FIPS_180_4`

* **File**: `SphincsCVerify/Bridge/Refinement.lean`
* **Statement**: The EVM precompile at address `0x02` implements
  FIPS 180-4 SHA-256.

### `Bridge.EntryPoint.entrypoint_honest`

* **File**: `SphincsCVerify/Bridge/EntryPoint.lean`
* **Statement**: For any `σ : State`, `op : UserOperation`, `effects`,
  if `handleOp σ op effects` decreases the wallet's balance, then
  `validateSignature σ.walletStorage op σ.entryPointAddress σ.chainId
   deployedVerifier = (Result.success, (handleOp σ op effects).walletStorage)`.

  Captures: (a) wallet execution runs only after `validateUserOp`
  returned success; (b) the EntryPoint never directly debits the wallet
  balance; (c) `userOpHash` is computed per ERC-4337 v0.6 (channelled
  through the wallet's `sphincsDigest`).
* **Mitigation**: Audited (OpenZeppelin / ChainSecurity / Spearbit)
  and immutable contract at the canonical EntryPoint v0.6 address;
  ≥18 months of mainnet operation as of 2026-05.
* **Elimination path**: Model EntryPoint v0.6 in Lean and discharge
  against KEVM / EVMYulLean. Multi-person-year work; not pursued.

## C. Section-lemma `sorry`s — work-in-progress

These are not `axiom`s — they are `theorem` declarations whose proofs
end with `sorry`. They do **not** block the headline `theft_free`
(which has its own complete proof using A1–A5); they are
functional-correctness theorems whose closure strengthens the
verifier characterisation. See [`BLOCKERS.md`](BLOCKERS.md) for the
honest scope report.

| Location | Theorem | Discharge plan |
|---|---|---|
| `Spec/Theorems.lean` | `verify_signs` | Four round-trip sub-lemmas (Merkle, WOTS+C chain, FORS+C, chain-hash compose) on top of a kernel-computable FIPS 180-4 SHA-256. |
| `Verifier/Equivalence.lean` | `load_R_consistent` | `simp` after real `deserialise` is in place. |
| `Verifier/Equivalence.lean` | `verifyRefined_eq_spec` | Composes the four section lemmas. |

| Location | Theorem | Status |
|---|---|---|
| `Crypto/EUFCMA.lean` | `cannot_forge_without_breaking_SHA256` | ✅ Closed via restructured `EUF_CMA_SPHINCSplusC` taking the three primitives as preconditions. |
| `Wallet/Invariants.lean` | `validateSignature_only_via_verify` (I-1) | ✅ Closed. |
| `Wallet/Invariants.lean` | `validateSignature_bootstrap_monotonic` (I-2) | ✅ Closed. |
| `Wallet/Invariants.lean` | `validateSignature_slot_monotonic` (I-2) | ✅ Closed. |
| `Wallet/Invariants.lean` | `combinedCap_inductive` (I-5 full) | ✅ Closed. |
| `Wallet/Invariants.lean` | `eip1271_forbids_bootstrap` (I-6) | ✅ Closed (via `Wallet/IsValidSignature.lean`). |
| `Wallet/Invariants.lean` | `factory_requires_bootstrap_sig` (I-8) | ✅ Closed. |
| `Spec/Theorems.lean` | `theft_free` (headline) | ✅ Closed with exact required axiom set. |

## D. Behavioural — declared `opaque`, not axioms

* `Spec.Hash.sha256 : List ByteSeg → ByteVec 32` — declared `opaque`
  pre-completion. Becomes definitional (FIPS 180-4) as part of the
  Verifier group; this entry disappears at that point.

---

## Build-time audit

```bash
cd contracts/verification/lean
lake build
lake env lean --run scripts/dump_axioms.lean
```

After completion of `OPEN_PROOF_OBLIGATIONS.md`, the audit should show
exactly:

```text
#print axioms SphincsCVerify.Spec.Theorems.theft_free
-- propext, Classical.choice, Quot.sound,
-- Crypto.SM_DT_TCR_F, Crypto.ITSR_F, Crypto.hMsg_random_oracle,
-- Crypto.EUF_CMA_SPHINCSplusC,
-- Bridge.precompile_0x02_is_FIPS_180_4,
-- Bridge.solidityVerifier_compiles_correctly,
-- Bridge.evm_bytecode_executes_correctly,
-- Bridge.EntryPoint.entrypoint_honest
```

**As of 2026-05-17**, this is the exact set printed by
`#print axioms SphincsCVerify.Spec.Theorems.theft_free`. The headline
theorem is closed; the remaining `sorry`s sit in independent
functional-correctness theorems (see § C above and
[`BLOCKERS.md`](BLOCKERS.md)).
