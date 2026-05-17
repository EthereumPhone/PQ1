# Axioms — SPHINCS+C10 PQSmartWallet Formal Verification

This document is the **machine-checkable inventory** of every `axiom`
declaration in the SphincsCVerify Lean project. To regenerate it:

```bash
cd contracts/verification/lean
lake env lean --run scripts/dump_axioms.lean
```

Every axiom is cross-referenced with `TRUST_ASSUMPTIONS.md`. If a new
`axiom` ever appears that is not on this list, the CI build fails.

## A. Cryptographic axioms (over `Spec.sha256`)

### `Crypto.SM_DT_TCR_F`

* **File**: `SphincsCVerify/Crypto/Assumptions.lean`
* **Statement**: For every list of distinct ADRS tweaks and every set of
  message inputs, no PPT adversary produces a tweak-distinct collision
  on the SPHINCS+ chain-step tweakable hash `F`.
* **Justification**: Barbosa/Dupressoir/Hülsing/Meijers/Strub
  ASIACRYPT 2024 (IACR ePrint 2024/910) §§ 4-5 and Theorem 1; reduction
  to the 128-bit SM-DT-TCR generic-attack lower bound on SHA-256.
* **TCB layer**: 4 (cryptographic).
* **Elimination path**: Mechanise the multi-target target-collision
  argument in EasyCrypt and port to Lean.

### `Crypto.ITSR_F`

* **File**: `SphincsCVerify/Crypto/Assumptions.lean`
* **Statement**: Interleaved Target Subset Resilience holds for the
  FORS roots compression hash.
* **Justification**: Barbosa et al. ASIACRYPT 2024 § 6. Standard
  hash-based-signature property; the security of the FORS construction
  reduces to it via Theorem 2.
* **TCB layer**: 4.
* **Elimination path**: Same as `SM_DT_TCR_F`.

### `Crypto.hMsg_random_oracle`

* **File**: `SphincsCVerify/Crypto/Assumptions.lean`
* **Statement**: The message-hash function `H_msg` is modelled as a
  random oracle.
* **Justification**: Required for the tight bound in Barbosa et al.
  ASIACRYPT 2024 § 7. Can be weakened to "indistinguishable from
  random" with a constant-factor loss.
* **TCB layer**: 4.
* **Elimination path**: Switch to a standard-model security proof
  (significant theory change; bound loosens).

### `Crypto.EUF_CMA_SPHINCSplusC`

* **File**: `SphincsCVerify/Crypto/EUFCMA.lean`
* **Statement**: For every PPT adversary `A`, `A`'s forgery probability
  against SPHINCS+C10 is bounded by `ε(A) + Q · negligible(n)`.
* **Justification**: Extension of Barbosa/Dupressoir/Hülsing/Meijers/Strub
  ASIACRYPT 2024 SPHINCS+ proof to the WOTS+C/FORS+C variants per
  Hülsing et al. PQC2022.
* **TCB layer**: 4.
* **Elimination path**: Multi-person-year EasyCrypt extension; see
  § 3.2 and § 4.7 of `docs/how_to_math_proof_secureness.md`.

## B. EVM / compilation TCB axioms

### `Bridge.solidityVerifier_compiles_correctly`

* **File**: `SphincsCVerify/Bridge/Refinement.lean`
* **Statement**: `solc 0.8.28` correctly compiles `SPHINCsC10Asm.verify`
  to EVM bytecode that produces the same boolean as `verifyYulModel`.
* **Justification**: Empirically validated by Foundry differential
  tests against the Rust reference.
* **TCB layer**: 2 (compilation).
* **Elimination path**: Verity-style verified compilation (re-author
  the verifier in a verified Lean EDSL → Yul pipeline).

### `Bridge.evm_bytecode_executes_correctly`

* **File**: `SphincsCVerify/Bridge/Refinement.lean`
* **Statement**: EVM bytecode executes per the official EVM
  specification (Cancun upgrade or as configured per chain).
* **Justification**: Universal Ethereum assumption.
* **TCB layer**: 3.
* **Elimination path**: Adopt a formal EVM semantics (KEVM, Dafny-EVM,
  EVMYulLean) and discharge against it.

### `Bridge.precompile_0x02_is_FIPS_180_4`

* **File**: `SphincsCVerify/Bridge/Refinement.lean`
* **Statement**: The EVM precompile at address `0x02` implements
  FIPS 180-4 SHA-256.
* **Justification**: Consensus-client assumption; validated by
  Ethereum test-vector conformance.
* **TCB layer**: 3.
* **Elimination path**: Verify the SHA-256 implementation in geth/reth
  against FIPS 180-4 (Appel-style VST/Coq SHA-256 work). Far outside
  the scope of any single smart-contract project.

## C. Selector opacity (Solidity ABI assumption)

### `Wallet.ValidateUserOp.Selector.addOwnerBytes` (and siblings)

* **File**: `SphincsCVerify/Wallet/ValidateUserOp.lean`
* **Statement**: These are 4-byte function selectors, modelled as
  opaque `ByteVec 4` constants. The actual byte values come from
  `bytes4(keccak256("addOwnerBytes(bytes)"))` etc.
* **Justification**: Solidity ABI convention; the Lean spec does not
  need the concrete values to reason about non-bypass — only that the
  Solidity verifier and Lean spec agree on the *same* selector for the
  *same* function.
* **TCB layer**: 5 (wallet-specific; trivially discharged by
  inspection).
* **Elimination path**: Compute the selectors via a kernel-checked
  keccak256 implementation in Lean (small enough to do; on the
  roadmap).

### `Wallet.ValidateUserOp.sphincsDigest`

* **File**: `SphincsCVerify/Wallet/ValidateUserOp.lean`
* **Statement**: `sphincsDigest` is the deterministic SHA-256 hash of
  the UserOp fields per the formula in `PQSmartWallet.sol::sphincsDigest`.
* **Justification**: Modelled abstractly because the wallet-level
  invariants do not depend on the specific byte layout, only on
  determinism.
* **TCB layer**: 5.
* **Elimination path**: Inline the concrete sha256-of-fields definition
  once we have the kernel-computable SHA-256 spec.

### `Wallet.Factory.factoryAddSlotDomain`

* **File**: `SphincsCVerify/Wallet/Factory.lean`
* **Statement**: A 26-byte domain tag whose bytes are
  `pqsigner.factoryAddSlot.v1`.
* **Justification**: Mirrors `PqsignerProto.FACTORY_ADD_SLOT_DOMAIN`.
* **TCB layer**: 5.
* **Elimination path**: Use a `ByteVec.ofAscii "pqsigner.factoryAddSlot.v1"`
  literal once that helper has its length lemma discharged.

## D. Section-lemma `sorry`s (work-in-progress functional proofs)

These are **not** `axiom`s — they are `theorem` declarations whose
proofs end with `sorry`. They reduce to mechanical structural reasoning
and are listed here so they show up in the build audit.

| Location | Theorem | Discharge plan |
|---|---|---|
| `Util/Bits.lean` | `readBitsLe_lt` | Induction on `numBits`; OR-with-shifted-bit is bounded by `2^numBits - 1`. ~30 LoC. |
| `Util/Bits.lean` | `extractForsIndices_lt` | Direct from `readBitsLe_lt`. ~5 LoC. |
| `Util/Bits.lean` | `extractDigits_lt` | Direct from `readBitsLe_lt` with `LogW = 3`. ~5 LoC. |
| `Spec/Bytes.lean` | `ByteVec.ofAscii.size_eq` | `Array.size_map` + `String.length_eq_data_length`. ~10 LoC. |
| `Spec/Theorems.lean` | `verify_signs` | Four round-trip lemmas (Merkle, WOTS+C chain, FORS+C, hypertree). ~500-1500 LoC. |
| `Spec/Theorems.lean` | `verify_rejects_nonzero_last_fors_idx` | `simp` on the `if-then-else` cascade in `Hypertree.verify`. ~20 LoC. |
| `Verifier/Equivalence.lean` | `verifyRefined_eq_spec` (+ 4 section lemmas) | Offset-arithmetic alignment between `Refined` and `Spec.Signature.verify`. ~1000-3000 LoC. |
| `Wallet/Invariants.lean` | `validateSignature_only_via_verify` | Awaits `decodeWrappedSig` completion + `split`-based case analysis. ~200 LoC. |
| `Wallet/Invariants.lean` | `validateSignature_bootstrap_monotonic`, `_slot_monotonic` | Same as `_only_via_verify`. ~50 LoC each. |
| `Crypto/EUFCMA.lean` | `cannot_forge_without_breaking_SHA256` | Need a probability-game model to discharge from the EUF-CMA axiom. Strictly tied to the cryptographic-soundness path. ~3-6 person-months in Lean, or step out to EasyCrypt. |

## E. Behavioural axioms (not really axioms — restated theorems)

The following look like axioms but are extracted as `theorem` /
`opaque` declarations whose meaning is *implementation*, not
*assumption*. Included here for transparency.

* `Spec.Hash.sha256 : List ByteSeg → ByteVec 32` — declared `opaque`.
  Treating SHA-256 as opaque is **not** an axiom about its behaviour —
  it is a deliberate abstraction. The behaviour is constrained by the
  cryptographic axioms in group A.

---

## Build-time audit

Run `#print axioms` over the headline theorems to confirm the full
axiom dependency tree. Specifically these calls should each show only
the axioms listed above (plus Lean kernel `propext`, `Classical.choice`,
`Quot.sound`):

```lean
#print axioms SphincsCVerify.Spec.Theorems.verify_signs
#print axioms SphincsCVerify.Wallet.Invariants.cannot_remove_bootstrap
#print axioms SphincsCVerify.Wallet.Invariants.combinedCap_preserved_by_bumpSlot
#print axioms SphincsCVerify.Wallet.Invariants.create2_address_chain_independent
```
