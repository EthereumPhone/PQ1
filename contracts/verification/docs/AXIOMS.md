# Axioms — SPHINCS+C10 Verifier Formal Verification

This document is the **machine-checkable inventory** of every `axiom`
declaration in the SphincsCVerify Lean project under the current
verifier-only scope. Regenerate with:

```bash
cd contracts/verification/lean
lake env lean --run scripts/dump_axioms.lean
```

Every axiom is cross-referenced with [`TRUST_ASSUMPTIONS.md`](TRUST_ASSUMPTIONS.md).
If a new `axiom` ever appears that is not on this list, the CI build
fails.

The wallet contracts and the hardware-wallet firmware are out of scope
and do not contribute axioms to this inventory; see
[`OPEN_PROOF_OBLIGATIONS.md`](OPEN_PROOF_OBLIGATIONS.md) for what would
need to be added if their scope were re-included.

---

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
* **Justification**: Barbosa et al. ASIACRYPT 2024 § 6. The security of
  FORS reduces to it via Theorem 2.
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
* **Justification**: Extension of Barbosa et al. ASIACRYPT 2024 to the
  WOTS+C/FORS+C variants per Hülsing PQC2022.
* **TCB layer**: 4.
* **Elimination path**: Multi-person-year EasyCrypt extension; see
  Phase "Out of scope" in [`OPEN_PROOF_OBLIGATIONS.md`](OPEN_PROOF_OBLIGATIONS.md).

## B. EVM / compilation TCB axioms

### `Bridge.solidityVerifier_compiles_correctly`

* **File**: `SphincsCVerify/Bridge/Refinement.lean`
* **Statement**: `solc 0.8.28` correctly compiles `SPHINCsC10Asm.verify`
  to EVM bytecode that produces the same boolean as `verifyYulModel`.
* **Justification**: Empirically validated by Foundry differential
  tests against the Rust reference.
* **TCB layer**: 2 (compilation).
* **Elimination path**: Verity-style verified compilation — re-author
  `SPHINCsC10Asm` in Verity's Lean EDSL → Yul pipeline
  (~3–6 person-months).

### `Bridge.evm_bytecode_executes_correctly`

* **File**: `SphincsCVerify/Bridge/Refinement.lean`
* **Statement**: EVM bytecode executes per the official EVM
  specification (Cancun upgrade or as configured per chain).
* **Justification**: Universal Ethereum assumption.
* **TCB layer**: 3.
* **Elimination path**: Adopt a formal EVM semantics (KEVM,
  Dafny-EVM, EVMYulLean) and discharge against it.

### `Bridge.precompile_0x02_is_FIPS_180_4`

* **File**: `SphincsCVerify/Bridge/Refinement.lean`
* **Statement**: The EVM precompile at address `0x02` implements
  FIPS 180-4 SHA-256.
* **Justification**: Consensus-client assumption; validated by Ethereum
  test-vector conformance.
* **TCB layer**: 3.
* **Elimination path**: Verify the SHA-256 implementation in geth/reth
  against FIPS 180-4 (Appel-style VST/Coq SHA-256 work). Outside any
  single smart-contract project's scope.

## C. Section-lemma `sorry`s (work-in-progress functional proofs)

These are **not** `axiom`s — they are `theorem` declarations whose
proofs end with `sorry`. They are pending closure under the phased plan
in [`OPEN_PROOF_OBLIGATIONS.md`](OPEN_PROOF_OBLIGATIONS.md).

| Location | Theorem | Phase | Discharge plan |
|---|---|---|---|
| `Spec/Theorems.lean` | `verify_signs` | 5 | Four round-trip sub-lemmas (Merkle, WOTS+C chain, FORS+C, chain-hash compose); ~500–1500 LoC. |
| `Verifier/Equivalence.lean` | `load_R_consistent` | 6 | `simp` after Phase 4 makes `deserialise` concrete. |
| `Verifier/Equivalence.lean` | `fors_section_consistent` | 6 | Offset arithmetic; ~200 LoC. |
| `Verifier/Equivalence.lean` | `ht_layer0_consistent` | 6 | Same shape; ~200 LoC. |
| `Verifier/Equivalence.lean` | `ht_layer1_consistent` | 6 | Same shape, copy of layer-0; ~150 LoC. |
| `Verifier/Equivalence.lean` | `verifyRefined_eq_spec` | 6 | Composes the four section lemmas; ~50 LoC. |
| `Crypto/EUFCMA.lean` | `cannot_forge_without_breaking_SHA256` | Out of scope | Needs probability-game model in Lean; tied to the cryptographic-soundness research path. |

**Phase 1 (2026-05) closed:** `readBitsLe_lt`, `extractForsIndices_lt`,
`extractDigits_lt` in `Util/Bits.lean`;
`verify_rejects_nonzero_last_fors_idx` in `Spec/Theorems.lean`. The
`True`-placeholder `verify_rejects_bad_digit_sum` was replaced with a
meaningful structural-propagation lemma plus a new unit-content lemma
`pkFromSig_returns_none_of_bad_digit_sum`. See
[`OPEN_PROOF_OBLIGATIONS.md`](OPEN_PROOF_OBLIGATIONS.md) § "Phase 1
closing notes" for the full diff.

## D. Behavioural (declared `opaque`, not axioms)

* `Spec.Hash.sha256 : List ByteSeg → ByteVec 32` — declared `opaque`
  pre-Phase 2. After Phase 2 it becomes definitional and this entry
  disappears.

---

## Build-time audit

```bash
cd contracts/verification/lean
lake build
lake env lean --run scripts/dump_axioms.lean
```

Run `#print axioms` over the headline theorems to confirm the full
axiom dependency tree. After every phase, the audit should show only
the axioms listed above plus Lean kernel built-ins (`propext`,
`Classical.choice`, `Quot.sound`):

```lean
#print axioms SphincsCVerify.Spec.Theorems.verify_signs
#print axioms SphincsCVerify.Verifier.verifyRefined_eq_spec
#print axioms SphincsCVerify.Bridge.deployed_verifier_refines_spec
```
