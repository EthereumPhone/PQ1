# Proof Map — PQSmartWallet Theft-Freedom

> **Current-status correction — 2026-07-15.** The reference signer,
> `findCount_post`, component roundtrips, and `honest_consistent` are closed in
> the Lean model. The open boundary is production firmware signer/serialization
> → that model; KATs are not a kernel refinement theorem. Clean compilation
> establishes type/kernel acceptance of the committed artifact, not extraction
> freshness or deployed identity. Exact closure claims must resolve through the
> machine-readable closure entries, not the shorthand “A1–A5.” See the
> [coordinator report](../../../docs/security/adversarial-review/findings/fv-full-stack-2026-07-15-coordinator.md).

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
| Kernel-computable SHA-256 | `sha256` (def) | `Spec/Hash.lean` | ✅ Closed — FIPS 180-4 port from Trail of Bits scroll-fv, sealed `@[irreducible]` so axiom set unchanged; NIST CAVS vectors verified. |
| Tweakable-hash unfolds to SHA-256 | `sha256_eq_impl` | `Spec/Hash.lean` | ✅ Closed via `rfl` (since `sha256 := sha256_impl` under the irreducible seal, with `sha256_eq_impl` as the unfolding bridge). |
| Reference signer complete | `Signer.sign` (def) | `Spec/Signer.lean` | ✅ Closed in the Lean model; production implementation bridge remains open. Not load-bearing for `theft_free`. |
| `findCount` correctness | `findCount_post` | `Spec/SignerPost.lean` | ✅ Closed in the Lean model; not load-bearing for `theft_free`. |
| Real `deserialise` | `Signature.deserialise` (def) | `Spec/Signature.lean` | ✅ Concretised — byte-level decoder mirroring Yul's `calldataload(add(sigBase, …))` arithmetic. |
| `serialise/deserialise` round-trip | `serialise_deserialise_roundtrip` | `Spec/Signature.lean` | ⏳ Not stated; not load-bearing. |
| Merkle round-trip | `merkle_roundtrip` | `Verifier/MerkleRoundtrip.lean` | ✅ Closed in the Lean model. |
| WOTS+C chain round-trip | `wots_chain_roundtrip` | `Verifier/WotsRoundtrip.lean` | ✅ Closed in the Lean model. |
| FORS+C round-trip | `fors_roundtrip` | `Verifier/ForsRoundtrip.lean` | ✅ Closed in the Lean model. |
| Chain-hash composition | `chainHash_compose` | `Verifier/WotsRoundtrip.lean` | ✅ Closed in the Lean model. |
| Sign/verify round-trip | `verify_signs`, `honest_consistent` | `Spec/Theorems.lean`, `Verifier/HonestConsistent.lean` | ✅ Closed for `WellFormed` Lean-model keys. Production firmware signer/serialization→model refinement remains open and is not in `theft_free`'s dependency closure. |

## Verifier refinement (Lean spec ↔ Yul shape)

| Claim | Lean theorem | File | Status |
|---|---|---|---|
| Load R consistent | `load_R_consistent` | `Verifier/Equivalence.lean` | ✅ Closed (`rfl`) after `loadValue16`/`loadU32BE` moved to `Spec/Bytes.lean` and `deserialise` concretised. |
| FORS section consistent | `fors_section_consistent` | `Verifier/Equivalence.lean` | ✅ Folded into `Refined.reconstructForsPkRefined`'s body — the per-section equality now holds by construction. |
| HT layer-0 consistent | `ht_layer0_consistent` | `Verifier/Equivalence.lean` | ✅ Folded into `Refined.hypertreeLayerStep`'s body. |
| HT layer-1 consistent | `ht_layer1_consistent` | `Verifier/Equivalence.lean` | ✅ Folded into `Refined.hypertreeLayerStep`'s body. |
| Refined ≡ Spec | `verifyRefined_eq_spec` | `Verifier/Equivalence.lean` | ✅ Closed (`rfl`) after `Refined.verifyRefined` was refactored to delegate the byte-offset arithmetic to `Spec.Signature.deserialise`. |
| Yul model ≡ Refined | `yul_eq_refined` | `Bridge/SolidityVerifier.lean` | ✅ Closed (`rfl`) |

## Wallet invariants

| Invariant | Lean theorem | File | Status |
|---|---|---|---|
| I-1 Non-bypass | `validateSignature_only_via_verify` | `Wallet/Invariants.lean` | ✅ Closed |
| I-2 Bootstrap monotonicity | `validateSignature_bootstrap_monotonic` | `Wallet/Invariants.lean` | ✅ Closed |
| I-2 Slot monotonicity | `validateSignature_slot_monotonic` | `Wallet/Invariants.lean` | ✅ Closed |
| I-3 No reset (structural) | `no_reset_path` + Storage no-decrease lemmas | `Wallet/Invariants.lean` | ✅ Closed (per-mutator; now incl. cross-counter preservation; covers the 5 counter mutators bumpBootstrap/bumpSlot/setOffchain/addOwner/removeOwner; since 2026-10-20 the 4 that remain, `removeOwner` having been deleted with the Solidity function. `tryInitialize` — a 6th counter mutator that zeroes the counters at construction — is excluded by the one-shot `nextOwnerIndex == 0` init guard, NOT by `no_reset_path`. `no_reset_path` is a per-method monotonicity statement, not an assembled reachable-state theorem.) |
| I-4 Bootstrap unremovable | `cannot_remove_bootstrap` / `bootstrap_unremovable` | `Wallet/Invariants.lean` / `Wallet/MultiOwnable.lean` | ✅ Closed (restated 2026-10-20 after removal was deleted: on an initialised state `addOwner` leaves `ownerAtIndex 0` unchanged, and no other operation writes the owner table; per-mutator + one-shot init guard; the owner-set-never-empty guarantee is per-mutator preservation of `ownerAtIndex 0` plus `owner_set_nonempty_after_init` on the `initialised` state, NOT an assembled reachable-state theorem) |
| I-9 Append-only owner set (2026-10-20, #131) | `reachable_ownerTableWF`, `reachable_key_installed_at_most_once`, `reachable_addOwner_refuses_installed_key` | `Wallet/Invariants.lean` | ✅ Closed (assembled over `Reachable`: the owner table is injective, every installed key is flagged and below `nextOwnerIndex`, and `addOwner` refuses an installed key, so a key's counters can never be reset by re-installing it; closures `[propext, Quot.sound]`) |
| I-5 Combined cap (per-method + inductive) | `combinedCap_preserved_by_*`, `combinedCap_inductive` | `Wallet/Invariants.lean` | ✅ Closed |
| I-6 EIP-1271 forbids bootstrap | `eip1271_forbids_bootstrap` + `test/halmos/HalmosIsValidSignature.t.sol` | `Wallet/Invariants.lean` (model in `Wallet/IsValidSignature.lean`) | ✅ Model-proven AND now bytecode-discharged (2026-06-29): `HalmosIsValidSignature` (3 rules, BOTH profiles; 5 since 2026-10-20, adding the legacy `isValidSignature(bytes,bytes)` entry's agreement with the `bytes32` entry and its bootstrap rejection, with Lean `erc1271IsValidSignatureLegacy_rejects_bootstrap`) covers the net-new EIP-1271 surface the A3.2 harnesses skip. `check_isValidSignature_forbids_bootstrap` is a clean bytecode **∀** over `hash` + symbolic verifier (ownerIndex 0 rejected before the `ownerAtIndex` read + keccak nesting); `_nonbypass_slot1` (magic ⇒ verifier-true) + `_no_counter_bump` (view-only) over the **installed** slot 1. Disclosed ceiling (= A3.2): the non-bypass/view-only rules use the installed index as a concrete rep — a symbolic unset index `NotConcreteError`s on the `ownerAtIndex` dynamic getter, so those two are per-property B, not symbolic-∀ over all indices. No `solidityEip1271_compiles_correctly` bridge axiom; the Halmos session stands alone (as the per-property `HalmosValidateUserOp` rules do for A3.2). keccak (`replaySafeHash`) uninterpreted. |
| I-7 CREATE2 chain-independent | `create2_address_chain_independent`, `create2_salt_definition` | `Wallet/Invariants.lean` | ✅ Salt-preimage chain-freeness is kernel-proven (`create2_salt_definition`, `create2_address_chain_independent` — both reduce the salt to `sha256(masterPkSeed‖masterPkRoot)`, no chain id). Address-level chain-independence is CONDITIONAL: the distinct `create2Address_chain_independent` (camelCase — NOT the snake_case salt-only theorem above) requires the EVM-TCB facts `d1=d2` (singleton-deployer factory deployed to one address per chain) and `ich1=ich2` (chain-free `keccak256(initCode)`); it is not an unconditional kernel theorem. |
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
