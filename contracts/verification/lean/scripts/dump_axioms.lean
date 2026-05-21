/-
Audit script: prints every axiom used by the headline theorems.

Run via `lake env lean scripts/dump_axioms.lean`.

This is the mechanical equivalent of Verity's `--trust-report`: every
axiom transitively used by the project's claimed theorems appears here.
-/

import SphincsCVerify

-- (Run as `lake env lean scripts/dump_axioms.lean` so the `#print axioms`
-- commands are elaborated and their output appears.)

#print axioms SphincsCVerify.Spec.signatureLen_eq_4008
#print axioms SphincsCVerify.Spec.maxUses_lt_positions
#print axioms SphincsCVerify.Spec.Theorems.verify_deterministic
#print axioms SphincsCVerify.Spec.Theorems.verify_rejects_wrong_length
#print axioms SphincsCVerify.Wallet.MultiOwnable.bumpBootstrap_monotonic
#print axioms SphincsCVerify.Wallet.MultiOwnable.bumpSlot_monotonic
#print axioms SphincsCVerify.Wallet.MultiOwnable.bootstrap_unremovable
#print axioms SphincsCVerify.Wallet.Invariants.combinedCap_preserved_by_bumpSlot
#print axioms SphincsCVerify.Wallet.Invariants.create2_address_chain_independent
#print axioms SphincsCVerify.Wallet.Invariants.validateSignature_only_via_verify
#print axioms SphincsCVerify.Wallet.Invariants.combinedCap_inductive
#print axioms SphincsCVerify.Wallet.Invariants.eip1271_forbids_bootstrap
#print axioms SphincsCVerify.Wallet.Invariants.factory_requires_bootstrap_sig
#print axioms SphincsCVerify.Crypto.cannot_forge_without_breaking_SHA256
#print axioms SphincsCVerify.Bridge.yul_eq_refined
-- Headline theorem — should depend on exactly:
--   propext, Classical.choice, Quot.sound  (Lean kernel)
--   SM_DT_TCR_F, ITSR_F, hMsg_random_oracle, EUF_CMA_SPHINCSplusC  (A5)
--   precompile_0x02_is_FIPS_180_4 (A1), entrypoint_honest (A2),
--   solidityVerifier_compiles_correctly (A3.1), evm_bytecode_executes_correctly (A4)
#print axioms SphincsCVerify.Spec.Theorems.theft_free

-- Claim 1 corollary — adds sha256_injective_on_fixed_length to the closure.
#print axioms SphincsCVerify.Spec.Theorems.theft_free_with_calldata_binding

-- Claim 3 corollary — composes the 6 Wallet.Execute theorems.
#print axioms SphincsCVerify.Spec.Theorems.executeBatch_faithful

-- Claim 2 corollaries — owner-set integrity + initialization atomicity
-- (covered by I-4 + initialize_called_exactly_once + owner_set_nonempty_after_init).
#print axioms SphincsCVerify.Wallet.Invariants.initialize_called_exactly_once
#print axioms SphincsCVerify.Wallet.Invariants.owner_set_nonempty_after_init
#print axioms SphincsCVerify.Wallet.Invariants.storage_mutations_preserve_impl_slot_disjointness
