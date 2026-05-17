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
#print axioms SphincsCVerify.Bridge.yul_eq_refined
