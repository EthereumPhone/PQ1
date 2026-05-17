/-
PQMultiOwnable invariants — the access-control machinery underlying
`PQSmartWallet`. The state-transition operations (`addOwner`,
`removeOwner`, `bumpBootstrap`, `bumpSlot`, `setOffchain`) are all in
`Storage`; this module proves the *monotonicity* and *invariants* that
the wallet relies on.

Every theorem here is fully discharged (no `sorry`).
-/

import SphincsCVerify.Wallet.Storage

namespace SphincsCVerify.Wallet.MultiOwnable

open SphincsCVerify.Wallet
open SphincsCVerify.Wallet.Storage

/-! ## Monotonicity of usage counters -/

theorem bumpBootstrap_monotonic
    (s : Storage) (cap : Nat) (s' : Storage)
    (h : bumpBootstrap s cap = some s') :
    s'.bootstrapUses = s.bootstrapUses + 1 := by
  unfold bumpBootstrap at h
  by_cases hcap : s.bootstrapUses + 1 > cap
  · simp [hcap] at h
  · simp [hcap] at h
    rw [← h]

theorem bumpBootstrap_capped
    (s : Storage) (cap : Nat) (s' : Storage)
    (h : bumpBootstrap s cap = some s') :
    s'.bootstrapUses ≤ cap := by
  unfold bumpBootstrap at h
  by_cases hcap : s.bootstrapUses + 1 > cap
  · simp [hcap] at h
  · simp [hcap] at h
    rw [← h]
    show s.bootstrapUses + 1 ≤ cap
    omega

theorem bumpSlot_monotonic
    (s : Storage) (i cap : Nat) (s' : Storage)
    (h : bumpSlot s i cap = some s') :
    s'.slotUses i = s.slotUses i + 1 := by
  unfold bumpSlot at h
  by_cases hcap : s.slotUses i + 1 > cap
  · simp [hcap] at h
  · simp [hcap] at h
    rw [← h]
    simp

theorem bumpSlot_no_cross_effect
    (s : Storage) (i j cap : Nat) (s' : Storage)
    (h : bumpSlot s i cap = some s') (hne : i ≠ j) :
    s'.slotUses j = s.slotUses j := by
  unfold bumpSlot at h
  by_cases hcap : s.slotUses i + 1 > cap
  · simp [hcap] at h
  · simp [hcap] at h
    rw [← h]
    simp
    intro h_eq
    exact absurd h_eq.symm hne

/-! ## Off-chain monotonicity -/

theorem setOffchain_monotonic
    (s : Storage) (i newCount slotUsesNow cap : Nat) (s' : Storage)
    (h : setOffchain s i newCount slotUsesNow cap = some s') :
    s.offchainSigCount i ≤ s'.offchainSigCount i := by
  unfold setOffchain at h
  by_cases hlt : newCount < s.offchainSigCount i
  · simp [hlt] at h
  · by_cases hcap : slotUsesNow + newCount > cap
    · simp [hlt, hcap] at h
    · simp [hlt, hcap] at h
      rw [← h]
      change s.offchainSigCount i ≤
        (fun i_1 => if i_1 = i then newCount else s.offchainSigCount i_1) i
      simp
      omega

/-! ## Combined cap invariant -/

theorem combined_cap_invariant
    (s : Storage) (i cap : Nat) (s' : Storage)
    (h : setOffchain s i (s.offchainSigCount i) (s.slotUses i) cap = some s') :
    s'.slotUses i + s'.offchainSigCount i ≤ cap + s.slotUses i := by
  unfold setOffchain at h
  by_cases hlt : s.offchainSigCount i < s.offchainSigCount i
  · simp [hlt] at h
  · by_cases hcap : s.slotUses i + s.offchainSigCount i > cap
    · simp [hlt, hcap] at h
    · simp [hlt, hcap] at h
      rw [← h]
      change s.slotUses i +
        (fun i_1 => if i_1 = i then s.offchainSigCount i else s.offchainSigCount i_1) i
        ≤ cap + s.slotUses i
      simp
      omega

/-! ## Bootstrap key is unremovable

`removeOwner s 0 _ = none` no matter what. This is the on-chain
equivalent of the firmware-side bootstrap-immutability invariant
(CLAUDE.md non-negotiable #6). -/

theorem bootstrap_unremovable
    (s : Storage) (expected : OwnerBytes) :
    removeOwner s 0 expected = none := by
  unfold removeOwner
  simp

end SphincsCVerify.Wallet.MultiOwnable
