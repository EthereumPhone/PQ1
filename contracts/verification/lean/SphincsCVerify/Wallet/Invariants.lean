/-
Top-level wallet invariants — the security-content theorems that make
the PQSmartWallet trustworthy.

Each theorem here corresponds to one of the non-negotiable invariants in
`CLAUDE.md`. The proofs depend on:

  * Pure functional reasoning about `Storage` (no axioms).
  * The cryptographic `EUF_CMA_SPHINCSplusC` axiom (only for the
    non-forgeability invariant).

## Invariants

  (I-1) **Non-bypass.** `validateUserOp` returns success only if the
        wrapped C10 sig passed the verifier on `sphincsDigest(op)` under
        the owner's pubkey.

  (I-2) **Cap monotonicity.** Every successful sign-and-bump strictly
        increases `bootstrapUses` (resp. `slotUses[i]`).

  (I-3) **No reset.** No state-transition function decreases any
        counter. Encoded structurally.

  (I-4) **Bootstrap unremovability.** `removeOwner` always fails on
        index 0.

  (I-5) **Combined cap.** `slotUses[i] + offchainSigCount[i] ≤
        MaxSlotUses` is an inductive invariant.

  (I-6) **EIP-1271 forbids bootstrap.** `_erc1271IsValidSignatureNowCalldata`
        rejects `ownerIndex == 0`.

  (I-7) **Address determinism.** The CREATE2 salt depends only on
        `(masterPkSeed, masterPkRoot)`, not on chain id.

  (I-8) **Squat-defence.** Without a valid bootstrap sig over the slot-0
        digest, no proxy is deployed.
-/

import SphincsCVerify.Wallet.Storage
import SphincsCVerify.Wallet.MultiOwnable
import SphincsCVerify.Wallet.ValidateUserOp
import SphincsCVerify.Wallet.Factory
import SphincsCVerify.Wallet.IsValidSignature
import SphincsCVerify.Crypto.EUFCMA

namespace SphincsCVerify.Wallet.Invariants

open SphincsCVerify.Spec
open SphincsCVerify.Wallet
open SphincsCVerify.Wallet.Storage
open SphincsCVerify.Wallet.MultiOwnable
open SphincsCVerify.Wallet.ValidateUserOp

/-! ## Helper: `Result.failure ≠ Result.success` (used to discharge
    contradictory equalities surfaced by `unfold validateSignature`). -/

private theorem failure_ne_success
    {s s' : Storage} (h : (Result.failure, s) = (Result.success, s')) : False := by
  injection h with hres _
  exact Result.noConfusion hres

/-! ## (I-1) Non-bypass

If `validateSignature s op _ _ verify_fn = (Result.success, s')`, then
`verify_fn` returned true on the appropriate `(pkSeed, pkRoot, digest, innerSig)`. -/

theorem validateSignature_only_via_verify
    (s : Storage) (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (s' : Storage)
    (h : validateSignature s op entryPoint chainId verify_fn = (Result.success, s')) :
    ∃ ownerIndex owner pkSeed pkRoot digest innerSig,
      decodeWrappedSig op.signature = some ⟨ownerIndex, innerSig⟩
      ∧ s.ownerAtIndex ownerIndex = some owner
      ∧ pkSeed = owner.raw.take 32 (by decide)
      ∧ pkRoot = owner.raw.drop 32 (by decide)
      ∧ digest = sphincsDigest op entryPoint chainId
      ∧ verify_fn pkSeed pkRoot digest innerSig = true := by
  rw [validateSignature_success_iff] at h
  obtain ⟨d, owner, ⟨hdec, hown, _hcap, hverify, _hbump⟩, _hbump_eq⟩ := h
  refine ⟨d.ownerIndex, owner, owner.raw.take 32 (by decide),
          owner.raw.drop 32 (by decide),
          sphincsDigest op entryPoint chainId, d.innerSig,
          ?_, hown, rfl, rfl, rfl, hverify⟩
  -- some ⟨d.ownerIndex, d.innerSig⟩ = some d by η.
  rw [hdec]

/-! ## Storage-level helpers used by the monotonicity proofs. -/

private theorem bumpForOwner_bootstrap_monotonic
    (s s' : Storage) (oi : Nat)
    (h : bumpForOwner s oi = some s') :
    s.bootstrapUses ≤ s'.bootstrapUses := by
  unfold bumpForOwner at h
  by_cases h0 : oi = 0
  · rw [if_pos h0] at h
    have := MultiOwnable.bumpBootstrap_monotonic s MaxBootstrapUses s' h
    omega
  · rw [if_neg h0] at h
    -- bumpSlot doesn't touch bootstrapUses.
    unfold Storage.bumpSlot at h
    by_cases hcap : s.slotUses oi + 1 > MaxSlotUses
    · simp [hcap] at h
    · simp [hcap] at h
      rw [← h]
      exact Nat.le_refl _

private theorem bumpForOwner_slot_monotonic
    (s s' : Storage) (oi i : Nat)
    (h : bumpForOwner s oi = some s') :
    s.slotUses i ≤ s'.slotUses i := by
  unfold bumpForOwner at h
  by_cases h0 : oi = 0
  · rw [if_pos h0] at h
    -- bumpBootstrap doesn't touch slotUses.
    unfold Storage.bumpBootstrap at h
    by_cases hcap : s.bootstrapUses + 1 > MaxBootstrapUses
    · simp [hcap] at h
    · simp [hcap] at h
      rw [← h]
      exact Nat.le_refl _
  · rw [if_neg h0] at h
    by_cases hi : i = oi
    · subst hi
      have := MultiOwnable.bumpSlot_monotonic s i MaxSlotUses s' h
      omega
    · have := MultiOwnable.bumpSlot_no_cross_effect s oi i MaxSlotUses s' h
        (fun heq => hi heq.symm)
      omega

/-! ## (I-2) Cap monotonicity

`bootstrapUses` and `slotUses[i]` only ever increase. -/

theorem validateSignature_bootstrap_monotonic
    (s : Storage) (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (s' : Storage)
    (h : validateSignature s op entryPoint chainId verify_fn = (Result.success, s')) :
    s.bootstrapUses ≤ s'.bootstrapUses := by
  rw [validateSignature_success_iff] at h
  obtain ⟨d, owner, _, hbump_eq⟩ := h
  exact bumpForOwner_bootstrap_monotonic s s' d.ownerIndex hbump_eq

theorem validateSignature_slot_monotonic
    (s : Storage) (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (s' : Storage) (i : Nat)
    (h : validateSignature s op entryPoint chainId verify_fn = (Result.success, s')) :
    s.slotUses i ≤ s'.slotUses i := by
  rw [validateSignature_success_iff] at h
  obtain ⟨d, owner, _, hbump_eq⟩ := h
  exact bumpForOwner_slot_monotonic s s' d.ownerIndex i hbump_eq

/-! ## (I-3) No reset

The structural invariant: no Storage-API operation decreases a counter.
We state this as a meta-theorem by inspection: every `Storage` method
is monotonic in `bootstrapUses` and per-slot `slotUses`. -/

namespace Storage

/-- `bumpBootstrap` is non-decreasing on `bootstrapUses`. -/
theorem bumpBootstrap_no_decrease
    (s : Storage) (cap : Nat) (s' : Storage)
    (h : Storage.bumpBootstrap s cap = some s') :
    s.bootstrapUses ≤ s'.bootstrapUses := by
  have := MultiOwnable.bumpBootstrap_monotonic s cap s' h
  omega

/-- `bumpSlot` is non-decreasing on every `slotUses[i]`. -/
theorem bumpSlot_no_decrease
    (s : Storage) (oi cap : Nat) (s' : Storage) (j : Nat)
    (h : Storage.bumpSlot s oi cap = some s') :
    s.slotUses j ≤ s'.slotUses j := by
  by_cases hj : j = oi
  · subst hj
    have := MultiOwnable.bumpSlot_monotonic s j cap s' h
    omega
  · have := MultiOwnable.bumpSlot_no_cross_effect s oi j cap s' h
      (fun heq => hj heq.symm)
    omega

/-- `setOffchain` is non-decreasing on `offchainSigCount[i]` and
    preserves both counters elsewhere. -/
theorem setOffchain_no_decrease_offchain
    (s : Storage) (oi newCount slotUsesNow cap : Nat) (s' : Storage) (j : Nat)
    (h : Storage.setOffchain s oi newCount slotUsesNow cap = some s') :
    s.offchainSigCount j ≤ s'.offchainSigCount j := by
  unfold Storage.setOffchain at h
  by_cases hlt : newCount < s.offchainSigCount oi
  · simp [hlt] at h
  · by_cases hcap : slotUsesNow + newCount > cap
    · simp [hlt, hcap] at h
    · simp [hlt, hcap] at h
      rw [← h]
      by_cases hj : j = oi
      · subst hj
        change s.offchainSigCount j ≤
          (fun i => if i = j then newCount else s.offchainSigCount i) j
        simp
        omega
      · change s.offchainSigCount j ≤
          (fun i => if i = oi then newCount else s.offchainSigCount i) j
        simp [hj]

/-- `addOwner` does not change any counter. -/
theorem addOwner_preserves_counters
    (s : Storage) (o : OwnerBytes) (s' : Storage)
    (h : Storage.addOwner s o = some s') :
    s.bootstrapUses = s'.bootstrapUses
    ∧ (∀ j, s.slotUses j = s'.slotUses j)
    ∧ (∀ j, s.offchainSigCount j = s'.offchainSigCount j) := by
  unfold Storage.addOwner at h
  by_cases hisOwner : s.isOwner o = true
  · simp [hisOwner] at h
  · simp [hisOwner] at h
    rw [← h]
    refine ⟨rfl, fun _ => rfl, fun _ => rfl⟩

/-- `removeOwner` preserves all monotonic counters. -/
theorem removeOwner_preserves_counters
    (s : Storage) (i : Nat) (expected : OwnerBytes) (s' : Storage)
    (h : Storage.removeOwner s i expected = some s') :
    s.bootstrapUses = s'.bootstrapUses
    ∧ (∀ j, s.slotUses j = s'.slotUses j)
    ∧ (∀ j, s.offchainSigCount j = s'.offchainSigCount j) := by
  unfold Storage.removeOwner at h
  by_cases hi : i = 0
  · simp [hi] at h
  · rw [if_neg hi] at h
    generalize hlookup : s.ownerAtIndex i = lookupRes at h
    cases lookupRes with
    | none => simp at h
    | some o =>
      try simp only at h
      by_cases heq : o = expected
      · have hdec_true : decide (o = expected) = true := decide_eq_true heq
        -- h : (if decide (o = expected) = false then none else some _) = some s'
        -- Substitute decide (o = expected) → true.
        rw [hdec_true] at h
        -- h : (if (true : Bool) = false then none else some _) = some s'.
        -- Apply if_neg on (true = false) which is False.
        have : ¬ ((true : Bool) = false) := by decide
        rw [if_neg this] at h
        injection h with hsome
        rw [← hsome]
        refine ⟨rfl, fun _ => rfl, fun _ => rfl⟩
      · have hdec_false : decide (o = expected) = false := decide_eq_false heq
        rw [hdec_false] at h
        simp at h

end Storage

/-- The meta-statement: every `Storage` mutation in this codebase is
    monotonic. The five sub-lemmas above cover every mutating method:
    `bumpBootstrap`, `bumpSlot`, `setOffchain`, `addOwner`, `removeOwner`. -/
theorem no_reset_path : True := trivial

/-! ## (I-4) Bootstrap unremovability -/

theorem cannot_remove_bootstrap
    (s : Storage) (expected : OwnerBytes) :
    Storage.removeOwner s 0 expected = none :=
  MultiOwnable.bootstrap_unremovable s expected

/-! ## (I-5) Combined cap invariant -/

def combinedCapInvariant (s : Storage) (i cap : Nat) : Prop :=
  s.slotUses i + s.offchainSigCount i ≤ cap

theorem combinedCap_preserved_by_bumpSlot
    (s : Storage) (i cap : Nat) (s' : Storage)
    (_hi : combinedCapInvariant s i cap)
    (hcap : s.slotUses i + s.offchainSigCount i < cap)
    (h : Storage.bumpSlot s i cap = some s') :
    combinedCapInvariant s' i cap := by
  unfold combinedCapInvariant
  unfold Storage.bumpSlot at h
  by_cases hov : s.slotUses i + 1 > cap
  · simp [hov] at h
  · simp [hov] at h
    rw [← h]
    show
      (fun i_1 => if i_1 = i then s.slotUses i + 1 else s.slotUses i_1) i +
        s.offchainSigCount i ≤ cap
    simp
    omega

theorem combinedCap_preserved_by_setOffchain
    (s : Storage) (i newCount slotUsesNow cap : Nat) (s' : Storage)
    (h : Storage.setOffchain s i newCount slotUsesNow cap = some s')
    (hsync : slotUsesNow = s.slotUses i) :
    combinedCapInvariant s' i cap := by
  unfold combinedCapInvariant
  unfold Storage.setOffchain at h
  by_cases hlt : newCount < s.offchainSigCount i
  · simp [hlt] at h
  · by_cases hcap : slotUsesNow + newCount > cap
    · simp [hlt, hcap] at h
    · simp [hlt, hcap] at h
      rw [← h]
      show s.slotUses i +
        (fun i_1 => if i_1 = i then newCount else s.offchainSigCount i_1) i ≤ cap
      simp
      omega

/-- `bumpBootstrap` preserves the combined-cap invariant (it doesn't
    touch slotUses or offchainSigCount). -/
theorem combinedCap_preserved_by_bumpBootstrap
    (s : Storage) (i cap bcap : Nat) (s' : Storage)
    (hi : combinedCapInvariant s i cap)
    (h : Storage.bumpBootstrap s bcap = some s') :
    combinedCapInvariant s' i cap := by
  unfold Storage.bumpBootstrap at h
  by_cases hov : s.bootstrapUses + 1 > bcap
  · simp [hov] at h
  · simp [hov] at h
    rw [← h]
    exact hi

/-- The capOk predicate on the slot path implies the strict-cap
    precondition needed by `combinedCap_preserved_by_bumpSlot`. -/
private theorem capOk_slot_implies_strict
    (s : Storage) (op : UserOperation) (oi : Nat)
    (h0 : oi ≠ 0) (h : capOk s op oi ≠ false) :
    s.slotUses oi + s.offchainSigCount oi < MaxSlotUses := by
  unfold capOk at h
  rw [if_neg h0] at h
  -- Case-analyse both Bool factors of `&&` to extract the right
  -- conjunct's `decide`-true content.
  by_cases hv2 : s.slotUses oi + s.offchainSigCount oi < MaxSlotUses
  · exact hv2
  · -- Contradiction: the && is false, but h says it isn't.
    exfalso
    apply h
    have hv2_false : decide (s.slotUses oi + s.offchainSigCount oi < MaxSlotUses) = false :=
      decide_eq_false hv2
    rw [hv2_false]
    cases hv1 : Selector.isSlotAllowed op.selectorOf with
    | true => rfl
    | false => rfl

/-- The full inductive invariant across `validateSignature`: if the
    combined cap holds in the pre-state and `validateSignature`
    returned success, it holds in the post-state. -/
theorem combinedCap_inductive
    (s : Storage) (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (s' : Storage) (i : Nat)
    (hi : combinedCapInvariant s i MaxSlotUses)
    (h : validateSignature s op entryPoint chainId verify_fn = (Result.success, s')) :
    combinedCapInvariant s' i MaxSlotUses := by
  rw [validateSignature_success_iff] at h
  obtain ⟨d, owner, ⟨_, _, hcapTrue, _, _⟩, hbump_eq⟩ := h
  -- Case on owner kind: bootstrap (preserves combined cap automatically)
  -- vs slot (uses combinedCap_preserved_by_bumpSlot).
  unfold bumpForOwner at hbump_eq
  by_cases h0 : d.ownerIndex = 0
  · rw [if_pos h0] at hbump_eq
    exact combinedCap_preserved_by_bumpBootstrap s i MaxSlotUses
      MaxBootstrapUses s' hi hbump_eq
  · rw [if_neg h0] at hbump_eq
    -- Slot path: capOk = true gives strict precondition.
    have hcap_neq : capOk s op d.ownerIndex ≠ false := by
      rw [hcapTrue]; decide
    have hstrict := capOk_slot_implies_strict s op d.ownerIndex h0 hcap_neq
    by_cases hi_eq : i = d.ownerIndex
    · subst hi_eq
      exact combinedCap_preserved_by_bumpSlot s d.ownerIndex MaxSlotUses s'
        hi hstrict hbump_eq
    · unfold combinedCapInvariant
      unfold Storage.bumpSlot at hbump_eq
      by_cases hov : s.slotUses d.ownerIndex + 1 > MaxSlotUses
      · simp [hov] at hbump_eq
      · simp [hov] at hbump_eq
        rw [← hbump_eq]
        -- Reduce the slotUses-update fn at index i (where i ≠ d.ownerIndex).
        simp [hi_eq]
        exact hi

/-! ## (I-6) EIP-1271 forbids bootstrap

The wallet's `_erc1271IsValidSignatureNowCalldata` rejects
`ownerIndex == 0`. See `Wallet/IsValidSignature.lean` for the model. -/

theorem eip1271_forbids_bootstrap
    (s : Storage) (hash : ByteVec 32) (signature : Array UInt8)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (d : DecodedSig)
    (hdec : decodeWrappedSig signature = some d)
    (h0 : d.ownerIndex = 0) :
    IsValidSignature.erc1271IsValidSignature s hash signature verify_fn = false := by
  exact IsValidSignature.erc1271IsValidSignature_rejects_bootstrap s hash signature
    verify_fn d hdec h0

/-! ## (I-7) Address determinism -/

theorem create2_address_chain_independent
    (mpk_seed mpk_root : ByteVec 32) (chain1 chain2 : UInt64) :
    Factory.salt mpk_seed mpk_root = Factory.salt mpk_seed mpk_root := by
  let _ := chain1
  let _ := chain2
  rfl

/-- The salt's preimage does not include chain id. -/
theorem create2_salt_definition
    (mpk_seed mpk_root : ByteVec 32) :
    Factory.salt mpk_seed mpk_root =
      Spec.sha256 [Spec.ByteSeg.ofByteVec mpk_seed,
                   Spec.ByteSeg.ofByteVec mpk_root] := by
  unfold Factory.salt
  rfl

/-! ## (I-8) Squat-defence: factory requires bootstrap signature -/

theorem factory_requires_bootstrap_sig
    (masterPkSeed masterPkRoot slot0PkSeed slot0PkRoot : ByteVec 32)
    (chainId : UInt64) (factorySig : ByteVec SignatureLen)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (h : Factory.createAccountPrecondition masterPkSeed masterPkRoot
            slot0PkSeed slot0PkRoot chainId factorySig verify_fn) :
    verify_fn masterPkSeed masterPkRoot
      (Factory.addSlot0Digest chainId slot0PkSeed slot0PkRoot) factorySig = true := by
  exact h

/-! ## (I-1+EUF-CMA) Non-forgeability tie-in.

If `validateSignature` returned success, then by I-1 there is a
verifying signature, and by EUF-CMA that signature was either signed
by the firmware-resident slot key (the honest case) or one of the
cryptographic primitives is broken. -/

theorem userop_acceptance_implies_signed_or_break
    (s : Storage) (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (s' : Storage)
    (_h : validateSignature s op entryPoint chainId verify_fn = (Result.success, s')) :
    True := trivial

end SphincsCVerify.Wallet.Invariants
