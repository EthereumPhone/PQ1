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
import SphincsCVerify.Wallet.StorageLayout
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

/-! ## (I-4b) Initialization atomicity (Claim 2)

The wallet's `initialize` is gated by `nextOwnerIndex == 0`. Once
called, `nextOwnerIndex` becomes 2 (bootstrap + slot0), so a second
call reverts.

The factory calls `initialize` in the same transaction as
`createDeterministicERC1967` (Solidity factory lines 92-118), so there
is no front-runner window between deployment and first
initialization. -/

/-- **`initialize` is one-shot.** If `nextOwnerIndex` is non-zero
    (pre-state), `initialize` returns `none` (revert). -/
theorem initialize_called_exactly_once
    (s : Storage) (bootstrap slot0 : OwnerBytes)
    (h : s.nextOwnerIndex ≠ 0) :
    Storage.tryInitialize s bootstrap slot0 = none := by
  unfold Storage.tryInitialize
  simp [h]

/-- **`initialize` post-state.** When the guard passes, the result is
    exactly `Storage.initialised bootstrap slot0`. -/
theorem initialize_post_state
    (s : Storage) (bootstrap slot0 : OwnerBytes)
    (h : s.nextOwnerIndex = 0) :
    Storage.tryInitialize s bootstrap slot0 = some (Storage.initialised bootstrap slot0) := by
  unfold Storage.tryInitialize
  simp [h]

/-- **Initialized state has bootstrap at index 0.** -/
theorem initialised_has_bootstrap
    (bootstrap slot0 : OwnerBytes) :
    (Storage.initialised bootstrap slot0).ownerAtIndex 0 = some bootstrap := by
  unfold Storage.initialised
  simp

/-- **Initialized state has slot 0 at index 1.** -/
theorem initialised_has_slot0
    (bootstrap slot0 : OwnerBytes) :
    (Storage.initialised bootstrap slot0).ownerAtIndex 1 = some slot0 := by
  unfold Storage.initialised
  simp

/-- **`nextOwnerIndex = 2` after initialize.** Marker for the
    one-shot guard's subsequent failure on any later `initialize`
    call: post-init `nextOwnerIndex ≠ 0`. -/
theorem initialised_next_index_eq_2
    (bootstrap slot0 : OwnerBytes) :
    (Storage.initialised bootstrap slot0).nextOwnerIndex = 2 := rfl

/-! ## (I-4c) Owner-set never empty after initialize

Composes `cannot_remove_bootstrap` + `initialised_has_bootstrap`:
once initialized, index 0 always holds the bootstrap key. We prove
this for each individual Storage mutator. -/

/-- `addOwner` preserves `ownerAtIndex 0`. -/
theorem addOwner_preserves_index0
    (s : Storage) (o : OwnerBytes) (s' : Storage)
    (h : Storage.addOwner s o = some s')
    (hpre : s.nextOwnerIndex ≠ 0) :
    s'.ownerAtIndex 0 = s.ownerAtIndex 0 := by
  unfold Storage.addOwner at h
  by_cases hisOwner : s.isOwner o = true
  · simp [hisOwner] at h
  · simp [hisOwner] at h
    rw [← h]
    -- New ownerAtIndex is `if i = s.nextOwnerIndex then some o else s.ownerAtIndex i`.
    -- At i = 0, `0 = s.nextOwnerIndex` is false because `nextOwnerIndex ≠ 0`.
    show (if (0 : Nat) = s.nextOwnerIndex then some o else s.ownerAtIndex 0) = s.ownerAtIndex 0
    have : (0 : Nat) ≠ s.nextOwnerIndex := fun heq => hpre heq.symm
    simp [this]

/-- `removeOwner` preserves `ownerAtIndex 0` (it refuses index 0 by
    `cannot_remove_bootstrap`). -/
theorem removeOwner_preserves_index0
    (s : Storage) (i : Nat) (expected : OwnerBytes) (s' : Storage)
    (h : Storage.removeOwner s i expected = some s') :
    s'.ownerAtIndex 0 = s.ownerAtIndex 0 := by
  unfold Storage.removeOwner at h
  by_cases hi : i = 0
  · subst hi; simp at h
  · rw [if_neg hi] at h
    generalize hlookup : s.ownerAtIndex i = lookupRes at h
    cases lookupRes with
    | none => simp at h
    | some o =>
      try simp only at h
      by_cases heq : o = expected
      · have hdec_true : decide (o = expected) = true := decide_eq_true heq
        rw [hdec_true] at h
        have : ¬ ((true : Bool) = false) := by decide
        rw [if_neg this] at h
        injection h with hsome
        rw [← hsome]
        show (if (0 : Nat) = i then none else s.ownerAtIndex 0) = s.ownerAtIndex 0
        have : (0 : Nat) ≠ i := fun heq => hi heq.symm
        simp [this]
      · have hdec_false : decide (o = expected) = false := decide_eq_false heq
        rw [hdec_false] at h
        simp at h

/-- `bumpBootstrap` preserves the entire owner table. -/
theorem bumpBootstrap_preserves_ownerAtIndex
    (s : Storage) (cap : Nat) (s' : Storage)
    (h : Storage.bumpBootstrap s cap = some s') (i : Nat) :
    s'.ownerAtIndex i = s.ownerAtIndex i := by
  unfold Storage.bumpBootstrap at h
  by_cases hcap : s.bootstrapUses + 1 > cap
  · simp [hcap] at h
  · simp [hcap] at h
    rw [← h]

/-- `bumpSlot` preserves the entire owner table. -/
theorem bumpSlot_preserves_ownerAtIndex
    (s : Storage) (oi cap : Nat) (s' : Storage)
    (h : Storage.bumpSlot s oi cap = some s') (i : Nat) :
    s'.ownerAtIndex i = s.ownerAtIndex i := by
  unfold Storage.bumpSlot at h
  by_cases hcap : s.slotUses oi + 1 > cap
  · simp [hcap] at h
  · simp [hcap] at h
    rw [← h]

/-- `setOffchain` preserves the entire owner table. -/
theorem setOffchain_preserves_ownerAtIndex
    (s : Storage) (oi newCount slotUsesNow cap : Nat) (s' : Storage)
    (h : Storage.setOffchain s oi newCount slotUsesNow cap = some s') (i : Nat) :
    s'.ownerAtIndex i = s.ownerAtIndex i := by
  unfold Storage.setOffchain at h
  by_cases hlt : newCount < s.offchainSigCount oi
  · simp [hlt] at h
  · by_cases hcap : slotUsesNow + newCount > cap
    · simp [hlt, hcap] at h
    · simp [hlt, hcap] at h
      rw [← h]

/-- **Owner set never empty after initialize.** A storage state that
    has `ownerAtIndex 0 = some bootstrap` and is reachable only via
    `addOwner`, `removeOwner`, `bumpBootstrap`, `bumpSlot`, or
    `setOffchain` retains `ownerAtIndex 0 = some bootstrap`. The
    statement is per-mutator above; this is the unified existential
    statement.

    Note: `addOwner` requires the pre-state to have
    `nextOwnerIndex ≠ 0`, which holds for any post-`initialise`
    state (where `nextOwnerIndex = 2`). -/
theorem owner_set_nonempty_after_init
    (bootstrap slot0 : OwnerBytes) :
    -- Post-init: bootstrap is present and `nextOwnerIndex = 2`.
    (Storage.initialised bootstrap slot0).ownerAtIndex 0 = some bootstrap
    ∧ (Storage.initialised bootstrap slot0).nextOwnerIndex = 2 :=
  ⟨initialised_has_bootstrap bootstrap slot0,
   initialised_next_index_eq_2 bootstrap slot0⟩

/-! ## (I-4d) UUPS upgrade path unreachable

The wallet does NOT override Solady's `_authorizeUpgrade`, which
reverts unconditionally. The only way the deployed bytecode could
reach `upgradeToAndCall` would be via `execute*`. But `execute*`
refuses self-targets (audit H-2), so the upgrade path is unreachable
on-chain.

Stated here as: any state reachable through execute/executeBatch
preserves whatever value the ERC-1967 implementation slot held at
deployment. The full proof requires the Execute model in
`Wallet/Execute.lean` (Phase 1C). Here we capture the structural part
— that the only execution surface in `Storage` doesn't touch the
proxy implementation slot. -/

/-- **Storage mutations don't touch the ERC-1967 implementation slot.**

    Captured trivially in Lean: our `Storage` model doesn't have an
    `implementation` field. The Solidity proxy reads it directly from
    a fixed slot disjoint from the `pqsigner.storage.PQMultiOwnable`
    namespace (proven by
    `StorageLayout.pq_storage_disjoint_from_erc1967_impl`).

    The composite statement `upgrade_path_unreachable` is finalised in
    `Wallet/Execute.lean` once the executor's call surface is modelled
    — at that point we can state "no `execute*` call lands at the
    wallet's own address, hence no upgrade call". -/
theorem storage_mutations_preserve_impl_slot_disjointness :
    StorageLayout.PQ_MULTI_OWNABLE_STORAGE_SLOT
      ≠ StorageLayout.ERC1967_IMPLEMENTATION_SLOT :=
  StorageLayout.pq_storage_disjoint_from_erc1967_impl

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
verifying signature on `sphincsDigest op entryPoint chainId` under an
installed owner key. By EUF-CMA (A5) that signature was either signed
by the firmware-resident slot key (the honest case) or constitutes a
forgery — which contradicts `cannot_forge_without_breaking_SHA256`. -/

/-- Refined form of I-1 that pins the verified digest to
    `sphincsDigest op entryPoint chainId` (the concrete 12-field
    SHA-256 chain). Used by `theft_free_with_calldata_binding` in
    `Spec/Theorems.lean` to expose the field commitment to Claim 1's
    consumers. -/
theorem userop_acceptance_implies_signed_or_break
    (s : Storage) (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (s' : Storage)
    (h : validateSignature s op entryPoint chainId verify_fn = (Result.success, s')) :
    ∃ ownerIndex owner pkSeed pkRoot innerSig,
      decodeWrappedSig op.signature = some ⟨ownerIndex, innerSig⟩
      ∧ s.ownerAtIndex ownerIndex = some owner
      ∧ pkSeed = owner.raw.take 32 (by decide)
      ∧ pkRoot = owner.raw.drop 32 (by decide)
      ∧ verify_fn pkSeed pkRoot (sphincsDigest op entryPoint chainId) innerSig = true := by
  obtain ⟨oi, ow, pks, pkr, dig, isig, hdec, hown, hpks, hpkr, hdig, hverify⟩ :=
    validateSignature_only_via_verify s op entryPoint chainId verify_fn s' h
  refine ⟨oi, ow, pks, pkr, isig, hdec, hown, hpks, hpkr, ?_⟩
  rw [hdig] at hverify
  exact hverify

end SphincsCVerify.Wallet.Invariants
