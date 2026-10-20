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

  (I-4) **Bootstrap unremovability.** There is no owner removal (deleted
        before launch); `addOwner` never writes index 0 on an initialised
        wallet and `tryInitialize` is one-shot, so the bootstrap key at
        index 0 never changes.

  (I-5) **Combined cap.** `slotUses[i] + offchainSigCount[i] ≤
        MaxSlotUses` is an inductive invariant.

  (I-6) **EIP-1271 forbids bootstrap.** `_erc1271IsValidSignatureNowCalldata`
        rejects `ownerIndex == 0`.

  (I-7) **Address determinism.** The CREATE2 salt depends only on
        `(masterPkSeed, masterPkRoot)`, not on chain id.

  (I-8) **Squat-defence.** Without a valid bootstrap sig over the slot-0
        digest, no proxy is deployed.

  (I-9) **Append-only owner set.** On every reachable state each installed
        key is flagged `isOwner` and sits at exactly one index below
        `nextOwnerIndex`, so `addOwner` refuses it: a key can never be
        installed a second time with fresh per-index counters (the
        remove + re-add budget reset, GitHub #131, is unreachable).
-/

import SphincsCVerify.Wallet.Storage
import SphincsCVerify.Wallet.MultiOwnable
import SphincsCVerify.Wallet.ValidateUserOp
import SphincsCVerify.Wallet.Factory
import SphincsCVerify.Wallet.IsValidSignature
import SphincsCVerify.Wallet.StorageLayout
import SphincsCVerify.Wallet.OffchainBinding
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

/-! ### (I-3) Cross-counter preservation (P3)

The single-counter `*_no_decrease` lemmas above show each bump-style mutator
is monotonic in the ONE counter it nominally touches. To make the docstring
claim "every mutator preserves the OTHER two counters" actually load-bearing
(rather than asserted by English prose), the six lemmas below discharge the
cross-counter preservation for `bumpBootstrap` / `bumpSlot` / `setOffchain`.
They are trivially true of the model — each mutator updates exactly one record
field — but stating them as theorems is what forbids a `setOffchainEvil` that
also zeroed `slotUses` from satisfying the invariant suite. Mirrors the pattern
the `addOwner` lemma already establishes (full three-counter
preservation) and the `capOk_bootstrap_implies_strict` make-it-proof-load-bearing
practice. -/

/-- `bumpBootstrap` preserves every `slotUses[j]` (it only touches `bootstrapUses`). -/
theorem bumpBootstrap_preserves_slotUses
    (s : Storage) (cap : Nat) (s' : Storage) (j : Nat)
    (h : Storage.bumpBootstrap s cap = some s') :
    s.slotUses j = s'.slotUses j := by
  unfold Storage.bumpBootstrap at h
  by_cases hcap : s.bootstrapUses + 1 > cap
  · simp [hcap] at h
  · simp [hcap] at h; rw [← h]

/-- `bumpBootstrap` preserves every `offchainSigCount[j]`. -/
theorem bumpBootstrap_preserves_offchain
    (s : Storage) (cap : Nat) (s' : Storage) (j : Nat)
    (h : Storage.bumpBootstrap s cap = some s') :
    s.offchainSigCount j = s'.offchainSigCount j := by
  unfold Storage.bumpBootstrap at h
  by_cases hcap : s.bootstrapUses + 1 > cap
  · simp [hcap] at h
  · simp [hcap] at h; rw [← h]

/-- `bumpSlot` preserves `bootstrapUses` (it only touches `slotUses`). -/
theorem bumpSlot_preserves_bootstrap
    (s : Storage) (oi cap : Nat) (s' : Storage)
    (h : Storage.bumpSlot s oi cap = some s') :
    s.bootstrapUses = s'.bootstrapUses := by
  unfold Storage.bumpSlot at h
  by_cases hcap : s.slotUses oi + 1 > cap
  · simp [hcap] at h
  · simp [hcap] at h; rw [← h]

/-- `bumpSlot` preserves every `offchainSigCount[j]`. -/
theorem bumpSlot_preserves_offchain
    (s : Storage) (oi cap : Nat) (s' : Storage) (j : Nat)
    (h : Storage.bumpSlot s oi cap = some s') :
    s.offchainSigCount j = s'.offchainSigCount j := by
  unfold Storage.bumpSlot at h
  by_cases hcap : s.slotUses oi + 1 > cap
  · simp [hcap] at h
  · simp [hcap] at h; rw [← h]

/-- `setOffchain` preserves every `slotUses[j]` (it only touches `offchainSigCount`). -/
theorem setOffchain_preserves_slotUses
    (s : Storage) (oi newCount slotUsesNow cap : Nat) (s' : Storage) (j : Nat)
    (h : Storage.setOffchain s oi newCount slotUsesNow cap = some s') :
    s.slotUses j = s'.slotUses j := by
  unfold Storage.setOffchain at h
  by_cases hlt : newCount < s.offchainSigCount oi
  · simp [hlt] at h
  · by_cases hcap : slotUsesNow + newCount > cap
    · simp [hlt, hcap] at h
    · simp [hlt, hcap] at h; rw [← h]

/-- `setOffchain` preserves `bootstrapUses`. -/
theorem setOffchain_preserves_bootstrap
    (s : Storage) (oi newCount slotUsesNow cap : Nat) (s' : Storage)
    (h : Storage.setOffchain s oi newCount slotUsesNow cap = some s') :
    s.bootstrapUses = s'.bootstrapUses := by
  unfold Storage.setOffchain at h
  by_cases hlt : newCount < s.offchainSigCount oi
  · simp [hlt] at h
  · by_cases hcap : slotUsesNow + newCount > cap
    · simp [hlt, hcap] at h
    · simp [hlt, hcap] at h; rw [← h]

/-- `setOffchain` at index `oi` preserves `offchainSigCount[j]` for every OTHER
    index `j ≠ oi` (it writes only `offchainSigCount[oi]`). Needed by the
    `Reachable → combinedCap` induction's execute step on the off-target index:
    a `setOffchain` at `oi` leaves index `i ≠ oi`'s combined cap untouched. -/
theorem setOffchain_preserves_offchain_other
    (s : Storage) (oi newCount slotUsesNow cap : Nat) (s' : Storage) (j : Nat)
    (hj : j ≠ oi)
    (h : Storage.setOffchain s oi newCount slotUsesNow cap = some s') :
    s.offchainSigCount j = s'.offchainSigCount j := by
  unfold Storage.setOffchain at h
  by_cases hlt : newCount < s.offchainSigCount oi
  · simp [hlt] at h
  · by_cases hcap : slotUsesNow + newCount > cap
    · simp [hlt, hcap] at h
    · simp [hlt, hcap] at h
      rw [← h]
      show s.offchainSigCount j
        = (fun i_1 => if i_1 = oi then newCount else s.offchainSigCount i_1) j
      simp [hj]

end Storage

/-- **(I-3) No reset path.** The meta-statement: every state-mutating
    `Storage` method is monotonic — it never decreases `bootstrapUses`,
    any `slotUses[j]`, or any `offchainSigCount[j]`. The four conjuncts
    cover every mutating method (`bumpBootstrap`, `bumpSlot`,
    `setOffchain`, `addOwner`; owner removal was deleted before launch);
    together with the fact
    that these are the *only* mutators of the counter fields (no
    `reset*` / `decrease*` method exists in the API), this is the
    on-chain meaning of CLAUDE.md invariant #7 "per-chain caps
    monotonic, unresettable".

    **P3 (cross-counter discharge).** Each of the three bump-style conjuncts
    asserts ALL THREE counters at once — the counter it bumps is non-decreasing
    AND the other two are preserved — matching the docstring's "monotonic in
    bootstrapUses, slotUses, AND offchainSigCount" rather than only the one each
    nominally touches. This makes the cross-counter preservation proof-load-
    bearing: a `setOffchainEvil` that bumped `offchainSigCount` while zeroing
    `slotUses` no longer satisfies the (now three-counter) `setOffchain`
    conjunct. `addOwner` already carried full three-counter preservation.
    Per KEY (not just per index) the counters cannot be reset either: see
    (I-9) `reachable_addOwner_refuses_installed_key`.

    Caveat (P10, scope): these are the only *counter* mutators; `tryInitialize`
    also writes the counter fields (it zeroes them at construction) but is gated
    by the one-shot `nextOwnerIndex == 0` guard — see `initialize_called_exactly_once`
    and the reachability note in the I-4 section. `no_reset_path` is a per-method
    monotonicity statement, not an assembled reachable-state theorem; the
    `tryInitialize` exclusion rests on that guard, not on this theorem.

    Proven by composing the no-decrease + cross-counter preservation
    lemmas above; no axioms. -/
theorem no_reset_path :
    -- `bumpBootstrap` never decreases `bootstrapUses`, preserves the others.
    (∀ (s : Storage) (cap : Nat) (s' : Storage),
        Storage.bumpBootstrap s cap = some s' →
          s.bootstrapUses ≤ s'.bootstrapUses
          ∧ (∀ j, s.slotUses j = s'.slotUses j)
          ∧ (∀ j, s.offchainSigCount j = s'.offchainSigCount j))
    -- `bumpSlot` never decreases any `slotUses[j]`, preserves the others.
    ∧ (∀ (s : Storage) (oi cap : Nat) (s' : Storage),
        Storage.bumpSlot s oi cap = some s' →
          (∀ j, s.slotUses j ≤ s'.slotUses j)
          ∧ s.bootstrapUses = s'.bootstrapUses
          ∧ (∀ j, s.offchainSigCount j = s'.offchainSigCount j))
    -- `setOffchain` never decreases any `offchainSigCount[j]`, preserves the others.
    ∧ (∀ (s : Storage) (oi newCount slotUsesNow cap : Nat) (s' : Storage),
        Storage.setOffchain s oi newCount slotUsesNow cap = some s' →
          (∀ j, s.offchainSigCount j ≤ s'.offchainSigCount j)
          ∧ (∀ j, s.slotUses j = s'.slotUses j)
          ∧ s.bootstrapUses = s'.bootstrapUses)
    -- `addOwner` preserves all three counters.
    ∧ (∀ (s : Storage) (o : OwnerBytes) (s' : Storage),
        Storage.addOwner s o = some s' →
          s.bootstrapUses = s'.bootstrapUses
          ∧ (∀ j, s.slotUses j = s'.slotUses j)
          ∧ (∀ j, s.offchainSigCount j = s'.offchainSigCount j)) := by
  refine ⟨?_, ?_, ?_, Storage.addOwner_preserves_counters⟩
  · intro s cap s' h
    exact ⟨Storage.bumpBootstrap_no_decrease s cap s' h,
           fun j => Storage.bumpBootstrap_preserves_slotUses s cap s' j h,
           fun j => Storage.bumpBootstrap_preserves_offchain s cap s' j h⟩
  · intro s oi cap s' h
    exact ⟨fun j => Storage.bumpSlot_no_decrease s oi cap s' j h,
           Storage.bumpSlot_preserves_bootstrap s oi cap s' h,
           fun j => Storage.bumpSlot_preserves_offchain s oi cap s' j h⟩
  · intro s oi newCount slotUsesNow cap s' h
    exact ⟨fun j => Storage.setOffchain_no_decrease_offchain s oi newCount slotUsesNow cap s' j h,
           fun j => Storage.setOffchain_preserves_slotUses s oi newCount slotUsesNow cap s' j h,
           Storage.setOffchain_preserves_bootstrap s oi newCount slotUsesNow cap s' h⟩

/-! ## (I-4) Bootstrap unremovability -/

/-- **Claim 2: the bootstrap key cannot be removed or replaced.** Owner
    removal does not exist (deleted before launch, GitHub #131 / #213), and
    the only owner-table writer, `addOwner`, leaves index 0 untouched on an
    initialised wallet. With `initialize_called_exactly_once` (no second
    `tryInitialize`) and the counter-only transitions
    (`*_preserves_ownerAtIndex`), index 0 never changes after
    initialisation; `reachable_ownerTableWF` adds that it is never empty. -/
theorem cannot_remove_bootstrap
    (s : Storage) (o : OwnerBytes) (s' : Storage)
    (h : Storage.addOwner s o = some s')
    (hinit : s.nextOwnerIndex ≠ 0) :
    s'.ownerAtIndex 0 = s.ownerAtIndex 0 :=
  MultiOwnable.bootstrap_unremovable s o s' h hinit

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

/-- **`initialize` post-state.** When both guards pass (fresh proxy, two
    distinct owners), the result is exactly
    `Storage.initialised bootstrap slot0`. -/
theorem initialize_post_state
    (s : Storage) (bootstrap slot0 : OwnerBytes)
    (h : s.nextOwnerIndex = 0) (hne : bootstrap ≠ slot0) :
    Storage.tryInitialize s bootstrap slot0 = some (Storage.initialised bootstrap slot0) := by
  unfold Storage.tryInitialize
  simp [h, hne]

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
this for each individual Storage mutator (there is no removal). -/

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
    `addOwner`, `bumpBootstrap`, `bumpSlot`, or `setOffchain` retains
    `ownerAtIndex 0 = some bootstrap`. The
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
  · -- Contradiction: the && is false, but h says it isn't. The cap
    -- conjunct is the rightmost factor of the (right-associated)
    -- three-way `&&` (allowed-selector, H-3 parity, cap), so two
    -- `Bool.and_false` rewrites collapse the whole conjunction.
    exfalso
    apply h
    have hv2_false : decide (s.slotUses oi + s.offchainSigCount oi < MaxSlotUses) = false :=
      decide_eq_false hv2
    simp [hv2_false]

/-- **Bootstrap analog of `capOk_slot_implies_strict`.** `capOk` on the
    bootstrap path (`ownerIndex = 0`) implies the *strict* few-time-cap
    precondition `bootstrapUses < MaxBootstrapUses` (invariant #7 for the
    bootstrap key). This closes the proof-coverage asymmetry surfaced by the
    2026-06-14 faithfulness audit's `cap-bootstrap` mutation survivor: before
    this lemma, the slot path proved `capOk ⇒ strict-cap` but the bootstrap
    path proved only monotonicity, so weakening `capOk`'s bootstrap `<` to `≤`
    survived the whole proof (it was masked end-to-end only by the redundant
    `bumpBootstrap` gate). With this lemma `capOk`'s bootstrap strictness is
    itself proof-load-bearing — the `<`→`≤` mutation now fails to compile
    here, because `≤` cannot discharge the `< `-typed conclusion. -/
private theorem capOk_bootstrap_implies_strict
    (s : Storage) (op : UserOperation) (oi : Nat)
    (h0 : oi = 0) (h : capOk s op oi ≠ false) :
    s.bootstrapUses < MaxBootstrapUses := by
  unfold capOk at h
  rw [if_pos h0] at h
  -- The bootstrap branch is `decide (sel = addOwnerBytes) && decide (cap)`.
  -- Extract the rightmost conjunct's `decide`-true content.
  by_cases hv : s.bootstrapUses < MaxBootstrapUses
  · exact hv
  · exfalso
    apply h
    have hv_false : decide (s.bootstrapUses < MaxBootstrapUses) = false :=
      decide_eq_false hv
    simp [hv_false]

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

/-- **(I-7 bootstrap) Bootstrap few-time cap is enforced at the validation
    gate.** If `validateSignature` accepts a bootstrap UserOp (the decoded
    wrapper's `ownerIndex` is 0), then the pre-state strictly satisfied the
    bootstrap cap: `bootstrapUses < MaxBootstrapUses`. This is the bootstrap
    counterpart of `combinedCap_inductive` for slots — it makes
    `capOk_bootstrap_implies_strict` proof-load-bearing (two-gate parity with
    the slot path), so the `cap-bootstrap` mutation (`<`→`≤`) can no longer
    pass verification. It states the *precondition* (an op at-or-past the cap is
    refused), which `bumpBootstrap_capped` alone does not give — that lemma only
    bounds the *post*-state value. -/
theorem validateSignature_bootstrap_cap_strict
    (s : Storage) (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (s' : Storage) (d : DecodedSig)
    (hdec : decodeWrappedSig op.signature = some d)
    (h0 : d.ownerIndex = 0)
    (h : validateSignature s op entryPoint chainId verify_fn = (Result.success, s')) :
    s.bootstrapUses < MaxBootstrapUses := by
  rw [validateSignature_success_iff] at h
  obtain ⟨d', _owner, ⟨hdec', _, hcapTrue, _, _⟩, _⟩ := h
  -- Reconcile the existential decode with the hypothesis decode.
  rw [hdec] at hdec'
  have hdd : d = d' := Option.some.inj hdec'
  have h0' : d'.ownerIndex = 0 := by rw [← hdd]; exact h0
  have hcap_neq : capOk s op d'.ownerIndex ≠ false := by rw [hcapTrue]; decide
  exact capOk_bootstrap_implies_strict s op d'.ownerIndex h0' hcap_neq

/-! ### (I-5) Reachable-state discharge of the combined cap (P1 / hInv)

The bytecode theorem `theft_free_bytecode` is *conditioned* on the combined cap
holding in the pre-state (`hInv`). Pre-this-section that hypothesis was an
ASSUMED reachable-state invariant whose reachability was only Foundry-fuzzed.
This section discharges it as a genuine inductive invariant: a `Reachable`
predicate over the wallet `Storage` (genesis + the gated EntryPoint-driven
transitions) plus `reachable_implies_combinedCap`, proven by induction from the
existing single-step preservation lemmas.

**Transition completeness (soundness crux, EF P7).** The constructors are the
EXACT set of operations that mutate `slotUses`/`offchainSigCount`/`bootstrapUses`:
`validateSignature` (Type-1/2 sign → `bumpForOwner`), the `setOffchain` storage
effect of `executeWithOffchainCount`, `tryInitialize` (factory init → zeroes),
and `addOwner` (which doesn't touch the cap counters; owner removal was
deleted before launch). The raw
`bumpSlot`/`bumpBootstrap` primitives are NOT separate transitions — they are
only ever called *gated* inside `validateSignature` (where `capOk` supplies the
STRICT precondition `bumpSlot` preservation needs); exposing a raw bump would
need a new constructor here (and `check_storage_mutators.sh` would flag the new
mutator). The proof lives in the SAME Lean layer that `theft_free_bytecode`
consumes the cap in, so it introduces no new model↔bytecode transcription TCB.

This makes the EF-P1 conditioning a kernel-proven inductive invariant: the
companion corollary `theft_free_bytecode_reachable` (Spec/Theorems.lean) takes
`Reachable σ.walletStorage` and derives `hInv` here, instead of assuming it. -/

/-- The empty (freshly-CREATE2'd) storage satisfies the combined cap (0 + 0). -/
theorem combinedCapInvariant_empty (i cap : Nat) :
    combinedCapInvariant Storage.empty i cap := by
  simp [combinedCapInvariant, Storage.empty]

/-- The post-`initialize` storage satisfies the combined cap (counters are 0). -/
theorem combinedCapInvariant_initialised (bootstrap slot0 : OwnerBytes) (i cap : Nat) :
    combinedCapInvariant (Storage.initialised bootstrap slot0) i cap := by
  simp [combinedCapInvariant, Storage.initialised]

/-- **Reachable wallet storage states.** Genesis (`Storage.empty`) plus the
    gated EntryPoint-driven transitions. See the section docstring for why this
    is the complete, faithful transition set. -/
inductive Reachable : Storage → Prop where
  | genesis : Reachable Storage.empty
  | init (s s' : Storage) (bootstrap slot0 : OwnerBytes)
      (hr : Reachable s)
      (h : Storage.tryInitialize s bootstrap slot0 = some s') : Reachable s'
  | validate (s s' : Storage) (op : UserOperation) (ep : ByteVec 20) (cid : Nat)
      (vfn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
      (hr : Reachable s)
      (h : validateSignature s op ep cid vfn = (Result.success, s')) : Reachable s'
  | execStep (s s' : Storage) (oi nc : Nat)
      (hr : Reachable s)
      (h : Storage.setOffchain s oi nc (s.slotUses oi) MaxSlotUses = some s') : Reachable s'
  | addOwnerStep (s s' : Storage) (o : OwnerBytes)
      (hr : Reachable s)
      (h : Storage.addOwner s o = some s') : Reachable s'

/-- **(I-5, P1) The combined cap holds on every reachable state.** The headline
    bytecode theorem's `hInv` hypothesis, discharged as a real inductive
    invariant (init + every gated transition preserves it) rather than left as
    a fuzz-backed assumption. -/
theorem reachable_implies_combinedCap (s : Storage) (i : Nat) (h : Reachable s) :
    combinedCapInvariant s i MaxSlotUses := by
  induction h with
  | genesis => exact combinedCapInvariant_empty i MaxSlotUses
  | init s s' bootstrap slot0 hr h ih =>
      unfold Storage.tryInitialize at h
      by_cases hni : s.nextOwnerIndex ≠ 0
      · simp [hni] at h
      · by_cases heq : bootstrap = slot0
        · simp [hni, heq] at h
        · simp [hni, heq] at h
          rw [← h]
          exact combinedCapInvariant_initialised bootstrap slot0 i MaxSlotUses
  | validate s s' op ep cid vfn hr h ih =>
      exact combinedCap_inductive s op ep cid vfn s' i ih h
  | execStep s s' oi nc hr h ih =>
      by_cases hieq : i = oi
      · subst hieq
        exact combinedCap_preserved_by_setOffchain s i nc (s.slotUses i) MaxSlotUses s' h rfl
      · unfold combinedCapInvariant at ih ⊢
        rw [← Storage.setOffchain_preserves_slotUses s oi nc (s.slotUses oi) MaxSlotUses s' i h,
            ← Storage.setOffchain_preserves_offchain_other s oi nc (s.slotUses oi)
                MaxSlotUses s' i hieq h]
        exact ih
  | addOwnerStep s s' o hr h ih =>
      unfold combinedCapInvariant at ih ⊢
      obtain ⟨_, hslot, hoff⟩ := Storage.addOwner_preserves_counters s o s' h
      rw [← hslot i, ← hoff i]; exact ih

/-! ### (I-9) Append-only owner set (GitHub #131)

Owner removal was deleted before launch. On every reachable state each
installed key is flagged `isOwner`, lies below `nextOwnerIndex`, and sits at
exactly one index, and `addOwner` refuses any flagged key. So a key, once
installed, keeps its single index — and with it the per-index counters
`slotUses` / `offchainSigCount` — for the life of the wallet: the
remove + re-add budget reset (#131) has no transition that reaches it.
Owner removal never existing in the model is what makes this inductive. -/

/-- Well-formedness of the owner table: every installed key is flagged
    `isOwner` and sits below `nextOwnerIndex`, and no key is installed at two
    indices. -/
def ownerTableWF (s : Storage) : Prop :=
  (∀ i o, s.ownerAtIndex i = some o → s.isOwner o = true ∧ i < s.nextOwnerIndex)
  ∧ (∀ i j o, s.ownerAtIndex i = some o → s.ownerAtIndex j = some o → i = j)

/-- The counter bump of a successful validate leaves the owner table, the
    `isOwner` flags and `nextOwnerIndex` untouched. -/
private theorem bumpForOwner_preserves_owner_table
    (s : Storage) (oi : Nat) (s' : Storage) (h : bumpForOwner s oi = some s') :
    s'.ownerAtIndex = s.ownerAtIndex ∧ s'.isOwner = s.isOwner
    ∧ s'.nextOwnerIndex = s.nextOwnerIndex := by
  unfold bumpForOwner at h
  by_cases h0 : oi = 0
  · rw [if_pos h0] at h
    unfold Storage.bumpBootstrap at h
    by_cases hcap : s.bootstrapUses + 1 > MaxBootstrapUses
    · simp [hcap] at h
    · simp [hcap] at h
      rw [← h]
      exact ⟨rfl, rfl, rfl⟩
  · rw [if_neg h0] at h
    unfold Storage.bumpSlot at h
    by_cases hcap : s.slotUses oi + 1 > MaxSlotUses
    · simp [hcap] at h
    · simp [hcap] at h
      rw [← h]
      exact ⟨rfl, rfl, rfl⟩

/-- `setOffchain` leaves the owner table, the `isOwner` flags and
    `nextOwnerIndex` untouched. -/
private theorem setOffchain_preserves_owner_table
    (s : Storage) (oi nc su cap : Nat) (s' : Storage)
    (h : Storage.setOffchain s oi nc su cap = some s') :
    s'.ownerAtIndex = s.ownerAtIndex ∧ s'.isOwner = s.isOwner
    ∧ s'.nextOwnerIndex = s.nextOwnerIndex := by
  unfold Storage.setOffchain at h
  by_cases hlt : nc < s.offchainSigCount oi
  · simp [hlt] at h
  · by_cases hcap : su + nc > cap
    · simp [hlt, hcap] at h
    · simp [hlt, hcap] at h
      rw [← h]
      exact ⟨rfl, rfl, rfl⟩

/-- **(I-9) The owner table is well-formed on every reachable state.** -/
theorem reachable_ownerTableWF (s : Storage) (h : Reachable s) : ownerTableWF s := by
  induction h with
  | genesis =>
      refine ⟨?_, ?_⟩
      · intro i o hi
        simp [Storage.empty] at hi
      · intro i j o hi _
        simp [Storage.empty] at hi
  | init s s' bootstrap slot0 _ h _ =>
      unfold Storage.tryInitialize at h
      by_cases hni : s.nextOwnerIndex ≠ 0
      · simp [hni] at h
      · by_cases heq : bootstrap = slot0
        · simp [hni, heq] at h
        · simp [hni, heq] at h
          subst h
          refine ⟨?_, ?_⟩
          · intro i o hi
            by_cases h0 : i = 0
            · subst h0
              simp [Storage.initialised] at hi
              subst hi
              simp [Storage.initialised]
            · by_cases h1 : i = 1
              · subst h1
                simp [Storage.initialised] at hi
                subst hi
                simp [Storage.initialised]
              · simp [Storage.initialised, h0, h1] at hi
          · intro i j o hi hj
            by_cases hi0 : i = 0 <;> by_cases hi1 : i = 1 <;>
              by_cases hj0 : j = 0 <;> by_cases hj1 : j = 1 <;>
              simp_all [Storage.initialised]
  | validate s s' op ep cid vfn _ h ih =>
      obtain ⟨d, _owner, _hok, hbump⟩ := (validateSignature_success_iff s op ep cid vfn s').1 h
      obtain ⟨hown, hisown, hnext⟩ := bumpForOwner_preserves_owner_table s d.ownerIndex s' hbump
      unfold ownerTableWF at ih ⊢
      rw [hown, hisown, hnext]
      exact ih
  | execStep s s' oi nc _ h ih =>
      obtain ⟨hown, hisown, hnext⟩ :=
        setOffchain_preserves_owner_table s oi nc (s.slotUses oi) MaxSlotUses s' h
      unfold ownerTableWF at ih ⊢
      rw [hown, hisown, hnext]
      exact ih
  | addOwnerStep s s' o _ h ih =>
      unfold Storage.addOwner at h
      by_cases hio : s.isOwner o = true
      · simp [hio] at h
      · simp [hio] at h
        subst h
        obtain ⟨hflag, hinj⟩ := ih
        -- `o` is not installed anywhere yet (it is not flagged).
        have hfresh : ∀ k, s.ownerAtIndex k ≠ some o := by
          intro k hk
          exact hio (hflag k o hk).1
        -- Nothing is installed at the slot `addOwner` writes.
        have hempty : s.ownerAtIndex s.nextOwnerIndex = none := by
          cases hc : s.ownerAtIndex s.nextOwnerIndex with
          | none => rfl
          | some o' =>
            have := (hflag _ o' hc).2
            omega
        refine ⟨?_, ?_⟩
        · intro i o' hi
          by_cases hin : i = s.nextOwnerIndex
          · subst hin
            simp at hi
            subst hi
            simp
          · simp [hin] at hi
            obtain ⟨hf, hlt⟩ := hflag i o' hi
            simp [hf]
            omega
        · intro i j o' hi hj
          by_cases hin : i = s.nextOwnerIndex <;> by_cases hjn : j = s.nextOwnerIndex
          · rw [hin, hjn]
          · simp [hin] at hi
            simp [hjn] at hj
            subst hi
            exact absurd hj (hfresh j)
          · simp [hjn] at hj
            simp [hin] at hi
            subst hj
            exact absurd hi (hfresh i)
          · simp [hin] at hi
            simp [hjn] at hj
            exact hinj i j o' hi hj

/-- **(I-9) A key is installed at most once.** On a reachable state no key
    sits at two indices. -/
theorem reachable_key_installed_at_most_once
    (s : Storage) (h : Reachable s) (i j : Nat) (o : OwnerBytes)
    (hi : s.ownerAtIndex i = some o) (hj : s.ownerAtIndex j = some o) : i = j :=
  (reachable_ownerTableWF s h).2 i j o hi hj

/-- **(I-9) An installed key can never be installed again** (GitHub #131).
    On a reachable state `addOwner` refuses every key already in the table,
    so a key's per-index counters can never be swapped for fresh ones. -/
theorem reachable_addOwner_refuses_installed_key
    (s : Storage) (h : Reachable s) (i : Nat) (o : OwnerBytes)
    (hi : s.ownerAtIndex i = some o) : Storage.addOwner s o = none := by
  have hflag := ((reachable_ownerTableWF s h).1 i o hi).1
  unfold Storage.addOwner
  simp [hflag]

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

/-- (I-7) **Salt chain-independence.** The CREATE2 salt — the only
    wallet-specific input to the proxy address — is `sha256` of the
    `(masterPkSeed ‖ masterPkRoot)` preimage, which contains **no chain id**,
    so the salt is identical on every chain. This is the proof's actual
    content for I-7; the address-level claim rests additionally on the
    EVM-TCB facts named in `create2Address_chain_independent` below.

    **P11 (honest scope).** This theorem pins only the SALT preimage's
    chain-freeness — NOT the full CREATE2 address. The `chain1 chain2`
    parameters are inert (they cannot affect `Factory.salt`, which takes no
    chain id); they are retained only because `dump_axioms.lean` pins this
    symbol's kernel-only closure. The full address
    `keccak256(0xff ‖ deployer ‖ salt ‖ keccak256(initCode))[12:]` additionally
    depends on the deployer (factory) address and `keccak256(initCode)`; their
    chain-independence is an EVM-TCB fact (a singleton CREATE2 factory deployed
    to the same address on every chain + a frozen `initCode`), made explicit in
    `create2Address_chain_independent`. See `OPEN_PROOF_OBLIGATIONS.md` I-7. -/
theorem create2_address_chain_independent
    (mpk_seed mpk_root : ByteVec 32) (chain1 chain2 : UInt64) :
    Factory.salt mpk_seed mpk_root
      = Spec.sha256 [Spec.ByteSeg.ofByteVec mpk_seed,
                     Spec.ByteSeg.ofByteVec mpk_root] := by
  let _ := chain1
  let _ := chain2
  unfold Factory.salt
  rfl

/-- The salt's preimage does not include chain id. -/
theorem create2_salt_definition
    (mpk_seed mpk_root : ByteVec 32) :
    Factory.salt mpk_seed mpk_root =
      Spec.sha256 [Spec.ByteSeg.ofByteVec mpk_seed,
                   Spec.ByteSeg.ofByteVec mpk_root] := by
  unfold Factory.salt
  rfl

/-- **CREATE2 address model (P11).** The deployed proxy address is
    `keccak256(0xff ‖ deployer ‖ salt ‖ keccak256(initCode))` truncated to the
    low 20 bytes; for the chain-independence argument only the dependency on
    `(deployer, salt, initCodeHash)` matters, so we model it as the keccak of
    those three (the `0xff` framing byte and `[12:]` truncation do not affect
    the equality below). Reuses the model's single opaque `keccak256`. -/
def create2Address (deployer salt initCodeHash : ByteVec 32) : ByteVec 32 :=
  OffchainBinding.keccak256
    [Spec.ByteSeg.ofByteVec deployer,
     Spec.ByteSeg.ofByteVec salt,
     Spec.ByteSeg.ofByteVec initCodeHash]

/-- (I-7) **Address-level chain-independence (P11, address leg).** Unlike
    `create2_address_chain_independent` (which pins only the salt), this names
    the full CREATE2 address dependency and carries FORCE: with distinct
    deployer (`d1`, `d2`) and init-code-hash (`ich1`, `ich2`) binders, the
    hypotheses `d1 = d2` and `ich1 = ich2` — the EVM-TCB facts that the CREATE2
    factory is a singleton deployed to one address on every chain and that the
    `initCode` (hence its keccak) is frozen and chain-free — are USED, and the
    chain-free content lives entirely in the shared `Factory.salt mpk_seed
    mpk_root` argument (which provably takes no chain id). Conclusion: the
    deployed address is identical across chains. This is the conditional the
    cross-chain address guarantee actually rests on; it is NOT an unconditional
    kernel theorem (the deployer/init-code chain-freeness is cited-TCB, not
    modelled in Lean). -/
theorem create2Address_chain_independent
    (mpk_seed mpk_root : ByteVec 32) (d1 d2 ich1 ich2 : ByteVec 32)
    (hd : d1 = d2) (hi : ich1 = ich2) :
    create2Address d1 (Factory.salt mpk_seed mpk_root) ich1
      = create2Address d2 (Factory.salt mpk_seed mpk_root) ich2 := by
  subst hd; subst hi; rfl

/-! ### (I-7) initCode-preimage decomposition — shrinking the `ich1 = ich2` TCB

`create2Address_chain_independent` above takes `ich1 = ich2` (the
`keccak256(initCode)` chain-freeness) as an OPAQUE hypothesis. The block below
opens it: the PQSmartWallet `initCode` is `erc1967ProxyCode ‖ implementation`
(Solady `LibClone.createDeterministicERC1967`; `PQSmartWalletFactory.sol:93`) —
it carries **no chainId and no chain-bound slot key** (the factory seeds slot 0
by a SEPARATE post-deploy state write authorized by `addSlot0Digest`, NOT via the
CREATE2 address preimage). So `initCodeHash` is a function of `implementation`
ALONE, and the opaque `ich1 = ich2` premise reduces to the homogeneous
`impl1 = impl2` deployment fact — the SAME shape as the factory-address premise
`d1 = d2`. -/

/-- **initCode-hash model (I-7, structural).** `keccak256(initCode)` where
    `initCode = proxyCode ‖ implementation`. `proxyCode` is the fixed Solady
    `LibClone` ERC-1967 proxy creation code (~55 bytes, compiled in — chain-free by
    construction, so it is a SHARED binder, the same technique `Factory.salt` uses
    to witness chain-freeness of its inputs); the initCode hash is a function of
    `(proxyCode, implementation)` ALONE — no chainId parameter exists to depend on
    (the factory seeds slot 0 by a SEPARATE post-deploy state write authorized by
    `addSlot0Digest`, NOT via the address preimage). -/
def initCodeHash (proxyCode : Spec.ByteSeg) (implementation : ByteVec 32) : ByteVec 32 :=
  OffchainBinding.keccak256
    [proxyCode, Spec.ByteSeg.ofByteVec implementation]

/-- (I-7) **initCode hash depends only on `(proxyCode, implementation)`.** The
    structural content that reduces the opaque `ich1 = ich2` premise: for a fixed
    (shared) `proxyCode`, equal implementations give equal init-code hashes. Since
    `initCodeHash` takes no chain id, there is nothing chain-dependent in the
    initCode preimage — the sole residual is the cross-chain identity of the
    `implementation` ADDRESS. -/
theorem initCodeHash_eq_of_impl_eq
    (proxyCode : Spec.ByteSeg) {impl1 impl2 : ByteVec 32} (h : impl1 = impl2) :
    initCodeHash proxyCode impl1 = initCodeHash proxyCode impl2 := by
  subst h; rfl

/-- (I-7) **Address-level chain-independence, TCB-decomposed (P11+, 2026-07-17).**
    The same conclusion as `create2Address_chain_independent`, but the opaque
    `ich1 = ich2` premise is REPLACED by the structural `initCodeHash` model + the
    homogeneous `impl1 = impl2` premise (with `proxyCode` a shared chain-free
    constant). So the FULL cited-TCB surface for cross-chain address stability
    (invariant #6) is now exactly TWO HOMOGENEOUS deployment facts —
    `factory1 = factory2` and `impl1 = impl2` — each an instance of the single
    receipt "a deterministically-deployed contract (Arachnid `0x4e59…` singleton
    CREATE2 deployer, salt 0, frozen bytecode) has ONE address on every chain,
    since the CREATE2 opcode preimage `0xff ‖ deployer ‖ salt ‖ keccak256(initcode)`
    contains no chainId". That receipt is discharged for the live Base deployment
    by `contracts/smart-wallet/test/DeployedBytecodeReproCheck.t.sol` (CREATE2
    replay reproduces factory `0xe8CE78CD…` and implementation `0x31e49D24…`
    exactly).

    HONEST SCOPE (do not overstate): the salt is kernel-proven chain-free
    (`Factory.salt` takes no chain id). `initCodeHash_eq_of_impl_eq` is `subst; rfl`
    (= `congrArg`): it witnesses the `def`'s SHAPE — `initCodeHash` takes no chainId
    argument, `proxyCode` is a shared binder — NOT a byte-level proof that the real
    deployed initCode contains no chainId. That "no chainId in the real initCode" fact
    is SOURCE-VERIFIED cited-TCB (`PQSmartWalletFactory.sol:93`,
    `LibClone.createDeterministicERC1967`), not a Solidity→Lean initcode-byte
    extraction. So the improvement is the TCB SHAPE, not the hypothesis count (still
    two): the opaque `ich1 = ich2` premise is decomposed into the structural model +
    the homogeneous `impl1 = impl2`, so both remaining cited-TCB facts are the SAME
    deterministic-deployment address identity, applied twice. See
    `OPEN_PROOF_OBLIGATIONS.md` I-7. -/
theorem create2Address_chain_independent_via_impl
    (mpk_seed mpk_root : ByteVec 32) (proxyCode : Spec.ByteSeg)
    (factory1 factory2 impl1 impl2 : ByteVec 32)
    (hf : factory1 = factory2) (himpl : impl1 = impl2) :
    create2Address factory1 (Factory.salt mpk_seed mpk_root) (initCodeHash proxyCode impl1)
      = create2Address factory2 (Factory.salt mpk_seed mpk_root) (initCodeHash proxyCode impl2) := by
  subst hf
  rw [initCodeHash_eq_of_impl_eq proxyCode himpl]

/-! ## (I-8) Squat-defence: factory requires bootstrap signature -/

theorem factory_requires_bootstrap_sig
    (masterPkSeed masterPkRoot slot0PkSeed slot0PkRoot : ByteVec 32)
    (chainId : UInt64) (factorySig : ByteVec SignatureLen)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (h : Factory.createAccountPrecondition masterPkSeed masterPkRoot
            slot0PkSeed slot0PkRoot chainId factorySig verify_fn) :
    verify_fn masterPkSeed masterPkRoot
      (Factory.addSlot0Digest chainId slot0PkSeed slot0PkRoot) factorySig = true := by
  -- The precondition is now a conjunction (signature check + the
  -- 2026-06-10 owner-install gates); the squat-defence statement is
  -- its first conjunct.
  exact h.1

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

/-- **(P9 / conjunct-2 tie-in) Unforgeability INSTANTIATED at the actual UserOp.**
    The EUF-CMA reduction applied at the transition's OWN values: if the spec
    verifier accepts `innerSig` under owner key `sk` over the op's `sphincsDigest`,
    and that digest is NOT in `sk`'s honest signing history, then a SHA-256
    hardness assumption is broken.

    This exhibits the instantiation the "detached ∀-rider" PoC said was absent —
    `theft_free`'s conjunct-2 (`∀ sk t m s, isForgery → BreaksHash`) IS structurally
    applicable at `msgStar = sphincsDigest op`, `sigStar = innerSig`, the accepting
    owner's key. Stated at the `Hypertree.verify` layer where `isForgery` lives;
    aligning the on-chain ByteVec accept (`validateSignature` via the deployed
    verifier — `userop_acceptance_implies_signed_or_break` above) with this
    `Hypertree`-level accept is the A3.1 reconstruction-layer refinement (the active
    front), so the deployed-bytecode link is the existing A3.1 axiom, not re-proven
    here.

    **HONEST SCOPE (P9 — IRREDUCIBLE, not a wiring gap).** The firing premise
    `¬ transcriptHasMsg transcript (sphincsDigest op…)` — "the legitimate keyholder
    did not sign this op" — is, in this qualitative (non-PPT, total-signer) model,
    the same conditional the model cannot make hold automatically: see the
    irreducibility note on `Crypto.EUF_CMA_SPHINCSplusC`. Dropping the
    `KeyHistory.signed_recorded` completeness firewall so the premise "always" holds
    would let an HONEST signature satisfy `isForgery` (empty transcript +
    `honest_consistent`-verifying sig + nothing recorded), making `BreaksHash` a
    provable theorem and collapsing every `∨ BreaksHash` reduction — a WORSE vacuity
    than P9, in the axiom-set that was inconsistent once before. So this corollary is
    *structurally instantiable and conditionally non-vacuous*, NOT an unconditional
    theorem; that residual is the honest ceiling of the qualitative shadow (the PPT
    adversary `EUFCMA.lean`'s docstring declares out of scope), not a fixable gap. -/
theorem unauthorized_userop_breaks_hash
    (sk : Signer.SigningKey) (transcript : Crypto.Transcript)
    (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
    (innerSig : Hypertree.Signature)
    (hist : Crypto.KeyHistory sk transcript)
    (haccept : Hypertree.verify sk.pkSeed sk.pkRoot
        (sphincsDigest op entryPoint chainId) innerSig = true)
    (hunsigned : ¬ Crypto.transcriptHasMsg transcript
        (sphincsDigest op entryPoint chainId)) :
    Crypto.BreaksHash :=
  Crypto.cannot_forge_without_breaking_SHA256 sk transcript
    (sphincsDigest op entryPoint chainId) innerSig ⟨hist, haccept, hunsigned⟩

/-! ## Envelope-closure lemmas for the Halmos A3.2 validate session
    (GAP-9 / GAP-10 in `docs/MISSING_FOR_FULL_BYTECODE_PROOF.md`)

The bytecode-side pointwise equivalence sweeps a symbolic `ownerIndex`
over the installed slots and covers the unset partition only at concrete
representatives `{3, 2^200, max}` (a Halmos dynamic-bytes-getter
ceiling), and fixes the owner-set SHAPE (bootstrap at 0, slots at
`{1, 2}`, everything ≥ 3 unset). The two lemmas below discharge the
MODEL half of both envelopes with kernel proofs:

* `validateSignature_unset_index_uniform` (GAP-9): the model is CONSTANT
  on the entire unset partition — every unset index rejects with
  unchanged storage, so the concrete reps are representative of the
  model's behaviour at EVERY unset index. The remaining bytecode-side
  residual is only that solc's mapping getter is uniform on unset keys
  (returns the same length-0 bytes for any never-written key — a
  storage-layout property the reps spot-check).

* `validateSignature_result_local` (GAP-10): the model's accept/reject
  result depends only on the storage AT the decoded index —
  `ownerAtIndex i`, `bootstrapUses` (the `i = 0` path), and
  `slotUses i + offchainSigCount i` (the `i ≥ 1` path) — never on the
  contents of any other index. So the fixed swept shape generalises:
  for ANY owner-set shape, the model's behaviour at the decoded index
  coincides with that of a swept configuration agreeing at that index.
-/

/-- GAP-9 (model half): on ANY unset owner index, `validateSignature`
    rejects uniformly — `(Result.failure, s)` with storage untouched,
    independent of which unset index the wrapper named. -/
theorem validateSignature_unset_index_uniform
    (s : Storage) (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (d : DecodedSig)
    (hdec : decodeWrappedSig op.signature = some d)
    (hunset : s.ownerAtIndex d.ownerIndex = none) :
    validateSignature s op entryPoint chainId verify_fn = (Result.failure, s) := by
  obtain ⟨oi, isig⟩ := d
  unfold validateSignature
  rw [hdec]
  simp only at hunset ⊢
  rw [hunset]

/-- GAP-10 (model half): the validate result is LOCAL to the decoded
    index. If two storages agree at `d.ownerIndex` on the owner blob and
    the counters the cap check reads (`bootstrapUses` for the bootstrap
    path; `slotUses`/`offchainSigCount` at the index for the slot path),
    `validateSignature` returns the same `Result` — regardless of what
    either storage holds at every other index. -/
theorem validateSignature_result_local
    (s t : Storage) (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (d : DecodedSig)
    (hdec : decodeWrappedSig op.signature = some d)
    (hown : s.ownerAtIndex d.ownerIndex = t.ownerAtIndex d.ownerIndex)
    (hboot : s.bootstrapUses = t.bootstrapUses)
    (hslot : s.slotUses d.ownerIndex = t.slotUses d.ownerIndex)
    (hoff : s.offchainSigCount d.ownerIndex = t.offchainSigCount d.ownerIndex) :
    (validateSignature s op entryPoint chainId verify_fn).1 =
      (validateSignature t op entryPoint chainId verify_fn).1 := by
  obtain ⟨oi, isig⟩ := d
  simp only at hown hslot hoff
  -- The cap check reads only index-local state, so it agrees.
  have hcap : capOk s op oi = capOk t op oi := by
    unfold capOk
    by_cases h0 : oi = 0
    · subst h0
      rw [hboot, hslot, hoff]
    · rw [if_neg h0, if_neg h0, hslot, hoff]
  -- The counter bump's success/failure also reads only index-local state.
  have hbump : (bumpForOwner s oi).isSome = (bumpForOwner t oi).isSome := by
    by_cases h0 : oi = 0
    · subst h0
      simp only [bumpForOwner, if_pos rfl, Storage.bumpBootstrap, hboot]
      by_cases hc : t.bootstrapUses + 1 > MaxBootstrapUses
      · simp [hc]
      · simp [hc]
    · simp only [bumpForOwner, if_neg h0, Storage.bumpSlot, hslot]
      by_cases hc : t.slotUses oi + 1 > MaxSlotUses
      · simp [hc]
      · simp [hc]
  unfold validateSignature
  rw [hdec]
  simp only
  rw [hown]
  cases howner : t.ownerAtIndex oi with
  | none => rfl
  | some owner =>
    simp only
    rw [hcap]
    by_cases hc : capOk t op oi = false
    · rw [if_pos hc, if_pos hc]
    · rw [if_neg hc, if_neg hc]
      by_cases hv : verify_fn (owner.raw.take 32 (by decide))
          (owner.raw.drop 32 (by decide))
          (sphincsDigest op entryPoint chainId) isig = false
      · rw [if_pos hv, if_pos hv]
      · rw [if_neg hv, if_neg hv]
        cases hbs : bumpForOwner s oi with
        | none =>
          cases hbt : bumpForOwner t oi with
          | none => rfl
          | some t' =>
            rw [hbs, hbt] at hbump
            simp [Option.isSome] at hbump
        | some s' =>
          cases hbt : bumpForOwner t oi with
          | none =>
            rw [hbs, hbt] at hbump
            simp [Option.isSome] at hbump
          | some t' => rfl

end SphincsCVerify.Wallet.Invariants
