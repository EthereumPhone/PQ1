/-
Lean model of `PQMultiOwnableStorage` (the ERC-7201 storage struct used
by `PQSmartWallet` via `PQMultiOwnable`).

This is a pure functional model: we represent each `mapping(K => V)` as
a function `K → V`. The Solidity contract uses keccak256-derived storage
slots (ERC-7201); we abstract over that because:

  * The storage-slot computation is in the EVM TCB (the Solidity
    compiler emits the right `sload` / `sstore` offsets).
  * Our invariants are about the *values*, not the slot layout.

If a future engagement needs to verify storage-slot-derivation
correctness, that becomes a Verity-style obligation discharged once and
reused by every contract.
-/

import SphincsCVerify.Spec.Bytes
import SphincsCVerify.Spec.Params

namespace SphincsCVerify.Wallet

open SphincsCVerify.Spec

/-- The 64-byte owner blob: `pkSeed (32) ‖ pkRoot (32)`. The N-mask
    layout is enforced in `MultiOwnable._addOwnerAtIndex` via Solidity
    `uint128` casts; we mirror it as a `Prop` predicate. -/
structure OwnerBytes where
  raw : ByteVec 64
deriving DecidableEq

namespace OwnerBytes

/-- The N-mask layout: bytes [16..32) and [48..64) must be zero. -/
def hasNMaskLayout (o : OwnerBytes) : Prop :=
  ∀ (i : Fin 64),
    (i.val ≥ 16 ∧ i.val < 32) ∨ (i.val ≥ 48 ∧ i.val < 64) →
    o.raw.get i = 0

end OwnerBytes

/-- The `PQMultiOwnableStorage` struct as a Lean record. Mirrors
    `contracts/smart-wallet/src/PQMultiOwnable.sol`. `removedOwnersCount` is
    reserved and always zero: owner removal was deleted before launch (the
    owner set is append-only) and nothing writes the field; it is kept so the
    record keeps mirroring the Solidity struct field-for-field. -/
structure Storage where
  nextOwnerIndex : Nat
  removedOwnersCount : Nat
  ownerAtIndex : Nat → Option OwnerBytes
  isOwner : OwnerBytes → Bool
  bootstrapUses : Nat
  slotUses : Nat → Nat
  offchainSigCount : Nat → Nat

namespace Storage

/-- The empty storage that every freshly-CREATE2'd proxy starts with. -/
def empty : Storage :=
  { nextOwnerIndex := 0,
    removedOwnersCount := 0,
    ownerAtIndex := fun _ => none,
    isOwner := fun _ => false,
    bootstrapUses := 0,
    slotUses := fun _ => 0,
    offchainSigCount := fun _ => 0 }

/-- After the factory-driven `initialize`: bootstrap key at index 0,
    slot 0 key at index 1; both N-mask compliant. -/
def initialised
    (bootstrap slot0 : OwnerBytes) : Storage :=
  { nextOwnerIndex := 2,
    removedOwnersCount := 0,
    ownerAtIndex := fun i =>
      if i = 0 then some bootstrap
      else if i = 1 then some slot0
      else none,
    isOwner := fun o => decide (o = bootstrap) || decide (o = slot0),
    bootstrapUses := 0,
    slotUses := fun _ => 0,
    offchainSigCount := fun _ => 0 }

/-- Increment `bootstrapUses` (capped at `MaxBootstrapUses`). Returns
    `none` if the cap would be exceeded. -/
def bumpBootstrap (s : Storage) (cap : Nat) : Option Storage :=
  if s.bootstrapUses + 1 > cap then none
  else some { s with bootstrapUses := s.bootstrapUses + 1 }

/-- Increment `slotUses[ownerIndex]` (capped at `MaxSlotUses`). -/
def bumpSlot (s : Storage) (ownerIndex cap : Nat) : Option Storage :=
  if s.slotUses ownerIndex + 1 > cap then none
  else some {
    s with slotUses := fun i =>
      if i = ownerIndex then s.slotUses i + 1 else s.slotUses i }

/-- Set `offchainSigCount[ownerIndex]` to `newCount`. Refuses if
    `newCount < current` (non-monotonic) or if the combined cap would
    be exceeded. -/
def setOffchain
    (s : Storage) (ownerIndex newCount slotUsesNow cap : Nat) : Option Storage :=
  let prev := s.offchainSigCount ownerIndex
  if newCount < prev then none
  else if slotUsesNow + newCount > cap then none
  else some {
    s with offchainSigCount := fun i =>
      if i = ownerIndex then newCount else s.offchainSigCount i }

/-- Add an owner at the next index. -/
def addOwner (s : Storage) (o : OwnerBytes) : Option Storage :=
  if s.isOwner o then none
  else some {
    s with
    nextOwnerIndex := s.nextOwnerIndex + 1,
    ownerAtIndex := fun i =>
      if i = s.nextOwnerIndex then some o else s.ownerAtIndex i,
    isOwner := fun o' => decide (o' = o) || s.isOwner o' }

/-- The wallet's `initialize` function. Returns `none` (i.e. revert)
    if the one-shot guard `nextOwnerIndex == 0` fails, or if the two owners
    are the same key (`PQMultiOwnable._addOwnerAtIndex` reverts
    `AlreadyOwner` on the second install); otherwise installs `bootstrap` at
    index 0 and `slot0` at index 1.

    Mirrors `PQSmartWallet.initialize` + `PQMultiOwnable._initializeOwners`.
    (The N-mask and length gates live in the factory precondition,
    `Factory.createAccountPrecondition`.)

    Named `tryInitialize` (rather than `initialize`) because
    `initialize` is reserved in Lean 4. -/
def tryInitialize (s : Storage) (bootstrap slot0 : OwnerBytes) : Option Storage :=
  if s.nextOwnerIndex ≠ 0 then none
  else if bootstrap = slot0 then none
  else some (Storage.initialised bootstrap slot0)

end Storage

end SphincsCVerify.Wallet
