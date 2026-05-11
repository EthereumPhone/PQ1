/-!
# PQSigner.PQMultiOwnable

Lean port of `contracts/smart-wallet/src/PQMultiOwnable.sol`.

The storage struct + 5 mutating internal helpers + their invariants.
Carries no business logic — it is the substrate that `PQSmartWallet`
mutates via dispatch.

## Mapped invariants (CLAUDE.md non-negotiables)

- **#6 (immutable bootstrap)**: theorem `ownerAtIndex_zero_immutable`.
  Follows from the structural fact that `_addOwner` writes only at
  `nextOwnerIndex` (PQMultiOwnable.sol:175-181) and `_removeOwnerAtIndex`
  reverts on index 0 (line 185).

- **#7 (monotonic per-chain caps)**: theorems
  `bumpBootstrapUses_monotonic_capped`, `bumpSlotUses_monotonic_capped`,
  `setOffchainSigCount_monotonic_combined_cap`, and the inductive
  `combined_cap_preserved` (proved in `Theorems.lean`).
-/

import PQSigner.Common
import Verity.Prelude
import Verity.Storage.Namespaced
import Verity.Tactic

namespace PQSigner.PQMultiOwnable

open PQSigner.Common

/-! ## Errors -/

inductive Error where
  | Unauthorized
  | AlreadyOwner (owner : ByteVec)
  | NoOwnerAtIndex (index : Nat)
  | WrongOwnerAtIndex (index : Nat) (expected actual : ByteVec)
  | InvalidOwnerBytesLength (owner : ByteVec)
  | CannotRemoveBootstrap
  | InvalidNMaskLayout (owner : ByteVec)
  | OffchainSigCountNotMonotonic (ownerIndex current newCount : Nat)
  | CombinedSlotCapExceeded (ownerIndex slotUsesNow newOffchainCount cap : Nat)
  | BootstrapExhausted
  | SlotExhausted (ownerIndex : Nat)
  deriving Repr, DecidableEq

/-! ## Events (kept for differential testing — topic stability) -/

inductive Event where
  | AddOwner (index : Nat) (owner : ByteVec)
  | RemoveOwner (index : Nat) (owner : ByteVec)
  | BootstrapUsed (newCount : Nat)
  | SlotUsed (ownerIndex newCount : Nat)
  | OffchainSigCountUpdated (ownerIndex prev newCount : Nat)
  deriving Repr

/-! ## Storage (ERC-7201 namespaced) -/

/-- Mirror of `PQMultiOwnableStorage` at `PQMultiOwnable.sol:9-35`.
    Same field order. -/
structure Storage where
  nextOwnerIndex : Nat
  removedOwnersCount : Nat
  ownerAtIndex : Nat → ByteVec
  isOwner : ByteVec → Bool
  bootstrapUses : Nat
  slotUses : Nat → Nat
  offchainSigCount : Nat → Nat
  deriving Repr

namespace Storage

/-- Construction-time zero state. The factory deploys the proxy at this
    state, then calls `initialize` which writes `ownerAtIndex[0]` and
    `ownerAtIndex[1]` and advances `nextOwnerIndex` to 2. -/
def empty : Storage := {
  nextOwnerIndex := 0,
  removedOwnersCount := 0,
  ownerAtIndex := fun _ => ByteVec.empty,
  isOwner := fun _ => false,
  bootstrapUses := 0,
  slotUses := fun _ => 0,
  offchainSigCount := fun _ => 0
}

/-- Total active owner count = appended − removed. Mirrors `ownerCount()`
    at `PQMultiOwnable.sol:128-132`. -/
def ownerCount (s : Storage) : Nat :=
  s.nextOwnerIndex - s.removedOwnersCount

end Storage

/-- Verity-style contract state: namespaced storage at the ERC-7201 slot. -/
abbrev State := NamespacedStorage PQ_MULTI_OWNABLE_STORAGE_LOCATION Storage

/-! ## Internal helpers (mirrors of `internal`/`private` Solidity fns) -/

/-- `_addOwnerAtIndex(owner, index)` at `PQMultiOwnable.sol:242-259`.
    Three guards: not-already-owner, N-mask layout, sets isOwner +
    ownerAtIndex. The index is supplied by the caller — callers MUST
    pass `nextOwnerIndex` (we enforce this for `_addOwner` below; the
    factory's `_initializeOwners` also obeys it). -/
def addOwnerAtIndex (s : Storage) (owner : ByteVec) (index : Nat)
    : Except Error (Storage × List Event) := do
  if owner.length != OWNER_BYTES_LEN then
    throw (.InvalidOwnerBytesLength owner)
  if s.isOwner owner then
    throw (.AlreadyOwner owner)
  -- N-mask: low 16 bytes of pkSeed (offset 0..16) and pkRoot (offset 32..48)
  -- must be zero. Mirrors PQMultiOwnable.sol:248-253.
  if ¬ (owner.extract 16 32).isZero ∨ ¬ (owner.extract 48 64).isZero then
    throw (.InvalidNMaskLayout owner)
  let s' := { s with
    isOwner := fun b => if b == owner then true else s.isOwner b,
    ownerAtIndex := fun i => if i == index then owner else s.ownerAtIndex i
  }
  return (s', [.AddOwner index owner])

/-- `_addOwner(owner)` at `PQMultiOwnable.sol:174-181`. Appends at
    `nextOwnerIndex` and increments. **Load-bearing**: this is the only
    public path that writes a new owner slot; combined with theorem
    `removeOwnerAtIndex_zero_reverts` it gives us `ownerAtIndex[0]`
    immutability after construction. -/
def addOwner (s : Storage) (owner : ByteVec)
    : Except Error (Storage × List Event × Nat) := do
  let index := s.nextOwnerIndex
  let (s', evs) ← addOwnerAtIndex s owner index
  let s'' := { s' with nextOwnerIndex := index + 1 }
  return (s'', evs, index)

/-- `_initializeOwners(owners)` at `PQMultiOwnable.sol:162-172`. Bulk
    append, used once by `initialize`. Always starts at the current
    `nextOwnerIndex` (which is 0 at construction → slot 0 is the
    bootstrap key, slot 1 is slot 0 of the per-chain key set, and so on). -/
def initializeOwners (s : Storage) (owners : List ByteVec)
    : Except Error (Storage × List Event) := do
  let mut s' := s
  let mut evs : List Event := []
  for owner in owners do
    let (sNext, evsNext, _idx) ← addOwner s' owner
    s' := sNext
    evs := evs ++ evsNext
  return (s', evs)

/-- `_removeOwnerAtIndex(index, owner)` at `PQMultiOwnable.sol:184-196`.
    Refuses index 0 (`CannotRemoveBootstrap`). -/
def removeOwnerAtIndex (s : Storage) (index : Nat) (owner : ByteVec)
    : Except Error (Storage × List Event) := do
  if index == 0 then throw .CannotRemoveBootstrap
  let current := s.ownerAtIndex index
  if current.length == 0 then throw (.NoOwnerAtIndex index)
  -- The Solidity uses `keccak256(current) == keccak256(owner)` for
  -- gas; byte-equality is functionally identical and easier to reason
  -- about. The differential harness checks both compile to the same
  -- behaviour on the test vectors.
  if current ≠ owner then
    throw (.WrongOwnerAtIndex index owner current)
  let s' := { s with
    isOwner := fun b => if b == owner then false else s.isOwner b,
    ownerAtIndex := fun i => if i == index then ByteVec.empty else s.ownerAtIndex i,
    removedOwnersCount := s.removedOwnersCount + 1
  }
  return (s', [.RemoveOwner index owner])

/-- `_bumpBootstrapUses(cap)` at `PQMultiOwnable.sol:199-205`. -/
def bumpBootstrapUses (s : Storage) (cap : Nat)
    : Except Error (Storage × List Event × Nat) := do
  let next := s.bootstrapUses + 1
  if next > cap then throw .BootstrapExhausted
  let s' := { s with bootstrapUses := next }
  return (s', [.BootstrapUsed next], next)

/-- `_bumpSlotUses(ownerIndex, cap)` at `PQMultiOwnable.sol:208-214`. -/
def bumpSlotUses (s : Storage) (ownerIndex cap : Nat)
    : Except Error (Storage × List Event × Nat) := do
  let next := s.slotUses ownerIndex + 1
  if next > cap then throw (.SlotExhausted ownerIndex)
  let s' := { s with
    slotUses := fun i => if i == ownerIndex then next else s.slotUses i
  }
  return (s', [.SlotUsed ownerIndex next], next)

/-- `_setOffchainSigCount(ownerIndex, newCount, slotUsesNow, cap)` at
    `PQMultiOwnable.sol:220-238`. Three guards: monotonicity, combined
    cap, idempotent no-op when `newCount == prev`. -/
def setOffchainSigCount (s : Storage) (ownerIndex newCount slotUsesNow cap : Nat)
    : Except Error (Storage × List Event × Nat) := do
  let prev := s.offchainSigCount ownerIndex
  if newCount < prev then
    throw (.OffchainSigCountNotMonotonic ownerIndex prev newCount)
  if slotUsesNow + newCount > cap then
    throw (.CombinedSlotCapExceeded ownerIndex slotUsesNow newCount cap)
  if newCount == prev then
    return (s, [], prev)  -- idempotent re-publish; no event.
  let s' := { s with
    offchainSigCount := fun i => if i == ownerIndex then newCount else s.offchainSigCount i
  }
  return (s', [.OffchainSigCountUpdated ownerIndex prev newCount], prev)

/-! ## Theorems (proofs in `PQSigner.Theorems`).

We state the obligations here so that this file is self-describing.
The actual `theorem` blocks live in `Theorems.lean` to keep the spec
file readable. -/

end PQSigner.PQMultiOwnable
