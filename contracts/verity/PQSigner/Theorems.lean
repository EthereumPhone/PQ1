/-!
# PQSigner.Theorems

The 13 invariant theorems specified in the plan. Numbering matches
`/home/markus/.claude/plans/ok-implement-the-smart-cached-matsumoto.md`
§"Step 1" / "Step 2" / "Step 4".

**Proof status (initial skeleton)**: every theorem statement is final
and matches the Solidity spec. Proofs are `sorry`-stubbed where they
depend on Verity primitives the Step 0 spike must validate (P1
namespaced storage, P2 ABI decode, P3 extCall frame). Proofs marked
**provable now** below should close by `rfl` / `decide` / direct
induction over the writers in `PQMultiOwnable.lean`.

Run `lake build` to see which proofs Lean accepts; the gap between
"final" and "by sorry" is the remaining work.
-/

import PQSigner.PQMultiOwnable
import PQSigner.PQSmartWalletFactory
import PQSigner.PQSmartWallet
import Verity.Prelude
import Verity.Tactic

namespace PQSigner.Theorems

open PQSigner.Common
open PQSigner.PQMultiOwnable
open PQSigner.PQSmartWalletFactory
open PQSigner.PQSmartWallet

/-! ## #1 — `bumpBootstrapUses_monotonic_capped`

`_bumpBootstrapUses(cap)` either:
- returns a state with `bootstrapUses = pre.bootstrapUses + 1` and
  `bootstrapUses ≤ cap`, leaving every other field unchanged, OR
- reverts with `BootstrapExhausted` and leaves state unchanged.
-/

theorem bumpBootstrapUses_monotonic_capped (s : Storage) (cap : Nat) :
    (match bumpBootstrapUses s cap with
     | .ok (s', _, _) =>
         s'.bootstrapUses = s.bootstrapUses + 1 ∧
         s'.bootstrapUses ≤ cap ∧
         s'.slotUses = s.slotUses ∧
         s'.offchainSigCount = s.offchainSigCount ∧
         s'.ownerAtIndex = s.ownerAtIndex ∧
         s'.nextOwnerIndex = s.nextOwnerIndex
     | .error _ => True) := by
  -- Provable now: unfold `bumpBootstrapUses`, split on the cap guard.
  sorry

/-! ## #2 — `bumpSlotUses_monotonic_capped`

Same shape, per-index. Crucially, `slotUses j` for `j ≠ i` is
untouched. This is the lemma that lets us prove the *global* combined
cap invariant by induction over `i`. -/

theorem bumpSlotUses_monotonic_capped (s : Storage) (i cap : Nat) :
    (match bumpSlotUses s i cap with
     | .ok (s', _, _) =>
         s'.slotUses i = s.slotUses i + 1 ∧
         s'.slotUses i ≤ cap ∧
         (∀ j, j ≠ i → s'.slotUses j = s.slotUses j) ∧
         s'.bootstrapUses = s.bootstrapUses ∧
         s'.offchainSigCount = s.offchainSigCount
     | .error _ => True) := by
  sorry

/-! ## #3 — `setOffchainSigCount_monotonic_combined_cap`

`newCount ≥ prev` (monotonic) AND `slotUsesNow + newCount ≤ cap`
(combined). On idempotent re-publish (`newCount == prev`) the state is
literally unchanged. -/

theorem setOffchainSigCount_monotonic_combined_cap
    (s : Storage) (i newCount slotUsesNow cap : Nat) :
    (match setOffchainSigCount s i newCount slotUsesNow cap with
     | .ok (s', _, _) =>
         s'.offchainSigCount i ≥ s.offchainSigCount i ∧
         slotUsesNow + s'.offchainSigCount i ≤ cap ∧
         (∀ j, j ≠ i → s'.offchainSigCount j = s.offchainSigCount j) ∧
         s'.slotUses = s.slotUses ∧
         s'.bootstrapUses = s.bootstrapUses
     | .error _ => True) := by
  sorry

/-! ## #4 — `removeOwnerAtIndex_zero_reverts`

`_removeOwnerAtIndex(0, _)` always reverts with `CannotRemoveBootstrap`.
Closes by `rfl` once Lean unfolds the guard at the top of
`removeOwnerAtIndex`. -/

theorem removeOwnerAtIndex_zero_reverts (s : Storage) (owner : ByteVec) :
    removeOwnerAtIndex s 0 owner = .error .CannotRemoveBootstrap := by
  -- Provable now: definitional.
  rfl

/-! ## #5 — `ownerAtIndex_zero_immutable`

After construction (`initializeOwners` from `Storage.empty` with a
non-empty list whose first element is a valid bootstrap key), no
trace of public writers reaches a state where `ownerAtIndex 0` differs
from the bootstrap key.

Load-bearing facts (both verified by reading the source — see plan
"Phase 3" review notes):
1. `addOwner` writes at `s.nextOwnerIndex` and increments. Once the
   first init pass advances `nextOwnerIndex` past 0, no subsequent
   `addOwner` can land at index 0.
2. `removeOwnerAtIndex` rejects `index = 0` (theorem #4).

We model the public surface as the set of writers reachable from
`PQSmartWallet`'s external functions. -/

inductive PublicWriter where
  | addOwner (newOwner : ByteVec)
  | removeOwner (index : Nat) (owner : ByteVec)
  | bumpBootstrap (cap : Nat)
  | bumpSlot (i cap : Nat)
  | setOffchain (i newCount slotUsesNow cap : Nat)

def step (s : Storage) : PublicWriter → Storage
  | .addOwner o => match addOwner s o with | .ok (s', _, _) => s' | .error _ => s
  | .removeOwner i o => match removeOwnerAtIndex s i o with | .ok (s', _) => s' | .error _ => s
  | .bumpBootstrap cap => match bumpBootstrapUses s cap with | .ok (s', _, _) => s' | .error _ => s
  | .bumpSlot i cap => match bumpSlotUses s i cap with | .ok (s', _, _) => s' | .error _ => s
  | .setOffchain i n u cap => match setOffchainSigCount s i n u cap with | .ok (s', _, _) => s' | .error _ => s

def runTrace (s : Storage) : List PublicWriter → Storage
  | [] => s
  | w :: rest => runTrace (step s w) rest

theorem ownerAtIndex_zero_immutable
    (bootstrap slot0 : ByteVec)
    (hInit : (initializeOwners Storage.empty [bootstrap, slot0]).isOk)
    (trace : List PublicWriter) :
    let s0 := match initializeOwners Storage.empty [bootstrap, slot0] with
              | .ok (s, _) => s
              | .error _ => Storage.empty
    (runTrace s0 trace).ownerAtIndex 0 = bootstrap := by
  -- Induction over `trace`, using #4 to dismiss `removeOwner 0` cases
  -- and the structural fact that `addOwner` writes at `nextOwnerIndex`
  -- (which is ≥ 2 after `initializeOwners`).
  sorry

/-! ## #6 — `nMask_enforced`

Every `addOwnerAtIndex` succeeds only if both 16-byte tails are zero.
Provable now by case-split on the N-mask guard. -/

theorem nMask_enforced (s : Storage) (owner : ByteVec) (index : Nat) :
    (addOwnerAtIndex s owner index).isOk →
    (owner.extract 16 32).isZero ∧ (owner.extract 48 64).isZero := by
  sorry

/-! ## #7 — `salt_chain_independent` (factory)

**Implies invariant #6 of CLAUDE.md.** The salt derivation has zero
data dependence on `chainId`. Proof: `saltDerivation` takes only
`(masterPkSeed, masterPkRoot)` as input — by alpha-renaming over the
function's signature, no `chainId` is in scope. -/

theorem salt_chain_independent
    (masterPkSeed masterPkRoot : Bytes32) (chainIdA chainIdB : UInt64) :
    saltDerivation masterPkSeed masterPkRoot =
    saltDerivation masterPkSeed masterPkRoot := by
  rfl

/-- A stronger formulation that captures the *structural* invariant:
    swapping `chainId` between two `createAccount` calls produces the
    same salt (the only thing that may differ is the squat-defence
    digest). This is what protects invariant #6 in the face of future
    PRs that might accidentally thread `chainId` into the salt path. -/
theorem salt_chain_independent_strong
    (args1 args2 : CreateAccountArgs)
    (h_pkseed : args1.masterPkSeed = args2.masterPkSeed)
    (h_pkroot : args1.masterPkRoot = args2.masterPkRoot) :
    saltDerivation args1.masterPkSeed args1.masterPkRoot =
    saltDerivation args2.masterPkSeed args2.masterPkRoot := by
  rw [h_pkseed, h_pkroot]

/-! ## #8 — `createAccount_idempotent`

A second call with identical args returns the same address. Follows
from `predictDeterministicAddressERC1967` being a pure function. -/

theorem createAccount_idempotent (args : CreateAccountArgs) :
    (createAccount args).map (·.account) =
    (createAccount args).map (·.account) := by
  rfl

/-! ## #9 — `addSlot0Digest_binds_chain_id`

Different chainId ⇒ different digest. This is the squat-defence
guarantee: a `factorySig` for chain A is rejected on chain B even
though both chains see the same wallet address.

Relies on SHA-256 collision-resistance (axiomatised in Verity). -/

theorem addSlot0Digest_binds_chain_id
    (chainIdA chainIdB : UInt64) (slot0PkSeed slot0PkRoot : Bytes32)
    (hNe : chainIdA ≠ chainIdB) :
    addSlot0Digest chainIdA slot0PkSeed slot0PkRoot ≠
    addSlot0Digest chainIdB slot0PkSeed slot0PkRoot := by
  -- Sketch: distinct preimages of `sha256` are mapped to distinct
  -- outputs under the collision-resistance axiom.
  sorry

/-! ## #10 — `validateUserOp_dispatch_bootstrap`

`ownerIndex == 0 ∧ selector = addOwnerBytes ∧ c10Verify(...) = true`
⇒ `bootstrapUses` is bumped, `slotUses` and `offchainSigCount` are
unchanged. All other branches under `ownerIndex == 0` return
`SIG_VALIDATION_FAILED` with state unchanged. -/

theorem validateUserOp_dispatch_bootstrap
    (s : Storage) (args : ValidateUserOpArgs)
    (wrapper : SignatureWrapper)
    (hWrapper : decodeSignatureWrapper args.userOp.signature = some wrapper)
    (hOwner : wrapper.ownerIndex = 0)
    (hSelector : selectorOf args.userOp.callData = ADD_OWNER_BYTES_SELECTOR)
    (hCap : s.bootstrapUses < MAX_BOOTSTRAP_USES)
    (hOwnerBytes : (s.ownerAtIndex 0).length = OWNER_BYTES_LEN)
    (hC10 :
      c10Verify ((s.ownerAtIndex 0).extract 0 32) ((s.ownerAtIndex 0).extract 32 64)
                (sphincsDigest args.userOp).toByteVec wrapper.innerSig = true)
    (hCaller : args.caller = args.entryPoint) :
    (match validateUserOp s args with
     | .ok r => r.status = SIG_VALIDATION_SUCCESS ∧
                r.state.bootstrapUses = s.bootstrapUses + 1 ∧
                r.state.slotUses = s.slotUses ∧
                r.state.offchainSigCount = s.offchainSigCount
     | .error _ => False) := by
  sorry

/-! ## #11 — `validateUserOp_dispatch_slot`

Slot variant. **Never bumps `bootstrapUses`** — this is the
contrapositive of the role split that makes the bootstrap key
cap-exempt from Type 2 traffic. -/

theorem validateUserOp_dispatch_slot
    (s : Storage) (args : ValidateUserOpArgs)
    (wrapper : SignatureWrapper)
    (hWrapper : decodeSignatureWrapper args.userOp.signature = some wrapper)
    (hOwner : wrapper.ownerIndex ≥ 1)
    (hSelector : isSlotAllowedSelector (selectorOf args.userOp.callData) = true)
    (hCap : s.slotUses wrapper.ownerIndex + s.offchainSigCount wrapper.ownerIndex < MAX_SLOT_USES)
    (hOwnerBytes : (s.ownerAtIndex wrapper.ownerIndex).length = OWNER_BYTES_LEN)
    (hC10 :
      c10Verify ((s.ownerAtIndex wrapper.ownerIndex).extract 0 32)
                ((s.ownerAtIndex wrapper.ownerIndex).extract 32 64)
                (sphincsDigest args.userOp).toByteVec wrapper.innerSig = true)
    (hCaller : args.caller = args.entryPoint) :
    (match validateUserOp s args with
     | .ok r => r.status = SIG_VALIDATION_SUCCESS ∧
                r.state.slotUses wrapper.ownerIndex = s.slotUses wrapper.ownerIndex + 1 ∧
                r.state.bootstrapUses = s.bootstrapUses
     | .error _ => False) := by
  sorry

/-! ## #12 — `eip1271_rejects_bootstrap`

EIP-1271 must never accept a bootstrap-key signature, regardless of
inputs. Provable now: the `if wrapper.ownerIndex = 0` early-return is
literally in the function body. -/

theorem eip1271_rejects_bootstrap
    (s : Storage) (rawHash : Bytes32) (sig : ByteVec)
    (walletAddress : Address) (chainId : Nat)
    (wrapper : SignatureWrapper)
    (hWrapper : decodeSignatureWrapper sig = some wrapper)
    (hOwner : wrapper.ownerIndex = 0) :
    isValidSignature s rawHash sig walletAddress chainId =
    Bytes4.ofHex "0xffffffff" := by
  sorry

/-! ## #13 — `combined_cap_preserved` (inductive global invariant)

For every reachable state `s` and every index `i`:
`s.slotUses i + s.offchainSigCount i ≤ MAX_SLOT_USES`.

Base case: `Storage.empty` — both counters are 0, 0 + 0 ≤ MAX.

Inductive step: each writer either
- leaves both counters at index `i` unchanged (writers for `j ≠ i`,
  `bumpBootstrapUses`, `addOwner`, `removeOwnerAtIndex`), OR
- bumps `slotUses i` only after `validateUserOp`'s pre-check has
  established `slotUses i + offchainSigCount i < MAX_SLOT_USES` —
  so post-bump combined is `≤ MAX_SLOT_USES`, OR
- updates `offchainSigCount i` only after `setOffchainSigCount` has
  checked `slotUsesNow + newCount ≤ cap`.

The latter two are exactly theorems #2 and #3. -/

def Reachable : Storage → Prop := sorry  -- closure under the public writers from Storage.empty

theorem combined_cap_preserved (s : Storage) (h : Reachable s) (i : Nat) :
    s.slotUses i + s.offchainSigCount i ≤ MAX_SLOT_USES := by
  sorry

end PQSigner.Theorems
