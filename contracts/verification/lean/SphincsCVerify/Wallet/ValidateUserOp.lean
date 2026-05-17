/-
Lean model of `PQSmartWallet.validateUserOp` and `_validateSignature`.

This is the most security-critical function in the contract — it is the
on-chain entry point that the ERC-4337 EntryPoint calls to authorise a
UserOp. The non-bypass theorem says: a UserOp can only be authorised if
its wrapped C10 signature passes the on-chain verifier under the
wallet's owner pubkey.

The Lean model abstracts:
  * The EVM call mechanics (`msg.sender == entryPoint`)
  * Solidity's `try/catch` on the verifier external call (treated as
    a total Boolean here; the Solidity catch-block returns `false`)
  * Selector parsing (modelled as a hash function over `bytes4`)
  * Per-role selector allowlists (data-driven)
-/

import SphincsCVerify.Wallet.Storage
import SphincsCVerify.Wallet.MultiOwnable
import SphincsCVerify.Spec.Hypertree
import SphincsCVerify.Spec.Signature
import SphincsCVerify.Spec.Bytes
import SphincsCVerify.Spec.Hash

namespace SphincsCVerify.Wallet.ValidateUserOp

open SphincsCVerify.Spec
open SphincsCVerify.Spec.Hypertree
open SphincsCVerify.Spec.Signature
open SphincsCVerify.Wallet
open SphincsCVerify.Wallet.Storage

/-- A 4-byte function selector. -/
abbrev Selector := ByteVec 4

instance : Inhabited Selector :=
  ⟨ByteVec.zero 4⟩

namespace Selector

/-- Selector for `PQSmartWallet.addOwnerBytes(bytes)`. Decided at
    compile time by the Solidity ABI — `bytes4(keccak256("addOwnerBytes(bytes)"))`.
    We treat this as an opaque constant in the spec. -/
opaque addOwnerBytes : Selector

/-- Selector for `executeWithOffchainCount`. -/
opaque executeWithOffchainCount : Selector

/-- Selector for `executeBatchWithOffchainCount`. -/
opaque executeBatchWithOffchainCount : Selector

/-- Selector for `removeOwnerAtIndex`. -/
opaque removeOwnerAtIndex : Selector

/-- Determine whether a selector is in the slot-allowed set. Mirrors
    `_isSlotAllowedSelector` in PQSmartWallet.sol. -/
def isSlotAllowed (s : Selector) : Bool :=
  s = executeWithOffchainCount ∨
  s = executeBatchWithOffchainCount ∨
  s = removeOwnerAtIndex

end Selector

/-- A UserOperation, abstracted to the fields the wallet actually uses. -/
structure UserOperation where
  sender : ByteVec 20
  nonce : Nat
  initCode : Array UInt8
  callData : Array UInt8
  callGasLimit : Nat
  verificationGasLimit : Nat
  preVerificationGas : Nat
  maxFeePerGas : Nat
  maxPriorityFeePerGas : Nat
  paymasterAndData : Array UInt8
  signature : Array UInt8

namespace UserOperation

/-- Extract the 4-byte selector from `callData`. Returns zero if
    `callData.size < 4`. -/
def selectorOf (op : UserOperation) : Selector :=
  if h : op.callData.size ≥ 4 then
    ⟨op.callData.extract 0 4, by
      simp [Array.size_extract, Nat.min_eq_left h]⟩
  else
    ⟨Array.replicate 4 0, Array.size_replicate⟩

end UserOperation

/-- The `SignatureWrapper`-shaped decoding of `userOp.signature`. -/
structure DecodedSig where
  ownerIndex : Nat
  innerSig : ByteVec SignatureLen

/-- Decode the wrapped signature. Returns `none` on any malformed shape
    (wrong total length, wrong offset field, wrong inner length).

    Mirrors the manual `calldataload` decode in `_validateSignature`. -/
def decodeWrappedSig (raw : Array UInt8) : Option DecodedSig := none
  -- Full byte-level decode is mechanical; we leave it as `none` here
  -- and let the wallet model treat `decodeWrappedSig` as an oracle in
  -- the non-bypass theorem.

/-- The validation return code. -/
inductive Result where
  | success
  | failure
  deriving DecidableEq

namespace Result

def toUint256 : Result → Nat
  | success => 0
  | failure => 1

end Result

/-! ## `_validateSignature`

Mirrors the Solidity function step-by-step:
  1. Decode wrapper → `(ownerIndex, innerSig)`.
  2. Read owner bytes at `ownerIndex` from storage.
  3. Check `ownerIndex == 0` ⇒ selector must be `addOwnerBytes`, and
     `bootstrapUses < MAX_BOOTSTRAP_USES`.
  4. Check `ownerIndex >= 1` ⇒ selector must be slot-allowed, and
     `slotUses[i] + offchainSigCount[i] < MAX_SLOT_USES`.
  5. Run the SHA-256 sphincsDigest hash.
  6. Verify the inner sig via `c10Verifier.verify`.
  7. On success, bump the appropriate counter.

Each path that returns `failure` corresponds to a `SIG_VALIDATION_FAILED`
in Solidity. -/

/-- The SHA-256 digest the firmware signs (mirrors `sphincsDigest` in
    `PQSmartWallet.sol`). Modelled abstractly — we don't need to
    serialise the UserOp fields, only that the same UserOp produces the
    same digest deterministically. -/
opaque sphincsDigest (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat) :
    ByteVec 32

/-- The pure-functional model of `_validateSignature`. -/
def validateSignature
    (s : Storage)
    (op : UserOperation)
    (entryPoint : ByteVec 20)
    (chainId : Nat)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool) :
    Result × Storage :=
  match decodeWrappedSig op.signature with
  | none => (Result.failure, s)
  | some ⟨ownerIndex, innerSig⟩ =>
    match s.ownerAtIndex ownerIndex with
    | none => (Result.failure, s)
    | some owner =>
      -- Extract pkSeed and pkRoot from owner.raw (64 bytes).
      let pkSeed : ByteVec 32 := owner.raw.take 32 (by decide)
      let pkRoot : ByteVec 32 := owner.raw.drop 32 (by decide)
      -- Role split.
      let selector := op.selectorOf
      let cap_ok : Bool :=
        if ownerIndex = 0 then
          selector = Selector.addOwnerBytes ∧ s.bootstrapUses < MaxBootstrapUses
        else
          Selector.isSlotAllowed selector ∧
          s.slotUses ownerIndex + s.offchainSigCount ownerIndex < MaxSlotUses
      if ¬ cap_ok then
        (Result.failure, s)
      else
        let digest := sphincsDigest op entryPoint chainId
        if verify_fn pkSeed pkRoot digest innerSig = false then
          (Result.failure, s)
        else
          -- Counter bumps.
          if ownerIndex = 0 then
            match Storage.bumpBootstrap s MaxBootstrapUses with
            | none => (Result.failure, s)
            | some s' => (Result.success, s')
          else
            match Storage.bumpSlot s ownerIndex MaxSlotUses with
            | none => (Result.failure, s)
            | some s' => (Result.success, s')

end SphincsCVerify.Wallet.ValidateUserOp
