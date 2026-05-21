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
  * Selector parsing (modelled at the byte level)
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

/-- Selector for `PQSmartWallet.addOwnerBytes(bytes)`.

    `bytes4(keccak256("addOwnerBytes(bytes)")) = 0x101490cb`. The
    constant is parity-tested against `forge inspect PQSmartWallet
    methodIdentifiers` by `test/LeanSelectorParity.t.sol`; any future
    ABI drift fails CI. -/
def addOwnerBytes : Selector :=
  ⟨#[0x10, 0x14, 0x90, 0xcb], by decide⟩

/-- Selector for `executeWithOffchainCount(uint256,uint256,address,uint256,bytes)`.

    `bytes4(keccak256("executeWithOffchainCount(uint256,uint256,address,uint256,bytes)")) = 0x14443c57`. -/
def executeWithOffchainCount : Selector :=
  ⟨#[0x14, 0x44, 0x3c, 0x57], by decide⟩

/-- Selector for `executeBatchWithOffchainCount(uint256,uint256,address[],uint256[],bytes[])`.

    `bytes4(keccak256(...)) = 0x7a389933`. -/
def executeBatchWithOffchainCount : Selector :=
  ⟨#[0x7a, 0x38, 0x99, 0x33], by decide⟩

/-- Selector for `removeOwnerAtIndex(uint256,bytes)`.

    `bytes4(keccak256("removeOwnerAtIndex(uint256,bytes)")) = 0x89625b57`. -/
def removeOwnerAtIndex : Selector :=
  ⟨#[0x89, 0x62, 0x5b, 0x57], by decide⟩

/-- Determine whether a selector is in the slot-allowed set. Mirrors
    `_isSlotAllowedSelector` in PQSmartWallet.sol. -/
def isSlotAllowed (s : Selector) : Bool :=
  decide (s = executeWithOffchainCount) ||
  decide (s = executeBatchWithOffchainCount) ||
  decide (s = removeOwnerAtIndex)

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

namespace DecodedSig

instance : Inhabited DecodedSig :=
  ⟨{ ownerIndex := 0,
     innerSig := ⟨Array.replicate SignatureLen 0, Array.size_replicate⟩ }⟩

end DecodedSig

/-- The padded inner-signature length (rounded up to a 32-byte
    boundary, per `abi.encode`). For SPHINCS+C10's 4008-byte sig this
    is `⌈4008/32⌉ * 32 = 4032`. -/
def paddedInnerLen : Nat := ((SignatureLen + 31) / 32) * 32

/-- The total expected length of the ABI-encoded `SignatureWrapper`:
    32 (ownerIndex) + 32 (offset) + 32 (length) + paddedInner. -/
def wrappedLen : Nat := 96 + paddedInnerLen

/-- Layout sanity. -/
theorem paddedInnerLen_eq : paddedInnerLen = 4032 := by decide
theorem wrappedLen_eq : wrappedLen = 4128 := by decide

/-- Read a big-endian 32-byte unsigned word from a byte array at
    `offset`. Out-of-bounds bytes are read as zero (matches
    `calldataload`'s zero-padding). -/
def readWordBE (raw : Array UInt8) (offset : Nat) : Nat := Id.run do
  let mut acc : Nat := 0
  for i in [:32] do
    let b : UInt8 :=
      if h : offset + i < raw.size then raw[offset + i]'h else 0
    acc := (acc <<< 8) ||| b.toNat
  pure acc

/-- Extract a `ByteVec SignatureLen` from `raw` starting at byte
    `offset`. If insufficient bytes remain, returns the all-zero
    fallback (signal to upper layers that decoding failed). -/
def extractInnerSig (raw : Array UInt8) (offset : Nat) : ByteVec SignatureLen :=
  if h : offset + SignatureLen ≤ raw.size then
    ⟨raw.extract offset (offset + SignatureLen), by
      simp [Array.size_extract, Nat.min_eq_left h]⟩
  else
    ⟨Array.replicate SignatureLen 0, Array.size_replicate⟩

/-- Decode the wrapped signature. Returns `none` on any malformed
    shape (wrong total length, wrong offset field, wrong inner length).

    Mirrors the manual `calldataload`-based decode in
    `_validateSignature` (`contracts/smart-wallet/src/PQSmartWallet.sol`
    lines 280-295). The layout is:

    ```
      [0..32)   ownerIndex   (u256 BE)
      [32..64)  offsetField  (u256 BE; MUST be 0x40)
      [64..96)  innerLen     (u256 BE; MUST be 4008)
      [96..96+paddedInner)   inner C10 signature (padded to 32B boundary)
    ```
-/
def decodeWrappedSig (raw : Array UInt8) : Option DecodedSig :=
  if raw.size ≠ wrappedLen then
    none
  else
    let ownerIndex := readWordBE raw 0
    let offsetField := readWordBE raw 32
    let innerLen := readWordBE raw 64
    if offsetField ≠ 0x40 then
      none
    else if innerLen ≠ SignatureLen then
      none
    else
      some { ownerIndex := ownerIndex, innerSig := extractInnerSig raw 96 }

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

/-- The 360-byte concatenation that `sphincsDigest` hashes. Exact
    byte-for-byte mirror of `PQSmartWallet.sphincsDigest`'s
    `abi.encodePacked(...)` argument:

    ```
      [  0..20 )   sender                       (20)
      [ 20..52 )   nonce                        (uint256 BE, 32)
      [ 52..84 )   sha256(initCode)             (32)
      [ 84..116)   sha256(callData)             (32)
      [116..148)   callGasLimit                 (uint256 BE)
      [148..180)   verificationGasLimit         (uint256 BE)
      [180..212)   preVerificationGas           (uint256 BE)
      [212..244)   maxFeePerGas                 (uint256 BE)
      [244..276)   maxPriorityFeePerGas         (uint256 BE)
      [276..308)   sha256(paymasterAndData)     (32)
      [308..328)   entryPoint                   (20)
      [328..360)   chainId                      (uint256 BE)
    ```

    The fixed `ByteVec 360` return type gives the preimage-length
    lemma `sphincsDigest_preimage_len` for free, and lets the
    per-field binding theorems extract specific byte ranges by
    structure. -/
def sphincsDigestPreimage
    (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat) :
    ByteVec 360 :=
  ByteVec.cast (by decide) <|
    op.sender
    ++ ByteVec.natToB32 op.nonce
    ++ sha256OfArr op.initCode
    ++ sha256OfArr op.callData
    ++ ByteVec.natToB32 op.callGasLimit
    ++ ByteVec.natToB32 op.verificationGasLimit
    ++ ByteVec.natToB32 op.preVerificationGas
    ++ ByteVec.natToB32 op.maxFeePerGas
    ++ ByteVec.natToB32 op.maxPriorityFeePerGas
    ++ sha256OfArr op.paymasterAndData
    ++ entryPoint
    ++ ByteVec.natToB32 chainId

/-- The SHA-256 digest the firmware signs. Concrete 12-field
    `abi.encodePacked` + outer `sha256`, exact mirror of
    `PQSmartWallet.sphincsDigest` (Solidity lines 326-343). The
    binding properties (preimage-injectivity, per-field commitment)
    are proven in `Wallet/SphincsDigestSpec.lean`. -/
def sphincsDigest
    (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat) :
    ByteVec 32 :=
  sha256_concat (sphincsDigestPreimage op entryPoint chainId)

/-- The cap-check predicate (role-split): bootstrap path requires
    `addOwnerBytes` selector + `bootstrapUses` budget; slot path
    requires a slot-allowed selector + combined cap budget. -/
def capOk
    (s : Storage) (op : UserOperation) (ownerIndex : Nat) : Bool :=
  if ownerIndex = 0 then
    decide (op.selectorOf = Selector.addOwnerBytes) &&
    decide (s.bootstrapUses < MaxBootstrapUses)
  else
    Selector.isSlotAllowed op.selectorOf &&
    decide (s.slotUses ownerIndex + s.offchainSigCount ownerIndex < MaxSlotUses)

/-- The counter-bump step run on the success path. Returns the
    post-bump storage, or `none` if the cap has been reached
    (defensive: `validateSignature`'s `capOk` already rules this out
    on the success path). -/
def bumpForOwner (s : Storage) (ownerIndex : Nat) : Option Storage :=
  if ownerIndex = 0 then
    Storage.bumpBootstrap s MaxBootstrapUses
  else
    Storage.bumpSlot s ownerIndex MaxSlotUses

/-- The success predicate: the conjunction of all conditions that must
    hold for `validateSignature` to return `Result.success`.

    Decomposed into a `Prop` so the non-bypass theorem `validateSignature_only_via_verify`
    can read off the existentials cleanly. -/
def validateSignatureOk
    (s : Storage)
    (op : UserOperation)
    (entryPoint : ByteVec 20)
    (chainId : Nat)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (d : DecodedSig) (owner : OwnerBytes) : Prop :=
  decodeWrappedSig op.signature = some d
  ∧ s.ownerAtIndex d.ownerIndex = some owner
  ∧ capOk s op d.ownerIndex = true
  ∧ verify_fn (owner.raw.take 32 (by decide))
              (owner.raw.drop 32 (by decide))
              (sphincsDigest op entryPoint chainId) d.innerSig = true
  ∧ (bumpForOwner s d.ownerIndex).isSome = true

/-- The pure-functional model of `_validateSignature`. Refactored to
    derive the success result from `validateSignatureOk` so invariant
    proofs work directly on the conjunctive form. -/
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
      let pkSeed : ByteVec 32 := owner.raw.take 32 (by decide)
      let pkRoot : ByteVec 32 := owner.raw.drop 32 (by decide)
      if capOk s op ownerIndex = false then
        (Result.failure, s)
      else
        let digest := sphincsDigest op entryPoint chainId
        if verify_fn pkSeed pkRoot digest innerSig = false then
          (Result.failure, s)
        else
          match bumpForOwner s ownerIndex with
          | none => (Result.failure, s)
          | some s' => (Result.success, s')

/-- Characterisation: `validateSignature` returns `Result.success` iff
    there is a decoded sig and owner satisfying `validateSignatureOk`,
    and `s' = bumpForOwner s d.ownerIndex` (the post-counter-bump
    storage).

    This is the load-bearing lemma all invariant proofs key off of. -/
theorem validateSignature_success_iff
    (s : Storage)
    (op : UserOperation)
    (entryPoint : ByteVec 20)
    (chainId : Nat)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (s' : Storage) :
    validateSignature s op entryPoint chainId verify_fn = (Result.success, s') ↔
    ∃ d owner, validateSignatureOk s op entryPoint chainId verify_fn d owner
      ∧ bumpForOwner s d.ownerIndex = some s' := by
  constructor
  · -- Forward direction.
    intro h
    unfold validateSignature at h
    generalize hdec_def : decodeWrappedSig op.signature = decRes at h
    cases decRes with
    | none => simp at h
    | some d =>
      simp only at h  -- reduce `match some d with`
      generalize hown_def : s.ownerAtIndex d.ownerIndex = ownRes at h
      cases ownRes with
      | none => simp at h
      | some owner =>
        try simp only at h
        by_cases hcap : capOk s op d.ownerIndex = false
        · rw [if_pos hcap] at h; simp at h
        · rw [if_neg hcap] at h
          try simp only at h
          by_cases hvf : verify_fn (owner.raw.take 32 (by decide))
              (owner.raw.drop 32 (by decide))
              (sphincsDigest op entryPoint chainId) d.innerSig = false
          · rw [if_pos hvf] at h; simp at h
          · rw [if_neg hvf] at h
            generalize hbump_def : bumpForOwner s d.ownerIndex = bumpRes at h
            cases bumpRes with
            | none => simp at h
            | some s'' =>
              simp only at h
              -- h : (Result.success, s'') = (Result.success, s')
              obtain ⟨_, hseq⟩ := Prod.mk.inj h
              have hcapTrue : capOk s op d.ownerIndex = true := by
                match hv : capOk s op d.ownerIndex with
                | true => rfl
                | false => exact absurd hv hcap
              have hvTrue : verify_fn (owner.raw.take 32 (by decide))
                  (owner.raw.drop 32 (by decide))
                  (sphincsDigest op entryPoint chainId) d.innerSig = true := by
                match hv : verify_fn (owner.raw.take 32 (by decide))
                    (owner.raw.drop 32 (by decide))
                    (sphincsDigest op entryPoint chainId) d.innerSig with
                | true => rfl
                | false => exact absurd hv hvf
              refine ⟨d, owner, ⟨hdec_def, hown_def, hcapTrue, hvTrue, ?_⟩, ?_⟩
              · rw [hbump_def]; rfl
              · rw [hbump_def, hseq]
  · -- Reverse direction.
    rintro ⟨d, owner, ⟨hdec, hown, hcap, hverify, _hbump_some⟩, hbump_eq⟩
    unfold validateSignature
    rw [hdec]
    try simp only
    rw [hown]
    try simp only
    have hcap_neg : ¬ (capOk s op d.ownerIndex = false) := by
      rw [hcap]; decide
    rw [if_neg hcap_neg]
    try simp only
    have hvf_neg : ¬ (verify_fn (owner.raw.take 32 (by decide))
        (owner.raw.drop 32 (by decide))
        (sphincsDigest op entryPoint chainId) d.innerSig = false) := by
      rw [hverify]; decide
    rw [if_neg hvf_neg]
    rw [hbump_eq]

end SphincsCVerify.Wallet.ValidateUserOp
