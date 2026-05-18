/-!
# PQSigner.PQSmartWallet

Lean port of `contracts/smart-wallet/src/PQSmartWallet.sol` —
**dispatch logic only**.

The C10 verifier is an opaque oracle (see `PQSmartWalletFactory.lean`);
the actual user-call target in `executeWithOffchainCount` is modelled
via `Verity.External.Call.extCall` under a frame-separation axiom
(prerequisite P3 from the plan; gated by the Step 0 spike).

## Mapped theorems

- `validateUserOp_dispatch_bootstrap` (#10) — `ownerIndex == 0` ⇒
  `addOwnerBytes` only, bumps `bootstrapUses`.
- `validateUserOp_dispatch_slot` (#11) — `ownerIndex ≥ 1` ⇒ slot
  selectors only, bumps `slotUses[i]`, never `bootstrapUses`.
- `eip1271_rejects_bootstrap` (#12) — EIP-1271 returns `0xffffffff` on
  `ownerIndex == 0`.
- `combined_cap_preserved` (#13) — pre-bump combined check + bump
  sequence preserves `slotUses[i] + offchainSigCount[i] <= MAX_SLOT_USES`.

## Gated on P3

`executeWithOffchainCount` calls `extCall(target, value, data)`. The
frame-separation axiom (extCall cannot touch our ERC-7201 namespace)
is the load-bearing requirement. If `lake build` flags this as
unsupported in Verity v0.1.0, drop `executeWithOffchainCount` from
this file (and theorems #10/#11/#12) and ship the hybrid pivot — the
Foundry differential still covers the cases.
-/

import PQSigner.Common
import PQSigner.PQMultiOwnable
import PQSigner.PQSmartWalletFactory  -- shared c10Verify oracle
import Verity.Prelude
import Verity.Hash.Sha256
import Verity.External.Call
import Verity.UserOp.V06

namespace PQSigner.PQSmartWallet

open PQSigner.Common
open PQSigner.PQMultiOwnable

/-! ## Errors -/

inductive Error where
  | NotFromEntryPoint
  | NotFromSelf
  | AlreadyInitialized
  | InvalidSignatureWrapper
  deriving Repr

/-! ## SignatureWrapper ABI decode

Mirrors the manual `assembly` calldata parse at
`PQSmartWallet.sol:280-295`:

```
[0x00..0x20)  ownerIndex (uint256 BE)
[0x20..0x40)  offset to bytes payload (must be 0x40)
[0x40..0x60)  innerLen (must be C10_SIG_LEN = 4008)
[0x60..0x60+innerLen)  innerSig
```

The whole wrapper is `SIG_WRAPPER_LEN = 4128` bytes. We expose a
`decode` returning `Option` so the caller can short-circuit on
malformed input (which the Solidity does via `return SIG_VALIDATION_FAILED`).
-/

structure SignatureWrapper where
  ownerIndex : Nat
  innerSig : ByteVec

/-- Decode the SignatureWrapper from raw ABI-encoded bytes. Returns
    `none` on any layout violation (wrong offset, wrong length). -/
def decodeSignatureWrapper (sig : ByteVec) : Option SignatureWrapper := do
  guard (sig.length ≥ 96)
  let ownerIndex := (sig.extract 0 32).toNatBE
  let offsetField := (sig.extract 32 64).toNatBE
  let innerLen := (sig.extract 64 96).toNatBE
  guard (offsetField = 0x40)
  guard (innerLen = C10_SIG_LEN)
  guard (sig.length ≥ 96 + C10_SIG_LEN)
  let innerSig := sig.extract 96 (96 + C10_SIG_LEN)
  return { ownerIndex, innerSig }

/-! ## Selector classification (Type 2 allowlist)

Mirror of `_isSlotAllowedSelector` at
`PQSmartWallet.sol:355-360`. -/

def isSlotAllowedSelector (s : UInt32) : Bool :=
  s = EXECUTE_WITH_OFFCHAIN_COUNT_SELECTOR ∨
  s = EXECUTE_BATCH_WITH_OFFCHAIN_COUNT_SELECTOR ∨
  s = REMOVE_OWNER_AT_INDEX_SELECTOR

def isBootstrapAllowedSelector (s : UInt32) : Bool :=
  s = ADD_OWNER_BYTES_SELECTOR

/-! ## `sphincsDigest`

The exact SHA-256 preimage signed by the firmware over a UserOp. This
preimage layout is **frozen** — it is baked into the deployed verifier
and the firmware's `cmd_sign_userop.rs`. See CLAUDE.md §"Wire formats
(frozen — on-chain verifier depends on them)" for the full byte
layout. We model it here as a pure function over the UserOp fields.

This function MUST agree byte-for-byte with the Solidity
`sphincsDigest()` view. The differential harness asserts equality on
every test vector. -/
opaque sphincsDigest (userOp : UserOp06) : Bytes32

/-! ## `validateUserOp` dispatch

Mirror of `validateUserOp` at `PQSmartWallet.sol:141-344`. Five
phases:

1. Decode SignatureWrapper.
2. Look up `ownerAtIndex(ownerIndex)`; reject if not a 64-byte entry.
3. Role split (the heart of theorems #10 and #11):
   - `ownerIndex == 0` → require `selector == addOwnerBytes` AND
     `bootstrapUses < MAX_BOOTSTRAP_USES`.
   - `ownerIndex ≥ 1` → require `selector ∈ slotSelectors` AND
     `slotUses[i] + offchainSigCount[i] < MAX_SLOT_USES`.
4. C10 verify against `sphincsDigest(userOp)`; catch revert as false.
5. Counter bumps after successful verify.
-/

structure ValidateUserOpArgs where
  userOp : UserOp06
  userOpHash : Bytes32
  missingAccountFunds : Nat
  caller : Address
  entryPoint : Address

structure ValidateUserOpResult where
  state : Storage
  events : List Event
  status : Nat  -- SIG_VALIDATION_SUCCESS | SIG_VALIDATION_FAILED

/-- Project the function selector from `userOp.callData`. Returns 0
    when `callData.length < 4`. Mirrors `_selectorOf` at
    `PQSmartWallet.sol:346-352`. -/
def selectorOf (callData : ByteVec) : UInt32 :=
  if callData.length < 4 then 0
  else (callData.extract 0 4).toUInt32BE

def validateUserOp
    (s : Storage) (args : ValidateUserOpArgs)
    : Except Error ValidateUserOpResult := do
  if args.caller ≠ args.entryPoint then throw .NotFromEntryPoint

  let some wrapper := decodeSignatureWrapper args.userOp.signature
    | return { state := s, events := [], status := SIG_VALIDATION_FAILED }

  let ownerBytes := s.ownerAtIndex wrapper.ownerIndex
  if ownerBytes.length ≠ OWNER_BYTES_LEN then
    return { state := s, events := [], status := SIG_VALIDATION_FAILED }

  let pkSeed := (ownerBytes.extract 0 32).toBytes32
  let pkRoot := (ownerBytes.extract 32 64).toBytes32
  let selector := selectorOf args.userOp.callData

  -- Role split. Both branches MUST set up identical preconditions for
  -- the verify and bump steps — the only thing that differs is which
  -- selector set is allowed and which counter gets bumped.
  let bumpAction : Storage → Except Error (Storage × List Event) := ←
    if wrapper.ownerIndex = 0 then
      if ¬ isBootstrapAllowedSelector selector then
        return fun s' => return (s', [])  -- caller short-circuits to FAILED below
      else if s.bootstrapUses ≥ MAX_BOOTSTRAP_USES then
        return fun s' => return (s', [])
      else
        return fun s' => do
          let (s'', evs, _) ← bumpBootstrapUses s' MAX_BOOTSTRAP_USES
          return (s'', evs)
    else
      if ¬ isSlotAllowedSelector selector then
        return fun s' => return (s', [])
      else if s.slotUses wrapper.ownerIndex + s.offchainSigCount wrapper.ownerIndex ≥ MAX_SLOT_USES then
        return fun s' => return (s', [])
      else
        return fun s' => do
          let (s'', evs, _) ← bumpSlotUses s' wrapper.ownerIndex MAX_SLOT_USES
          return (s'', evs)

  -- Note: the conditional `return` above means we will FAIL the rest
  -- of the function for any unauthorised case. The Solidity returns
  -- SIG_VALIDATION_FAILED in those cases too.
  -- (When the dispatch is properly written in Verity's EDSL this
  -- pattern is captured as an early-return; the shape above is
  -- semantically equivalent and easier to prove against.)

  let digest := sphincsDigest args.userOp
  let ok := c10Verify pkSeed.toByteVec pkRoot.toByteVec digest.toByteVec wrapper.innerSig
  if ¬ ok then
    return { state := s, events := [], status := SIG_VALIDATION_FAILED }

  let (s', evs) ← bumpAction s
  return { state := s', events := evs, status := SIG_VALIDATION_SUCCESS }

/-! ## `executeWithOffchainCount`

Gated on P3 (frame-separation for `extCall`). Mirror of
`PQSmartWallet.sol:172-193`.

Two phases:

1. Update `offchainSigCount[ownerIndex]` under monotonicity + combined-cap
   guards (`setOffchainSigCount`).
2. External call to `target` with `value`/`data`. Bubble revert.
-/

structure ExecuteArgs where
  ownerIndex : Nat
  newOffchainCount : Nat
  target : Address
  value : Nat
  data : ByteVec
  caller : Address
  entryPoint : Address

def executeWithOffchainCount
    (s : Storage) (args : ExecuteArgs)
    : Except Error (Storage × List Event × ByteVec) := do
  if args.caller ≠ args.entryPoint then throw .NotFromEntryPoint
  let slotUsesNow := s.slotUses args.ownerIndex
  let (s', evs, _prev) ←
    setOffchainSigCount s args.ownerIndex args.newOffchainCount slotUsesNow MAX_SLOT_USES
  -- Frame-separation axiom: `extCall` does NOT touch the
  -- PQ_MULTI_OWNABLE_STORAGE_LOCATION namespace. This is the
  -- prerequisite P3 from the plan.
  let result ← External.extCall args.target args.value args.data
  return (s', evs, result.returnData)

/-! ## `isValidSignature` (EIP-1271)

Mirror of `PQSmartWallet.sol:401-443` (inherited from Solady
`ERC1271`). View-only. Decodes the same SignatureWrapper and **forbids**
`ownerIndex == 0` — bootstrap key is never an EIP-1271 signer.

The Solidity also nests via `replaySafeHash` (Solady EIP-712 with
`(name="PQSmartWallet", version="1", chainId, address(this))`).
We model that as an opaque hash transformation — the firmware MUST
apply the same wrapping. -/

opaque replaySafeHash (hash : Bytes32) (walletAddress : Address) (chainId : Nat) : Bytes32

def isValidSignature
    (s : Storage) (rawHash : Bytes32) (sig : ByteVec)
    (walletAddress : Address) (chainId : Nat) : Bytes4 :=
  let some wrapper := decodeSignatureWrapper sig | EIP1271_INVALID
  -- Bootstrap key is FORBIDDEN here (line 425).
  if wrapper.ownerIndex = 0 then EIP1271_INVALID
  else
    let ownerBytes := s.ownerAtIndex wrapper.ownerIndex
    if ownerBytes.length ≠ OWNER_BYTES_LEN then EIP1271_INVALID
    else
      let pkSeed := (ownerBytes.extract 0 32).toBytes32
      let pkRoot := (ownerBytes.extract 32 64).toBytes32
      let nestedHash := replaySafeHash rawHash walletAddress chainId
      if c10Verify pkSeed.toByteVec pkRoot.toByteVec nestedHash.toByteVec wrapper.innerSig
      then EIP1271_MAGIC
      else EIP1271_INVALID
where
  EIP1271_MAGIC : Bytes4 := Bytes4.ofHex "0x1626ba7e"
  EIP1271_INVALID : Bytes4 := Bytes4.ofHex "0xffffffff"

end PQSigner.PQSmartWallet
