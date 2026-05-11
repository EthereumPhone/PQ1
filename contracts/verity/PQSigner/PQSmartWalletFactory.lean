/-!
# PQSigner.PQSmartWalletFactory

Lean port of `contracts/smart-wallet/src/PQSmartWalletFactory.sol`.

The factory only does three things that matter for verification:

1. Derive a CREATE2 salt that is **chain-independent** (load-bearing
   for invariant #6).
2. Derive a per-(chain, slot-0) digest that the bootstrap key signs.
   Squat-defence — different chains require fresh bootstrap-sig
   authorisation even though they share an address.
3. Verify the bootstrap C10 sig over (2) before CREATE2-ing the proxy.

The actual CREATE2 + ERC-1967 proxy deploy is delegated to Solady's
`LibClone`, which we treat as an uninterpreted axiomatised primitive
(see `TRUST_ASSUMPTIONS.md` §4).
-/

import PQSigner.Common
import Verity.Prelude
import Verity.Hash.Sha256
import Verity.External.Call

namespace PQSigner.PQSmartWalletFactory

open PQSigner.Common

/-! ## Errors -/

inductive Error where
  | WrongChainId (block_chainid declared_chainid : Nat)
  | InvalidFactorySignature
  deriving Repr

/-! ## Opaque oracle: C10 verifier

The on-chain verifier is the hand-tuned Yul contract at
`contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol`. Verity
treats it as a black box (see `TRUST_ASSUMPTIONS.md` §1 — formal
verification of the verifier itself is Part B,
`docs/handoff-verity-c10-verifier.md`).

The oracle:
- is deterministic in its inputs,
- may revert (caller traps via try/catch and treats revert as false),
- has no observable effect on our storage.
-/
opaque c10Verify (pkSeed pkRoot digest sig : ByteVec) : Bool

/-! ## Opaque oracle: Solady `LibClone`

Two functions: `predictDeterministicAddressERC1967` and
`createDeterministicERC1967`. We axiomatise the property we need —
they agree on the address as a pure function of `(impl, salt,
factory)` — and leave their implementation outside our scope. -/

opaque predictDeterministicAddressERC1967
    (impl : Address) (salt : Bytes32) (factory : Address) : Address

opaque createDeterministicERC1967
    (value : Nat) (impl : Address) (salt : Bytes32) (factory : Address)
    : Address × Bool  -- (deployed, alreadyDeployed)

axiom predict_matches_create :
  ∀ impl salt factory value,
    (createDeterministicERC1967 value impl salt factory).fst =
      predictDeterministicAddressERC1967 impl salt factory

/-! ## Core derivation logic -/

/-- `_salt(masterPkSeed, masterPkRoot)` at
    `PQSmartWalletFactory.sol:138-139`. **Chain-independent by
    construction** — the only inputs are the two master pubkey halves.

    Theorem `salt_chain_independent` (in `Theorems.lean`) proves this
    formally: the value has zero data dependence on `block.chainid`.
    A future regression that threads `chainId` into this preimage
    fails the proof obligation. -/
def saltDerivation (masterPkSeed masterPkRoot : Bytes32) : Bytes32 :=
  sha256 (masterPkSeed.toByteVec ++ masterPkRoot.toByteVec) |>.toBytes32

/-- `addSlot0Digest(chainId, slot0PkSeed, slot0PkRoot)` at
    `PQSmartWalletFactory.sol:130-136`. **Chain-dependent by
    construction** — separates the bootstrap authorisation per chain,
    which is what makes the same wallet address on different chains
    safe to share (a stolen `factorySig` for chain A is rejected on
    chain B). -/
def addSlot0Digest (chainId : UInt64) (slot0PkSeed slot0PkRoot : Bytes32) : Bytes32 :=
  let preimage :=
    FACTORY_ADD_SLOT_DOMAIN ++
    ByteVec.ofUInt64BE chainId ++
    slot0PkSeed.toByteVec ++
    slot0PkRoot.toByteVec
  sha256 preimage |>.toBytes32

/-! ## `createAccount` body

Mirror of `PQSmartWalletFactory.sol:75-114`. Five steps:

1. Reject mismatched `chainId`.
2. Compute salt + predicted address.
3. If already deployed → idempotent short-circuit.
4. Verify bootstrap C10 sig over `addSlot0Digest`. Revert on fail.
5. CREATE2 + atomic `initialize` (the latter is on the deployed
   wallet, not the factory — the call lives in `PQSmartWallet`).
-/

structure CreateAccountArgs where
  masterPkSeed : Bytes32
  masterPkRoot : Bytes32
  slot0PkSeed : Bytes32
  slot0PkRoot : Bytes32
  chainId : UInt64
  factorySig : ByteVec
  blockChainId : Nat  -- supplied by the EVM via `block.chainid`
  msgValue : Nat
  impl : Address
  factoryAddress : Address

structure CreateAccountResult where
  account : Address
  alreadyDeployed : Bool

def createAccount (args : CreateAccountArgs) : Except Error CreateAccountResult := do
  if args.chainId.toNat ≠ args.blockChainId then
    throw (.WrongChainId args.blockChainId args.chainId.toNat)

  let salt := saltDerivation args.masterPkSeed args.masterPkRoot
  let predicted := predictDeterministicAddressERC1967 args.impl salt args.factoryAddress

  -- Idempotency short-circuit (PQSmartWalletFactory.sol:88-90).
  -- We cannot peek code size from inside the Lean spec — the caller
  -- supplies the boolean. Differential harness pairs both branches.
  if (← External.codeSizeNonZero predicted) then
    return { account := predicted, alreadyDeployed := true }

  let digest := addSlot0Digest args.chainId args.slot0PkSeed args.slot0PkRoot
  let ok := c10Verify args.masterPkSeed.toByteVec args.masterPkRoot.toByteVec
                     digest.toByteVec args.factorySig
  if ¬ ok then throw .InvalidFactorySignature

  let (deployed, _already) :=
    createDeterministicERC1967 args.msgValue args.impl salt args.factoryAddress
  return { account := deployed, alreadyDeployed := false }

end PQSigner.PQSmartWalletFactory
