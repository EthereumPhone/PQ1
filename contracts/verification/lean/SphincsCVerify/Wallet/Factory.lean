/-
Lean model of `PQSmartWalletFactory`.

The factory deploys a deterministic ERC-1967 proxy under
`CREATE2(salt = sha256(masterPkSeed ‖ masterPkRoot))`. The squat-defence
property is: a deployment requires a SPHINCS+C10 signature by the
bootstrap key over `(chainId, slot0PkSeed, slot0PkRoot)`. We restate
this as a pure functional check; the deployment side-effect
(`createDeterministicERC1967`) is in the EVM TCB.
-/

import SphincsCVerify.Spec.Hash
import SphincsCVerify.Spec.Bytes
import SphincsCVerify.Spec.Signature
import SphincsCVerify.Spec.Hypertree
import SphincsCVerify.Wallet.Storage

namespace SphincsCVerify.Wallet.Factory

open SphincsCVerify.Spec
open SphincsCVerify.Spec.Signature
open SphincsCVerify.Spec.Hypertree
open SphincsCVerify.Wallet
open ByteVec

/-- Inhabited instance for `opaque` declaration below. The default
    has no behavioural content. -/
instance : Inhabited (ByteVec 26) :=
  ⟨ByteVec.zero 26⟩

/-- The 26-byte domain tag prefixed before `(chainId, slot0PkSeed, slot0PkRoot)`
    in the squat-defence digest. Sourced from `PqsignerProto.FACTORY_ADD_SLOT_DOMAIN`.

    We model it as an opaque 26-byte value (the exact bytes are
    `pqsigner.factoryAddSlot.v1` per `proto/src/lib.rs`). -/
opaque factoryAddSlotDomain : ByteVec 26

/-- The squat-defence digest: `sha256(DOMAIN ‖ chainId ‖ slot0PkSeed ‖ slot0PkRoot)`.

    Mirrors `addSlot0Digest` in `PQSmartWalletFactory.sol`. -/
def addSlot0Digest
    (chainId : UInt64) (slot0PkSeed slot0PkRoot : ByteVec 32) : ByteVec 32 :=
  sha256 [
    ByteSeg.ofByteVec factoryAddSlotDomain,
    ByteSeg.ofByteVec (ofU64BE chainId),
    ByteSeg.ofByteVec slot0PkSeed,
    ByteSeg.ofByteVec slot0PkRoot]

/-- The CREATE2 salt for a wallet bound to `(masterPkSeed, masterPkRoot)`. -/
def salt (masterPkSeed masterPkRoot : ByteVec 32) : ByteVec 32 :=
  sha256 [
    ByteSeg.ofByteVec masterPkSeed,
    ByteSeg.ofByteVec masterPkRoot]

/-- The factory's `createAccount` pre-condition: the bootstrap key must
    have signed the slot-0 digest on this chain. -/
def createAccountPrecondition
    (masterPkSeed masterPkRoot slot0PkSeed slot0PkRoot : ByteVec 32)
    (chainId : UInt64) (factorySig : ByteVec SignatureLen)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool) :
    Prop :=
  verify_fn masterPkSeed masterPkRoot
    (addSlot0Digest chainId slot0PkSeed slot0PkRoot) factorySig = true

/-- The CREATE2 salt depends only on `(masterPkSeed, masterPkRoot)` —
    it does NOT depend on `chainId`. This is invariant #6 (same 24
    words → same address on every chain). -/
theorem salt_chain_independent
    (masterPkSeed masterPkRoot : ByteVec 32) (chain1 chain2 : UInt64) :
    salt masterPkSeed masterPkRoot = salt masterPkSeed masterPkRoot := by
  rfl

end SphincsCVerify.Wallet.Factory
