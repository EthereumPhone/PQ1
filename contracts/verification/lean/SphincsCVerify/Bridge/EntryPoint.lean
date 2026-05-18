/-
Bridge/EntryPoint: model of ERC-4337 EntryPoint v0.6 as a transition
system, plus the single new axiom `entrypoint_honest` (A2 in
`docs/TRUST_ASSUMPTIONS.md`).

This module is the load-bearing bridge from the on-chain EntryPoint
behaviour to the wallet-side `validateUserOp` we have modelled in
`SphincsCVerify/Wallet/`. The semantic content captured here is:

  * EntryPoint v0.6 invokes wallet execution *only after*
    `wallet.validateUserOp(...)` returned the success sentinel
    (`SIG_VALIDATION_SUCCESS = 0`).
  * The EntryPoint never directly debits the wallet's balance — every
    wallet-balance decrement comes from a wallet-initiated `CALL`
    (`executeWithOffchainCount`) invoked under `msg.sender == entryPoint`.
  * `userOpHash` is the ERC-4337 v0.6 keccak256-based digest; we route
    *around* it inside the wallet by hashing UserOp fields under
    SHA-256 (`sphincsDigest`), keeping the firmware on its fast hash
    path.

We do not model the EntryPoint's internal accounting (paymaster pre-
charges, refunds, nonce-management). That lives inside the TCB.
Auditors who want to eliminate A2 can replay the OpenZeppelin /
ChainSecurity / Spearbit audits, or extend this Lean model to mirror
the EntryPoint v0.6 source. The audited+immutable+18-months-mainnet
status is the practical justification for axiomatising.
-/

import SphincsCVerify.Spec.Bytes
import SphincsCVerify.Wallet.Storage
import SphincsCVerify.Wallet.ValidateUserOp
import SphincsCVerify.Bridge.SolidityVerifier

namespace SphincsCVerify.Bridge.EntryPoint

open SphincsCVerify.Spec
open SphincsCVerify.Wallet
open SphincsCVerify.Wallet.Storage
open SphincsCVerify.Wallet.ValidateUserOp
open SphincsCVerify.Bridge

/-! ## State -/

/-- An EVM-flavoured address. Modelled as a 20-byte vector. -/
abbrev Address := ByteVec 20

/-- The subset of EVM state we care about: per-address balances, the
    deployed `PQSmartWallet` proxy at `walletAddress`, that proxy's
    per-wallet `Storage`, the EntryPoint address, and the configured
    `chainId`.

    This is the *observation interface* on which the theft-freedom
    theorem is stated. We do not model gas, paymaster pre-charges, or
    storage of other contracts — those are part of the EVM TCB. -/
structure State where
  /-- The deployed wallet proxy address (the `W` in `theft_free`). -/
  walletAddress : Address
  /-- The EntryPoint v0.6 contract address. -/
  entryPointAddress : Address
  /-- The chain id of the EVM state. -/
  chainId : Nat
  /-- The wallet's `PQMultiOwnable` storage. -/
  walletStorage : Storage
  /-- Per-address balance (Wei). -/
  balance : Address → Nat
  /-- True iff the EntryPoint has called the wallet's execution path
      in this transition. Set by `handleOp` on a successful
      `validateUserOp`. -/
  walletCalled : Bool

/-- The deployed verifier, modelled at the Lean level. By
    `Bridge.yul_eq_refined` and the bridge axioms in
    `Bridge/Refinement.lean` (A1, A3, A4), this Lean stub equals the
    on-chain `SPHINCsC10Asm.verify` invocation. -/
def deployedVerifier
    (pkSeed pkRoot : ByteVec 32) (digest : ByteVec 32)
    (sig : ByteVec SignatureLen) : Bool :=
  verifyYulModel pkSeed pkRoot digest sig

/-! ## Transition -/

/-- Process one UserOp under EntryPoint v0.6.

    The `effects` argument represents the wallet-initiated balance
    changes that occur on the success path (the wallet's
    `executeWithOffchainCount` calling `target.call{value: value}` and
    the EVM moving value out of `walletAddress`). It is bound by A2
    (`entrypoint_honest`) to only act if `validateSignature` returns
    success.

    Concretely:

      * If `validateSignature` returns `(Result.success, s')`:
        - Update wallet storage to `s'` (counter bump).
        - Apply `effects` to balances.
        - Set `walletCalled := true`.

      * If `validateSignature` returns `(Result.failure, _)`:
        - State unchanged (no balance change, no counter bump).

    The internal EVM mechanics — paymaster funding, gas refund, nonce
    maintenance — are abstracted. The theft-freedom theorem quotes only
    wallet-balance differentials, which are captured here exactly. -/
def handleOp
    (σ : State) (op : UserOperation) (effects : Address → Nat → Nat) : State :=
  let (res, s') :=
    validateSignature
      σ.walletStorage op σ.entryPointAddress σ.chainId
      deployedVerifier
  match res with
  | Result.failure => σ
  | Result.success =>
    { σ with
        walletStorage := s'
        balance := fun a => effects a (σ.balance a)
        walletCalled := true }

/-! ## A2 — `entrypoint_honest`

The trust axiom: EntryPoint v0.6 is unhackable. Concretely:

  (1) **Honest dispatch.** The wallet's execution path runs iff
      `validateUserOp` returned success.

  (2) **No EntryPoint-initiated balance theft.** The EntryPoint never
      decreases `balance σ walletAddress` without first having executed
      the wallet's authorised path.

  (3) **`userOpHash` is per ERC-4337 v0.6.** The wallet's
      `sphincsDigest` consumes the raw `op` fields plus `entryPoint`
      and `chainId`, so the bridge is exact at the wallet boundary.

For the theft-freedom proof we only need (1) and (2). (3) is included
for documentation and to keep the axiom self-contained.

**Mitigation.** Audited (OpenZeppelin / ChainSecurity / Spearbit) and
immutable contract at the canonical EntryPoint v0.6 address; ≥18
months of mainnet operation as of 2026-05. -/

/-- **A2 — EntryPoint v0.6 honest dispatch.**

    If executing one UserOp via `handleOp σ op effects` decreases the
    wallet's balance, then `validateSignature` returned success on the
    wallet's pre-state, with the post-storage exactly equal to the
    storage component of the resulting state. -/
axiom entrypoint_honest
    (σ : State) (op : UserOperation) (effects : Address → Nat → Nat) :
    (handleOp σ op effects).balance σ.walletAddress < σ.balance σ.walletAddress →
    validateSignature
      σ.walletStorage op σ.entryPointAddress σ.chainId
      deployedVerifier
      = (Result.success,
         (handleOp σ op effects).walletStorage)

end SphincsCVerify.Bridge.EntryPoint
