/-
Bridge/EntryPoint: model of ERC-4337 EntryPoint v0.6 as a transition
system, plus the `entrypoint_honest` theorem (formerly the A2 axiom in
`docs/TRUST_ASSUMPTIONS.md`; PROVED kernel-only 2026-08-20 — it follows
from the `handleOp` definition alone).

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
The audited+immutable+18-months-mainnet status is the practical
justification for trusting `handleOp` as a FAITHFUL model of the
deployed EntryPoint v0.6 — the theorem below is proved from this model,
so what the audits back is the model's faithfulness, not a proof axiom.
-/

import SphincsCVerify.Spec.Bytes
import SphincsCVerify.Wallet.Storage
import SphincsCVerify.Wallet.ValidateUserOp
import SphincsCVerify.Bridge.SolidityVerifier
import SphincsCVerify.Interpreter.C10Program

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

/-- The deployed verifier, modelled at the Lean level as the *faithful
    transcription* of the on-chain Yul (`execC10Asm`, which includes the
    two leading N-mask input guards the deployed bytecode runs before the
    verify body). By `solidityVerifier_compiles_correctly` (A3.1) this Lean
    function equals the on-chain `SPHINCsC10Asm.verify` invocation; by
    `execC10Asm_eq` it equals `nMaskedB pkSeed && nMaskedB pkRoot &&
    verifyYulModel …`, i.e. the declarative spec gated on N-masked keys. -/
def deployedVerifier
    (pkSeed pkRoot : ByteVec 32) (digest : ByteVec 32)
    (sig : ByteVec SignatureLen) : Bool :=
  SphincsCVerify.Interpreter.C10.execC10Asm pkSeed pkRoot digest sig

/-! ## Transition -/

/-- Process one UserOp under EntryPoint v0.6.

    The `effects` argument represents the wallet-initiated balance
    changes that occur on the success path (the wallet's
    `executeWithOffchainCount` calling `target.call{value: value}` and
    the EVM moving value out of `walletAddress`). `entrypoint_honest`
    below proves (was: "is bound by A2 to") they only act if
    `validateSignature` returns success.

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

/-! ## A2 — `entrypoint_honest` (PROVED 2026-08-20, formerly an axiom)

The bridge premise: EntryPoint v0.6 is honest dispatch. Concretely:

  (1) **Honest dispatch.** The wallet's execution path runs iff
      `validateUserOp` returned success.

  (2) **No EntryPoint-initiated balance theft.** The EntryPoint never
      decreases `balance σ walletAddress` without first having executed
      the wallet's authorised path.

  (3) **`userOpHash` is per ERC-4337 v0.6.** The wallet's
      `sphincsDigest` consumes the raw `op` fields plus `entryPoint`
      and `chainId`, so the bridge is exact at the wallet boundary.

For the theft-freedom proof we only need (1) and (2). (3) is included
for documentation and to keep the statement self-contained.

**Status.** This used to be trust axiom A2 ("audited (OpenZeppelin /
ChainSecurity / Spearbit) and immutable contract at the canonical
EntryPoint v0.6 address; ≥18 months of mainnet operation as of
2026-05"). The 2026-08-20 adversarial pass found it PROVABLE from the
`handleOp` definition — the failure arm never moves the balance, so a
decrease forces the success arm — and it is now a kernel-checked
theorem with closure {propext, Classical.choice, Quot.sound}. The
audit/mainnet citation remains the justification that `handleOp`
faithfully models the deployed contract; it no longer underwrites a
logical premise. -/

/-- **A2 — EntryPoint v0.6 honest dispatch — PROVED, not axiomed.**

    If executing one UserOp via `handleOp σ op effects` decreases the
    wallet's balance, then `validateSignature` returned success on the
    wallet's pre-state, with the post-storage exactly equal to the
    storage component of the resulting state.

    This was the A2 trust axiom until 2026-08-20, when the adversarial
    pass observed it is provable kernel-only from the `handleOp`
    definition: on the failure arm the state is returned unchanged, so a
    strict balance decrease is `Nat.lt_irrefl`-absurd; on the success arm
    the equation holds definitionally. Closure: the kernel triple
    {propext, Classical.choice, Quot.sound} — NO project axiom. The
    statement is retained (under the same name, so `theft_free` and its
    transports are unchanged at the use site) because it is the exact
    bridge premise the theft-freedom proof consumes; what changed is
    that it no longer costs a TCB axiom. The cited EntryPoint v0.6
    audit/mainnet evidence now backs only the FAITHFULNESS of `handleOp`
    as a model of the deployed contract (V11 territory), not a logical
    premise of the proof. -/
theorem entrypoint_honest
    (σ : State) (op : UserOperation) (effects : Address → Nat → Nat) :
    (handleOp σ op effects).balance σ.walletAddress < σ.balance σ.walletAddress →
    validateSignature
      σ.walletStorage op σ.entryPointAddress σ.chainId
      deployedVerifier
      = (Result.success,
         (handleOp σ op effects).walletStorage) := by
  intro hdec
  unfold handleOp at hdec ⊢
  split at hdec <;> split <;> simp_all

/-! ## `entrypoint_no_replay` — REMOVED 2026-06-14.

The prior `entrypoint_no_replay` axiom was DANGLING (referenced by zero
theorems — adversarial axiom audit) AND latent-false against its own model:
`handleOp` never reads `op.nonce`, so the model structurally admits a
distinct-fresh-slot second success, contradicting the axiom's "the second
`handleOp` is a no-op" conclusion. It protected nothing, so it was deleted
rather than left as latent-false debt. EntryPoint v0.6's real `NonceManager`
replay protection remains a cited-TCB fact (simply not modelled in Lean, and
no theorem needs it). -/

end SphincsCVerify.Bridge.EntryPoint
