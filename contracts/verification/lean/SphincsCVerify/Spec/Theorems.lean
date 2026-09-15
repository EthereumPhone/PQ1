/-
Top-level functional-correctness theorems for SPHINCS+C10.

This file states the spec-level guarantees the Lean reference proves.

Each theorem in this file is a Lean `theorem` declaration. Its proof is
either:
  * fully discharged inside this file (closed; no `sorry`);
  * decomposed into section lemmas living in `Spec/*.lean`, each fully
    discharged; or
  * stated as an `axiom` in `Crypto/EUFCMA.lean` (cryptographic
    assumption — see § 5 of `how_to_math_proof_secureness.md` for why
    this is intrinsic, not eliminable).

The split is deliberate:

  * Functional correctness (signing → verifying round-trip; rejection of
    malformed signatures) is provable from `sha256`'s **algebraic
    behaviour as an opaque function** — no axioms needed.

  * EUF-CMA security is unprovable from algebraic behaviour alone — it
    needs the cryptographic content of SHA-256 (SM-TCR, ITSR, ROM).
    Those properties become axioms.

  * Bytecode-level refinement (Lean ≡ Yul ≡ EVM) needs Verity-style
    verified compilation. We state the obligation; we do not discharge
    it ourselves.

The headline `theft_free` composes all of the above:
  * `Bridge.EntryPoint.entrypoint_honest` (A2 — PROVED kernel-only
    2026-08-20, formerly an axiom) — a wallet-balance
    decrement implies `validateSignature` returned success.
  * `Wallet.Invariants.validateSignature_only_via_verify` (I-1) — a
    successful validate implies the deployed verifier accepted.
  * `Bridge.solidityVerifier_compiles_correctly` (A3) +
    `Bridge.evm_bytecode_executes_correctly` (A4) +
    `Bridge.precompile_0x02_is_FIPS_180_4` (A1) — the deployed Yul
    verifier matches its Lean model.
  * `Crypto.cannot_forge_without_breaking_SHA256` (A5 via
    `EUF_CMA_SPHINCSplusC` + `SM_DT_TCR_F` + `ITSR_F` +
    `hMsg_random_oracle`) — under standard SHA-256 cryptographic
    assumptions, a verifying signature on a never-signed digest is
    impossible.
-/

import SphincsCVerify.Spec.Signature
import SphincsCVerify.Spec.Signer
import SphincsCVerify.Spec.Hypertree
import SphincsCVerify.Bridge.EntryPoint
import SphincsCVerify.Bridge.Refinement
import SphincsCVerify.Wallet.Invariants
import SphincsCVerify.Wallet.SphincsDigestSpec
import SphincsCVerify.Wallet.Execute
import SphincsCVerify.Wallet.TxFlow
import SphincsCVerify.Wallet.CreditLedger
import SphincsCVerify.Crypto.EUFCMA

namespace SphincsCVerify.Spec.Theorems

open SphincsCVerify.Spec
open SphincsCVerify.Spec.Signer
open SphincsCVerify.Spec.Hypertree
open SphincsCVerify.Spec.Signature

/-! ## 1. Signing/verifying round-trip

The core functional-correctness theorem. Mirrors the spec-level
statement in § 4.2 of the playbook:

  ∀ sk pk msg, keygen produces (sk, pk) → verify pk msg (sign sk msg) = true.

In our setting:
  * `keygen` is implicit in the `SigningKey` structure (any
    `(sk_seed, pk_seed, pk_root)` such that `pk_root = hypertree::compute_pk_root`).
  * `sign` is `Signer.sign`.
  * `verify` is `Hypertree.verify`.
-/

/-- A signing key is **consistent** when its `pk_root` is the hypertree
    root reconstructed from `(sk_seed, pk_seed)` via the spec-level
    keygen *and* its signing routine round-trips with the verifier on
    every well-formed message.

    Concretely: for every message `m` such that `Signer.sign sk m` is
    `some sig`, the spec verifier accepts `sig` under the key's
    `(pkSeed, pkRoot)`.

    This consolidates the four classical SPHINCS+C10 round-trip
    sub-lemmas (Merkle / WOTS+C chain / FORS+C / chain-hash compose) +
    the keygen-consistency condition into a single load-bearing
    predicate. Under this packaging:

      * The round-trip theorem `verify_signs` below closes by a
        one-line appeal to `consistent`.
      * The non-trivial mechanical content — proving `consistent sk`
        for any honestly-keygen'd `sk` — is the open Group V work
        documented in `docs/OPEN_PROOF_OBLIGATIONS.md`. The Rust
        reference signer in `sphincs-c10/src/` provides the executable
        witness that pins down what `Signer.sign` *should* compute;
        the four round-trip lemmas remain to be discharged inside
        Lean.

    The Rust `SigningKey::keygen` already enforces consistency at
    construction time, and the Solidity factory never sees a
    non-consistent key (the bootstrap pk is supplied by firmware that
    did the keygen). Within Lean, `consistent` is the right place to
    carry that fact pending mechanisation. -/
def consistent (sk : SigningKey) : Prop :=
  ∀ (message : ByteVec 32) (sig : Hypertree.Signature),
    Signer.sign sk message = some sig →
    Hypertree.verify sk.pkSeed sk.pkRoot message sig = true

/-- **Functional correctness — round-trip.**

    For any consistent signing key `sk` and any 32-byte `message`, if
    `sign sk message` returns `some sig`, then
    `verify sk.verifyingKey message sig = true`.

    Proof: direct from the consistency hypothesis. The non-trivial
    content — that *every* honestly-keygen'd `sk` is consistent —
    decomposes into four standard round-trip sub-lemmas (Merkle, WOTS+C
    chain, FORS+C, chain-hash compose) on top of FIPS 180-4 SHA-256.
    The kernel-computable SHA-256 reference at `Spec/Sha256Impl.lean`
    is the foundation that future Group V work will build on; see
    `docs/OPEN_PROOF_OBLIGATIONS.md` for the breakdown.

    Note: this round-trip theorem is **not in the dependency closure
    of `theft_free`**. Theft-freedom uses only the *acceptance ⇒
    verifier-returned-true* direction (supplied by I-1 and the bridge
    axioms) plus the EUF-CMA cryptographic axiom (A5). The signer's
    completeness in this direction matters for usability — the wallet
    must accept signatures produced by the firmware — not for safety. -/
theorem verify_signs
    (sk : SigningKey) (message : ByteVec 32)
    (hc : consistent sk) (sig : Hypertree.Signature)
    (hsign : Signer.sign sk message = some sig) :
    Hypertree.verify sk.pkSeed sk.pkRoot message sig = true :=
  hc message sig hsign

/-! ## 2. Rejection of malformed signatures -/

/-- Wrong length is rejected at the type level — `Signature.verify`
    takes `ByteVec SignatureLen` so a non-4008-byte input cannot
    type-check. -/
theorem verify_rejects_wrong_length :
    ∀ (_vk : VerifyingKey) (_msg : ByteVec 32) (sig : ByteVec SignatureLen),
      sig.data.size = SignatureLen := by
  intro _ _ sig; exact sig.size_eq

/-- If the last FORS index in the digest is non-zero (the forced-zero
    constraint is violated), `verify` returns `false`.

    Phase-1 refactor: `Hypertree.verify` delegates to `verifyWithDigest`,
    which surfaces the last-FORS-index predicate at the top of its
    `if`-cascade. The proof then closes by `simp` driving `if_pos h`. -/
theorem verify_rejects_nonzero_last_fors_idx
    (pkSeed pkRoot : ByteVec 16) (msg : ByteVec 32) (sig : Hypertree.Signature)
    (h : (Util.extractForsIndices
            (hMsg (ByteVec.pad16 pkSeed) (ByteVec.pad16 pkRoot)
                  (ByteVec.pad16 sig.r) msg)).getD (K - 1) 0 ≠ 0) :
    Hypertree.verify pkSeed pkRoot msg sig = false := by
  unfold Hypertree.verify Hypertree.verifyWithDigest
  rw [if_pos h]

/-- The unit content of digit-sum rejection: `Wots.pkFromSig` returns
    `none` exactly when the WOTS+C target-sum check fails. The hypothesis
    threads the `wotsDigest` from the on-chain verifier's calldata-read
    form. -/
theorem pkFromSig_returns_none_of_bad_digit_sum
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (msgHash : ByteVec 16) (sigma : Wots.Sigma)
    (hbad : Util.digitSum (Util.extractDigits
              (wotsDigest seed (Adrs.wots layer tree kp)
                          (ByteVec.pad16 msgHash) sigma.count))
            ≠ TargetSum) :
    Wots.pkFromSig seed layer tree kp msgHash sigma = none := by
  unfold Wots.pkFromSig
  simp [hbad]

/-- The structural propagation: when the D=2 hypertree walk returns
    `none` (whether because a per-layer WOTS+C digit-sum check failed,
    or any other in-walk rejection), `verify` returns `false`.

    Structural form only. The original "if any layer's digits don't
    sum to `TargetSum`, `verify = false`" statement requires unrolling
    the `for layer in [:D]` loop's mutable-state propagation. The two
    pieces shipped here — `pkFromSig_returns_none_of_bad_digit_sum`
    (unit content) and `verify_rejects_bad_digit_sum` (structural
    propagation) — together suffice once the loop lemma lands as part
    of the `verify_signs` round-trip work (see
    docs/OPEN_PROOF_OBLIGATIONS.md, Group V). -/
theorem verify_rejects_bad_digit_sum
    (pkSeed pkRoot : ByteVec 16) (msg : ByteVec 32) (sig : Hypertree.Signature)
    (hidx : (Util.extractForsIndices
              (hMsg (ByteVec.pad16 pkSeed) (ByteVec.pad16 pkRoot)
                    (ByteVec.pad16 sig.r) msg)).getD (K - 1) 0 = 0)
    (forsPk : ByteVec 16)
    (hfors : Fors.reconstructForsPk (ByteVec.pad16 pkSeed)
              (hMsg (ByteVec.pad16 pkSeed) (ByteVec.pad16 pkRoot)
                    (ByteVec.pad16 sig.r) msg)
              sig.fors = some forsPk)
    (hht : Hypertree.verifyHypertree (ByteVec.pad16 pkSeed) forsPk
              (Util.extractHtIndex (hMsg (ByteVec.pad16 pkSeed)
                                          (ByteVec.pad16 pkRoot)
                                          (ByteVec.pad16 sig.r) msg))
              sig.layers = none) :
    Hypertree.verify pkSeed pkRoot msg sig = false := by
  unfold Hypertree.verify Hypertree.verifyWithDigest
  -- hidx says ... = 0, so ¬(... ≠ 0).
  have hne : ¬ ((Util.extractForsIndices
                  (hMsg (ByteVec.pad16 pkSeed) (ByteVec.pad16 pkRoot)
                        (ByteVec.pad16 sig.r) msg)).getD (K - 1) 0 ≠ 0) :=
    fun h => h hidx
  rw [if_neg hne]
  -- After the if reduces to the else-branch, simp reduces the two matches
  -- using hfors (Fors result) and hht (hypertree result).
  simp [hfors, hht]

/-! ## 3. Determinism

The verifier is a pure function — it returns the same result on the
same input. This is intrinsic from `def`. We state it explicitly so
clients can quote it. -/

theorem verify_deterministic
    (vk : VerifyingKey) (msg : ByteVec 32) (sig : ByteVec SignatureLen) :
    Signature.verify vk msg sig = Signature.verify vk msg sig :=
  rfl

/-! ## 4. Theft-freedom — the headline theorem.

For any reachable wallet state `s : Storage`, any `UserOperation` `op`,
any entry-point address `entryPoint`, and any `chainId`, if EntryPoint
v0.6 (modelled by `Bridge.EntryPoint.handleOp`) processes `op` from a
state `σ` to a state `σ'` such that `σ'.balance σ.walletAddress <
σ.balance σ.walletAddress`, then there exist `ownerIndex`, `owner`,
`pkSeed`, `pkRoot`, `digest`, `innerSig` such that:

  * `decodeWrappedSig op.signature = some ⟨ownerIndex, innerSig⟩`
  * `s.ownerAtIndex ownerIndex = some owner`
  * `pkSeed = owner.raw.take 32`
  * `pkRoot = owner.raw.drop 32`
  * `digest = sphincsDigest op entryPoint chainId`
  * `SPHINCsC10Asm.verify pkSeed pkRoot digest innerSig = true`

Equivalently: no wallet-balance decrement without a SPHINCS+C10
signature valid under an installed owner key over the canonical
`userOpHash` (proxied through SHA-256-based `sphincsDigest` for
firmware-compatible signing).

The proof composes:
  - A2 (`entrypoint_honest`, a kernel-only theorem since 2026-08-20):
    balance decrement → validateSignature
    returned `(Result.success, _)`.
  - I-1 (`validateSignature_only_via_verify`): a successful validate
    implies the verifier function accepted.
  - The deployed verifier is `SolidityVerifier.verifyYulModel` by the
    A1/A3/A4 bridge axioms.
  - A5 (`cannot_forge_without_breaking_SHA256`): used as a corollary
    that ties the existential to the EUF-CMA bound — captured here as
    an additional consequence that brings the crypto axioms into the
    dep closure of `theft_free`.
-/

open SphincsCVerify.Bridge
open SphincsCVerify.Bridge.EntryPoint
open SphincsCVerify.Wallet
open SphincsCVerify.Wallet.Storage
open SphincsCVerify.Wallet.ValidateUserOp
open SphincsCVerify.Wallet.Invariants
open SphincsCVerify.Crypto

/-- **Theft-freedom — the headline theorem.**

    No wallet-balance decrement under EntryPoint v0.6 processing
    without a valid SPHINCS+C10 signature, decoded from the wrapped
    `op.signature`, under an installed owner key, over the canonical
    `sphincsDigest(op)`.

    Modulo A1, A3.1, A4, A5 (the listed axioms; A2 `entrypoint_honest`
    is a proved kernel-only theorem since 2026-08-20, not an axiom). -/
theorem theft_free
    (op : UserOperation)
    (σ σ' : Bridge.EntryPoint.State)
    (effects : Bridge.EntryPoint.Address → Nat → Nat)
    (hExec : Bridge.EntryPoint.handleOp σ op effects = σ')
    (hDecrease : σ'.balance σ.walletAddress < σ.balance σ.walletAddress) :
    -- Existence of a verifying signature under an installed owner key.
    (∃ (ownerIndex : Nat) (owner : OwnerBytes)
       (pkSeed pkRoot : ByteVec 32) (digest : ByteVec 32)
       (innerSig : ByteVec SignatureLen),
      decodeWrappedSig op.signature = some ⟨ownerIndex, innerSig⟩
      ∧ σ.walletStorage.ownerAtIndex ownerIndex = some owner
      ∧ pkSeed = owner.raw.take 32 (by decide)
      ∧ pkRoot = owner.raw.drop 32 (by decide)
      ∧ digest = sphincsDigest op σ.entryPointAddress σ.chainId
      -- The DEPLOYED SPHINCsC10Asm.verify bytecode (at the pinned
      -- codehash) returned `true`. The chain of identities to the Lean
      -- model is `solidityVerifier_compiles_correctly` (A3.1).
      ∧ Bridge.DeployedBytecode.SPHINCsC10Asm_verify pkSeed pkRoot digest innerSig = true)
    -- And cryptographic well-foundedness: the EUF-CMA framework holds,
    -- so any forgery attempt against this verifier on this transcript
    -- contradicts the SHA-256 hardness assumptions (A5).
    ∧ (∀ (sk : Signer.SigningKey)
         (transcript : Crypto.Transcript)
         (msgStar : ByteVec 32) (sigStar : Hypertree.Signature),
        Crypto.isForgery sk transcript msgStar sigStar → Crypto.BreaksHash) := by
  -- Substitute σ' = handleOp σ op effects.
  subst hExec
  -- Apply A2 (entrypoint_honest):
  have hSuccess :=
    Bridge.EntryPoint.entrypoint_honest σ op effects hDecrease
  -- Apply I-1 (validateSignature_only_via_verify):
  have hExist :=
    Wallet.Invariants.validateSignature_only_via_verify
      σ.walletStorage op σ.entryPointAddress σ.chainId
      Bridge.EntryPoint.deployedVerifier
      _ hSuccess
  refine ⟨?_, ?_⟩
  · -- Existence half. By construction `deployedVerifier` is
    -- `verifyYulModel`, so I-1 gives us `verifyYulModel ... = true`.
    -- We then bridge to the deployed bytecode via A3.1
    -- (`solidityVerifier_compiles_correctly`), the load-bearing axiom
    -- equating `DeployedBytecode.SPHINCsC10Asm_verify` with the Lean
    -- model. A1 / A4 are kept in the dep closure because the chain of
    -- refinement implicitly relies on the SHA-256 precompile being
    -- correct and the EVM executing per spec.
    obtain ⟨oi, ow, pks, pkr, dig, isig, hdec, hown, hpks, hpkr, hdig, hverify⟩ := hExist
    refine ⟨oi, ow, pks, pkr, dig, isig, hdec, hown, hpks, hpkr, hdig, ?_⟩
    have hbridge := Bridge.solidityVerifier_compiles_correctly pks pkr dig isig
    -- A4 + A1 as named TCB MARKERS (NOT semantic premises of this theorem).
    -- The two `have`s below pull A4 (`evm_bytecode_executes_correctly`, the
    -- EVM-delivers-the-emitted-CALL boundary) and A1
    -- (`precompile_0x02_is_FIPS_180_4`) into `theft_free`'s `#print axioms`
    -- closure so the closure self-documents the full on-chain TCB.
    -- HONEST SCOPE (corrected by faithfulness-audit pass-2, 2026-06-14): these
    -- bindings are NOT consumed by the safety argument — deleting them (axioms
    -- retained) leaves `theft_free` proven, and the proof closes via
    -- `rw [hbridge]; exact hverify` (A3.1 + the EUF-CMA conjunct). So
    -- `theft_free`'s genuine SEMANTIC premises are A3.1
    -- (solidityVerifier_compiles_correctly) + A5 (EUF-CMA ×4) + the kernel
    -- triple — EIGHT axioms since 2026-08-20 (A2 `entrypoint_honest` was
    -- PROVED kernel-only that day — it follows from the `handleOp`
    -- definition — so it no longer appears in any `#print axioms`
    -- closure; before the demotion the count was NINE);
    -- A4/A1 are real-world TCB surfaced here for
    -- completeness, not logical content of the model theorem. (The earlier
    -- "A4 is now LOAD-BEARING" wording was an over-claim; A4's content-bearing
    -- *type* genuinely names the assumption, but it is still a non-consumed
    -- marker. A4's mere presence in the closure relies on `evmDeliversCall`
    -- staying `opaque`: a `def := fun _ => True` regression would let `trivial`
    -- discharge `_a4_delivers` and silently drop A4 from the closure.)
    have _a4_delivers : Bridge.evmDeliversCall (default : Wallet.Execute.Call) :=
      Bridge.evm_bytecode_executes_correctly (default : Wallet.Execute.Call)
    have := Bridge.precompile_0x02_is_FIPS_180_4 []
    -- Rewrite `DeployedBytecode.SPHINCsC10Asm_verify` into `verifyYulModel`
    -- using A3.1, then close with `hverify`.
    show Bridge.DeployedBytecode.SPHINCsC10Asm_verify pks pkr dig isig = true
    rw [hbridge]
    exact hverify
  · -- Cryptographic non-forgeability half (reduction form, 2026-06-14):
    -- a forgery against the slot key's honest history breaks SHA-256
    -- (`cannot_forge_without_breaking_SHA256 : isForgery → BreaksHash`).
    -- This is the cited crypto rider; the substantive safety guarantee is
    -- conjunct 1 above, which is EUF-CMA-free.
    intro sk transcript msgStar sigStar hf
    -- Acknowledge `Classical.choice` is part of the trusted Lean kernel
    -- — pulling it into the dep closure documents the classical
    -- reasoning licence the cryptographic argument operates under.
    have _classical_choice_acknowledged : Unit :=
      Classical.choice (Nonempty.intro ())
    exact Crypto.cannot_forge_without_breaking_SHA256 sk transcript msgStar sigStar hf

/-! ## 4b. Bytecode-transported corollaries.

`theft_free` quantifies the wallet step at the Lean model (`handleOp`
calls `validateSignature ... deployedVerifier`). The corollaries below
transport the same statements to the OPAQUE deployed-bytecode symbols,
so the axiom closure printed by `#print axioms` names the wallet and
factory bridge axioms explicitly: A3.2 joins `theft_free_bytecode`'s
closure and A3.3 joins `factory_squat_defence_bytecode`'s. They are
the Lean-side counterpart of the Halmos pointwise-equivalence sessions
(`test/halmos/HalmosValidateUserOpEquiv.t.sol`,
`test/halmos/HalmosFactory.t.sol`) recorded in AXIOM_STATUS.json. -/

/-- `Bridge.EntryPoint.handleOp` with the wallet validation step taken
    from the deployed-bytecode symbol (A3.2's left-hand side) instead
    of the Lean model. -/
def handleOpBytecode
    (σ : Bridge.EntryPoint.State) (op : UserOperation)
    (effects : Bridge.EntryPoint.Address → Nat → Nat) :
    Bridge.EntryPoint.State :=
  let (res, s') :=
    Bridge.DeployedBytecode.PQSmartWallet_validateUserOp
      σ.walletStorage op σ.entryPointAddress σ.chainId
  match res with
  | Result.failure => σ
  | Result.success =>
    { σ with
        walletStorage := s'
        balance := fun a => effects a (σ.balance a)
        walletCalled := true }

/-- **Theft-freedom, stated against the deployed wallet bytecode.**

    Same hypotheses and conclusion as `theft_free`, except the
    EntryPoint transition runs the wallet validation step at the opaque
    `DeployedBytecode.PQSmartWallet_validateUserOp` symbol — "the code
    at the pinned codehash" — rather than at the Lean model.

    **P1 (status of `hInv` — now kernel-discharged via reachability).** The
    extra hypothesis `hInv` (the per-index combined cap
    `slotUses i + offchainSigCount i ≤ MaxSlotUses`) conditions A3.2's pointwise
    equality because outside it the deployed bytecode reverts on a
    checked-arithmetic overflow where the ℕ-valued model returns failure (a
    divergence on unreachable states only — see AXIOM_STATUS.json A3.2). This
    theorem keeps `hInv` as a raw hypothesis (it is what the A3.2 axiom is stated
    against), but the REACHABILITY of `hInv` is now a kernel-PROVEN inductive
    invariant, NOT a Foundry-fuzz-backed assumption: `Invariants.Reachable`
    (genesis + the gated EntryPoint transitions) +
    `Invariants.reachable_implies_combinedCap` (`[propext, Quot.sound]`, kernel-
    only) assemble `combinedCap_inductive` + the P3 cross-counter preservation
    lemmas + the init base case into `Reachable s → ∀ i, combinedCapInvariant s i`.
    The discharged corollary is `theft_free_bytecode_reachable` below: it takes
    `Reachable σ.walletStorage` instead of `hInv` and derives the cap — its
    `#print axioms` is IDENTICAL to this theorem's (the discharge adds no axiom).
    It stays (correctly) conditional on reachability — not unconditional — since
    off the cap the bytecode reverts with no characterising axiom (EF P1).

    `#print axioms theft_free_bytecode` = `theft_free`'s closure
    ∪ { solidityWallet_compiles_correctly }. -/
theorem theft_free_bytecode
    (op : UserOperation)
    (σ σ' : Bridge.EntryPoint.State)
    (effects : Bridge.EntryPoint.Address → Nat → Nat)
    (hInv : ∀ i, σ.walletStorage.slotUses i + σ.walletStorage.offchainSigCount i
                   ≤ MaxSlotUses)
    (hExec : handleOpBytecode σ op effects = σ')
    (hDecrease : σ'.balance σ.walletAddress < σ.balance σ.walletAddress) :
    (∃ (ownerIndex : Nat) (owner : OwnerBytes)
       (pkSeed pkRoot : ByteVec 32) (digest : ByteVec 32)
       (innerSig : ByteVec SignatureLen),
      decodeWrappedSig op.signature = some ⟨ownerIndex, innerSig⟩
      ∧ σ.walletStorage.ownerAtIndex ownerIndex = some owner
      ∧ pkSeed = owner.raw.take 32 (by decide)
      ∧ pkRoot = owner.raw.drop 32 (by decide)
      ∧ digest = sphincsDigest op σ.entryPointAddress σ.chainId
      ∧ Bridge.DeployedBytecode.SPHINCsC10Asm_verify pkSeed pkRoot digest innerSig = true)
    ∧ (∀ (sk : Signer.SigningKey)
         (transcript : Crypto.Transcript)
         (msgStar : ByteVec 32) (sigStar : Hypertree.Signature),
        Crypto.isForgery sk transcript msgStar sigStar → Crypto.BreaksHash) := by
  -- A3.1, in function form: the opaque deployed verifier IS the Lean
  -- Yul model (which is `deployedVerifier` by definition).
  have hfn : Bridge.DeployedBytecode.SPHINCsC10Asm_verify
      = Bridge.EntryPoint.deployedVerifier :=
    funext fun a => funext fun b => funext fun c => funext fun d =>
      Bridge.solidityVerifier_compiles_correctly a b c d
  -- A3.2 under the reachable-state invariant, then A3.1 to align the
  -- verifier parameter.
  have hwallet :
      Bridge.DeployedBytecode.PQSmartWallet_validateUserOp
        σ.walletStorage op σ.entryPointAddress σ.chainId
      = validateSignature σ.walletStorage op σ.entryPointAddress σ.chainId
          Bridge.EntryPoint.deployedVerifier := by
    rw [Bridge.solidityWallet_compiles_correctly σ.walletStorage op
          σ.entryPointAddress σ.chainId hInv, hfn]
  -- The bytecode-stepped transition coincides with the model-stepped
  -- one, so `theft_free` applies verbatim.
  have hExec' : Bridge.EntryPoint.handleOp σ op effects = σ' := by
    rw [← hExec]
    unfold handleOpBytecode Bridge.EntryPoint.handleOp
    rw [hwallet]
    rfl
  exact theft_free op σ σ' effects hExec' hDecrease

/-- **Theft-freedom on the deployed bytecode, conditioned on REACHABILITY
    (P1 discharge).** Identical to `theft_free_bytecode` except the combined-cap
    hypothesis `hInv` is replaced by `Invariants.Reachable σ.walletStorage` — and
    the cap is then DERIVED via the kernel-proven inductive invariant
    `Invariants.reachable_implies_combinedCap`, rather than ASSUMED. The theorem
    stays (correctly) conditional on reachability: off the cap the deployed
    bytecode reverts where the ℕ-model returns failure, and no axiom characterises
    that branch, so an unconditional ∀-σ version is not provable with the current
    axiom set (EF P1). The win is that the conditioning is now a genuine
    inductive-invariant theorem (init + every gated transition preserves the cap),
    NOT a Foundry-fuzz-backed assumption. `#print axioms` is unchanged from
    `theft_free_bytecode` (the discharge is kernel-only — no new axiom). -/
theorem theft_free_bytecode_reachable
    (op : UserOperation)
    (σ σ' : Bridge.EntryPoint.State)
    (effects : Bridge.EntryPoint.Address → Nat → Nat)
    (hReach : Invariants.Reachable σ.walletStorage)
    (hExec : handleOpBytecode σ op effects = σ')
    (hDecrease : σ'.balance σ.walletAddress < σ.balance σ.walletAddress) :
    (∃ (ownerIndex : Nat) (owner : OwnerBytes)
       (pkSeed pkRoot : ByteVec 32) (digest : ByteVec 32)
       (innerSig : ByteVec SignatureLen),
      decodeWrappedSig op.signature = some ⟨ownerIndex, innerSig⟩
      ∧ σ.walletStorage.ownerAtIndex ownerIndex = some owner
      ∧ pkSeed = owner.raw.take 32 (by decide)
      ∧ pkRoot = owner.raw.drop 32 (by decide)
      ∧ digest = sphincsDigest op σ.entryPointAddress σ.chainId
      ∧ Bridge.DeployedBytecode.SPHINCsC10Asm_verify pkSeed pkRoot digest innerSig = true)
    ∧ (∀ (sk : Signer.SigningKey)
         (transcript : Crypto.Transcript)
         (msgStar : ByteVec 32) (sigStar : Hypertree.Signature),
        Crypto.isForgery sk transcript msgStar sigStar → Crypto.BreaksHash) :=
  theft_free_bytecode op σ σ' effects
    (fun i => Invariants.reachable_implies_combinedCap σ.walletStorage i hReach)
    hExec hDecrease


/-- **Factory squat-defence, stated against the deployed factory
    bytecode (I-8 transported through A3.3).** If the code at the
    pinned factory codehash accepts a `createAccount` call, the
    deployed verifier accepted the bootstrap signature over the slot-0
    squat-defence digest.

    `#print axioms factory_squat_defence_bytecode`
    = { solidityFactory_compiles_correctly } ∪ kernel. -/
theorem factory_squat_defence_bytecode
    (masterPkSeed masterPkRoot slot0PkSeed slot0PkRoot : ByteVec 32)
    (chainId : UInt64) (factorySig : ByteVec SignatureLen)
    (h : Bridge.DeployedBytecode.PQSmartWalletFactory_createAccount_passes
          masterPkSeed masterPkRoot slot0PkSeed slot0PkRoot chainId factorySig = true) :
    Bridge.DeployedBytecode.SPHINCsC10Asm_verify masterPkSeed masterPkRoot
        (Wallet.Factory.addSlot0Digest chainId slot0PkSeed slot0PkRoot) factorySig
      = true := by
  have hpre := (Bridge.solidityFactory_compiles_correctly
      masterPkSeed masterPkRoot slot0PkSeed slot0PkRoot chainId factorySig).mp h
  unfold Wallet.Factory.createAccountPrecondition at hpre
  exact hpre.1

/-! ## 4c. Execution-gate non-bypass, transported to the deployed execute
    bytecode (Claim 4 / A3.2-exec).

The model-level `executeBatch_faithful` / `every_call_gated_by_verifier`
quantify the execute step at the Lean `Execute` model. The corollaries
below restate the load-bearing gate — *a money-moving execute requires
the in-transaction validated-owner token* — against the OPAQUE deployed
execute symbols, so `#print axioms` names the execute bridge axioms
(A3.2-exec). They are the Lean-side counterpart of the Halmos session
`test/halmos/HalmosExecuteEquiv.t.sol`.

**(EF-#15) "executed `(target,value,data)` = the SIGNED `callData`" — binding
decomposition.** A PoC asks whether a verifier-true validate of `op.callData = X`
can be followed by an execute of independent args `Y ≠ decode(X)`. The full binding
is a 4-link chain, of which ONLY the EntryPoint relay is not Lean-mechanized:
  1. signed digest ⇒ `sha256(op.callData)` committed — `theft_free_with_calldata_binding`
     + `Wallet.SphincsDigestSpec.sphincsDigest_field_binding` (Lean, modulo `BreaksHash`).
  2. EntryPoint passes `op.callData` verbatim as the wallet's execute calldata —
     **A2 cited-TCB** (the deployed EntryPoint v0.6 invocation behaviour; the wallet
     cannot self-verify it, and the Lean `Execute` model abstracts the relay by
     taking the args directly — exactly the model-abstraction the PoC probes).
  3. the deployed `executeWithOffchainCount` bytecode ABI-decodes its calldata into
     `(ownerIndex, target, value, data)` and runs exactly those — `HalmosExecuteEquiv`
     over a symbolic `ownerIndex` + symbolic args (A3.2-exec / B).
  4. the Lean `Execute` model dispatches those args in order — `executeBatch_faithful` (K).
So the executed payload IS bound to the signed `callData` modulo link 2 (A2). #15 is
therefore an **A2-relay residual** (irreducible cited-TCB, same boundary
TRUST_ASSUMPTIONS A2 already names), NOT a missing Lean decode proof — the decode is
discharged at link 3, the digest-binding at link 1. -/

open SphincsCVerify.Wallet.Execute

/-- **A successful deployed `executeWithOffchainCount` required a
    validated-op credit at `ownerIndex` on entry.** If the code at the
    pinned `PQSmartWallet` codehash performs a (non-reverting) single
    execute from state `σ`, then `σ.credits ownerIndex > 0` — i.e. an
    earlier in-transaction step stamped a per-index credit, which
    (model-side, via `TxFlow` + I-1) only a verifier-true slot-path
    validate can do.

    Composes A3.2-exec (`solidityWalletExecute_compiles_correctly`,
    success direction) with E-8 (`execute_only_validateSig_authorises`).

    `#print axioms deployed_execute_requires_prior_token` adds
    `solidityWalletExecute_compiles_correctly` to the closure. -/
theorem deployed_execute_requires_prior_token
    (σ σ' : Wallet.Execute.ExecState) (caller : ByteVec 20)
    (ownerIndex newOffchainCount : Nat)
    (target : ByteVec 20) (value : Nat) (data : Array UInt8)
    (hInv : ∀ i, σ.storage.slotUses i + σ.storage.offchainSigCount i ≤ MaxSlotUses)
    (h : Bridge.DeployedBytecode.PQSmartWallet_executeWithOffchainCount
          σ caller ownerIndex newOffchainCount target value data = some σ') :
    σ.credits ownerIndex > 0 :=
  Wallet.Execute.execute_only_validateSig_authorises
    (Bridge.solidityWalletExecute_compiles_correctly
      σ caller ownerIndex newOffchainCount target value data σ' hInv h)

/-- **A successful deployed `executeBatchWithOffchainCount` required a
    validated-op credit at `ownerIndex` on entry.** Batch peer of
    `deployed_execute_requires_prior_token`; composes A3.2-exec(batch)
    with E-8(batch). -/
theorem deployed_executeBatch_requires_prior_token
    (σ σ' : Wallet.Execute.ExecState) (caller : ByteVec 20)
    (ownerIndex newOffchainCount : Nat)
    (targets : List (ByteVec 20)) (values : List Nat) (datas : List (Array UInt8))
    (hInv : ∀ i, σ.storage.slotUses i + σ.storage.offchainSigCount i ≤ MaxSlotUses)
    (h : Bridge.DeployedBytecode.PQSmartWallet_executeBatchWithOffchainCount
          σ caller ownerIndex newOffchainCount targets values datas = some σ') :
    σ.credits ownerIndex > 0 :=
  Wallet.Execute.executeBatch_only_validateSig_authorises
    (Bridge.solidityWalletExecuteBatch_compiles_correctly
      σ caller ownerIndex newOffchainCount targets values datas σ' hInv h)

/-! ## 5. Claim 1 — the DIGEST FIELD-BINDING half of signature-to-execution binding.

`theft_free` (above) establishes that a wallet-balance decrement implies some
signature was verified over `sphincsDigest(op)`. This corollary adds the
cryptographic **field-binding** result it composes with: if two UserOps share
a `sphincsDigest` then they share the full preimage — hence every positional
field (sender, nonce, callData, gas params, chainId, entryPoint) — UNLESS
SHA-256 collides. It discharges to exactly ONE axiom,
`sha256_collision_resistance`, via `sphincsDigest_field_binding`.

SCOPE — HONEST (corrected 2026-07-02, finding exec-lean-F2/V4): this theorem
proves **only the digest-collision half** ("equal digest ⇒ equal preimage ∨
BreaksHash"). It is **link 1** of the 4-link signature-to-execution chain (see
`ASSURANCE_CASE.md` EF-#15): link 2 (EntryPoint relays `op.callData` as the
execute calldata) is the cited **A2** relay residual; link 3 (execute decodes
calldata→args) is `HalmosExecuteEquiv`; link 4 (in-order dispatch) is
`executeBatch_faithful`. Earlier revisions of this theorem carried four unused
execution hypotheses (`σ'`, `effects`, `hExec`, `hDecrease`) and a docstring
claiming it "composes I-1 + the bridge axioms" — BOTH FALSE: the proof consumed
only `hSameDigest`, so those hypotheses were dead and no bridge axiom / I-1 was
in the closure. The dead hypotheses are removed and the closure is now honestly
`{propext, Quot.sound, sha256_collision_resistance}`; the theorem is not the
whole "signature-to-execution binding" — it is its crypto field-binding link. -/

open SphincsCVerify.Wallet.SphincsDigestSpec

theorem theft_free_with_calldata_binding
    (op1 op2 : UserOperation)
    (σ : Bridge.EntryPoint.State)
    -- Hypothesis: `op2` is some other UserOp whose digest happens to match
    -- (the only way an attacker could "substitute" calldata).
    (hSameDigest : sphincsDigest op1 σ.entryPointAddress σ.chainId
                     = sphincsDigest op2 σ.entryPointAddress σ.chainId) :
    -- Then `op2` and `op1` agree on the preimage (and hence on every
    -- positional field) — UNLESS SHA-256 is broken: no calldata substitution
    -- is possible without a same-length SHA-256 collision, which lands in the
    -- (cited-infeasible) `BreaksHash` disjunct.
    sphincsDigestPreimage op1 σ.entryPointAddress σ.chainId
      = sphincsDigestPreimage op2 σ.entryPointAddress σ.chainId ∨ Crypto.BreaksHash := by
  -- Discharge by `sphincsDigest_field_binding`, which reduces to
  -- `sha256_collision_resistance` (equal preimages, or a SHA-256 break).
  exact sphincsDigest_field_binding op1 op2
    σ.entryPointAddress σ.chainId hSameDigest

/-! ## 6. Claim 3 — execution faithfulness composite.

The eight Execute theorems (E-1 through E-8 in
`Wallet/Execute.lean`) combine into the bundled "executeBatch
faithful to signed input" claim. Stated here as the composite
corollary so `#print axioms executeBatch_faithful` shows the
combined dep closure (the new `solidityWallet_compiles_correctly`
axiom A3.2 carries the execute-path discharge in tier-2.4 / Halmos). -/

open SphincsCVerify.Wallet.Execute

theorem executeBatch_faithful
    {σ : Wallet.Execute.ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    {σ' : Wallet.Execute.ExecState}
    (hlen1 : targets.length = values.length)
    (hlen2 : values.length = datas.length)
    (h : Wallet.Execute.executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
             targets values datas = some σ') :
    -- E-1: caller is EntryPoint
    caller = σ.entryPoint ∧
    -- E-2: no self-target in the batch
    (∀ t ∈ targets, t ≠ σ.selfAddress) ∧
    -- E-4: exactly one credit consumed at the index (one-shot replay guard)
    σ'.credits ownerIndex = σ.credits ownerIndex - 1 ∧
    -- E-5: callStack appends in input order
    σ'.callStack = σ.callStack ++ Wallet.Execute.buildBatchCalls targets values datas ∧
    -- E-6: value outflow equals sum of signed values
    Wallet.Execute.totalValue σ'.callStack
      = Wallet.Execute.totalValue σ.callStack + values.foldl (· + ·) 0 ∧
    -- E-8: a prior validateSignature stamped a credit at the index
    σ.credits ownerIndex > 0 :=
  ⟨Wallet.Execute.executeBatch_caller_is_entrypoint h,
   Wallet.Execute.executeBatch_rejects_self_target h,
   Wallet.Execute.executeBatch_consumes_credit h,
   Wallet.Execute.executeBatch_runs_in_signed_order h,
   Wallet.Execute.executeBatch_value_outflow_eq_sum_values hlen1 hlen2 h,
   Wallet.Execute.executeBatch_only_validateSig_authorises h⟩

/-! ## 7. Claim 4 — execution-gate non-bypass.

For any transaction trace `runTrace σ0 trace = some σ'` starting from a
clean transient (`∀ i, σ0.credits i = 0`, the EIP-1153 boundary at
transaction entry), every wallet-initiated external call appearing
in `σ'.callStack` (i.e. any growth beyond `σ0.callStack`) is authorised
by at least one `validate` step in `trace` whose on-chain
`c10Verifier.verify` returned `true` over `sphincsDigest(op)` under an
installed owner key.

The composition is:

  * `Wallet.TxFlow.applyStep_credit_lift_only_by_validate_success` —
    the per-index transient credit map cannot be lifted from all-zero
    except by a successful slot-path `validate` step.
  * `Wallet.Execute.execute_only_validateSig_authorises` (E-8) — every
    successful `execute` / `executeBatch` step required
    `credits ownerIndex > 0` on entry.
  * `Wallet.Invariants.validateSignature_only_via_verify` (I-1) — every
    successful `validateSignature` implies `verify_fn` returned `true`
    on the decoded `(pkSeed, pkRoot, sphincsDigest, innerSig)`.
  * `Wallet.TxFlow.callstack_grew_implies_some_verify_true` — assembles
    the above into the trace-level statement.

Removing any of {I-1, E-8, the `applyStep` token-write lemma} would
leave the conclusion unprovable.

**P13 (honest scope of `verify_fn`).** This trace-level theorem constrains
the trace's OWN SUPPLIED `verify_fn` field — it is NOT pinned here to the
deployed `SPHINCsC10Asm.verify`. Its `#print axioms` closure is kernel-only
(`{propext, Classical.choice, Quot.sound}`, asserted by
`scripts/dump_axioms_claim4.lean` and `make verify-exec-gate`), so it does NOT
consume the A1/A3.1/A4 bridge axioms; the earlier wording "under the bridge
axioms the model's `verify_fn` coincides with the deployed bytecode … lifts to
the on-chain verifier" was unmechanized prose contradicted by that gate. The
lift to the DEPLOYED verifier is performed in `theft_free` (via A2 + A3.1), not
in this Claim-4 trace gate. Note also: this gate pins ETH-value-moving calls;
`σ_pre` below is existentially quantified (some earlier trace state), not the
wallet's reachable owner state, and value=0 call-graph pinning to the deployed
verifier remains an OPEN obligation (see OPEN_PROOF_OBLIGATIONS / Claim 4).
-/

open SphincsCVerify.Wallet.TxFlow

/-- **Execution-gate non-bypass.** Any wallet-initiated external call in
    the post-state was authorised by at least one `validate` step
    earlier in the same transaction whose `verify_fn` returned `true`
    on the decoded `(pkSeed, pkRoot, sphincsDigest, innerSig)` under
    an installed owner key.

    The consequent here is existential ("some validated step in the
    trace") — already sufficient to rule out the bypass attack: a
    transaction trace containing zero verifier-true validates cannot
    produce any external call. The STRONGER per-step (injective)
    attribution — every stack-growing external-call step is backed by
    its OWN per-index credit, stamped only by a verifier-true validate —
    is now also proven, see `every_call_consumes_its_own_validated_credit`
    (per-index exactly-once anti-replay) and
    `credit_lift_implies_verified_validate` (lift ⇒ verified validate)
    below (Gap-2, credits-model form; see their section note). -/
theorem every_call_gated_by_verifier
    (σ0 σ' : Wallet.Execute.ExecState) (trace : List Wallet.TxFlow.Step)
    (hrun : Wallet.TxFlow.runTrace σ0 trace = some σ')
    (hinit : ∀ i, σ0.credits i = 0)
    (hgrew : σ0.callStack.length < σ'.callStack.length) :
    ∃ (σ_pre : Wallet.Execute.ExecState) (step : Wallet.TxFlow.Step),
      step ∈ trace ∧ Wallet.TxFlow.StepVerified σ_pre step :=
  Wallet.TxFlow.callstack_grew_implies_some_verify_true σ0 σ' trace hrun hinit hgrew

/-- Restated form auditors will reach for first: starting from an empty
    callStack, any non-empty post-state callStack implies a
    verifier-true validate appeared in the trace. -/
theorem no_call_without_prior_verifier_acceptance
    (σ0 σ' : Wallet.Execute.ExecState) (trace : List Wallet.TxFlow.Step)
    (hrun : Wallet.TxFlow.runTrace σ0 trace = some σ')
    (hinit : ∀ i, σ0.credits i = 0)
    (hempty : σ0.callStack = [])
    (hsome : σ'.callStack ≠ []) :
    ∃ (σ_pre : Wallet.Execute.ExecState) (step : Wallet.TxFlow.Step),
      step ∈ trace ∧ Wallet.TxFlow.StepVerified σ_pre step :=
  Wallet.TxFlow.any_call_implies_some_verify_true σ0 σ' trace hrun hinit hempty hsome

/-! ### Per-index anti-replay attribution — Gap-2 (credits model).

The two corollaries below strengthen the existential gate above to genuine
per-index attribution under the deployed EIP-1153 *per-index* credit
discipline (`Execute.ExecState.credits : Nat → Nat`): a verifier-true
slot-validate STAMPS a credit at its decoded `ownerIndex` (+1), and every
`execute`/`executeBatch` REQUIRES a live credit at its index and CONSUMES
exactly that one (−1), leaving all other indices untouched. So a single
stamp at index `i` funds AT MOST ONE execute at `i` — exactly-once
anti-replay, per index.

This is the faithful credits-model successor to the pre-credits
single-transient "token ledger" formulation (commit 488ba78, written
against the single `validatedOwnerPlusOne` transient that the GAP-11
refactor — commit 84ae543 — replaced with the per-index `credits` map; the
merge `b9f2e59` left the old-API ledger stranded on the new model). The
single-token ledger proved a GLOBAL aggregate `#executes ≤ #validates`; the
credits model proves the STRONGER PER-INDEX exactly-once bound directly from
the `Execute` require/consume lemmas. The per-index form IS the operative
anti-replay (it rules out the "one validate → two executes" replay the
existential gate cannot).

The credits-native GLOBAL aggregate (the completeness complement) is now ALSO
proven — `exec_count_le_validate_count` below (work-todo FV-#5), via a genuine
mathlib-free finite-support credit sum over the trace's finitely-many touched
indices (`Wallet.CreditLedger.sumOver`, the "machinery this project omits" the
playbook flagged). It is intentionally LOOSER than the per-index bound (it
counts ALL validates, not just stamping ones — "stamping" is state-dependent and
not a static `countP`); the per-index result remains operative. NOTE: this is
NOT a revival of the deleted single-`validatedOwnerPlusOne` token ledger (which
was unfaithful to the per-index bytecode) — it is rebuilt natively on the
`credits : Nat → Nat` map.

`#print axioms` for both = `{ propext, Classical.choice, Quot.sound }`
(kernel-only — same closure as the existential `every_call_gated_by_verifier`).

Granularity note unchanged: this is per-execute-STEP / per-index, not
per-individual-CALL. An `executeBatch` appends several calls under one
validate (one credit), so calls within a batch share one authorising
validate; a distinct validate *per call element* is false in this model and
is NOT claimed. -/

/-- **Per-index exactly-once anti-replay (credits form).** A money-moving
    `execute` step REQUIRES a live credit at its `ownerIndex` (some earlier
    step stamped it), CONSUMES exactly that one credit (−1), and leaves every
    OTHER index untouched. So the credit it spends is non-replayable: a
    second execute at the same index needs a fresh stamp — `n` executes at an
    index force `n` stamps there, which a purely existential `≥ 1` gate does
    NOT give. The credits-model successor to the pre-credits
    `every_call_attributed_to_distinct_validate`. -/
theorem every_call_consumes_its_own_validated_credit
    {σ σ' : Wallet.Execute.ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {target : ByteVec 20} {value : Nat} {data : Array UInt8}
    (h : Wallet.TxFlow.applyStep σ
           (.execute caller ownerIndex newOffchainCount target value data)
           = some σ') :
    σ.credits ownerIndex > 0
    ∧ σ'.credits ownerIndex = σ.credits ownerIndex - 1
    ∧ (∀ j, j ≠ ownerIndex → σ'.credits j = σ.credits j) := by
  refine ⟨Wallet.TxFlow.execute_step_requires_prior_credit h, ?_, ?_⟩
  · simp only [Wallet.TxFlow.applyStep] at h
    exact Wallet.Execute.execute_consumes_credit h
  · intro j hj
    simp only [Wallet.TxFlow.applyStep] at h
    exact Wallet.Execute.execute_preserves_other_credits h hj

/-- **A credit is lifted from zero only by a verifier-true validate.** If a
    step raises the all-zero credit map to a state with some live credit,
    that step is a slot-path `validate` whose `verify_fn` returned `true`
    over `sphincsDigest` (`StepVerified`). Composed with the anti-replay
    above: the credit every call consumes traces back to a verifier-true
    validate. The credits-model successor to the pre-credits
    `call_traces_to_authorising_validate`. -/
theorem credit_lift_implies_verified_validate
    {σ σ' : Wallet.Execute.ExecState} {step : Wallet.TxFlow.Step}
    (h : Wallet.TxFlow.applyStep σ step = some σ')
    (hwas : ∀ i, σ.credits i = 0)
    (hnow : ∃ i, σ'.credits i ≠ 0) :
    Wallet.TxFlow.StepVerified σ step := by
  obtain ⟨op, ep, cid, vfn, d, owner, hstep, hOk, _, _⟩ :=
    Wallet.TxFlow.applyStep_credit_lift_only_by_validate_success h hwas hnow
  exact ⟨op, ep, cid, vfn, d, owner, hstep, hOk.1, hOk.2.1, hOk.2.2.2.1⟩

/-- **Global credit aggregate (completeness complement).** In any successful
    transaction trace from a clean transient (`∀ i, σ0.credits i = 0`), the
    number of money-moving `execute`/`executeBatch` steps is ≤ the number of
    `validate` steps. The credits-native GLOBAL bound (work-todo FV-#5), the
    aggregate counterpart to the per-index exactly-once anti-replay above —
    proven via a mathlib-free finite-support credit sum
    (`Wallet.CreditLedger.creditConservation`). Looser than the per-index bound
    (counts ALL validates, not just stamping ones); the per-index result remains
    operative. Re-exported here alongside the rest of Claim 4. -/
theorem exec_count_le_validate_count
    (σ0 σf : Wallet.Execute.ExecState) (trace : List Wallet.TxFlow.Step)
    (hrun : Wallet.TxFlow.runTrace σ0 trace = some σf)
    (hinit : ∀ i, σ0.credits i = 0) :
    trace.countP Wallet.CreditLedger.isExec
      ≤ trace.countP Wallet.CreditLedger.isValidate :=
  Wallet.CreditLedger.exec_count_le_validate_count σ0 σf trace hrun hinit

end SphincsCVerify.Spec.Theorems
