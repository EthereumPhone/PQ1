/-
Per-transaction flow model for `PQSmartWallet`, and the headline
**execution-gate non-bypass** theorem (Claim 4):

  No wallet-initiated external call exists in any reachable post-state
  unless an earlier step in the same transaction was a `validate` whose
  `verify_fn` returned `true` on the appropriate `(pkSeed, pkRoot,
  sphincsDigest, innerSig)`.

The existing modules give us the static pieces:

  * `ValidateUserOp.validateSignature` — the role-split + cap + verifier
    check returning `(Result, Storage)`; the success direction is
    characterised by `validateSignature_success_iff`.
  * `Wallet.Invariants.validateSignature_only_via_verify` (I-1) — a
    successful validate implies `verify_fn` returned `true`.
  * `Wallet.Execute.execute{,Batch}_only_validateSig_authorises` (E-8) —
    a successful execute requires `validatedOwnerPlusOne = ownerIndex+1`
    on entry.

This module composes them into a **transaction-level** statement by
modelling a sequence of `Step`s the EntryPoint can drive against the
wallet and a `runTrace` function that threads `ExecState` through them.
Key load-bearing lemmas:

  * `applyStep_token_set_only_by_validate_success` — the transient
    `validatedOwnerPlusOne` field can only transition from `0` to a
    non-zero value via a successful slot-path `validate` step.
  * `validate_step_preserves_callstack` — `validate` never appends.
  * `callstack_grew_implies_some_verify_true` — trace-level: any
    growth in `σ'.callStack` implies the trace contained at least one
    `validate` step whose `verify_fn` returned `true` on the
    `sphincsDigest` of the validated UserOp.

`Spec.Theorems.every_call_gated_by_verifier` is the top-level corollary
that exposes the result alongside `theft_free` and `executeBatch_faithful`.
-/

import SphincsCVerify.Wallet.Storage
import SphincsCVerify.Wallet.MultiOwnable
import SphincsCVerify.Wallet.ValidateUserOp
import SphincsCVerify.Wallet.Execute
import SphincsCVerify.Wallet.Invariants

namespace SphincsCVerify.Wallet.TxFlow

open SphincsCVerify.Spec
open SphincsCVerify.Spec.Signature
open SphincsCVerify.Wallet
open SphincsCVerify.Wallet.Storage
open SphincsCVerify.Wallet.ValidateUserOp
open SphincsCVerify.Wallet.Execute
open SphincsCVerify.Wallet.Invariants

/-! ## Step model

A `Step` represents one EntryPoint-driven call into the wallet within a
single ERC-4337 transaction. The three constructors cover every
external-call-producing wallet entry-point in scope of the call-graph
non-bypass claim:

  * `validate` — `wallet.validateUserOp(...)`.
  * `execute` — `wallet.executeWithOffchainCount(...)`.
  * `executeBatch` — `wallet.executeBatchWithOffchainCount(...)`.

`addOwnerBytes` and `removeOwnerAtIndex` only mutate storage (no
external calls), so they are outside the call-graph scope; their
non-bypass facts are covered by Claim 2 (`Wallet.Invariants`). -/
inductive Step where
  | validate
      (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
      (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 →
                   ByteVec SignatureLen → Bool)
  | execute
      (caller : ByteVec 20)
      (ownerIndex newOffchainCount : Nat)
      (target : ByteVec 20) (value : Nat) (data : Array UInt8)
  | executeBatch
      (caller : ByteVec 20)
      (ownerIndex newOffchainCount : Nat)
      (targets : List (ByteVec 20)) (values : List Nat)
      (datas : List (Array UInt8))

/-! ## Step semantics

For `validate`, the model intentionally returns `some σ` (state
unchanged) when validation fails — a failing validate in EIP-4337 v0.6
makes the EntryPoint reject the UserOp without mutating the wallet, so
the transaction trace simply continues with the same `ExecState`.

For `validate` *success* on the slot path (`ownerIndex ≠ 0`), we set
`validatedOwnerPlusOne := ownerIndex + 1` to mirror the
`tstore(_TS_VALIDATED_OWNER_INDEX_PLUS_ONE, ...)` write in
`_validateSignature`. The bootstrap path (`ownerIndex = 0`) sets the
`_TS_PENDING_BOOTSTRAP_BUMP` transient instead — not the
`validatedOwnerPlusOne` token — and so does NOT enable the execute
guard. We mirror that by leaving `validatedOwnerPlusOne` untouched in
the bootstrap branch.

The if-then-else structure (rather than nested `match`) mirrors the
proof-friendly form used by `Execute.executeWithOffchainCount`. -/

/-- Helper: post-validate state mutation, factored out so the proof can
    case on individual sub-conditions. -/
def applyValidateSuccess
    (σ : ExecState) (s' : Storage) (d : DecodedSig) : ExecState :=
  if d.ownerIndex = 0 then { σ with storage := s' }
  else { σ with storage := s', validatedOwnerPlusOne := d.ownerIndex + 1 }

def applyStep (σ : ExecState) : Step → Option ExecState
  | .validate op entryPoint chainId verify_fn =>
      let r := validateSignature σ.storage op entryPoint chainId verify_fn
      if r.1 = Result.success then
        match decodeWrappedSig op.signature with
        | none => some σ
        | some d => some (applyValidateSuccess σ r.2 d)
      else some σ
  | .execute caller ownerIndex newOffchainCount target value data =>
      executeWithOffchainCount σ caller ownerIndex newOffchainCount
        target value data
  | .executeBatch caller ownerIndex newOffchainCount targets values datas =>
      executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount
        targets values datas

/-- Run a sequence of steps; abort on the first one that returns `none`
    (a revert). The threaded state carries storage, transient gating
    bits, and the accumulated external call stack. -/
def runTrace (σ : ExecState) : List Step → Option ExecState
  | [] => some σ
  | s :: rest => (applyStep σ s).bind (fun σ' => runTrace σ' rest)

/-! ## Step-level lemmas -/

/-- `applyValidateSuccess` preserves the callStack. -/
private theorem applyValidateSuccess_preserves_callstack
    (σ : ExecState) (s' : Storage) (d : DecodedSig) :
    (applyValidateSuccess σ s' d).callStack = σ.callStack := by
  unfold applyValidateSuccess
  by_cases h : d.ownerIndex = 0
  · rw [if_pos h]
  · rw [if_neg h]

/-- A `validate` step never appends to the callStack. -/
theorem validate_step_preserves_callstack
    {σ σ' : ExecState}
    {op : UserOperation} {ep : ByteVec 20} {cid : Nat}
    {vfn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool}
    (h : applyStep σ (.validate op ep cid vfn) = some σ') :
    σ'.callStack = σ.callStack := by
  simp only [applyStep] at h
  by_cases hsucc :
      (validateSignature σ.storage op ep cid vfn).1 = Result.success
  · rw [if_pos hsucc] at h
    -- Inner match on decodeWrappedSig.
    cases hdec : decodeWrappedSig op.signature with
    | none =>
        rw [hdec] at h
        injection h with h
        rw [← h]
    | some d =>
        rw [hdec] at h
        injection h with h
        rw [← h]
        exact applyValidateSuccess_preserves_callstack σ _ d
  · rw [if_neg hsucc] at h
    injection h with h
    rw [← h]

/-- An execute step that succeeds requires the *incoming* state to have
    `validatedOwnerPlusOne = ownerIndex + 1` — i.e. some earlier step
    must have stamped the token. Repackages
    `Execute.execute_only_validateSig_authorises` through the
    `applyStep` wrapper. -/
theorem execute_step_requires_prior_token
    {σ σ' : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {target : ByteVec 20} {value : Nat} {data : Array UInt8}
    (h : applyStep σ (.execute caller ownerIndex newOffchainCount target value data)
         = some σ') :
    σ.validatedOwnerPlusOne = ownerIndex + 1 := by
  simp only [applyStep] at h
  exact execute_only_validateSig_authorises h

/-- Same for the batch variant. -/
theorem executeBatch_step_requires_prior_token
    {σ σ' : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    (h : applyStep σ (.executeBatch caller ownerIndex newOffchainCount
                        targets values datas) = some σ') :
    σ.validatedOwnerPlusOne = ownerIndex + 1 := by
  simp only [applyStep] at h
  exact executeBatch_only_validateSig_authorises h

/-! ## Token-write monotonicity

The transient `validatedOwnerPlusOne` can ONLY transition from `0` to a
non-zero value via a `validate` step whose `validateSignature` returned
success and whose decoded `ownerIndex` was non-zero (i.e. a slot-path
sig). Execute steps clear the token (zero it). -/

/-- Successful `validate` step that lifts the token from zero must be a
    slot-path validate with a decoded sig and the storage updated by
    `bumpForOwner`. The conclusion is packaged as the same `∃` the
    Invariants module uses, so I-1 (`validateSignature_only_via_verify`)
    plugs in directly downstream. -/
theorem applyStep_token_set_only_by_validate_success
    {σ σ' : ExecState} {step : Step}
    (h : applyStep σ step = some σ')
    (hwas : σ.validatedOwnerPlusOne = 0)
    (hnow : σ'.validatedOwnerPlusOne ≠ 0) :
    ∃ (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
      (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 →
                   ByteVec SignatureLen → Bool)
      (d : DecodedSig) (owner : OwnerBytes),
      step = .validate op entryPoint chainId verify_fn ∧
      validateSignatureOk σ.storage op entryPoint chainId verify_fn d owner ∧
      bumpForOwner σ.storage d.ownerIndex = some σ'.storage ∧
      d.ownerIndex ≠ 0 ∧
      σ'.validatedOwnerPlusOne = d.ownerIndex + 1 := by
  cases hs : step with
  | validate op ep cid vfn =>
      subst hs
      simp only [applyStep] at h
      by_cases hsucc :
          (validateSignature σ.storage op ep cid vfn).1 = Result.success
      · rw [if_pos hsucc] at h
        -- Reconstruct the success witness.
        have hpair :
            validateSignature σ.storage op ep cid vfn
              = (Result.success, (validateSignature σ.storage op ep cid vfn).2) := by
          rw [← hsucc]
        -- Inner match on decode.
        cases hdec : decodeWrappedSig op.signature with
        | none =>
            rw [hdec] at h
            injection h with h
            rw [← h] at hnow
            exact absurd hwas hnow
        | some d =>
            rw [hdec] at h
            injection h with h
            -- h : applyValidateSuccess σ (validateSignature ...).2 d = σ'
            -- Decompose applyValidateSuccess into the two sub-cases.
            by_cases hd0 : d.ownerIndex = 0
            · -- Bootstrap branch: applyValidateSuccess returns σ with only
              -- storage updated; validatedOwnerPlusOne unchanged.
              have hv : σ'.validatedOwnerPlusOne = σ.validatedOwnerPlusOne := by
                rw [← h]
                unfold applyValidateSuccess
                rw [if_pos hd0]
              rw [hwas] at hv
              exact absurd hv hnow
            · -- Slot branch: validatedOwnerPlusOne becomes d.ownerIndex + 1,
              -- storage becomes the bumped value.
              have hv : σ'.validatedOwnerPlusOne = d.ownerIndex + 1 := by
                rw [← h]
                unfold applyValidateSuccess
                rw [if_neg hd0]
              have hst : σ'.storage = (validateSignature σ.storage op ep cid vfn).2 := by
                rw [← h]
                unfold applyValidateSuccess
                rw [if_neg hd0]
              -- Use validateSignature_success_iff to extract validateSignatureOk + bump-eq.
              have hsucc_pair :
                  validateSignature σ.storage op ep cid vfn
                    = (Result.success,
                       (validateSignature σ.storage op ep cid vfn).2) := hpair
              rw [validateSignature_success_iff] at hsucc_pair
              obtain ⟨d', owner, hOk, hBumpEq⟩ := hsucc_pair
              -- d' = d (both come from decoding the same op.signature).
              have hd_eq : d' = d := by
                have h1 : (some d' : Option DecodedSig) = some d := by
                  rw [← hOk.1, hdec]
                exact Option.some.inj h1
              -- Use d' as the witness, rewriting back to d where needed.
              refine ⟨op, ep, cid, vfn, d', owner, rfl, hOk, ?_, ?_, ?_⟩
              · rw [hst]; exact hBumpEq
              · rw [hd_eq]; exact hd0
              · rw [hd_eq]; exact hv
      · rw [if_neg hsucc] at h
        injection h with h
        rw [← h] at hnow
        exact absurd hwas hnow
  | execute caller oi noc t v d =>
      subst hs
      have htok := execute_step_requires_prior_token h
      rw [hwas] at htok
      exact absurd htok.symm (Nat.succ_ne_zero _)
  | executeBatch caller oi noc ts vs ds =>
      subst hs
      have htok := executeBatch_step_requires_prior_token h
      rw [hwas] at htok
      exact absurd htok.symm (Nat.succ_ne_zero _)

/-! ## Trace-level: callstack growth implies a verifier-true validate -/

/-- The verifier-truth predicate at a particular pre-state: there is a
    decoded sig and an installed owner against which the supplied
    `verify_fn` returned `true` over `sphincsDigest`. This is exactly
    the existential I-1 (`validateSignature_only_via_verify`) hands
    back, repackaged so trace-level reasoning can quote it cleanly. -/
def StepVerified (σ : ExecState) (step : Step) : Prop :=
  ∃ (op : UserOperation) (ep : ByteVec 20) (cid : Nat)
    (vfn : ByteVec 32 → ByteVec 32 → ByteVec 32 →
           ByteVec SignatureLen → Bool)
    (d : DecodedSig) (owner : OwnerBytes),
    step = .validate op ep cid vfn ∧
    decodeWrappedSig op.signature = some d ∧
    σ.storage.ownerAtIndex d.ownerIndex = some owner ∧
    vfn (owner.raw.take 32 (by decide))
        (owner.raw.drop 32 (by decide))
        (sphincsDigest op ep cid) d.innerSig = true

/-- Bridge from `applyStep_token_set_only_by_validate_success` to the
    `StepVerified` packaging: a slot-path validate that lifts the token
    is verified at the pre-state. -/
private theorem stepVerified_of_token_lift
    {σ σ' : ExecState} {step : Step}
    (h : applyStep σ step = some σ')
    (hwas : σ.validatedOwnerPlusOne = 0)
    (hnow : σ'.validatedOwnerPlusOne ≠ 0) :
    StepVerified σ step := by
  obtain ⟨op, ep, cid, vfn, d, owner, hstep, hOk, _hbump, _hd0, _hvop⟩ :=
    applyStep_token_set_only_by_validate_success h hwas hnow
  refine ⟨op, ep, cid, vfn, d, owner, hstep, hOk.1, hOk.2.1, hOk.2.2.2.1⟩

/-- **Trace-level non-bypass.** If `σ0.validatedOwnerPlusOne = 0` (the
    standard boundary at transaction entry — EIP-1153 transients zero
    at tx start) and `runTrace σ0 trace = some σ'` with `σ'.callStack`
    strictly longer than `σ0.callStack`, then `trace` contains at
    least one *successful* `validate` step whose `verify_fn` returned
    `true` on the appropriate `(pkSeed, pkRoot, sphincsDigest, innerSig)`.

    This is the headline non-bypass: a wallet-initiated external call
    cannot appear in the post-state unless the firmware signed off,
    the wallet decoded a wrapped sig, the on-chain `c10Verifier.verify`
    returned `true` over `sphincsDigest`, and the slot-path branch was
    taken. -/
theorem callstack_grew_implies_some_verify_true
    (σ0 σ' : ExecState) (trace : List Step)
    (hrun : runTrace σ0 trace = some σ')
    (hinit : σ0.validatedOwnerPlusOne = 0)
    (hgrew : σ0.callStack.length < σ'.callStack.length) :
    ∃ (σ_pre : ExecState) (step : Step),
      step ∈ trace ∧ StepVerified σ_pre step := by
  -- Strengthen to an inductive statement carrying the trace prefix.
  suffices aux :
      ∀ (σ : ExecState) (tr : List Step) (σf : ExecState),
        runTrace σ tr = some σf →
        σ.validatedOwnerPlusOne = 0 →
        σ.callStack.length < σf.callStack.length →
        ∃ σ_pre step, step ∈ tr ∧ StepVerified σ_pre step by
    exact aux σ0 trace σ' hrun hinit hgrew
  intro σ tr σf hrun hzero hgrew
  induction tr generalizing σ with
  | nil =>
      -- Empty trace ⇒ σf = σ, so callStack lengths are equal. Contradiction.
      unfold runTrace at hrun
      injection hrun with hrun
      rw [← hrun] at hgrew
      exact absurd hgrew (Nat.lt_irrefl _)
  | cons step rest ih =>
      unfold runTrace at hrun
      rw [Option.bind_eq_some_iff] at hrun
      obtain ⟨σ_mid, hStep, hRest⟩ := hrun
      -- Case-split: did this step grow the callStack?
      by_cases hmid : σ.callStack.length < σ_mid.callStack.length
      · -- Growth happened on `step`. Case-analyse by step shape.
        cases step with
        | validate op ep cid vfn =>
            -- A validate step preserves callStack — impossible.
            have hpres := validate_step_preserves_callstack hStep
            rw [hpres] at hmid
            exact absurd hmid (Nat.lt_irrefl _)
        | execute caller oi noc t v d =>
            -- An execute step requires σ.validatedOwnerPlusOne = oi + 1,
            -- contradicting hzero (= 0).
            have htok := execute_step_requires_prior_token hStep
            rw [hzero] at htok
            exact absurd htok.symm (Nat.succ_ne_zero _)
        | executeBatch caller oi noc ts vs ds =>
            have htok := executeBatch_step_requires_prior_token hStep
            rw [hzero] at htok
            exact absurd htok.symm (Nat.succ_ne_zero _)
      · -- Growth must come later in `rest`. Convert ¬ < to ≤.
        have hmid_le : σ_mid.callStack.length ≤ σ.callStack.length :=
          Nat.le_of_not_lt hmid
        by_cases htoken : σ_mid.validatedOwnerPlusOne = 0
        · -- Token still zero. Apply IH on `rest` starting from σ_mid.
          have hgrew_mid : σ_mid.callStack.length < σf.callStack.length := by
            calc σ_mid.callStack.length
                ≤ σ.callStack.length := hmid_le
              _ < σf.callStack.length := hgrew
          obtain ⟨σ_pre, s, hMem, hVer⟩ := ih σ_mid hRest htoken hgrew_mid
          exact ⟨σ_pre, s, List.mem_cons.mpr (Or.inr hMem), hVer⟩
        · -- Token became non-zero on this step ⇒ verifier-true validate.
          exact ⟨σ, step, List.mem_cons.mpr (Or.inl rfl),
                 stepVerified_of_token_lift hStep hzero htoken⟩

/-- Convenience corollary: a `σ0` with empty callStack reaching a
    non-empty `σ'.callStack` implies a successful `validate` somewhere
    in the trace. -/
theorem any_call_implies_some_verify_true
    (σ0 σ' : ExecState) (trace : List Step)
    (hrun : runTrace σ0 trace = some σ')
    (hinit : σ0.validatedOwnerPlusOne = 0)
    (hempty : σ0.callStack = [])
    (hsome : σ'.callStack ≠ []) :
    ∃ (σ_pre : ExecState) (step : Step),
      step ∈ trace ∧ StepVerified σ_pre step := by
  apply callstack_grew_implies_some_verify_true σ0 σ' trace hrun hinit
  rw [hempty, List.length_nil]
  exact List.length_pos_iff.mpr hsome

end SphincsCVerify.Wallet.TxFlow
