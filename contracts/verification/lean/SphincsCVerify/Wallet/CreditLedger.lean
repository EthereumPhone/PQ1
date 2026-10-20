/-
**Global credit-conservation aggregate** for the EIP-1153 per-index
validated-op credit discipline — the credits-native successor's *completeness*
complement to the per-index exactly-once anti-replay already proven in
`Spec.Theorems` (`every_call_consumes_its_own_validated_credit`).

## What this file adds (work-todo FV-#5)

The per-index lemmas prove the STRONGER fact (a single stamp at index `i`
funds at most one execute at `i`). This file proves the GLOBAL aggregate the
old single-`validatedOwnerPlusOne` token ledger used to give before the GAP-11
per-index refactor (commit 84ae543) stranded it:

  **In any successful transaction trace started from a clean transient
  (`∀ i, σ0.credits i = 0`, the EIP-1153 boundary at tx entry), the number of
  money-moving `execute`/`executeBatch` steps is ≤ the number of `validate`
  steps.**

The tight content is the *credit-reserve conservation*
(`exec_count_le_validate_count_aux` / `creditConservation`):

  `countExec tr ≤ countValidate tr + sumOver σ.credits S`

i.e. executes can outrun validates only by drawing on credits already banked
in the carrier `S`. At the tx boundary (`S = []`, all credits zero) the reserve
is zero, so `countExec ≤ countValidate` (`exec_count_le_validate_count`).

## Honest scope (do NOT oversell)

  * The headline counts **ALL** `validate` steps (including failed validates
    and bootstrap `ownerIndex = 0` validates — neither of which stamps a
    credit). It is therefore *looser* than
    `#executes ≤ #stamping-validates`; a static `countP` cannot express
    "stamping" because that is state-dependent (it needs the decode + cap +
    verifier outcome at that step). The per-index exactly-once result remains
    the OPERATIVE anti-replay; this is the global completeness complement.
  * This is the **credits-native** aggregate, derived directly from the
    `Execute` require/consume lemmas via a genuine (mathlib-free) finite-support
    sum (`sumOver` over a running duplicate-free carrier). It is NOT a revival
    of the deleted single-token `validatedOwnerPlusOne` ledger (which was
    unfaithful to the per-index bytecode model) — do not "restore" that.

The reusable deliverable is the `sumOver` / `carrierNodup` machinery: a small
mathlib-free finite-support-sum kit (`docs/.../how_to_math_proof_secureness.md`
flagged this as "machinery this project omits").

`#print axioms` for `exec_count_le_validate_count` and `creditConservation` =
`{ propext, Classical.choice, Quot.sound }` (kernel-only — same closure as the
existential `every_call_gated_by_verifier`). Gated in `dump_axioms.lean`.
-/

import SphincsCVerify.Wallet.Execute
import SphincsCVerify.Wallet.TxFlow

namespace SphincsCVerify.Wallet.CreditLedger

open SphincsCVerify.Spec
open SphincsCVerify.Spec.Signature
open SphincsCVerify.Wallet
open SphincsCVerify.Wallet.Storage
open SphincsCVerify.Wallet.ValidateUserOp
open SphincsCVerify.Wallet.Execute
open SphincsCVerify.Wallet.TxFlow

/-! ## Mathlib-free finite-support sum over a running duplicate-free carrier

`credits : Nat → Nat` has unbounded domain, so "total live credits" is a sum
over its (finite) support. With no mathlib we build the minimum kit: a sum over
an explicit carrier list `S` that we maintain duplicate-free and which contains
exactly the indices touched so far. Only four facts are needed: a congruence,
the off-carrier no-op, and the +1 / −1 deltas for a stamp / consume at an index
already in the (nodup) carrier. -/

/-- Sum of `f` over an explicit (maintained duplicate-free) carrier list. -/
def sumOver (f : Nat → Nat) : List Nat → Nat
  | [] => 0
  | i :: rest => f i + sumOver f rest

/-- Self-contained duplicate-free predicate (avoids depending on the exact
    availability of `List.Nodup` lemmas in bare Lean core). -/
def carrierNodup : List Nat → Prop
  | [] => True
  | i :: rest => i ∉ rest ∧ carrierNodup rest

/-- Insert keeping duplicate-freeness (no-op if already present). -/
def insertIdx (i : Nat) (S : List Nat) : List Nat :=
  if i ∈ S then S else i :: S

/-- `sumOver` depends only on the values `f` takes on carrier elements. -/
theorem sumOver_congr {f g : Nat → Nat} :
    ∀ S : List Nat, (∀ i ∈ S, f i = g i) → sumOver f S = sumOver g S
  | [], _ => rfl
  | i :: rest, h => by
      simp only [sumOver]
      rw [h i (by simp), sumOver_congr rest (fun j hj => h j (by simp [hj]))]

/-- Over a carrier NOT containing `i`, replacing the value at `i` (the `then`
    branch may itself depend on the index) leaves the sum unchanged. -/
theorem sumOver_update_not_mem {f g : Nat → Nat} {i : Nat}
    {S : List Nat} (hi : i ∉ S) :
    sumOver (fun j => if j = i then g j else f j) S = sumOver f S := by
  apply sumOver_congr
  intro j hj
  have hne : j ≠ i := by rintro rfl; exact hi hj
  simp [hne]

/-- Stamp (`+1` at `i`) over a nodup carrier containing `i`: sum grows by 1. -/
theorem sumOver_stamp_mem {f : Nat → Nat} {i : Nat} :
    ∀ {S : List Nat}, i ∈ S → carrierNodup S →
      sumOver (fun j => if j = i then f j + 1 else f j) S = sumOver f S + 1
  | [], hmem, _ => by simp at hmem
  | j :: rest, hmem, hnd => by
      rcases List.mem_cons.mp hmem with hji | hjr
      · subst hji
        have hni : i ∉ rest := hnd.1
        show (if i = i then f i + 1 else f i)
              + sumOver (fun k => if k = i then f k + 1 else f k) rest
              = (f i + sumOver f rest) + 1
        rw [if_pos rfl, sumOver_update_not_mem hni]; omega
      · have hjne : j ≠ i := by rintro rfl; exact hnd.1 hjr
        show (if j = i then f j + 1 else f j)
              + sumOver (fun k => if k = i then f k + 1 else f k) rest
              = (f j + sumOver f rest) + 1
        rw [if_neg hjne, sumOver_stamp_mem hjr hnd.2]; omega

/-- Stamp at a FRESH index (`i ∉ S`, `f i = 0`): prepending `i` to the carrier
    grows the sum by exactly 1 (the new index banks its single credit). -/
theorem sumOver_stamp_not_mem {f : Nat → Nat} {i : Nat} {S : List Nat}
    (hi : i ∉ S) (hz : f i = 0) :
    sumOver (fun j => if j = i then f j + 1 else f j) (i :: S) = sumOver f S + 1 := by
  show (if i = i then f i + 1 else f i)
        + sumOver (fun j => if j = i then f j + 1 else f j) S
        = sumOver f S + 1
  rw [if_pos rfl, sumOver_update_not_mem hi]; omega

/-- Consume (`−1` at `i`) over a nodup carrier containing `i` with `f i > 0`:
    the sum drops by exactly 1 (phrased `+1`-balanced to dodge Nat truncation). -/
theorem sumOver_consume_mem {f : Nat → Nat} {i : Nat} :
    ∀ {S : List Nat}, i ∈ S → carrierNodup S → 0 < f i →
      sumOver (fun j => if j = i then f j - 1 else f j) S + 1 = sumOver f S
  | [], hmem, _, _ => by simp at hmem
  | j :: rest, hmem, hnd, hpos => by
      rcases List.mem_cons.mp hmem with hji | hjr
      · subst hji
        have hni : i ∉ rest := hnd.1
        show ((if i = i then f i - 1 else f i)
              + sumOver (fun k => if k = i then f k - 1 else f k) rest) + 1
              = f i + sumOver f rest
        rw [if_pos rfl, sumOver_update_not_mem hni]; omega
      · have hjne : j ≠ i := by rintro rfl; exact hnd.1 hjr
        have ih := sumOver_consume_mem hjr hnd.2 hpos
        show ((if j = i then f j - 1 else f j)
              + sumOver (fun k => if k = i then f k - 1 else f k) rest) + 1
              = f j + sumOver f rest
        rw [if_neg hjne]; omega

/-- `insertIdx` preserves duplicate-freeness. -/
theorem carrierNodup_insert {i : Nat} {S : List Nat} (hnd : carrierNodup S) :
    carrierNodup (insertIdx i S) := by
  unfold insertIdx
  by_cases h : i ∈ S
  · simp [h]; exact hnd
  · simp [h]; exact ⟨h, hnd⟩

/-! ## Bridges to the model's stamp / consume deltas

`stampCredit`/`consumeCredit` (from `TxFlow`/`Execute`) are definitionally the
`fun j => if j = i then … else …` shape the infra lemmas expect, so the infra
applies directly. -/

/-- A successful `execute` step's post-credits are exactly `consumeCredit`. -/
theorem applyStep_execute_credits
    {σ σ' : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {target : ByteVec 20} {value : Nat} {data : Array UInt8}
    (h : applyStep σ (.execute caller ownerIndex newOffchainCount target value data)
         = some σ') :
    σ.credits ownerIndex > 0 ∧ σ'.credits = consumeCredit σ.credits ownerIndex := by
  simp only [applyStep] at h
  refine ⟨execute_requires_credit h, ?_⟩
  funext j
  by_cases hj : j = ownerIndex
  · subst hj
    rw [execute_consumes_credit h]; simp [consumeCredit]
  · rw [execute_preserves_other_credits h hj]; simp [consumeCredit, hj]

/-- A successful `executeBatch` step's post-credits are exactly `consumeCredit`. -/
theorem applyStep_executeBatch_credits
    {σ σ' : ExecState} {caller : ByteVec 20}
    {ownerIndex newOffchainCount : Nat}
    {targets : List (ByteVec 20)} {values : List Nat}
    {datas : List (Array UInt8)}
    (h : applyStep σ (.executeBatch caller ownerIndex newOffchainCount
                        targets values datas) = some σ') :
    σ.credits ownerIndex > 0 ∧ σ'.credits = consumeCredit σ.credits ownerIndex := by
  simp only [applyStep] at h
  refine ⟨executeBatch_requires_credit h, ?_⟩
  funext j
  by_cases hj : j = ownerIndex
  · subst hj
    rw [executeBatch_consumes_credit h]; simp [consumeCredit]
  · rw [executeBatch_preserves_other_credits h hj]; simp [consumeCredit, hj]

/-- A `validate` step either leaves `credits` untouched (failed / decode-fail /
    bootstrap `ownerIndex = 0`) or STAMPS `+1` at a decoded non-zero
    `ownerIndex`. Mirrors the case structure of
    `applyStep_credit_lift_only_by_validate_success` but characterises the
    post-credits exactly (not just "lifted from zero"). -/
theorem applyStep_validate_credits
    {σ σ' : ExecState}
    {op : UserOperation} {ep : ByteVec 20} {cid : Nat}
    {vfn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool}
    (h : applyStep σ (.validate op ep cid vfn) = some σ') :
    σ'.credits = σ.credits ∨
    ∃ d : DecodedSig,
      decodeWrappedSig op.signature = some d ∧ d.ownerIndex ≠ 0 ∧
      σ'.credits = stampCredit σ.credits d.ownerIndex := by
  simp only [applyStep] at h
  by_cases hsucc :
      (validateSignature σ.storage op ep cid vfn).1 = Result.success
  · rw [if_pos hsucc] at h
    cases hdec : decodeWrappedSig op.signature with
    | none =>
        rw [hdec] at h; injection h with h
        left; rw [← h]
    | some d =>
        rw [hdec] at h; injection h with h
        by_cases hd0 : d.ownerIndex = 0
        · left; rw [← h]; unfold applyValidateSuccess; rw [if_pos hd0]
        · right
          refine ⟨d, rfl, hd0, ?_⟩
          rw [← h]; unfold applyValidateSuccess; rw [if_neg hd0]
  · rw [if_neg hsucc] at h; injection h with h
    left; rw [← h]

/-! ## Trace counts -/

/-- A money-moving (external-call-producing) step. -/
def isExec : Step → Bool
  | .execute _ _ _ _ _ _ => true
  | .executeBatch _ _ _ _ _ _ => true
  | .validate _ _ _ _ => false

/-- A `validate` entry-point call (every credit stamp is one of these, but not
    conversely — failed and bootstrap validates do not stamp). -/
def isValidate : Step → Bool
  | .validate _ _ _ _ => true
  | .execute _ _ _ _ _ _ => false
  | .executeBatch _ _ _ _ _ _ => false

/-- `j ∉ insertIdx i S` splits into `j ≠ i` and `j ∉ S`. -/
theorem not_mem_insertIdx {i j : Nat} {S : List Nat}
    (h : j ∉ insertIdx i S) : j ≠ i ∧ j ∉ S := by
  unfold insertIdx at h
  by_cases hi : i ∈ S
  · rw [if_pos hi] at h
    exact ⟨fun hji => h (hji ▸ hi), h⟩
  · rw [if_neg hi] at h
    exact ⟨fun hji => h (by simp [hji]), fun hjS => h (by simp [hjS])⟩

/-! ## Credit-reserve conservation (the tight content)

The generalised inductive invariant: along any successful trace, the running
count of money-moving steps can exceed the running count of validate steps only
by drawing down credits already banked in the carrier `S`. -/

/-- **Credit-reserve conservation.** For any successful trace from `σ` with a
    nodup carrier `S` supporting all of `σ`'s live credits,
    `countExec ≤ countValidate + (banked credits over S)`. -/
theorem creditConservation (σf : ExecState) :
    ∀ (tr : List Step) (σ : ExecState) (S : List Nat),
      runTrace σ tr = some σf →
      carrierNodup S →
      (∀ j, j ∉ S → σ.credits j = 0) →
      tr.countP isExec ≤ tr.countP isValidate + sumOver σ.credits S := by
  intro tr
  induction tr with
  | nil =>
      intro σ S _ _ _
      simp [List.countP_nil]
  | cons s rest ih =>
      intro σ S hrun hnd hsupp
      unfold runTrace at hrun
      rw [Option.bind_eq_some_iff] at hrun
      obtain ⟨σ_mid, hStep, hRest⟩ := hrun
      cases s with
      | validate op ep cid vfn =>
          have hcE : (Step.validate op ep cid vfn :: rest).countP isExec
              = rest.countP isExec := by simp [isExec]
          have hcV : (Step.validate op ep cid vfn :: rest).countP isValidate
              = rest.countP isValidate + 1 := by simp [isValidate]
          rw [hcE, hcV]
          rcases applyStep_validate_credits hStep with heq | ⟨d, _hdec, hd0, hstamp⟩
          · -- no stamp: credits unchanged, validate count gains slack
            have hsupp_mid : ∀ j, j ∉ S → σ_mid.credits j = 0 := by
              intro j hj; rw [heq]; exact hsupp j hj
            have hih := ih σ_mid S hRest hnd hsupp_mid
            have hsum : sumOver σ_mid.credits S = sumOver σ.credits S := by rw [heq]
            rw [hsum] at hih; omega
          · -- stamp at d.ownerIndex: carrier gains the index, sum +1
            have hsupp_mid : ∀ j, j ∉ insertIdx d.ownerIndex S → σ_mid.credits j = 0 := by
              intro j hj
              obtain ⟨hjne, hjS⟩ := not_mem_insertIdx hj
              have heq : σ_mid.credits j = σ.credits j := by
                rw [hstamp]; simp [stampCredit, hjne]
              rw [heq]; exact hsupp j hjS
            have hih := ih σ_mid (insertIdx d.ownerIndex S) hRest
              (carrierNodup_insert hnd) hsupp_mid
            have hstampeq : stampCredit σ.credits d.ownerIndex
                = (fun j => if j = d.ownerIndex then σ.credits j + 1 else σ.credits j) := rfl
            have hsum : sumOver σ_mid.credits (insertIdx d.ownerIndex S)
                = sumOver σ.credits S + 1 := by
              rw [hstamp, hstampeq]
              by_cases hi : d.ownerIndex ∈ S
              · simp only [insertIdx, if_pos hi]
                exact sumOver_stamp_mem hi hnd
              · simp only [insertIdx, if_neg hi]
                exact sumOver_stamp_not_mem hi (hsupp d.ownerIndex hi)
            rw [hsum] at hih; omega
      | execute caller oi noc t v data =>
          have hcE : (Step.execute caller oi noc t v data :: rest).countP isExec
              = rest.countP isExec + 1 := by simp [isExec]
          have hcV : (Step.execute caller oi noc t v data :: rest).countP isValidate
              = rest.countP isValidate := by simp [isValidate]
          rw [hcE, hcV]
          obtain ⟨hpos, hcons⟩ := applyStep_execute_credits hStep
          have hi : oi ∈ S := by
            by_cases h : oi ∈ S
            · exact h
            · exact absurd (hsupp oi h) (by omega)
          have hsupp_mid : ∀ j, j ∉ S → σ_mid.credits j = 0 := by
            intro j hj
            have hjoi : j ≠ oi := by rintro rfl; exact hj hi
            have heq : σ_mid.credits j = σ.credits j := by
              rw [hcons]; simp [consumeCredit, hjoi]
            rw [heq]; exact hsupp j hj
          have hih := ih σ_mid S hRest hnd hsupp_mid
          have hsum : sumOver σ_mid.credits S + 1 = sumOver σ.credits S := by
            rw [hcons]; exact sumOver_consume_mem hi hnd hpos
          omega
      | executeBatch caller oi noc ts vs ds =>
          have hcE : (Step.executeBatch caller oi noc ts vs ds :: rest).countP isExec
              = rest.countP isExec + 1 := by simp [isExec]
          have hcV : (Step.executeBatch caller oi noc ts vs ds :: rest).countP isValidate
              = rest.countP isValidate := by simp [isValidate]
          rw [hcE, hcV]
          obtain ⟨hpos, hcons⟩ := applyStep_executeBatch_credits hStep
          have hi : oi ∈ S := by
            by_cases h : oi ∈ S
            · exact h
            · exact absurd (hsupp oi h) (by omega)
          have hsupp_mid : ∀ j, j ∉ S → σ_mid.credits j = 0 := by
            intro j hj
            have hjoi : j ≠ oi := by rintro rfl; exact hj hi
            have heq : σ_mid.credits j = σ.credits j := by
              rw [hcons]; simp [consumeCredit, hjoi]
            rw [heq]; exact hsupp j hj
          have hih := ih σ_mid S hRest hnd hsupp_mid
          have hsum : sumOver σ_mid.credits S + 1 = sumOver σ.credits S := by
            rw [hcons]; exact sumOver_consume_mem hi hnd hpos
          omega

/-! ## Global aggregate headline -/

/-- **Global credit aggregate.** In any successful transaction trace started
    from a clean transient (`∀ i, σ0.credits i = 0` — the EIP-1153 boundary at
    transaction entry), the number of money-moving `execute`/`executeBatch`
    steps is at most the number of `validate` steps.

    This is the credits-native global *completeness* complement to the
    per-index exactly-once anti-replay (`every_call_consumes_its_own_validated_credit`):
    a transaction cannot perform more credit-consuming executions than it made
    validate calls. It is intentionally LOOSER than `#executes ≤ #stamping-validates`
    (a static `countP` cannot see which validates stamp — that is state-dependent);
    the per-index result remains the operative bound. -/
theorem exec_count_le_validate_count
    (σ0 σf : ExecState) (trace : List Step)
    (hrun : runTrace σ0 trace = some σf)
    (hinit : ∀ i, σ0.credits i = 0) :
    trace.countP isExec ≤ trace.countP isValidate := by
  have h := creditConservation σf trace σ0 [] hrun (by trivial) (fun j _ => hinit j)
  simpa [sumOver] using h

/-! ## Non-vacuity

`exec_count_le_validate_count` (and the whole Claim-4 family) is conditional on
`runTrace σ0 trace = some σf`. Kernel-cleanliness proves the implication VALID
but says nothing about whether the hypothesis is SATISFIABLE by a trace with a
successful `execute` — if it weren't, the bound would be vacuous.

It is NOT vacuous. Every guard on the `[validate(stamp), execute]` path is
independently satisfiable: `decodeWrappedSig` is a total function with a
non-empty preimage at any slot index (any 4128-byte wrapper with
`offsetField=0x40`, `innerLen=4008`, zero tail-pad decodes); `ownerAtIndex 1`
is populated by `Storage.initialised`; `capOk` holds for a slot-allowed
index-matching selector under clean caps; `verify_fn` is a `Step` parameter
(take `fun _ _ _ _ => true`); and `bumpSlot`/`setOffchain` both succeed from
zero. The one piece that resists a FULLY-CONCRETE in-kernel witness is exhibiting
that 4128-byte decoding input: `decodeWrappedSig` evaluates `readWordBE` (a
32-iteration loop) over the array, so a `decide`/`rfl` discharge would force the
whole 4128-byte array through the kernel — only `native_decide` makes that
tractable, and `native_decide` is banned on proof paths here. (Hence no concrete
decode witness exists ANYWHERE in the development; it is a shared mechanization
gap across the Claim-4/Invariants families, tracked in `docs/archive/work-todo-retired-2026-07-19.md`.)

The DECODE-FREE half is mechanized below: a live credit funds exactly one
successful `execute` step (rules out a degenerate "`executeWithOffchainCount` is
unsatisfiable for all inputs" vacuity). The remaining clean-init composition
(validate-stamp THEN execute) is mechanized modulo that single decode-preimage
fact — tracked as the shared follow-up. -/

/-- **Non-vacuity (decode-free).** A live per-index credit funds exactly one
    successful `execute` step — so `executeWithOffchainCount` is satisfiable and
    the credit-consuming machinery the aggregate bounds is non-empty. -/
theorem execute_step_satisfiable :
    ∃ (σ : ExecState),
      σ.credits 1 > 0 ∧
      (applyStep σ (.execute σ.entryPoint 1 0
          ⟨Array.replicate 20 1, by simp⟩ 0 #[])).isSome = true := by
  refine ⟨{ storage := Storage.empty,
            selfAddress := ⟨Array.replicate 20 0, by simp⟩,
            entryPoint := ⟨Array.replicate 20 0, by simp⟩,
            credits := fun i => if i = 1 then 1 else 0,
            callStack := [] }, ?_, ?_⟩
  · decide
  · decide

end SphincsCVerify.Wallet.CreditLedger
