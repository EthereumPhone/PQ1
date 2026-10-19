import C10Probability.ObservedCoverage
import C10Probability.SessionExamples

/-! Finite boundary witnesses for actual pool observation and accepted-call
accounting. Cached tables here are explicit fixtures, not freshness premises. -/
namespace C10Probability
noncomputable section

def duplicateHmsgProgram : QueryProgram Bool Digest Unit 2 :=
  .query false (fun _ => .query false (fun _ => .done ()))

def emptyHmsgFixture : HmsgPoolOutput Bool Unit := ⟨(), fun _ => none, []⟩

theorem hmsg_prepend_accepted_example :
    (hmsgPoolPrepend (fun _ => true) false 0 emptyHmsgFixture).entries = [(false, 0)] := by
  decide +kernel

theorem hmsg_prepend_rejected_example :
    (hmsgPoolPrepend (fun _ => true) false (2 ^ 132) emptyHmsgFixture).entries = [] := by
  decide +kernel

theorem hmsg_prepend_unselected_example :
    (hmsgPoolPrepend (fun _ => false) false 0 emptyHmsgFixture).entries = [] := by
  decide +kernel

theorem hmsg_query_width_examples :
    hmsgQuery (.inl (List.replicate 160 0)) = true ∧
    hmsgQuery (.inr (List.replicate 160 0)) = false ∧
    hmsgQuery (.inl (List.replicate 159 0)) = false ∧
    hmsgQuery (.inl (List.replicate 161 0)) = false := by
  simp only [hmsgQuery, hmsgWidth, List.length_replicate]
  decide +kernel

theorem hmsg_cached_duplicate_pool_example :
    hmsgPoolProgram (fun _ => true) duplicateHmsgProgram (fun _ => some 0) =
      PMF.pure ⟨(), (fun _ => some 0), []⟩ := by
  simp only [duplicateHmsgProgram, hmsgPoolProgram]

theorem hmsg_fresh_duplicate_pool_example :
    hmsgPoolProgram (fun _ => true) duplicateHmsgProgram (fun _ => none) =
      digestDraw.map (fun value => hmsgPoolPrepend (fun _ => true) false value
        ⟨(), Function.update (fun _ : Bool => none) false (some value), []⟩) := by
  simp only [duplicateHmsgProgram, hmsgPoolProgram, Function.update_self, PMF.pure_map]
  rfl

theorem hmsg_reply_budget_counts_cached_calls :
    ¬ ReplyBudget (hmsgReplyCharge (fun _ : Bool => true)) duplicateHmsgProgram 1 := by
  intro budget
  have accepts : forsAccept (forsOfDigest 0) = true := by decide +kernel
  have first := budget 0
  simp only [hmsgReplyCharge, accepts, Bool.true_and, ↓reduceIte] at first
  have second := first.2 0
  simp only [hmsgReplyCharge, accepts, Bool.true_and, ↓reduceIte,
    Nat.sub_self, Nat.lt_irrefl, false_and] at second

theorem hmsg_observed_refusal_example (table : Memo WotsQuery Digest) :
    evalProgram digestDraw (c10ObservedSessionProgram id sessionExampleConfig
      (.sign ⟨[], [], []⟩ (fun reply => .done reply.isNone) : C10Client Bool 1)
      3 2 emptySessionLedger) table =
      PMF.pure (⟨⟨true, emptySessionLedger, 3, 2⟩, [], []⟩, table) := by
  have refused : sessionAdmits emptySessionLedger ⟨[], [], []⟩ = false := by decide +kernel
  simp only [c10ObservedSessionProgram, refused, Bool.false_eq_true, ↓reduceIte, evalProgram]
  rfl

theorem hmsg_observed_exhaustion_example (table : Memo WotsQuery Digest) :
    evalProgram digestDraw (c10ObservedSessionProgram id
      { sessionExampleConfig with rTrials := 0, rBound := by decide }
      (.sign sessionExampleRequest (fun first => .sign sessionExampleRequest
        (fun second => .done (first.isNone, second.isNone))) : C10Client (Bool × Bool) 2)
      3 2 emptySessionLedger) table =
      PMF.pure (⟨⟨(true, true), ⟨[], true⟩, 3, 1⟩, [], []⟩, table) := by
  have admitted : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  rw [c10_observed_session_program_eval]
  simp only [c10ObservedSession, admitted, ↓reduceIte, c10_sign_zero_r_budget,
    PMF.pure_bind, sessionAfterSign, session_failed_refuses ⟨emptySessionLedger.signedMessages, true⟩ sessionExampleRequest rfl,
    Bool.false_eq_true, PMF.pure_map, observe_sign_none]
  rfl

end
end C10Probability
