import C10Probability.RejectCompletion
import C10Probability.Counter

/-! An exhausted memoized search leaves a rejection at every scheduled key.
The initialized probability bound uses the number of distinct keys; repeated
keys and prefilled tables do not gain an independent-sampling exponent. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K α R : Type*} [DecidableEq K]

theorem memo_grind_exhaustion_rejects (p : PMF α) (accept : α → Bool)
    (keys : List K) (start : ℕ) (table final : Memo K α)
    (exhausted : (none, final) ∈ (memoGrind p accept table start keys).support) :
    CompleteRejection accept keys.toFinset final := by
  induction keys generalizing start table final with
  | nil => simp [CompleteRejection]
  | cons key rest ih =>
    rw [memoGrind, PMF.mem_support_bind_iff] at exhausted
    obtain ⟨reply, queried, finished⟩ := exhausted
    cases accepted : accept reply.1
    · simp only [accepted, Bool.false_eq_true, ↓reduceIte] at finished
      have remaining := ih (start + 1) reply.2 final finished
      intro other member
      simp only [List.toFinset_cons, Finset.mem_insert] at member
      rcases member with equal | member
      · subst other
        exact ⟨reply.1, memoGrind_preserves p accept reply.2 (start + 1) rest
          key reply.1 (memoQuery_stores p table key reply queried) (none, final) finished,
          accepted⟩
      · exact remaining other member
    · simp [accepted] at finished

theorem randomized_rejected_schedule_bound (p : PMF α) (accept : α → Bool)
    (keys : List K) (distinct : keys.Nodup) {n : ℕ}
    (clients : PMF (QueryProgram K α R n)) :
    (randomizedProgram p clients (fun _ => none)).toOuterMeasure
      {out | CompleteRejection accept keys.toFinset out.2} ≤ rejectMass p accept ^ keys.length := by
  simpa only [List.toFinset_card_of_nodup distinct] using
    randomized_complete_rejection_bound p accept keys.toFinset clients

theorem randomized_rejected_counter_bound {R : Type*} {budget : ℕ}
    (clients : PMF (QueryProgram ByteKey Digest R budget)) (stem : ByteKey)
    (start trials : ℕ) (bounded : start + trials ≤ 2 ^ 32) :
    (randomizedProgram digestDraw clients (fun _ => none)).toOuterMeasure
      {out | CompleteRejection (wotsAccept ∘ wotsOfDigest)
        (counterSchedule stem start trials bounded).toFinset out.2} ≤
      rejectMass digestDraw (wotsAccept ∘ wotsOfDigest) ^ trials := by
  simpa only [counter_schedule_length] using randomized_rejected_schedule_bound
    digestDraw (wotsAccept ∘ wotsOfDigest) (counterSchedule stem start trials bounded)
    (counter_schedule_nodup stem start trials bounded) clients

end
end C10Probability
