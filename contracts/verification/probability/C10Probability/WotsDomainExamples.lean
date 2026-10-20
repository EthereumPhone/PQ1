import C10Probability.WotsDomainNumeric
import C10Probability.C10Examples

/-! Zero/nonzero budgets, arbitrary rejecting prefill, and exact serialized
context witnesses. Arbitrary-table examples do not assign those tables an
initialized random-oracle probability. -/
namespace C10Probability
noncomputable section

theorem wots_domain_zero_trials (seed : ByteKey) (table : Memo ByteKey Digest) :
    WotsDomainExhausted seed 0 (by decide) table := by
  refine ⟨(fun _ => 0, fun _ => 0, fun _ => 0, fun _ => 0), ?_⟩
  simp [CompleteRejection, counterSchedule]

theorem wots_domain_empty_cache_nonzero (seed : ByteKey) (n : ℕ)
    (bounded : n ≤ 2 ^ 32) (positive : 0 < n) :
    ¬ WotsDomainExhausted seed n bounded (fun _ => none) := by
  intro exhausted
  obtain ⟨context, complete⟩ := exhausted
  let first := counterKey (wotsContextStem seed context) ⟨0, by decide⟩
  have member : first ∈
      (counterSchedule (wotsContextStem seed context) 0 n (by simpa using bounded)).toFinset := by
    rw [List.mem_toFinset, counterSchedule, List.mem_ofFn]
    exact ⟨⟨0, positive⟩, rfl⟩
  obtain ⟨value, impossible, _⟩ := complete first member
  cases impossible

theorem wots_domain_rejecting_prefill (seed : ByteKey) (n : ℕ) (bounded : n ≤ 2 ^ 32) :
    WotsDomainExhausted seed n bounded (fun _ => some 0) := by
  refine ⟨(fun _ => 0, fun _ => 0, fun _ => 0, fun _ => 0), ?_⟩
  intro key _
  exact ⟨0, rfl, by decide +kernel⟩

theorem wots_domain_accepting_prefill (seed : ByteKey) (n : ℕ)
    (bounded : n ≤ 2 ^ 32) (positive : 0 < n) :
    ¬ WotsDomainExhausted seed n bounded (fun _ => some recoveryAcceptedDigest) := by
  intro exhausted
  obtain ⟨context, complete⟩ := exhausted
  let first := counterKey (wotsContextStem seed context) ⟨0, by decide⟩
  have member : first ∈
      (counterSchedule (wotsContextStem seed context) 0 n (by simpa using bounded)).toFinset := by
    rw [List.mem_toFinset, counterSchedule, List.mem_ofFn]
    exact ⟨⟨0, positive⟩, rfl⟩
  obtain ⟨value, stored, rejected⟩ := complete first member
  have equal : value = recoveryAcceptedDigest := Option.some.inj stored.symm
  rw [equal] at rejected
  have accepted := recovery_digest_accepted
  simp only [Function.comp_def, accepted, Bool.true_eq_false] at rejected

theorem wots_context_zero_layout (seed : ByteKey) :
    wotsContextStem seed (fun _ => 0, fun _ => 0, fun _ => 0, fun _ => 0) =
      wotsCountStem seed 0 0 0 (List.replicate 16 0) := by
  simp [wotsContextStem, wotsCountStem, c10Address, be_bytes_zero]

theorem wots_context_field_sensitivity :
    wotsContextStem [] (fun _ => 1, fun _ => 2, fun _ => 3, fun _ => 4) =
      List.replicate 4 1 ++ List.replicate 8 2 ++ List.replicate 4 0 ++
      List.replicate 4 3 ++ List.replicate 12 0 ++ List.replicate 16 4 ++
      List.replicate 16 0 := by
  decide +kernel

end
end C10Probability
