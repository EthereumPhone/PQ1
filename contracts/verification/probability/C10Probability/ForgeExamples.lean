import C10Probability.SharedForgeBound

/-! Boundary witnesses for the composition interfaces. Populated caches are
synthetic counterexamples, not initialized-game probability experiments. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem six_events_overlap_example :
    (PMF.pure true).toOuterMeasure {true} ≤ (6 : ℝ≥0∞) ∧
    (PMF.pure true).toOuterMeasure {true} ≠ (6 : ℝ≥0∞) := by
  constructor
  · have bound := pmf_six_event_bound (PMF.pure true) {true} {true} {true} {true} {true} {true} {true}
      1 1 1 1 1 1 (fun _ _ hit => Or.inl hit)
      (by simp) (by simp) (by simp) (by simp) (by simp) (by simp)
    norm_num at bound ⊢
  · norm_num

theorem six_events_every_position_example (p : PMF (Fin 6)) :
    p.toOuterMeasure Set.univ ≤ p 0 + (p 1 + (p 2 + (p 3 + (p 4 + p 5)))) := by
  apply pmf_six_event_bound p Set.univ {0} {1} {2} {3} {4} {5}
  · intro out _ _
    fin_cases out <;> simp
  all_goals rw [PMF.toOuterMeasure_apply_singleton]

theorem node_budget_public_domains_example :
    nodeBudgetSelector (.inl []) = true ∧
    nodeBudgetSelector (.inl (List.replicate 96 0)) = true ∧
    nodeBudgetSelector (.inl (List.replicate 160 0)) = false ∧
    nodeBudgetSelector (.inl (List.replicate 128 0)) = false := by
  decide +kernel

theorem tagged_private_zero_not_public_example :
    let table : Memo WotsQuery Digest := fun key => match key with
      | .inl _ => none
      | .inr _ => some 0
    ¬ PublicNodeZero (fun key => table (.inl key)) ∧ ¬ NoTarget nodeZero table := by
  refine ⟨?_, ?_⟩
  · simp [PublicNodeZero]
  · intro free
    have impossible := free (.inr []) 0 rfl
    have zero : nodeZero 0 = true := by decide +kernel
    rw [zero] at impossible
    contradiction

theorem public_single_zero_without_collision_example :
    let table : Memo WotsQuery Digest := fun key => if key = .inl [] then some 0 else none
    PublicNodeCollisionFree Sum.inl table ∧ PublicNodeZero (fun key => table (.inl key)) := by
  refine ⟨?_, ⟨[], 0, by simp, by decide +kernel⟩⟩
  intro key other value reply first second _
  have keyEmpty : key = [] := by
    by_contra absent
    simp [selectedCache, absent] at first
  have otherEmpty : other = [] := by
    by_contra absent
    simp [selectedCache, absent] at second
  exact keyEmpty.trans otherEmpty.symm

theorem forge_no_signatures_retains_keygen_verification (cfg : C10SessionConfig) (qr : ℕ) :
    sessionGameRaw cfg qr 0 = qr + 177512 ∧
    sessionGameSelected cfg qr 0 = qr + 177509 ∧
    sessionGamePublic cfg qr 0 = qr + 155496 := by
  simp [sessionGameRaw, sessionGameSelected, sessionGamePublic]

theorem accepted_charge_zero_one_example :
    acceptedWotsGameCharge 0 = 0 ∧ acceptedWotsGameCharge 1 = 0 ∧
    acceptedWotsGameCharge 2 =
      (22169393903687611906220091621190388 : ℝ≥0∞) / 8 ^ 43 / 8 ^ 43 := by
  norm_num [acceptedWotsGameCharge]

theorem shared_charge_keeps_prefix_example (cfg : C10SessionConfig) (qr qs : ℕ) :
    sharedForgeCharge cfg qr qs = independentForgeCharge cfg qr qs +
      ((qr + qs * sessionSignPublic cfg + 155496 : ℕ) : ℝ≥0∞) / 2 ^ 256 := by
  rfl

end
end C10Probability
