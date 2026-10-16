import C10Probability.Projections

/-!
# Boundary cases and the repeated-reply countermodel

`cached` draws once and reuses that reply for every trial, as repeated queries
to one memoized key would. Its failure probability does not decay with the
number of retries. This is a small semantic countermodel, not a C10 attack.
-/

namespace C10Probability

open scoped ENNReal
noncomputable section

variable {α : Type*}

theorem budget_zero (p : PMF α) (accept : α → Bool) (start : ℕ) :
    grind p accept start 0 = PMF.pure none := by rfl

theorem always_reject (p : PMF α) (start n : ℕ) :
    grind p (fun _ => false) start n none = 1 := by
  rw [grind_none]
  simp [rejectMass]

theorem always_accept (p : PMF α) (start n : ℕ) :
    grind p (fun _ => true) start (n + 1) = p.map (fun x => some (start, x)) := by
  simp [grind, PMF.map, Function.comp_def]

theorem rejectMass_pure (x : α) (accept : α → Bool) :
    rejectMass (PMF.pure x) accept = if accept x then 0 else 1 := by
  classical
  rw [rejectMass, tsum_eq_single x]
  · simp
  · intro y hy
    simp [PMF.pure_apply, hy]

def cached (p : PMF α) (accept : α → Bool) (n : ℕ) : PMF (Option (ℕ × α)) :=
  p.bind fun x => grind (PMF.pure x) accept 0 n

/-- Every positive retry count has exactly the original one-draw failure mass. -/
theorem cached_none (p : PMF α) (accept : α → Bool) (n : ℕ) (hn : 0 < n) :
    cached p accept n none = rejectMass p accept := by
  rw [cached, PMF.bind_apply, rejectMass]
  apply tsum_congr
  intro x
  rw [grind_none, rejectMass_pure]
  cases accept x <;> simp [Nat.ne_of_gt hn]

def fairReply : PMF Bool := PMF.uniformOfFintype Bool

theorem fair_rejection : rejectMass fairReply id = (2 : ℝ≥0∞)⁻¹ := by
  simp [rejectMass, fairReply, tsum_fintype]

theorem fresh_two_failure :
    grind fairReply id 0 2 none = (4 : ℝ≥0∞)⁻¹ := by
  rw [grind_none, fair_rejection]
  rw [← ENNReal.inv_pow]
  norm_num

theorem cached_two_failure : cached fairReply id 2 none = (2 : ℝ≥0∞)⁻¹ := by
  rw [cached_none fairReply id 2 (by decide), fair_rejection]

theorem repeated_reply_not_iid :
    grind fairReply id 0 2 none < cached fairReply id 2 none := by
  rw [fresh_two_failure, cached_two_failure]
  norm_num

end
end C10Probability
