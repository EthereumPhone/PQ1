import C10Probability.WotsSignOpening

/-! Sealing follows the width actually returned by shuffle derivation. The
continuation is checked only on structural return values, not on an arbitrary
byte string supplied as an unproved width assumption. -/
namespace C10Probability
noncomputable section

theorem opening_sealed_lift_bind {K P α H R T : Type*} [DecidableEq K]
    (target : K) {n m : ℕ} (program : QueryProgram K α R n) (post : R → Prop)
    (excluded : QueryExclusion (fun key => decide (key = target)) post program)
    (after : R → OpeningProgram K P α H T m)
    (later : ∀ value, post value → OpeningSealed target (after value)) :
    OpeningSealed target (bindOpening (liftOpening program) after) := by
  induction program with
  | done value =>
    simpa only [liftOpening, bindOpening, opening_sealed_cast, opening_sealed_reserve] using
      later value excluded
  | query key next ih =>
    exact ⟨of_decide_eq_false excluded.1, fun reply => ih reply (excluded.2 reply)⟩

theorem shuffle_derive_wots_cut_excluded (seed shuffle label : ByteKey)
    (target : WotsCutTarget) (previous : Randomizer) (width : shuffle.length = 32)
    (labelWidth : label.length < 10) :
    QueryExclusion (fun key => decide (key = wotsCutIncoming seed target previous))
      (fun out => out.length = 32) (shuffleDeriveProgram Sum.inl shuffle label) := by
  by_cases zero : shuffle = List.replicate 32 0
  · rw [shuffleDeriveProgram, if_pos zero]
    simp only [QueryExclusion, List.length_replicate]
  · rw [shuffleDeriveProgram, if_neg zero]
    refine ⟨?_, fun reply => ?_⟩
    · apply decide_eq_false
      apply wots_public_width_ne_incoming
      rw [shuffle_derive_input_length shuffle label width]
      omega
    · simp only [QueryExclusion, secretBytes, List.length_ofFn]

end
end C10Probability
