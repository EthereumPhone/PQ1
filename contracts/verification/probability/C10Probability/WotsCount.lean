import C10Probability.CountVector

/-! Exact cardinality of the deployed WOTS acceptance predicate. The decimal
integer below is checked by kernel computation of a proved counting algorithm;
neither an external enumeration nor an EasyCrypt theorem is a premise. -/
namespace C10Probability
section

def wotsCountValue : ℕ := 22169393903687611906220091621190388

/-- The arithmetic computation is checked by Lean's kernel, not a native evaluator. -/
theorem wots_word_count_kernel :
    wordCount 8 43 205 = wotsCountValue := by
  have evaluated : (countRun 8 43 (countBasis 205))[0]?.getD 0 =
      22169393903687611906220091621190388 := by decide +kernel
  calc
    wordCount 8 43 205 = (countRun 8 43 (countBasis 205))[0]?.getD 0 := by
      simpa only [Nat.cast_ofNat] using word_count_vector 8 43 205
    _ = wotsCountValue := by rw [evaluated]; rfl

def acceptedWotsSumEquiv : AcceptedWots ≃ SumWords 8 43 205 :=
  Equiv.subtypeEquivRight fun word => by
    simp only [wotsAccept, decide_eq_true_eq]
    constructor <;> intro h <;> exact_mod_cast h

theorem accepted_wots_card_exact :
    Nat.card AcceptedWots = 22169393903687611906220091621190388 := by
  rw [← Fintype.card_eq_nat_card]
  simpa only [wotsCountValue] using
    (Fintype.card_congr acceptedWotsSumEquiv).trans wots_word_count_kernel

end
end C10Probability
