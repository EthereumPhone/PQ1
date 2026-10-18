import Mathlib.Combinatorics.Enumerative.Stirling
import Mathlib.Data.Fintype.CardEmbedding
import Mathlib.Tactic

/-! Reverse restricted-growth encodings. A coordinate either reuses a label
from its suffix or introduces the new final label. The finite type's cardinality
is derived from this construction and the Stirling recurrence. -/
namespace C10Probability
noncomputable section

def GrowthWord : ℕ → ℕ → Type
  | 0, 0 => Unit
  | 0, _ + 1 => Empty
  | _ + 1, 0 => Empty
  | n + 1, j + 1 => (Fin (j + 1) × GrowthWord n (j + 1)) ⊕ GrowthWord n j

instance growthWordFintype (n j : ℕ) : Fintype (GrowthWord n j) := by
  induction n generalizing j with
  | zero => cases j <;> simp only [GrowthWord] <;> infer_instance
  | succ n ih =>
    cases j with
    | zero => exact inferInstanceAs (Fintype Empty)
    | succ j =>
      letI := ih j
      letI := ih (j + 1)
      exact inferInstanceAs (Fintype ((Fin (j + 1) × GrowthWord n (j + 1)) ⊕ GrowthWord n j))

def growthEmpty : GrowthWord 0 0 := ()

def growthReuse {n : ℕ} : {j : ℕ} → Fin j → GrowthWord n j → GrowthWord (n + 1) j
  | 0, label, _ => Fin.elim0 label
  | _ + 1, label, word => Sum.inl (label, word)

def growthNew {n j : ℕ} (word : GrowthWord n j) : GrowthWord (n + 1) (j + 1) :=
  Sum.inr word

def growthAssignment : {n j : ℕ} → GrowthWord n j → Fin n → Fin j
  | 0, _, _, i => Fin.elim0 i
  | _ + 1, 0, word, _ => Empty.elim word
  | _ + 1, _ + 1, Sum.inl (label, word), i => Fin.cases label (growthAssignment word) i
  | _ + 1, j + 1, Sum.inr word, i =>
      Fin.cases (Fin.last j) (fun k => (growthAssignment word k).castSucc) i

theorem growth_reuse_assignment {n j : ℕ} (label : Fin j) (word : GrowthWord n j) :
    growthAssignment (growthReuse label word) = Fin.cases label (growthAssignment word) := by
  cases j with
  | zero => exact Fin.elim0 label
  | succ j => rfl

theorem growth_new_assignment {n j : ℕ} (word : GrowthWord n j) :
    growthAssignment (growthNew word) =
      Fin.cases (Fin.last j) (fun i => (growthAssignment word i).castSucc) := by
  rfl

theorem growth_word_card (n j : ℕ) : Fintype.card (GrowthWord n j) = Nat.stirlingSecond n j := by
  induction n generalizing j with
  | zero => cases j <;> simp [GrowthWord, Nat.stirlingSecond]
  | succ n ih =>
    cases j with
    | zero => simp [GrowthWord, Nat.stirlingSecond]
    | succ j =>
      change Fintype.card ((Fin (j + 1) × GrowthWord n (j + 1)) ⊕ GrowthWord n j) = _
      rw [Fintype.card_sum, Fintype.card_prod, Fintype.card_fin, ih, ih]
      rfl

theorem growth_assignment_surjective {n j : ℕ} (word : GrowthWord n j) :
    Function.Surjective (growthAssignment word) := by
  induction n generalizing j with
  | zero =>
    cases j with
    | zero => intro label; exact Fin.elim0 label
    | succ j => exact Empty.elim word
  | succ n ih =>
    cases j with
    | zero => exact Empty.elim word
    | succ j =>
      cases word with
      | inl pair =>
        intro label
        obtain ⟨i, hi⟩ := ih pair.2 label
        exact ⟨i.succ, hi⟩
      | inr tail =>
        intro label
        refine Fin.lastCases ?_ (fun smaller => ?_) label
        · exact ⟨0, rfl⟩
        · obtain ⟨i, hi⟩ := ih tail smaller
          exact ⟨i.succ, congrArg Fin.castSucc hi⟩

theorem growth_word_width_le {n j : ℕ} (word : GrowthWord n j) : j ≤ n := by
  simpa using Fintype.card_le_of_surjective (growthAssignment word)
    (growth_assignment_surjective word)

theorem growth_word_positive {n j : ℕ} (word : GrowthWord n j) (nonempty : 0 < n) :
    0 < j := by
  exact Nat.lt_of_le_of_lt (Nat.zero_le _) (growthAssignment word ⟨0, nonempty⟩).isLt

end
end C10Probability
