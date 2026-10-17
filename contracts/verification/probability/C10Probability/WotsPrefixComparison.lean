import C10Probability.WotsChainBinding

/-! Constant-sum accepted words are incomparable unless equal. Applying this
to actual chain prefixes yields an earlier position relative to a returned
signature. An earlier position is not asserted to be unknown to the client. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem wots_accepted_word_eq_or_lower (first second : WotsWord)
    (accepted : wotsAccept first = true) (accepted' : wotsAccept second = true) :
    first = second ∨ ∃ i, (first i).val < (second i).val := by
  classical
  by_cases lower : ∃ i, (first i).val < (second i).val
  · exact Or.inr lower
  · left
    have le : ∀ i, (second i).val ≤ (first i).val := by
      intro i
      exact Nat.le_of_not_gt (fun h => lower ⟨i, h⟩)
    have hs : (∑ i, (first i).val) = 205 := by
      simpa only [wotsAccept, decide_eq_true_eq] using accepted
    have hs' : (∑ i, (second i).val) = 205 := by
      simpa only [wotsAccept, decide_eq_true_eq] using accepted'
    have equal := (Finset.sum_eq_sum_iff_of_le (fun i (_ : i ∈ Finset.univ) => le i)).mp
      (hs'.trans hs.symm)
    funext i
    exact Fin.ext ((equal i (Finset.mem_univ i)).symm)

theorem wots_accepted_word_proper_cut (word : WotsWord) (accepted : wotsAccept word = true) :
    ∃ i, (word i).val < 7 := by
  have hs : (∑ i, (word i).val) = 205 := by
    simpa only [wotsAccept, decide_eq_true_eq] using accepted
  have less : (∑ i, (word i).val) < ∑ _i : Fin 43, (7 : ℕ) := by
    rw [hs]
    norm_num
  obtain ⟨i, _, hi⟩ := Finset.exists_lt_of_sum_lt less
  exact ⟨i, hi⟩

theorem wots_same_word_prefixes_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (word : WotsWord) (first second : WotsSigma)
    (recorded : ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val
      (word i).val) = some (first i))
    (recorded' : ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val
      (word i).val) = some (second i)) : first = second := by
  funext i
  exact replay_program_unique _ table (first i) (second i) (recorded i) (recorded' i)

theorem replay_wots_seed_chain_between (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp index first later : ℕ) (early late : Randomizer)
    (bound : first ≤ later)
    (recorded : replayProgram table
      (wotsSeedChainProgram encode seed layer tree kp index first) = some early)
    (recorded' : replayProgram table
      (wotsSeedChainProgram encode seed layer tree kp index later) = some late) :
    replayProgram table (chainProgram (fun position value => encode (.inl
      (wotsChainInput seed layer tree kp index position value))) randomizerOfDigest
      first (later - first) early) = some late := by
  obtain ⟨middle, hp, suffix⟩ := replay_wots_seed_chain_cut encode table seed
    layer tree kp index later first late bound recorded'
  have equal := replay_program_unique _ table middle early hp recorded
  exact equal ▸ suffix

theorem wots_accepted_prefix_comparison (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (word priorWord : WotsWord) (sigma prior : WotsSigma)
    (accepted : wotsAccept word = true) (accepted' : wotsAccept priorWord = true)
    (recorded : ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val
      (word i).val) = some (sigma i))
    (recorded' : ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val
      (priorWord i).val) = some (prior i)) :
    (word = priorWord ∧ sigma = prior) ∨
      ∃ i, (word i).val < (priorWord i).val ∧
        replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val
          (word i).val) = some (sigma i) ∧
        replayProgram table (chainProgram (fun position value => encode (.inl
          (wotsChainInput seed layer tree kp i.val position value))) randomizerOfDigest
          (word i).val ((priorWord i).val - (word i).val) (sigma i)) = some (prior i) := by
  rcases wots_accepted_word_eq_or_lower word priorWord accepted accepted' with same | ⟨i, lower⟩
  · subst priorWord
    exact Or.inl ⟨rfl, wots_same_word_prefixes_eq encode table seed layer tree kp word
      sigma prior recorded recorded'⟩
  · exact Or.inr ⟨i, lower, recorded i, replay_wots_seed_chain_between encode table seed
      layer tree kp i.val (word i).val (priorWord i).val (sigma i) (prior i)
      (Nat.le_of_lt lower) (recorded i) (recorded' i)⟩

end
end C10Probability
