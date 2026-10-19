import C10Probability.WotsForeignInputs
import C10Probability.HmsgForest

/-! Every ordinary forest call is separate from a selected WOTS incoming key.
The proof follows the actual tree, recovery, shuffle and compression programs;
no cache entry or duplicate query is removed. -/
namespace C10Probability
noncomputable section

set_option maxRecDepth 80000 in
theorem fors_tree_wots_cut_excluded {S : Type*} (seed : ByteKey)
    (target : WotsCutTarget) (previous : Randomizer) (ht tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    QueryExclusion (fun key => decide (key = wotsCutIncoming seed target previous))
      (fun _ => True) (forsTreeStateProgram id seed ht tree remember initial) := by
  rw [forsTreeStateProgram, queryExclusion_cast, queryExclusion_mapReturn]
  simp only [Function.comp_def, id_eq]
  let stack : ShapeStack Randomizer [] := PUnit.unit
  with_reducible refine (queryExclusion_tree _ 2
    (forsLeafProgram id seed ht tree) ?_
    (fun leaf h left right => Sum.inl (forsTreePairInput seed ht tree leaf h left right))
    randomizerOfDigest remember ?_ 2048 0 [] stack initial)
  · intro leaf
    refine ⟨decide_eq_false (fors_private_ne_wots_incoming seed target previous ht tree leaf),
      fun secret => ⟨?_, fun _ => True.intro⟩⟩
    exact decide_eq_false (fors_leaf_ne_wots_incoming seed target previous ht tree leaf _)
  · intro leaf h left right
    exact decide_eq_false (fors_pair_ne_wots_incoming seed target previous ht tree h
      (leaf / 2 ^ (h + 1)) left right)

theorem fors_recovery_wots_cut_excluded (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (ht tree : ℕ) (auth : List Randomizer)
    (steps height index : ℕ) (current : Randomizer) :
    QueryExclusion (fun key => decide (key = wotsCutIncoming seed target previous))
      (fun _ => True) (forsRecoveryProgram Sum.inl seed ht tree auth steps height index current) := by
  induction steps generalizing height index current with
  | zero => trivial
  | succ steps ih =>
    refine ⟨?_, fun _ => ih _ _ _⟩
    exact decide_eq_false (fors_pair_ne_wots_incoming seed target previous ht tree height
      (index / 2) _ _)

theorem fors_recover_wots_cut_excluded (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (ht tree leaf : ℕ) (secret : Randomizer) (auth : List Randomizer) :
    QueryExclusion (fun key => decide (key = wotsCutIncoming seed target previous))
      (fun _ => True) (forsRecoverProgram Sum.inl seed ht tree leaf secret auth) := by
  exact ⟨decide_eq_false (fors_leaf_ne_wots_incoming seed target previous ht tree leaf secret),
    fun _ => fors_recovery_wots_cut_excluded seed target previous ht tree auth 11 0 leaf _⟩

theorem forest_one_wots_cut_excluded (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (ht tree leaf : ℕ) :
    QueryExclusion (fun key => decide (key = wotsCutIncoming seed target previous))
      (fun _ => True) (forestOneProgram id seed ht tree leaf) := by
  rw [forestOneProgram]
  apply queryExclusion_bind _ (fun _ => True) _ _ _
  · rw [forsSignProgram]
    refine ⟨decide_eq_false (fors_private_ne_wots_incoming seed target previous ht tree leaf),
      fun _ => ?_⟩
    simp only [queryExclusion_mapReturn, forsTreeProgram]
    exact fors_tree_wots_cut_excluded seed target previous ht tree _ _
  · intro sig _
    rw [queryExclusion_mapReturn]
    exact fors_recover_wots_cut_excluded seed target previous ht tree leaf sig.1 sig.2

theorem forest_shuffle_wots_cut_excluded (seed shuffle : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (width : shuffle.length = 32) :
    QueryExclusion (fun key => decide (key = wotsCutIncoming seed target previous))
      (fun _ => True) (forestShuffleProgram Sum.inl shuffle) := by
  rw [forestShuffleProgram]
  apply queryExclusion_bind _ (fun out => out.length = 32) _ _ _
    (shuffle_derive_wots_cut_excluded seed shuffle forsTag target previous width (by decide))
  intro subseed subseedWidth
  by_cases zero : subseed = List.replicate 32 0
  · rw [forestPermutationProgram, if_pos zero]
    trivial
  · rw [forestPermutationProgram, if_neg zero, queryExclusion_mapReturn]
    exact wots_shuffle_blocks_cut_excluded seed subseed target previous subseedWidth 0 4

theorem forest_fill_wots_cut_excluded (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (ht : ℕ) (digest : Digest) (order : List (Fin 12))
    (state : ForestState) :
    QueryExclusion (fun key => decide (key = wotsCutIncoming seed target previous))
      (fun _ => True) (forestFillProgram id seed ht digest order state) := by
  apply queryExclusion_stateFold
  · intro tree initial _
    simpa only [forestFillStep, queryExclusion_mapReturn, Function.comp_def] using
      forest_one_wots_cut_excluded seed target previous ht tree.val (forestIndex digest tree.val)
  · trivial

theorem forest_finish_wots_cut_excluded (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (ht : ℕ) (state : ForestState) :
    QueryExclusion (fun key => decide (key = wotsCutIncoming seed target previous))
      (fun _ => True) (forestFinishProgram id seed ht state) := by
  rw [forestFinishProgram]
  apply queryExclusion_bind _ (fun _ => True) _ _ _
  · simp only [forsRootProgram, forsTreeProgram, queryExclusion_mapReturn]
    exact fors_tree_wots_cut_excluded seed target previous ht 12 _ _
  · intro last _
    refine ⟨decide_eq_false (fors_leaf_ne_wots_incoming seed target previous ht 12 0 last),
      fun leaf => ⟨?_, fun _ => True.intro⟩⟩
    exact decide_eq_false (fors_pk_ne_wots_incoming seed target previous ht _)

theorem forest_sign_wots_cut_excluded (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (ht : ℕ) (digest : Digest) (shuffle : ByteKey)
    (width : shuffle.length = 32) :
    QueryExclusion (fun key => decide (key = wotsCutIncoming seed target previous))
      (fun _ => True) (forestSignProgram id seed ht digest shuffle) := by
  rw [forestSignProgram]
  apply queryExclusion_bind _ (fun _ => True) _ _ _
    (forest_shuffle_wots_cut_excluded seed shuffle target previous width)
  intro order _
  apply queryExclusion_bind _ (fun _ => True) _ _ _
  · rw [forestOrderedProgram, queryExclusion_cast]
    exact forest_fill_wots_cut_excluded seed target previous ht digest order.val emptyForestState
  · exact fun state _ => forest_finish_wots_cut_excluded seed target previous ht state

theorem forest_sign_wots_cut_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (ht : ℕ) (digest : Digest) (shuffle : ByteKey)
    (width : shuffle.length = 32) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (liftOpening (P := Unit) (H := Digest) (forestSignProgram id seed ht digest shuffle)) := by
  exact query_exclusion_sealed _ _
    (forest_sign_wots_cut_excluded seed target previous ht digest shuffle width)

end
end C10Probability
