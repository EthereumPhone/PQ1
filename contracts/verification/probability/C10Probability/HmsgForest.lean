import C10Probability.HmsgTrees

/-! All forest calls exclude H_msg. In particular, the final compression width
is derived from the twelve ordinary roots and the special thirteenth root. -/
namespace C10Probability
noncomputable section

theorem shuffle_derive_hmsg_excluded (seed label : ByteKey) (width : seed.length = 32)
    (labelWidth : label.length ≠ 106) :
    QueryExclusion hmsgQuery (fun out => out.length = 32)
      (shuffleDeriveProgram Sum.inl seed label) := by
  by_cases zero : seed = List.replicate 32 0
  · rw [shuffleDeriveProgram, if_pos zero]
    simp only [QueryExclusion, List.length_replicate]
  · rw [shuffleDeriveProgram, if_neg zero]
    refine ⟨?_, fun reply => ?_⟩
    · simp only [hmsgQuery, hmsgWidth, shuffle_derive_input_length _ _ width, decide_eq_false_iff_not]
      omega
    · simp only [QueryExclusion, secretBytes, List.length_ofFn]

theorem forest_shuffle_hmsg_excluded (seed : ByteKey) (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True) (forestShuffleProgram Sum.inl seed) := by
  rw [forestShuffleProgram]
  apply queryExclusion_bind hmsgQuery (fun out => out.length = 32) _ _ _
    (shuffle_derive_hmsg_excluded seed forsTag width (by decide))
  intro subseed subseedWidth
  by_cases zero : subseed = List.replicate 32 0
  · rw [forestPermutationProgram, if_pos zero]
    trivial
  · rw [forestPermutationProgram, if_neg zero, queryExclusion_mapReturn]
    exact shuffle_blocks_hmsg_excluded subseed 0 4 subseedWidth

theorem forest_fill_hmsg_excluded (seed : ByteKey) (ht : ℕ) (digest : Digest)
    (order : List (Fin 12)) (state : ForestState) (width : seed.length = 32)
    (roots : state.roots.length = 13) :
    QueryExclusion hmsgQuery (fun out => out.roots.length = 13)
      (forestFillProgram id seed ht digest order state) := by
  apply queryExclusion_stateFold
  · intro tree initial valid
    simpa only [forestFillStep, queryExclusion_mapReturn, Function.comp_def,
      forestWrite, List.length_set, valid] using
      forest_one_hmsg_excluded seed ht tree.val (forestIndex digest tree.val) width
  · exact roots

theorem forest_finish_hmsg_excluded (seed : ByteKey) (ht : ℕ) (state : ForestState)
    (width : seed.length = 32) (roots : state.roots.length = 13) :
    QueryExclusion hmsgQuery (fun _ => True) (forestFinishProgram id seed ht state) := by
  rw [forestFinishProgram]
  apply queryExclusion_bind hmsgQuery (fun _ => True) _ _ _
  · simp only [forsRootProgram, forsTreeProgram, queryExclusion_mapReturn]
    exact fors_tree_hmsg_excluded seed ht 12 _ _ width
  · intro last _
    refine ⟨?_, fun leaf => ⟨?_, fun _ => True.intro⟩⟩
    · simp only [id_eq, hmsgQuery, hmsgWidth, fors_leaf_input_length _ _ _ _ _ width]
      decide
    · simp only [id_eq, hmsgQuery, hmsgWidth,
        fors_pk_input_length seed ht (state.roots.set 12 (randomizerOfDigest leaf)) width
          (by simpa only [List.length_set] using roots)]
      decide

theorem forest_sign_hmsg_excluded (seed : ByteKey) (ht : ℕ) (digest : Digest)
    (shuffle : ByteKey) (width : seed.length = 32) (shuffleWidth : shuffle.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True) (forestSignProgram id seed ht digest shuffle) := by
  rw [forestSignProgram]
  apply queryExclusion_bind hmsgQuery (fun _ => True) _ _ _
    (forest_shuffle_hmsg_excluded shuffle shuffleWidth)
  intro order _
  apply queryExclusion_bind hmsgQuery (fun state => state.roots.length = 13) _ _ _
  · rw [forestOrderedProgram, queryExclusion_cast]
    exact forest_fill_hmsg_excluded seed ht digest order.val emptyForestState width (by simp [emptyForestState])
  · exact fun state roots => forest_finish_hmsg_excluded seed ht state width roots

theorem forest_recovery_loop_hmsg_excluded (seed : ByteKey) (ht : ℕ) (digest : Digest)
    (secrets : List Randomizer) (auths : List (List Randomizer))
    (indices : List (Fin 12)) (roots : List Randomizer) (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun out => out.length = roots.length + indices.length)
      (forestRecoveryProgram Sum.inl seed ht digest secrets auths indices roots) := by
  induction indices generalizing roots with
  | nil => simp only [forestRecoveryProgram, stateFoldProgram, QueryExclusion, List.length_nil, Nat.add_zero]
  | cons tree rest ih =>
    rw [forestRecoveryProgram, stateFoldProgram, queryExclusion_cast]
    apply queryExclusion_bind hmsgQuery (fun out => out.length = roots.length + 1) _ _ _
    · simpa only [forestRecoveryStep, queryExclusion_mapReturn, Function.comp_def,
        List.length_append, List.length_singleton] using
        fors_recover_hmsg_excluded seed ht tree.val (forestIndex digest tree.val)
          ((secrets[tree.val]?).getD 0) ((auths[tree.val]?).getD []) width
    · intro middle length
      simpa only [forestRecoveryProgram, length, List.length_cons,
        Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using ih middle

theorem forest_recover_hmsg_excluded (seed : ByteKey) (ht : ℕ) (digest : Digest)
    (secrets : List Randomizer) (auths : List (List Randomizer)) (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True)
      (forestRecoverProgram Sum.inl seed ht digest secrets auths) := by
  rw [forestRecoverProgram]
  apply queryExclusion_bind hmsgQuery (fun roots => roots.length = 12) _ _ _
  · rw [queryExclusion_cast]
    simpa only [List.length_nil, forest_tree_indices_length, Nat.zero_add] using
      forest_recovery_loop_hmsg_excluded seed ht digest secrets auths forestTreeIndices [] width
  · intro roots length
    refine ⟨?_, fun last => ⟨?_, fun _ => True.intro⟩⟩
    · simp only [hmsgQuery, hmsgWidth, fors_leaf_input_length _ _ _ _ _ width]
      decide
    · simp only [hmsgQuery, hmsgWidth,
        fors_pk_input_length seed ht (roots ++ [randomizerOfDigest last]) width (by simp [length])]
      decide

end
end C10Probability
