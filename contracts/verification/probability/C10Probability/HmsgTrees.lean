import C10Probability.HmsgWots
import C10Probability.C10Finish
import C10Probability.C10Verify

/-! Tree construction and recovery stay outside the public H_msg input width.
The proofs retain all private leaves, merge calls and malformed-path defaults. -/
namespace C10Probability
noncomputable section

set_option maxRecDepth 20000 in
theorem subtree_hmsg_excluded {S : Type*} (seed : ByteKey) (layer tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S)
    (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True) (subtreeProgram id seed layer tree remember initial) := by
  rw [subtreeProgram, queryExclusion_cast, queryExclusion_mapReturn]
  simp only [Function.comp_def, id_eq]
  let stack : ShapeStack Randomizer [] := PUnit.unit
  with_reducible refine (queryExclusion_tree hmsgQuery 345
    (wotsLeafProgram id seed layer tree) ?_
    (fun kp h left right => Sum.inl (treePairInput seed layer tree kp h left right))
    randomizerOfDigest remember ?_ 512 0 [] stack initial)
  · exact fun kp => wots_leaf_hmsg_excluded seed layer tree kp width
  · intro kp h left right
    simp only [hmsgQuery, hmsgWidth, treePairInput,
      merkle_pair_length _ _ _ _ _ _ _ width]
    decide

theorem recovery_hmsg_excluded (seed : ByteKey) (layer tree : ℕ) (auth : List Randomizer)
    (steps height index : ℕ) (current : Randomizer) (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True)
      (recoveryProgram Sum.inl seed layer tree auth steps height index current) := by
  induction steps generalizing height index current with
  | zero => trivial
  | succ steps ih =>
    refine ⟨?_, fun reply => ih _ _ _⟩
    simp only [hmsgQuery, hmsgWidth, recoveryInput, merkle_pair_length _ _ _ _ _ _ _ width]
    decide

theorem layer_recover_hmsg_excluded (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (sig : LayerSignature) (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True)
      (layerRecoverProgram Sum.inl seed layer tree leaf message sig) := by
  rw [layerRecoverProgram]
  apply queryExclusion_bind hmsgQuery (fun _ => True) _ _ _
  · refine ⟨?_, fun digest => ?_⟩
    · simp only [hmsgQuery, hmsgWidth,
        wots_recover_count_length _ _ _ _ _ _ width (node_value_bytes_length message)]
      decide
    · rw [queryExclusion_map]
      exact (wots_recovery_hmsg_excluded seed layer tree leaf (nodeValueBytes message)
        sig.sigma 0 width (node_value_bytes_length message)).2 digest
  · intro pk _
    exact recovery_hmsg_excluded seed layer tree sig.auth 9 0 leaf pk width

theorem hypertree_recover_hmsg_excluded (seed : ByteKey) (signatures : List LayerSignature)
    (steps layer index : ℕ) (current : Randomizer) (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True)
      (hypertreeRecoverProgram Sum.inl seed signatures steps layer index current) := by
  induction steps generalizing layer index current with
  | zero => rw [hypertreeRecoverProgram]; trivial
  | succ steps ih =>
    rw [hypertreeRecoverProgram, queryExclusion_cast]
    exact queryExclusion_bind hmsgQuery (fun _ => True) _ _ _
      (layer_recover_hmsg_excluded _ _ _ _ _ _ width) (fun _ _ => ih _ _ _)

set_option maxRecDepth 80000 in
theorem fors_tree_hmsg_excluded {S : Type*} (seed : ByteKey) (ht tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S)
    (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True)
      (forsTreeStateProgram id seed ht tree remember initial) := by
  rw [forsTreeStateProgram, queryExclusion_cast, queryExclusion_mapReturn]
  simp only [Function.comp_def, id_eq]
  let stack : ShapeStack Randomizer [] := PUnit.unit
  with_reducible refine (queryExclusion_tree hmsgQuery 2
    (forsLeafProgram id seed ht tree) ?_
    (fun leaf h left right => Sum.inl (forsTreePairInput seed ht tree leaf h left right))
    randomizerOfDigest remember ?_ 2048 0 [] stack initial)
  · intro leaf
    refine ⟨rfl, fun secret => ⟨?_, fun _ => True.intro⟩⟩
    simp only [id_eq, hmsgQuery, hmsgWidth, fors_leaf_input_length _ _ _ _ _ width]
    decide
  · intro leaf h left right
    simp only [hmsgQuery, hmsgWidth, forsTreePairInput,
      fors_pair_input_length _ _ _ _ _ _ _ width]
    decide

theorem fors_recovery_hmsg_excluded (seed : ByteKey) (ht tree : ℕ) (auth : List Randomizer)
    (steps height index : ℕ) (current : Randomizer) (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True)
      (forsRecoveryProgram Sum.inl seed ht tree auth steps height index current) := by
  induction steps generalizing height index current with
  | zero => trivial
  | succ steps ih =>
    refine ⟨?_, fun reply => ih _ _ _⟩
    simp only [hmsgQuery, hmsgWidth, forsRecoveryInput,
      fors_pair_input_length _ _ _ _ _ _ _ width]
    decide

theorem fors_recover_hmsg_excluded (seed : ByteKey) (ht tree target : ℕ)
    (secret : Randomizer) (auth : List Randomizer) (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True)
      (forsRecoverProgram Sum.inl seed ht tree target secret auth) := by
  refine ⟨?_, fun _ => fors_recovery_hmsg_excluded seed ht tree auth 11 0 target _ width⟩
  simp only [hmsgQuery, hmsgWidth, fors_leaf_input_length _ _ _ _ _ width]
  decide

theorem forest_one_hmsg_excluded (seed : ByteKey) (ht tree target : ℕ)
    (width : seed.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True) (forestOneProgram id seed ht tree target) := by
  rw [forestOneProgram]
  apply queryExclusion_bind hmsgQuery (fun _ => True) _ _ _
  · rw [forsSignProgram]
    refine ⟨rfl, fun _ => ?_⟩
    simp only [queryExclusion_mapReturn, forsTreeProgram]
    exact fors_tree_hmsg_excluded seed ht tree _ _ width
  · intro sig _
    rw [queryExclusion_mapReturn]
    exact fors_recover_hmsg_excluded seed ht tree target sig.1 sig.2 width

end
end C10Probability
