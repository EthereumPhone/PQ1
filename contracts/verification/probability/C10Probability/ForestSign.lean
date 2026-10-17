import C10Probability.ForestFill

/-! Complete manual forest signing, including shuffle sub-seed, all twelve
sign/recover pairs, the special last transmitted root, its separate leaf hash
and ordered thirteen-root compression. Counts are worst-case, including cache
hits; zero-seed shuffle branches may use fewer calls. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

structure ForestOutput where
  secrets : List Randomizer
  auths : List (List Randomizer)
  pk : Randomizer
  deriving DecidableEq

def forestLastProgram (encode : WotsQuery → K) (seed : ByteKey) (ht : ℕ)
    (state : ForestState) (last : Randomizer) : QueryProgram K Digest ForestOutput 2 :=
  .query (encode (.inl (forsLeafInput seed ht 12 0 last))) (fun leaf =>
    .query (encode (.inl (forsPkInput seed ht (state.roots.set 12 (randomizerOfDigest leaf)))))
      (fun reply => .done ⟨state.secrets.set 12 last, state.auths, randomizerOfDigest reply⟩))

def forestLast [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (state : ForestState) (last : Randomizer) :
    PMF (ForestOutput × Memo K Digest) :=
  (memoQuery digestDraw table (encode (.inl (forsLeafInput seed ht 12 0 last)))).bind
    (fun leaf => (memoQuery digestDraw leaf.2
      (encode (.inl (forsPkInput seed ht (state.roots.set 12 (randomizerOfDigest leaf.1)))))).map
        (fun reply => (⟨state.secrets.set 12 last, state.auths, randomizerOfDigest reply.1⟩,
          reply.2)))

theorem forest_last_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (state : ForestState) (last : Randomizer) :
    evalProgram digestDraw (forestLastProgram encode seed ht state last) table =
      forestLast encode table seed ht state last := by rfl

theorem forest_last_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (ht : ℕ) (state : ForestState) (last : Randomizer) :
    mapProgram encode (forestLastProgram labels seed ht state last) =
      forestLastProgram (encode ∘ labels) seed ht state last := by rfl

def forestFinishProgram (encode : WotsQuery → K) (seed : ByteKey) (ht : ℕ)
    (state : ForestState) : QueryProgram K Digest ForestOutput 6145 :=
  bindProgram (forsRootProgram encode seed ht 12) (forestLastProgram encode seed ht state)

def forestFinish [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (state : ForestState) : PMF (ForestOutput × Memo K Digest) :=
  (forsRoot encode table seed ht 12).bind
    (fun last => forestLast encode last.2 seed ht state last.1)

theorem forest_finish_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (state : ForestState) :
    evalProgram digestDraw (forestFinishProgram encode seed ht state) table =
      forestFinish encode table seed ht state := by
  simp only [forestFinishProgram, evalProgram_bind, fors_root_eval,
    forest_last_eval, forestFinish]

theorem forest_finish_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (ht : ℕ) (state : ForestState) :
    mapProgram encode (forestFinishProgram labels seed ht state) =
      forestFinishProgram (encode ∘ labels) seed ht state := by
  simp only [forestFinishProgram, mapProgram_bind, fors_root_map, forest_last_map]

theorem forest_finish_public (seed : ByteKey) (ht : ℕ) (state : ForestState) :
    PublicBudget (forestFinishProgram id seed ht state) 4097 := by
  exact publicBudget_bind _ _ 4095 2 (fors_root_public seed ht 12)
    (fun _ => publicBudget_total _)

def forestSignProgram (encode : WotsQuery → K) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (shuffle : ByteKey) : QueryProgram K Digest ForestOutput 80022 :=
  bindProgram (forestShuffleProgram (fun key => encode (.inl key)) shuffle) (fun order =>
    bindProgram (forestOrderedProgram encode seed ht digest order)
      (forestFinishProgram encode seed ht))

attribute [irreducible] forestSignProgram

def forestSign [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (shuffle : ByteKey) :
    PMF (ForestOutput × Memo K Digest) :=
  (forestShuffle (fun key => encode (.inl key)) shuffle table).bind (fun order =>
    (forestFillLoop encode seed ht digest order.1.val emptyForestState order.2).bind
      (fun filled => forestFinish encode filled.2 seed ht filled.1))

theorem forest_sign_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (shuffle : ByteKey) :
    evalProgram digestDraw (forestSignProgram encode seed ht digest shuffle) table =
      forestSign encode table seed ht digest shuffle := by
  simp only [forestSignProgram, evalProgram_bind, forest_shuffle_eval,
    forest_ordered_eval, forest_finish_eval, forestSign]

theorem forest_sign_map (encode : K → L) (labels : WotsQuery → K) (seed : ByteKey)
    (ht : ℕ) (digest : Digest) (shuffle : ByteKey) :
    mapProgram encode (forestSignProgram labels seed ht digest shuffle) =
      forestSignProgram (encode ∘ labels) seed ht digest shuffle := by
  simp only [forestSignProgram, mapProgram_bind, forest_shuffle_map,
    forest_ordered_map, forest_finish_map, Function.comp_def]

theorem forest_sign_public (seed : ByteKey) (ht : ℕ) (digest : Digest) (shuffle : ByteKey) :
    PublicBudget (forestSignProgram id seed ht digest shuffle) 53386 := by
  rw [forestSignProgram]
  exact publicBudget_bind _ _ 5 53381 (publicBudget_total _) (fun order =>
    publicBudget_bind _ _ 49284 4097 (forest_ordered_public seed ht digest order)
      (fun state => forest_finish_public seed ht state))

end
end C10Probability
