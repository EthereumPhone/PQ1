import C10Probability.C10Sign
import C10Probability.LayerAccess

/-! Caller sequencing and short-circuit equations. Premises name actual layer
executions and their complete resulting table; neither a failed layer nor a
zero budget rewinds previously performed work. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem hypertree_first_failure [DecidableEq K] (encode : WotsQuery → K)
    (seed shuffle : ByteKey) (n : ℕ) (hn : n ≤ 2 ^ 32) (index : ℕ) (current : Randomizer)
    (table failedTable : Memo K Digest)
    (failed : layerSign encode table seed 0 (hypertreeParent index) (hypertreeLeaf index)
      current shuffle n hn = PMF.pure (none, failedTable)) :
    hypertreeSign encode seed shuffle n hn 2 0 index current [] table =
      PMF.pure (none, failedTable) := by
  rw [hypertreeSign, failed, PMF.pure_bind]

theorem hypertree_second_failure [DecidableEq K] (encode : WotsQuery → K)
    (seed shuffle : ByteKey) (n : ℕ) (hn : n ≤ 2 ^ 32) (index : ℕ) (current firstRoot : Randomizer)
    (sig : LayerSignature) (table firstTable failedTable : Memo K Digest)
    (first : layerSign encode table seed 0 (hypertreeParent index) (hypertreeLeaf index)
      current shuffle n hn = PMF.pure (some (sig, firstRoot), firstTable))
    (second : layerSign encode firstTable seed 1 (hypertreeParent (hypertreeParent index))
      (hypertreeLeaf (hypertreeParent index)) firstRoot shuffle n hn = PMF.pure (none, failedTable)) :
    hypertreeSign encode seed shuffle n hn 2 0 index current [] table =
      PMF.pure (none, failedTable) := by
  simp only [hypertreeSign, first, second, PMF.pure_bind]

theorem hypertree_two_success [DecidableEq K] (encode : WotsQuery → K)
    (seed shuffle : ByteKey) (n : ℕ) (hn : n ≤ 2 ^ 32) (index : ℕ)
    (current firstRoot finalRoot : Randomizer) (firstSig secondSig : LayerSignature)
    (table firstTable finalTable : Memo K Digest)
    (first : layerSign encode table seed 0 (hypertreeParent index) (hypertreeLeaf index)
      current shuffle n hn = PMF.pure (some (firstSig, firstRoot), firstTable))
    (second : layerSign encode firstTable seed 1 (hypertreeParent (hypertreeParent index))
      (hypertreeLeaf (hypertreeParent index)) firstRoot shuffle n hn =
        PMF.pure (some (secondSig, finalRoot), finalTable)) :
    hypertreeSign encode seed shuffle n hn 2 0 index current [] table =
      PMF.pure (some ([firstSig, secondSig], finalRoot), finalTable) := by
  simp only [hypertreeSign, first, second, PMF.pure_bind]
  rfl

theorem c10_sign_r_failure [DecidableEq K] (encode : WotsQuery → K)
    (table failedTable : Memo K Digest) (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32)
    (failed : randomizerUnder encode table random message seed root m hm =
      PMF.pure (none, failedTable)) :
    c10Sign encode table random message seed root shuffle m n hm hn = PMF.pure (none, failedTable) := by
  rw [c10Sign, failed, PMF.pure_bind]
  rfl

theorem c10_finish_zero_wots_budget [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (randomizer : Randomizer) (digest : Digest)
    (shuffle : ByteKey) (hn : 0 ≤ 2 ^ 32) :
    c10Finish encode table seed randomizer digest shuffle 0 hn =
      (forestSign encode table seed (hypertreeIndex digest) digest shuffle).bind
        (fun forest => (merkleBuild encode forest.2 seed 0
          (hypertreeParent (hypertreeIndex digest)) (hypertreeLeaf (hypertreeIndex digest))).bind
          (fun built => (shuffleDerive (fun key => encode (.inl key)) shuffle
            (layerShuffleLabel 0) built.2).map (fun out => (none, out.2)))) := by
  simp only [c10Finish, hypertreeSign, layer_sign_zero_budget, PMF.bind_bind, PMF.bind_map,
    PMF.map_bind, Function.comp_apply, PMF.pure_map, c10FinishOutput, Option.map_none]
  rfl

end
end C10Probability
