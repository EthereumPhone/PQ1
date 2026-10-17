import C10Probability.HypertreeSign
import C10Probability.ForestSign

/-! Complete structured C10 signing after R-grinding, following RawSigner.finish:
the actual shuffled forest followed by exactly two layers, with no assumption
equating a builder root to a reconstructed root. The4008-byte codec is separate. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

structure C10Signature where
  randomizer : Randomizer
  secrets : List Randomizer
  auths : List (List Randomizer)
  layers : List LayerSignature

def c10FinishOutput (randomizer : Randomizer) (forest : ForestOutput)
    (signed : HypertreeSigned) : Option C10Signature :=
  signed.map (fun result => ⟨randomizer, forest.secrets, forest.auths, result.1⟩)

def c10FinishProgram (encode : WotsQuery → K) (seed : ByteKey)
    (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) : QueryProgram K Digest (Option C10Signature) (2 * n + 435044) :=
  castProgram (by omega)
    (bindProgram (forestSignProgram encode seed (hypertreeIndex digest) digest shuffle)
      (fun forest => mapReturnProgram (c10FinishOutput randomizer forest)
        (hypertreeSignProgram encode seed shuffle n hb 2 0 (hypertreeIndex digest) forest.pk [])))

attribute [irreducible] c10FinishProgram

def c10Finish [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) : PMF (Option C10Signature × Memo K Digest) :=
  (forestSign encode table seed (hypertreeIndex digest) digest shuffle).bind
    (fun forest => (hypertreeSign encode seed shuffle n hb 2 0 (hypertreeIndex digest)
      forest.1.pk [] forest.2).map
        (fun signed => (c10FinishOutput randomizer forest.1 signed.1, signed.2)))

attribute [irreducible] c10Finish

theorem c10_finish_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) :
    evalProgram digestDraw (c10FinishProgram encode seed randomizer digest shuffle n hb) table =
      c10Finish encode table seed randomizer digest shuffle n hb := by
  simp only [c10FinishProgram, evalProgram_cast, evalProgram_bind, forest_sign_eval,
    evalProgram_mapReturn, hypertree_sign_eval, c10Finish]

theorem c10_finish_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) :
    mapProgram encode (c10FinishProgram labels seed randomizer digest shuffle n hb) =
      c10FinishProgram (encode ∘ labels) seed randomizer digest shuffle n hb := by
  simp only [c10FinishProgram, mapProgram_cast, mapProgram_bind, forest_sign_map,
    mapProgram_mapReturn, hypertree_sign_map]

theorem c10_finish_public (seed : ByteKey) (randomizer : Randomizer) (digest : Digest)
    (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    PublicBudget (c10FinishProgram id seed randomizer digest shuffle n hb) (2 * n + 364290) := by
  rw [c10FinishProgram, publicBudget_cast,
    show 2 * n + 364290 = 53386 + 2 * (n + 155452) by omega]
  apply publicBudget_bind _ _ 53386 (2 * (n + 155452)) (forest_sign_public _ _ _ _)
  intro forest
  rw [publicBudget_mapReturn]
  exact hypertree_sign_public _ _ _ _ _ _ _ _ _

theorem c10_finish_selected (secret : Digest) (seed : ByteKey)
    (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) (hs : seed.length = 32) :
    SelectedBudget nodeQuery (c10FinishProgram (privateKey prefixedPrivateInput secret)
      seed randomizer digest shuffle n hb) 435042 := by
  rw [c10FinishProgram, selectedBudget_cast]
  apply selectedBudget_bind _ _ _ 80022 (2 * 177510) (selectedBudget_total _ _)
  intro forest
  rw [selectedBudget_mapReturn]
  exact hypertree_sign_selected _ _ _ _ _ _ _ _ _ _ hs

end
end C10Probability
