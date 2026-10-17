import C10Probability.WotsPrivate

/-! Complete WOTS key-generation leaf:43 private derivations, seven public
steps each and ordered compression. No independent-chain premise is used. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K L : Type*}

def wotsZeroSigma : WotsSigma := fun _ => 0

theorem wots_leaf_fill_cost : collectionSteps (fun _ : Fin 43 => 7 + 1) wotsIndices = 344 := by
  simp [collectionSteps, wotsIndices]

theorem wots_leaf_public_cost : collectionSteps (fun _ : Fin 43 => 7) wotsIndices = 301 := by
  simp [collectionSteps, wotsIndices]

def wotsLeafFillProgram (encode : WotsQuery → K) (seed : ByteKey) (layer tree kp : ℕ) :
    QueryProgram K Digest WotsSigma 344 :=
  castProgram wots_leaf_fill_cost
    (wotsFillProgram encode seed layer tree kp (fun _ => 7) wotsIndices wotsZeroSigma)

attribute [irreducible] wotsLeafFillProgram

theorem wots_leaf_fill_eval [DecidableEq K] (encode : WotsQuery → K) (seed : ByteKey)
    (layer tree kp : ℕ) (table : Memo K Digest) :
    evalProgram digestDraw (wotsLeafFillProgram encode seed layer tree kp) table =
      wotsFillLoop encode seed layer tree kp (fun _ => 7) wotsIndices wotsZeroSigma table := by
  rw [wotsLeafFillProgram, evalProgram_cast, wots_fill_eval]

theorem wots_leaf_fill_public (seed : ByteKey) (layer tree kp : ℕ) :
    PublicBudget (wotsLeafFillProgram id seed layer tree kp) 301 := by
  rw [wotsLeafFillProgram, publicBudget_cast, ← wots_leaf_public_cost]
  exact wots_fill_public seed layer tree kp _ _ _

def wotsLeafProgram (encode : WotsQuery → K) (seed : ByteKey) (layer tree kp : ℕ) :
    QueryProgram K Digest Randomizer 345 :=
  bindProgram (wotsLeafFillProgram encode seed layer tree kp) (fun sigma =>
    .query (encode (.inl (wotsPkInput seed layer tree kp (List.ofFn sigma))))
      (fun digest => .done (randomizerOfDigest digest)))

def wotsLeaf [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) : PMF (Randomizer × Memo K Digest) :=
  (wotsFillLoop encode seed layer tree kp (fun _ => 7) wotsIndices wotsZeroSigma table).bind
    (fun out => (memoQuery digestDraw out.2
      (encode (.inl (wotsPkInput seed layer tree kp (List.ofFn out.1))))).map
        (fun reply => (randomizerOfDigest reply.1, reply.2)))

theorem wots_leaf_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) :
    evalProgram digestDraw (wotsLeafProgram encode seed layer tree kp) table =
      wotsLeaf encode table seed layer tree kp := by
  rw [wotsLeafProgram, evalProgram_bind, wots_leaf_fill_eval]
  rfl

theorem wots_leaf_public (seed : ByteKey) (layer tree kp : ℕ) :
    PublicBudget (wotsLeafProgram id seed layer tree kp) 302 := by
  exact publicBudget_bind _ _ 301 1 (wots_leaf_fill_public seed layer tree kp)
    (fun _ => publicBudget_total _)

theorem wots_leaf_map (encode : K → L) (labels : WotsQuery → K) (seed : ByteKey)
    (layer tree kp : ℕ) :
    mapProgram encode (wotsLeafProgram labels seed layer tree kp) =
      wotsLeafProgram (encode ∘ labels) seed layer tree kp := by
  simp only [wotsLeafProgram, mapProgram_bind, wotsLeafFillProgram,
    mapProgram_cast, wots_fill_map, mapProgram, Function.comp_def]

theorem wots_leaf_prefix_error (seed : ByteKey) (layer tree kp : ℕ)
    (event : Set Randomizer) :
    |((privateShared digestDraw digestDraw prefixedPrivateInput
        (PMF.pure (wotsLeafProgram id seed layer tree kp))).toOuterMeasure event).toReal -
      ((privateIndependent digestDraw
        (PMF.pure (wotsLeafProgram id seed layer tree kp))).toOuterMeasure event).toReal| ≤
      (302 : ℝ) / 2 ^ 256 := by
  apply private_secret_event_error_real _ 302
  intro program hp
  have he : program = wotsLeafProgram id seed layer tree kp := by simpa using hp
  rw [he]
  exact wots_leaf_public seed layer tree kp

theorem wots_leaf_physical_eval (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (layer tree kp : ℕ) :
    evalProgram digestDraw
      (mapProgram (privateKey prefixedPrivateInput secret)
        (wotsLeafProgram id seed layer tree kp)) table =
      wotsLeaf (privateKey prefixedPrivateInput secret) table seed layer tree kp := by
  rw [wots_leaf_map]
  exact wots_leaf_eval _ _ _ _ _ _

theorem wots_leaf_raw_trace (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (out : TraceOutput ByteKey Digest Randomizer)
    (ho : out ∈ (traceProgram digestDraw
      (wotsLeafProgram (privateKey prefixedPrivateInput secret) seed layer tree kp) table).support) :
    out.queries.length ≤ 345 := by
  exact traceProgram_length _ _ _ _ ho

end
end C10Probability
