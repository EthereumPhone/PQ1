import C10Probability.WotsShuffle

/-! Actual full-digest shuffle sub-seed derivation. A zero input returns zero
without a query; a nonzero input uses the literal domain and complete label. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

def shuffleTag : ByteKey :=
  [115,112,104,105,110,99,115,45,99,49,48,45,115,104,117,102,102,108,101,45,118,49]

def shuffleDeriveInput (seed label : ByteKey) : ByteKey := shuffleTag ++ seed ++ label

theorem shuffle_derive_input_length (seed label : ByteKey) (hs : seed.length = 32) :
    (shuffleDeriveInput seed label).length = 54 + label.length := by
  simp [shuffleDeriveInput, shuffleTag, hs]
  omega

def shuffleDeriveProgram (encode : ByteKey → K) (seed label : ByteKey) :
    QueryProgram K Digest ByteKey 1 :=
  if seed = List.replicate 32 0 then .done (List.replicate 32 0)
  else .query (encode (shuffleDeriveInput seed label)) (fun reply => .done (secretBytes reply))

def shuffleDerive [DecidableEq K] (encode : ByteKey → K) (seed label : ByteKey)
    (table : Memo K Digest) : PMF (ByteKey × Memo K Digest) :=
  if seed = List.replicate 32 0 then PMF.pure (List.replicate 32 0, table)
  else (memoQuery digestDraw table (encode (shuffleDeriveInput seed label))).map
    (fun reply => (secretBytes reply.1, reply.2))

theorem shuffle_derive_eval [DecidableEq K] (encode : ByteKey → K) (seed label : ByteKey)
    (table : Memo K Digest) :
    evalProgram digestDraw (shuffleDeriveProgram encode seed label) table =
      shuffleDerive encode seed label table := by
  by_cases hz : seed = List.replicate 32 0 <;>
    simp only [shuffleDeriveProgram, shuffleDerive, hz, ↓reduceIte, evalProgram]
  rfl

theorem shuffle_derive_map (encode : K → L) (labels : ByteKey → K) (seed label : ByteKey) :
    mapProgram encode (shuffleDeriveProgram labels seed label) =
      shuffleDeriveProgram (encode ∘ labels) seed label := by
  by_cases hz : seed = List.replicate 32 0 <;>
    simp only [shuffleDeriveProgram, hz, ↓reduceIte, mapProgram, Function.comp_def]

theorem shuffle_derive_zero [DecidableEq K] (encode : ByteKey → K) (label : ByteKey)
    (table : Memo K Digest) :
    shuffleDerive encode (List.replicate 32 0) label table =
      PMF.pure (List.replicate 32 0, table) := by
  simp only [shuffleDerive, ↓reduceIte]

theorem shuffle_derive_length [DecidableEq K] (encode : ByteKey → K) (seed label : ByteKey)
    (table : Memo K Digest) (out : ByteKey × Memo K Digest)
    (ho : out ∈ (shuffleDerive encode seed label table).support) : out.1.length = 32 := by
  by_cases hz : seed = List.replicate 32 0
  · have he : out = (List.replicate 32 0, table) := by simpa [shuffleDerive, hz] using ho
    simp [he]
  · rw [shuffleDerive, if_neg hz, PMF.mem_support_map_iff] at ho
    obtain ⟨reply, _, rfl⟩ := ho
    simp [secretBytes]

end
end C10Probability
