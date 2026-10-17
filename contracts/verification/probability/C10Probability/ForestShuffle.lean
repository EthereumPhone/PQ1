import C10Probability.ShuffleDerive
import C10Probability.ForsInputs

/-! The forest actually derives its FORS sub-seed, queries all four shuffle
blocks, then visits positions11..1 with the same little-endian multiply-high
choice. Its12-position permutation is proved, not provided by the caller. -/
namespace C10Probability
noncomputable section

def forestTreeIndices : List (Fin 12) := List.ofFn id

theorem forest_tree_indices_length : forestTreeIndices.length = 12 := by
  simp [forestTreeIndices]

def forestShuffleSwap (order : List (Fin 12)) (i j : ℕ) : List (Fin 12) :=
  (order.set i ((order[j]?).getD 0)).set j ((order[i]?).getD 0)

theorem forest_shuffle_swap_length (order : List (Fin 12)) (i j : ℕ) :
    (forestShuffleSwap order i j).length = order.length := by simp [forestShuffleSwap]

theorem forest_shuffle_swap_perm (order : List (Fin 12)) (i j : ℕ)
    (hi : i < order.length) (hj : j < order.length) :
    (forestShuffleSwap order i j).Perm order := by
  simpa only [forestShuffleSwap, List.getElem?_eq_getElem hi,
    List.getElem?_eq_getElem hj, Option.getD_some] using List.set_set_perm hi hj

def forestShuffleLoop (stream : ByteKey) : ℕ → ℕ → List (Fin 12) → List (Fin 12)
  | 0, _, order => order
  | i + 1, pos, order => forestShuffleLoop stream i (pos + 2)
      (forestShuffleSwap order (i + 1) (shuffleChoice stream pos (i + 1)))

theorem forest_shuffle_loop_perm (stream : ByteKey) (i pos : ℕ) (order : List (Fin 12))
    (hi : i < order.length) : (forestShuffleLoop stream i pos order).Perm order := by
  induction i generalizing pos order with
  | zero => exact List.Perm.refl _
  | succ i ih =>
    have hj : shuffleChoice stream pos (i + 1) < order.length :=
      lt_of_le_of_lt (shuffle_choice_le _ _ _) hi
    exact (ih (pos + 2) _ (by rw [forest_shuffle_swap_length]; omega)).trans
      (forest_shuffle_swap_perm order (i + 1) _ hi hj)

abbrev ForestOrder := {order : List (Fin 12) // order.Perm forestTreeIndices}

def forestIdentityOrder : ForestOrder := ⟨forestTreeIndices, List.Perm.refl _⟩

def forestShuffleOrder (stream : ByteKey) : ForestOrder :=
  ⟨forestShuffleLoop stream 11 0 forestTreeIndices,
    forest_shuffle_loop_perm stream 11 0 forestTreeIndices
      (by rw [forest_tree_indices_length]; decide)⟩

theorem forest_order_length (order : ForestOrder) : order.val.length = 12 := by
  rw [order.property.length_eq, forest_tree_indices_length]

theorem forest_order_nodup (order : ForestOrder) : order.val.Nodup := by
  apply order.property.nodup_iff.mpr
  simp [forestTreeIndices]

theorem forest_order_mem (order : ForestOrder) (i : Fin 12) : i ∈ order.val := by
  apply order.property.mem_iff.mpr
  exact List.mem_ofFn.mpr ⟨i, rfl⟩

variable {K L : Type*}

theorem forest_shuffle_reads_bound [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (table : Memo K Digest) (out : ByteKey × Memo K Digest)
    (ho : out ∈ (shuffleBlocks encode seed 0 4 table).support) :
    shuffleReadsBound out.1 11 0 := by
  apply shuffle_reads_bound
  rw [shuffle_blocks_length encode seed 0 4 table out ho]
  decide

def forestPermutationProgram (encode : ByteKey → K) (seed : ByteKey) :
    QueryProgram K Digest ForestOrder 4 :=
  if seed = List.replicate 32 0 then .done forestIdentityOrder
  else mapReturnProgram forestShuffleOrder (shuffleBlocksProgram encode seed 0 4)

def forestPermutation [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (table : Memo K Digest) : PMF (ForestOrder × Memo K Digest) :=
  if seed = List.replicate 32 0 then PMF.pure (forestIdentityOrder, table)
  else (shuffleBlocks encode seed 0 4 table).map
    (fun out => (forestShuffleOrder out.1, out.2))

theorem forest_permutation_eval [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (table : Memo K Digest) :
    evalProgram digestDraw (forestPermutationProgram encode seed) table =
      forestPermutation encode seed table := by
  by_cases hz : seed = List.replicate 32 0 <;>
    simp only [forestPermutationProgram, forestPermutation, hz, ↓reduceIte,
      evalProgram, evalProgram_mapReturn, shuffle_blocks_eval]

theorem forest_permutation_map (encode : K → L) (labels : ByteKey → K) (seed : ByteKey) :
    mapProgram encode (forestPermutationProgram labels seed) =
      forestPermutationProgram (encode ∘ labels) seed := by
  by_cases hz : seed = List.replicate 32 0 <;>
    simp only [forestPermutationProgram, hz, ↓reduceIte, mapProgram,
      mapProgram_mapReturn, shuffle_blocks_map]

def forestShuffleProgram (encode : ByteKey → K) (seed : ByteKey) :
    QueryProgram K Digest ForestOrder 5 :=
  bindProgram (shuffleDeriveProgram encode seed forsTag) (forestPermutationProgram encode)

def forestShuffle [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (table : Memo K Digest) : PMF (ForestOrder × Memo K Digest) :=
  (shuffleDerive encode seed forsTag table).bind
    (fun out => forestPermutation encode out.1 out.2)

theorem forest_shuffle_eval [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (table : Memo K Digest) :
    evalProgram digestDraw (forestShuffleProgram encode seed) table =
      forestShuffle encode seed table := by
  simp only [forestShuffleProgram, evalProgram_bind, shuffle_derive_eval,
    forest_permutation_eval, forestShuffle]

theorem forest_shuffle_map (encode : K → L) (labels : ByteKey → K) (seed : ByteKey) :
    mapProgram encode (forestShuffleProgram labels seed) =
      forestShuffleProgram (encode ∘ labels) seed := by
  simp only [forestShuffleProgram, mapProgram_bind, shuffle_derive_map, forest_permutation_map]

theorem forest_shuffle_zero [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest) :
    forestShuffle encode (List.replicate 32 0) table = PMF.pure (forestIdentityOrder, table) := by
  simp only [forestShuffle, shuffle_derive_zero, PMF.pure_bind, forestPermutation, ↓reduceIte]

end
end C10Probability
