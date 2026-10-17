import C10Probability.WotsPrivate

/-! The actual43-position Fisher-Yates computation and four ordered hash
blocks. The multiply-high selection is not claimed to be a uniform shuffle.
Zero seed skips every query. The128-byte stream retains all full digest bytes. -/
namespace C10Probability
noncomputable section

def fisherTag : ByteKey :=
  [115,112,104,105,110,99,115,45,99,49,48,45,102,105,115,104,101,114,45,121,97,116,101,115,45,118,49]

def shuffleBlockInput (seed : ByteKey) (block : ℕ) : ByteKey :=
  fisherTag ++ seed ++ beBytes 4 block

theorem shuffle_block_input_length (seed : ByteKey) (block : ℕ) (hs : seed.length = 32) :
    (shuffleBlockInput seed block).length = 63 := by
  simp [shuffleBlockInput, fisherTag, be_bytes_length, hs]

def shuffleChoice (stream : ByteKey) (pos i : ℕ) : ℕ :=
  (((stream[pos + 1]?).getD 0).val * 256 + ((stream[pos]?).getD 0).val) * (i + 1) / 65536

theorem shuffle_choice_le (stream : ByteKey) (pos i : ℕ) : shuffleChoice stream pos i ≤ i := by
  have hl := ((stream[pos]?).getD 0).isLt
  have hh := ((stream[pos + 1]?).getD 0).isLt
  have hb : ((stream[pos + 1]?).getD 0).val * 256 + ((stream[pos]?).getD 0).val < 65536 := by omega
  have hm := Nat.mul_lt_mul_of_pos_right hb (show 0 < i + 1 by omega)
  have hd : shuffleChoice stream pos i < i + 1 := by
    apply (Nat.div_lt_iff_lt_mul (by decide : 0 < 65536)).2
    simpa only [Nat.mul_comm] using hm
  omega

def shuffleSwap (order : List (Fin 43)) (i j : ℕ) : List (Fin 43) :=
  (order.set i ((order[j]?).getD 0)).set j ((order[i]?).getD 0)

theorem shuffle_swap_length (order : List (Fin 43)) (i j : ℕ) :
    (shuffleSwap order i j).length = order.length := by simp [shuffleSwap]

theorem shuffle_swap_perm (order : List (Fin 43)) (i j : ℕ)
    (hi : i < order.length) (hj : j < order.length) :
    (shuffleSwap order i j).Perm order := by
  simpa only [shuffleSwap, List.getElem?_eq_getElem hi,
    List.getElem?_eq_getElem hj, Option.getD_some] using List.set_set_perm hi hj

def shuffleLoop (stream : ByteKey) : ℕ → ℕ → List (Fin 43) → List (Fin 43)
  | 0, _, order => order
  | i + 1, pos, order => shuffleLoop stream i (pos + 2)
      (shuffleSwap order (i + 1) (shuffleChoice stream pos (i + 1)))

def shuffleReadsBound (stream : ByteKey) : ℕ → ℕ → Prop
  | 0, _ => True
  | i + 1, pos => pos + 1 < stream.length ∧ shuffleReadsBound stream i (pos + 2)

theorem shuffle_reads_bound (stream : ByteKey) (i pos : ℕ)
    (enough : pos + 2 * i ≤ stream.length) : shuffleReadsBound stream i pos := by
  induction i generalizing pos with
  | zero => trivial
  | succ i ih => exact ⟨by omega, ih (pos + 2) (by omega)⟩

theorem shuffle_loop_perm (stream : ByteKey) (i pos : ℕ) (order : List (Fin 43))
    (hi : i < order.length) : (shuffleLoop stream i pos order).Perm order := by
  induction i generalizing pos order with
  | zero => exact List.Perm.refl _
  | succ i ih =>
    have hj : shuffleChoice stream pos (i + 1) < order.length :=
      lt_of_le_of_lt (shuffle_choice_le _ _ _) hi
    exact (ih (pos + 2) _ (by rw [shuffle_swap_length]; omega)).trans
      (shuffle_swap_perm order (i + 1) _ hi hj)

abbrev WotsOrder := {order : List (Fin 43) // order.Perm wotsIndices}

def wotsIdentityOrder : WotsOrder := ⟨wotsIndices, List.Perm.refl _⟩

def wotsShuffleOrder (stream : ByteKey) : WotsOrder :=
  ⟨shuffleLoop stream 42 0 wotsIndices,
    shuffle_loop_perm stream 42 0 wotsIndices (by rw [wots_indices_length]; decide)⟩

theorem wots_order_length (order : WotsOrder) : order.val.length = 43 := by
  rw [order.property.length_eq, wots_indices_length]

theorem wots_order_nodup (order : WotsOrder) : order.val.Nodup := by
  apply order.property.nodup_iff.mpr
  simp [wotsIndices]

theorem wots_order_mem (order : WotsOrder) (i : Fin 43) : i ∈ order.val := by
  apply order.property.mem_iff.mpr
  exact List.mem_ofFn.mpr ⟨i, rfl⟩

variable {K L : Type*}

def shuffleBlocksProgram (encode : ByteKey → K) (seed : ByteKey) :
    (start n : ℕ) → QueryProgram K Digest ByteKey n
  | _, 0 => .done []
  | start, n + 1 => .query (encode (shuffleBlockInput seed start)) (fun digest =>
      mapReturnProgram (List.append (secretBytes digest))
        (shuffleBlocksProgram encode seed (start + 1) n))

def shuffleBlocks [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey) :
    ℕ → ℕ → Memo K Digest → PMF (ByteKey × Memo K Digest)
  | _, 0, table => PMF.pure ([], table)
  | start, n + 1, table =>
      (memoQuery digestDraw table (encode (shuffleBlockInput seed start))).bind (fun reply =>
        (shuffleBlocks encode seed (start + 1) n reply.2).map
          (fun out => (secretBytes reply.1 ++ out.1, out.2)))

theorem shuffle_blocks_eval [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (start n : ℕ) (table : Memo K Digest) :
    evalProgram digestDraw (shuffleBlocksProgram encode seed start n) table =
      shuffleBlocks encode seed start n table := by
  induction n generalizing start table with
  | zero => rfl
  | succ n ih =>
    simp only [shuffleBlocksProgram, evalProgram, evalProgram_mapReturn, ih, shuffleBlocks]
    rfl

theorem shuffle_blocks_map (encode : K → L) (labels : ByteKey → K) (seed : ByteKey)
    (start n : ℕ) :
    mapProgram encode (shuffleBlocksProgram labels seed start n) =
      shuffleBlocksProgram (encode ∘ labels) seed start n := by
  induction n generalizing start with
  | zero => rfl
  | succ n ih =>
    simp only [shuffleBlocksProgram, mapProgram, mapProgram_mapReturn, ih, Function.comp_def]

theorem shuffle_blocks_length [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (start n : ℕ) (table : Memo K Digest) (out : ByteKey × Memo K Digest)
    (ho : out ∈ (shuffleBlocks encode seed start n table).support) :
    out.1.length = 32 * n := by
  induction n generalizing start table out with
  | zero =>
    have he : out = ([], table) := by simpa [shuffleBlocks] using ho
    simp [he]
  | succ n ih =>
    rw [shuffleBlocks, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, _, ho⟩ := ho
    rw [PMF.mem_support_map_iff] at ho
    obtain ⟨later, hl, rfl⟩ := ho
    have h := ih (start + 1) reply.2 later hl
    simp only [List.length_append, secretBytes, List.length_ofFn, h]
    omega

theorem shuffle_blocks_reads_bound [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (table : Memo K Digest) (out : ByteKey × Memo K Digest)
    (ho : out ∈ (shuffleBlocks encode seed 0 4 table).support) :
    shuffleReadsBound out.1 42 0 := by
  apply shuffle_reads_bound
  rw [shuffle_blocks_length encode seed 0 4 table out ho]
  decide

def wotsShuffleProgram (encode : ByteKey → K) (seed : ByteKey) :
    QueryProgram K Digest WotsOrder 4 :=
  if seed = List.replicate 32 0 then .done wotsIdentityOrder
  else mapReturnProgram wotsShuffleOrder (shuffleBlocksProgram encode seed 0 4)

attribute [irreducible] wotsShuffleProgram

def wotsShuffle [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (table : Memo K Digest) : PMF (WotsOrder × Memo K Digest) :=
  if seed = List.replicate 32 0 then PMF.pure (wotsIdentityOrder, table)
  else (shuffleBlocks encode seed 0 4 table).map (fun out => (wotsShuffleOrder out.1, out.2))

theorem wots_shuffle_eval [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (table : Memo K Digest) :
    evalProgram digestDraw (wotsShuffleProgram encode seed) table =
      wotsShuffle encode seed table := by
  by_cases hz : seed = List.replicate 32 0 <;>
    simp only [wotsShuffleProgram, wotsShuffle, hz, ↓reduceIte, evalProgram,
      evalProgram_mapReturn, shuffle_blocks_eval]

theorem wots_shuffle_map (encode : K → L) (labels : ByteKey → K) (seed : ByteKey) :
    mapProgram encode (wotsShuffleProgram labels seed) =
      wotsShuffleProgram (encode ∘ labels) seed := by
  by_cases hz : seed = List.replicate 32 0 <;>
    simp only [wotsShuffleProgram, hz, ↓reduceIte, mapProgram,
      mapProgram_mapReturn, shuffle_blocks_map]

theorem wots_shuffle_zero [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest) :
    wotsShuffle encode (List.replicate 32 0) table = PMF.pure (wotsIdentityOrder, table) := by
  simp only [wotsShuffle, ↓reduceIte]

end
end C10Probability
