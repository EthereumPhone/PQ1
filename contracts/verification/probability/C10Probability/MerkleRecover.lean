import C10Probability.MerkleInputs

/-! The nine directional authentication-path calls, preserving index/parent
updates, input ordering, default siblings, projected replies and the full cache. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

def recoveryInput (seed : ByteKey) (layer tree height index : ℕ)
    (auth : List Randomizer) (current : Randomizer) : ByteKey :=
  let sibling := (auth[height]?).getD 0
  let left := if index % 2 = 0 then current else sibling
  let right := if index % 2 = 0 then sibling else current
  merklePairInput seed layer tree height (index / 2) left right

def recoveryProgram (encode : ByteKey → K) (seed : ByteKey) (layer tree : ℕ)
    (auth : List Randomizer) : (steps height index : ℕ) → Randomizer → QueryProgram K Digest Randomizer steps
  | 0, _, _, current => .done current
  | steps + 1, height, index, current =>
      .query (encode (recoveryInput seed layer tree height index auth current)) (fun reply =>
        recoveryProgram encode seed layer tree auth steps (height + 1) (index / 2)
          (randomizerOfDigest reply))

def recoveryLoop [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey) (layer tree : ℕ)
    (auth : List Randomizer) : ℕ → ℕ → ℕ → Randomizer → Memo K Digest → PMF (Randomizer × Memo K Digest)
  | 0, _, _, current, table => PMF.pure (current, table)
  | steps + 1, height, index, current, table =>
      (memoQuery digestDraw table (encode (recoveryInput seed layer tree height index auth current))).bind
        (fun reply => recoveryLoop encode seed layer tree auth steps (height + 1) (index / 2)
          (randomizerOfDigest reply.1) reply.2)

theorem recovery_program_eval [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (layer tree : ℕ) (auth : List Randomizer) (steps height index : ℕ)
    (current : Randomizer) (table : Memo K Digest) :
    evalProgram digestDraw (recoveryProgram encode seed layer tree auth steps height index current) table =
      recoveryLoop encode seed layer tree auth steps height index current table := by
  induction steps generalizing height index current table with
  | zero => rfl
  | succ steps ih => simp only [recoveryProgram, evalProgram, ih, recoveryLoop]

theorem recovery_program_map (encode : K → L) (labels : ByteKey → K) (seed : ByteKey)
    (layer tree : ℕ) (auth : List Randomizer) (steps height index : ℕ) (current : Randomizer) :
    mapProgram encode (recoveryProgram labels seed layer tree auth steps height index current) =
      recoveryProgram (encode ∘ labels) seed layer tree auth steps height index current := by
  induction steps generalizing height index current with
  | zero => rfl
  | succ steps ih => simp only [recoveryProgram, mapProgram, ih, Function.comp_def]

def merkleRecoverProgram (encode : ByteKey → K) (seed : ByteKey) (layer tree : ℕ)
    (leaf : Randomizer) (index : ℕ) (auth : List Randomizer) : QueryProgram K Digest Randomizer 9 :=
  recoveryProgram encode seed layer tree auth 9 0 index leaf

def merkleRecover [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree : ℕ) (leaf : Randomizer) (index : ℕ)
    (auth : List Randomizer) : PMF (Randomizer × Memo K Digest) :=
  recoveryLoop encode seed layer tree auth 9 0 index leaf table

theorem merkle_recover_eval [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree : ℕ) (leaf : Randomizer) (index : ℕ) (auth : List Randomizer) :
    evalProgram digestDraw (merkleRecoverProgram encode seed layer tree leaf index auth) table =
      merkleRecover encode table seed layer tree leaf index auth := by
  exact recovery_program_eval _ _ _ _ _ _ _ _ _ _

theorem merkle_recover_map (encode : K → L) (labels : ByteKey → K) (seed : ByteKey)
    (layer tree : ℕ) (leaf : Randomizer) (index : ℕ) (auth : List Randomizer) :
    mapProgram encode (merkleRecoverProgram labels seed layer tree leaf index auth) =
      merkleRecoverProgram (encode ∘ labels) seed layer tree leaf index auth := by
  exact recovery_program_map _ _ _ _ _ _ _ _ _ _

theorem recovery_input_selected (seed : ByteKey) (layer tree height index : ℕ)
    (auth : List Randomizer) (current : Randomizer) (hs : seed.length = 32) :
    nodeQuery (recoveryInput seed layer tree height index auth current) = true := by
  exact merkle_pair_selected _ _ _ _ _ _ _ hs

def recoveryReadsBound (auth : List Randomizer) : ℕ → ℕ → Prop
  | 0, _ => True
  | steps + 1, height => height < auth.length ∧ recoveryReadsBound auth steps (height + 1)

theorem recovery_reads_bound (auth : List Randomizer) (steps height : ℕ)
    (hb : height + steps ≤ auth.length) : recoveryReadsBound auth steps height := by
  induction steps generalizing height with
  | zero => trivial
  | succ steps ih => exact ⟨by omega, ih (height + 1) (by omega)⟩

theorem merkle_recover_reads_bound (auth : List Randomizer) (ha : auth.length = 9) :
    recoveryReadsBound auth 9 0 := by
  exact recovery_reads_bound auth 9 0 (by omega)

end
end C10Probability
