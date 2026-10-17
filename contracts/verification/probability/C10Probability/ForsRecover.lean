import C10Probability.ForsInputs
import C10Probability.MerkleRecover

/-! FORS recovery first hashes the supplied secret as a leaf, then executes
eleven ordered sibling queries. Defaults, index updates and final cache survive
the compilation; no honest-path or fresh-query assumption is required. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

def forsRecoveryInput (seed : ByteKey) (ht tree height index : ℕ)
    (auth : List Randomizer) (current : Randomizer) : ByteKey :=
  let sibling := (auth[height]?).getD 0
  let left := if index % 2 = 0 then current else sibling
  let right := if index % 2 = 0 then sibling else current
  forsPairInput seed ht tree height (index / 2) left right

def forsRecoveryProgram (encode : ByteKey → K) (seed : ByteKey) (ht tree : ℕ)
    (auth : List Randomizer) :
    (steps height index : ℕ) → Randomizer → QueryProgram K Digest Randomizer steps
  | 0, _, _, current => .done current
  | steps + 1, height, index, current =>
      .query (encode (forsRecoveryInput seed ht tree height index auth current)) (fun reply =>
        forsRecoveryProgram encode seed ht tree auth steps (height + 1) (index / 2)
          (randomizerOfDigest reply))

def forsRecoveryLoop [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey) (ht tree : ℕ)
    (auth : List Randomizer) :
    ℕ → ℕ → ℕ → Randomizer → Memo K Digest → PMF (Randomizer × Memo K Digest)
  | 0, _, _, current, table => PMF.pure (current, table)
  | steps + 1, height, index, current, table =>
      (memoQuery digestDraw table (encode (forsRecoveryInput seed ht tree height index auth current))).bind
        (fun reply => forsRecoveryLoop encode seed ht tree auth steps (height + 1) (index / 2)
          (randomizerOfDigest reply.1) reply.2)

theorem fors_recovery_program_eval [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (ht tree : ℕ) (auth : List Randomizer) (steps height index : ℕ)
    (current : Randomizer) (table : Memo K Digest) :
    evalProgram digestDraw (forsRecoveryProgram encode seed ht tree auth steps height index current) table =
      forsRecoveryLoop encode seed ht tree auth steps height index current table := by
  induction steps generalizing height index current table with
  | zero => rfl
  | succ steps ih => simp only [forsRecoveryProgram, evalProgram, ih, forsRecoveryLoop]

theorem fors_recovery_program_map (encode : K → L) (labels : ByteKey → K) (seed : ByteKey)
    (ht tree : ℕ) (auth : List Randomizer) (steps height index : ℕ) (current : Randomizer) :
    mapProgram encode (forsRecoveryProgram labels seed ht tree auth steps height index current) =
      forsRecoveryProgram (encode ∘ labels) seed ht tree auth steps height index current := by
  induction steps generalizing height index current with
  | zero => rfl
  | succ steps ih => simp only [forsRecoveryProgram, mapProgram, ih, Function.comp_def]

def forsRecoverProgram (encode : ByteKey → K) (seed : ByteKey) (ht tree target : ℕ)
    (secret : Randomizer) (auth : List Randomizer) : QueryProgram K Digest Randomizer 12 :=
  .query (encode (forsLeafInput seed ht tree target secret)) (fun reply =>
    forsRecoveryProgram encode seed ht tree auth 11 0 target (randomizerOfDigest reply))

def forsRecover [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) (secret : Randomizer) (auth : List Randomizer) :
    PMF (Randomizer × Memo K Digest) :=
  (memoQuery digestDraw table (encode (forsLeafInput seed ht tree target secret))).bind
    (fun reply => forsRecoveryLoop encode seed ht tree auth 11 0 target
      (randomizerOfDigest reply.1) reply.2)

theorem fors_recover_eval [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) (secret : Randomizer) (auth : List Randomizer) :
    evalProgram digestDraw (forsRecoverProgram encode seed ht tree target secret auth) table =
      forsRecover encode table seed ht tree target secret auth := by
  simp only [forsRecoverProgram, evalProgram, fors_recovery_program_eval, forsRecover]

theorem fors_recover_map (encode : K → L) (labels : ByteKey → K) (seed : ByteKey)
    (ht tree target : ℕ) (secret : Randomizer) (auth : List Randomizer) :
    mapProgram encode (forsRecoverProgram labels seed ht tree target secret auth) =
      forsRecoverProgram (encode ∘ labels) seed ht tree target secret auth := by
  simp only [forsRecoverProgram, mapProgram, fors_recovery_program_map, Function.comp_def]

theorem fors_recovery_input_selected (seed : ByteKey) (ht tree height index : ℕ)
    (auth : List Randomizer) (current : Randomizer) (hs : seed.length = 32) :
    nodeQuery (forsRecoveryInput seed ht tree height index auth current) = true := by
  exact fors_pair_input_selected _ _ _ _ _ _ _ hs

theorem fors_recover_reads_bound (auth : List Randomizer) (ha : auth.length = 11) :
    recoveryReadsBound auth 11 0 := by
  exact recovery_reads_bound auth 11 0 (by omega)

end
end C10Probability
