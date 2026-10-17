import C10Probability.PathReplay
import C10Probability.ForsRecover

/-! Connect recorded reference paths to the actual recovery programs, including
their zero defaults for missing siblings. No new oracle calls are introduced. -/
namespace C10Probability
noncomputable section

variable {K N : Type*}

def pathSiblings (auth : List N) (fallback : N) : ℕ → ℕ → List N
  | 0, _ => []
  | steps + 1, height => (auth[height]?).getD fallback :: pathSiblings auth fallback steps (height + 1)

theorem path_siblings_length (auth : List N) (fallback : N) (steps height : ℕ) :
    (pathSiblings auth fallback steps height).length = steps := by
  induction steps generalizing height with
  | zero => rfl
  | succ steps ih => simp only [pathSiblings, List.length_cons, ih]

theorem path_siblings_cons_shift (first : N) (auth : List N) (fallback : N) (steps height : ℕ) :
    pathSiblings (first :: auth) fallback steps (height + 1) = pathSiblings auth fallback steps height := by
  induction steps generalizing height with
  | zero => rfl
  | succ steps ih => simp only [pathSiblings, List.getElem?_cons_succ, ih]

theorem path_siblings_full (auth : List N) (fallback : N) :
    pathSiblings auth fallback auth.length 0 = auth := by
  induction auth with
  | nil => rfl
  | cons first rest ih =>
      simp only [pathSiblings, List.getElem?_cons_zero,
        Option.getD_some, path_siblings_cons_shift, ih]

theorem recovery_program_replay_path (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree : ℕ) (auth : List Randomizer)
    (steps height index : ℕ) (current : Randomizer) :
    replayProgram table (recoveryProgram encode seed layer tree auth steps height index current) =
      replayPath table (fun h parent left right => encode (merklePairInput seed layer tree h parent left right))
        randomizerOfDigest height index current (pathSiblings auth 0 steps height) := by
  induction steps generalizing height index current with
  | zero => rfl
  | succ steps ih =>
    by_cases parity : index % 2 = 0 <;>
      simp only [recoveryProgram, replayProgram, replayPath, pathSiblings, recoveryInput,
        pathPairInput, parity, ↓reduceIte, ih]

theorem fors_recovery_program_replay_path (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree : ℕ) (auth : List Randomizer)
    (steps height index : ℕ) (current : Randomizer) :
    replayProgram table (forsRecoveryProgram encode seed ht tree auth steps height index current) =
      replayPath table (fun h parent left right => encode (forsPairInput seed ht tree h parent left right))
        randomizerOfDigest height index current (pathSiblings auth 0 steps height) := by
  induction steps generalizing height index current with
  | zero => rfl
  | succ steps ih =>
    by_cases parity : index % 2 = 0 <;>
      simp only [forsRecoveryProgram, replayProgram, replayPath, pathSiblings, forsRecoveryInput,
        pathPairInput, parity, ↓reduceIte, ih]

theorem replay_merkle_recover_reference (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree index : ℕ) (leaf root : Randomizer) (auth : List Randomizer)
    (length : auth.length = 9)
    (recorded : replayPath table
      (fun h parent left right => encode (merklePairInput seed layer tree h parent left right))
      randomizerOfDigest 0 index leaf auth = some root) :
    replayProgram table (merkleRecoverProgram encode seed layer tree leaf index auth) = some root := by
  rw [merkleRecoverProgram, recovery_program_replay_path, ← length, path_siblings_full]
  exact recorded

theorem replay_fors_recover_reference (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree index : ℕ) (secret root : Randomizer) (digest : Digest)
    (auth : List Randomizer) (length : auth.length = 11)
    (leaf : table (encode (forsLeafInput seed ht tree index secret)) = some digest)
    (recorded : replayPath table
      (fun h parent left right => encode (forsPairInput seed ht tree h parent left right))
      randomizerOfDigest 0 index (randomizerOfDigest digest) auth = some root) :
    replayProgram table (forsRecoverProgram encode seed ht tree index secret auth) = some root := by
  rw [forsRecoverProgram, replay_program_cached table _ _ digest leaf,
    fors_recovery_program_replay_path, ← length, path_siblings_full]
  exact recorded

end
end C10Probability
