import C10Probability.PathBinding
import C10Probability.PathRecovery
import C10Probability.NodeInputBinding
import C10Probability.SelectedObserver

/-! Concrete path binding uses the already charged selected-node collision
predicate. The full cache remains available, including unselected entries.
Missing sibling defaults are included in comparisons of actual recovery. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def PublicNodeCollisionFree (encode : ByteKey → K) (table : Memo K Digest) : Prop :=
  CollisionFree randomizerOfDigest (selectedCache nodeQuery (fun key => table (encode key)))

theorem merkle_path_leaf_eq (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree : ℕ) (width : seed.length = 32)
    (free : PublicNodeCollisionFree encode table)
    (height index : ℕ) (first second root : Randomizer) (auth auth' : List Randomizer)
    (length : auth.length = auth'.length)
    (recorded : replayPath table (fun h p l r => encode (merklePairInput seed layer tree h p l r))
      randomizerOfDigest height index first auth = some root)
    (recorded' : replayPath table (fun h p l r => encode (merklePairInput seed layer tree h p l r))
      randomizerOfDigest height index second auth' = some root) : first = second := by
  apply replay_path_leaf_eq table _ randomizerOfDigest _ height index first second root auth auth'
    length recorded recorded'
  intro h p left right left' right' first second hf hs equal
  apply merkle_pair_children seed layer tree h p left right left' right'
  exact free _ _ first second
    (by simpa only [selectedCache, merkle_pair_selected _ _ _ _ _ _ _ width, ↓reduceIte] using hf)
    (by simpa only [selectedCache, merkle_pair_selected _ _ _ _ _ _ _ width, ↓reduceIte] using hs) equal

theorem fors_path_leaf_eq (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree : ℕ) (width : seed.length = 32)
    (free : PublicNodeCollisionFree encode table)
    (height index : ℕ) (first second root : Randomizer) (auth auth' : List Randomizer)
    (length : auth.length = auth'.length)
    (recorded : replayPath table (fun h p l r => encode (forsPairInput seed ht tree h p l r))
      randomizerOfDigest height index first auth = some root)
    (recorded' : replayPath table (fun h p l r => encode (forsPairInput seed ht tree h p l r))
      randomizerOfDigest height index second auth' = some root) : first = second := by
  apply replay_path_leaf_eq table _ randomizerOfDigest _ height index first second root auth auth'
    length recorded recorded'
  intro h p left right left' right' first second hf hs equal
  apply fors_pair_children seed ht tree h p left right left' right'
  exact free _ _ first second
    (by simpa only [selectedCache, fors_pair_input_selected _ _ _ _ _ _ _ width, ↓reduceIte] using hf)
    (by simpa only [selectedCache, fors_pair_input_selected _ _ _ _ _ _ _ width, ↓reduceIte] using hs) equal

theorem merkle_recover_leaf_eq (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree index : ℕ) (width : seed.length = 32)
    (free : PublicNodeCollisionFree encode table)
    (first second root : Randomizer) (auth auth' : List Randomizer)
    (recorded : replayProgram table (merkleRecoverProgram encode seed layer tree first index auth) = some root)
    (recorded' : replayProgram table (merkleRecoverProgram encode seed layer tree second index auth') = some root) :
    first = second := by
  rw [merkleRecoverProgram, recovery_program_replay_path] at recorded recorded'
  exact merkle_path_leaf_eq encode table seed layer tree width free 0 index first second root _ _
    (by rw [path_siblings_length, path_siblings_length]) recorded recorded'

theorem fors_recover_secret_eq (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree index : ℕ) (width : seed.length = 32)
    (free : PublicNodeCollisionFree encode table)
    (first second root : Randomizer) (auth auth' : List Randomizer)
    (recorded : replayProgram table (forsRecoverProgram encode seed ht tree index first auth) = some root)
    (recorded' : replayProgram table (forsRecoverProgram encode seed ht tree index second auth') = some root) :
    first = second := by
  unfold forsRecoverProgram at recorded recorded'
  cases hf : table (encode (forsLeafInput seed ht tree index first)) with
  | none => simp only [replayProgram, hf, Option.bind_none] at recorded; cases recorded
  | some firstDigest =>
    rw [replay_program_cached table _ _ firstDigest hf, fors_recovery_program_replay_path] at recorded
    cases hs : table (encode (forsLeafInput seed ht tree index second)) with
    | none => simp only [replayProgram, hs, Option.bind_none] at recorded'; cases recorded'
    | some secondDigest =>
      rw [replay_program_cached table _ _ secondDigest hs, fors_recovery_program_replay_path] at recorded'
      have equal := fors_path_leaf_eq encode table seed ht tree width free 0 index
        (randomizerOfDigest firstDigest) (randomizerOfDigest secondDigest) root _ _
        (by rw [path_siblings_length, path_siblings_length]) recorded recorded'
      apply fors_leaf_input_injective seed ht tree index
      exact free _ _ firstDigest secondDigest
        (by simpa only [selectedCache, fors_leaf_input_selected _ _ _ _ _ width, ↓reduceIte] using hf)
        (by simpa only [selectedCache, fors_leaf_input_selected _ _ _ _ _ width, ↓reduceIte] using hs) equal

theorem merkle_recover_leaf_or_collision (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree index : ℕ) (width : seed.length = 32)
    (first second root : Randomizer) (auth auth' : List Randomizer)
    (recorded : replayProgram table (merkleRecoverProgram encode seed layer tree first index auth) = some root)
    (recorded' : replayProgram table (merkleRecoverProgram encode seed layer tree second index auth') = some root) :
    first = second ∨ ¬ PublicNodeCollisionFree encode table := by
  by_cases free : PublicNodeCollisionFree encode table
  · exact Or.inl (merkle_recover_leaf_eq encode table seed layer tree index width free
      first second root auth auth' recorded recorded')
  · exact Or.inr free

theorem fors_recover_secret_or_collision (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree index : ℕ) (width : seed.length = 32)
    (first second root : Randomizer) (auth auth' : List Randomizer)
    (recorded : replayProgram table (forsRecoverProgram encode seed ht tree index first auth) = some root)
    (recorded' : replayProgram table (forsRecoverProgram encode seed ht tree index second auth') = some root) :
    first = second ∨ ¬ PublicNodeCollisionFree encode table := by
  by_cases free : PublicNodeCollisionFree encode table
  · exact Or.inl (fors_recover_secret_eq encode table seed ht tree index width free
      first second root auth auth' recorded recorded')
  · exact Or.inr free

end
end C10Probability
