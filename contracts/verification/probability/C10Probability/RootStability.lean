import C10Probability.LayerHonest
import C10Probability.ForestRecords

/-! Actual successful builders and signers at one tree coordinate have the
same root in one consistent cache, even when selected paths and shuffles
differ. This is functional uniqueness, without a collision exclusion. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_merkle_build_roots_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree firstTarget secondTarget : ℕ)
    (first second : List Randomizer × Randomizer)
    (one : replayProgram table (merkleBuildProgram encode seed layer tree firstTarget) = some first)
    (two : replayProgram table (merkleBuildProgram encode seed layer tree secondTarget) = some second) :
    first.2 = second.2 := by
  exact recorded_tree_node_unique table _ _ randomizerOfDigest
    (replay_merkle_build_certificate encode table seed layer tree firstTarget first one)
    (replay_merkle_build_certificate encode table seed layer tree secondTarget second two)

theorem replay_layer_sign_roots_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree firstTarget secondTarget : ℕ)
    (firstMessage secondMessage : Randomizer) (firstShuffle secondShuffle : ByteKey)
    (firstTrials secondTrials : ℕ) (firstBound : firstTrials ≤ 2 ^ 32)
    (secondBound : secondTrials ≤ 2 ^ 32) (firstSig secondSig : LayerSignature)
    (firstRoot secondRoot : Randomizer)
    (one : replayProgram table (layerSignProgram encode seed layer tree firstTarget
      firstMessage firstShuffle firstTrials firstBound) = some (some (firstSig, firstRoot)))
    (two : replayProgram table (layerSignProgram encode seed layer tree secondTarget
      secondMessage secondShuffle secondTrials secondBound) = some (some (secondSig, secondRoot)))
    (firstValid : firstTarget < 512) (secondValid : secondTarget < 512) :
    firstRoot = secondRoot := by
  exact recorded_tree_node_unique table _ _ randomizerOfDigest
    (replay_layer_sign_correct encode table seed layer tree firstTarget firstMessage firstShuffle
      firstTrials firstBound firstSig firstRoot one firstValid).2.2.2
    (replay_layer_sign_correct encode table seed layer tree secondTarget secondMessage secondShuffle
      secondTrials secondBound secondSig secondRoot two secondValid).2.2.2

theorem replay_fors_tree_roots_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree firstTarget secondTarget : ℕ)
    (first second : Randomizer × List Randomizer)
    (one : replayProgram table (forsTreeProgram encode seed ht tree firstTarget) = some first)
    (two : replayProgram table (forsTreeProgram encode seed ht tree secondTarget) = some second) :
    first.1 = second.1 := by
  exact recorded_tree_node_unique table _ _ randomizerOfDigest
    (replay_fors_tree_certificate encode table seed ht tree firstTarget first one)
    (replay_fors_tree_certificate encode table seed ht tree secondTarget second two)

theorem replay_forest_one_roots_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree firstTarget secondTarget : ℕ)
    (first second : ForestTreeResult)
    (one : replayProgram table (forestOneProgram encode seed ht tree firstTarget) = some first)
    (two : replayProgram table (forestOneProgram encode seed ht tree secondTarget) = some second)
    (firstValid : firstTarget < 2048) (secondValid : secondTarget < 2048) :
    first.root = second.root := by
  exact replay_fors_tree_roots_eq encode table seed ht tree firstTarget secondTarget
    (first.root, first.auth) (second.root, second.auth)
    (replay_forest_one_builder encode table seed ht tree firstTarget first one firstValid).2
    (replay_forest_one_builder encode table seed ht tree secondTarget second two secondValid).2

end
end C10Probability
