import C10Probability.LayerSigningReplay
import C10Probability.WotsPrefixComparison

/-! Successful WOTS calls at one address, message and trial budget return the
same count and positional values even when their shuffles differ. The shared
accepted word is derived from the actual bounded count program. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_wots_sign_values_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message firstShuffle secondShuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (first second : WotsSigma) (firstCount secondCount : ℕ)
    (one : replayProgram table (wotsSignProgram encode seed layer tree kp message firstShuffle n bound) =
      some (some (first, firstCount)))
    (two : replayProgram table (wotsSignProgram encode seed layer tree kp message secondShuffle n bound) =
      some (some (second, secondCount))) :
    firstCount = secondCount ∧ first = second := by
  obtain ⟨digest, counted, _, positions⟩ := replay_wots_sign_witness encode table seed
    layer tree kp message firstShuffle n bound first firstCount one
  obtain ⟨digest', counted', _, positions'⟩ := replay_wots_sign_witness encode table seed
    layer tree kp message secondShuffle n bound second secondCount two
  have pairEq := Option.some.inj
    (replay_program_unique _ table (some (firstCount, digest)) (some (secondCount, digest')) counted counted')
  have countEq : firstCount = secondCount := congrArg Prod.fst pairEq
  have digestEq : digest = digest' := congrArg Prod.snd pairEq
  subst digest'
  exact ⟨countEq, wots_same_word_prefixes_eq encode table seed layer tree kp
    (wotsOfDigest digest) first second positions positions'⟩

theorem replay_layer_sign_wots_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message : Randomizer)
    (firstShuffle secondShuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32)
    (first second : LayerSignature) (firstRoot secondRoot : Randomizer)
    (one : replayProgram table (layerSignProgram encode seed layer tree kp message firstShuffle n bound) =
      some (some (first, firstRoot)))
    (two : replayProgram table (layerSignProgram encode seed layer tree kp message secondShuffle n bound) =
      some (some (second, secondRoot))) :
    first.count = second.count ∧ first.sigma = second.sigma := by
  obtain ⟨_, shuffle, _, _, signed, _, _⟩ := replay_layer_sign_witness encode table seed
    layer tree kp message firstShuffle n bound first firstRoot one
  obtain ⟨_, shuffle', _, _, signed', _, _⟩ := replay_layer_sign_witness encode table seed
    layer tree kp message secondShuffle n bound second secondRoot two
  exact replay_wots_sign_values_eq encode table seed layer tree kp (nodeValueBytes message)
    shuffle shuffle' n bound first.sigma second.sigma first.count second.count signed signed'

theorem replay_layer_sign_result_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message : Randomizer)
    (firstShuffle secondShuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32)
    (first second : LayerSignature) (firstRoot secondRoot : Randomizer)
    (one : replayProgram table (layerSignProgram encode seed layer tree kp message firstShuffle n bound) =
      some (some (first, firstRoot)))
    (two : replayProgram table (layerSignProgram encode seed layer tree kp message secondShuffle n bound) =
      some (some (second, secondRoot))) :
    first = second ∧ firstRoot = secondRoot := by
  obtain ⟨countEq, sigmaEq⟩ := replay_layer_sign_wots_eq encode table seed layer tree kp message
    firstShuffle secondShuffle n bound first second firstRoot secondRoot one two
  obtain ⟨built, _, builtReplay, _, _, auth, recovered⟩ := replay_layer_sign_witness encode table seed
    layer tree kp message firstShuffle n bound first firstRoot one
  obtain ⟨built', _, builtReplay', _, _, auth', recovered'⟩ := replay_layer_sign_witness encode table seed
    layer tree kp message secondShuffle n bound second secondRoot two
  have builtEq := replay_program_unique _ table built built' builtReplay builtReplay'
  have authEq := auth.trans ((congrArg Prod.fst builtEq).trans auth'.symm)
  have sigEq : first = second := by
    cases first
    cases second
    simp_all only
  subst second
  exact ⟨rfl, replay_program_unique _ table firstRoot secondRoot recovered recovered'⟩

end
end C10Probability
