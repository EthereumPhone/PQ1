import C10Probability.RandomizerReplay
import C10Probability.ForestHonest
import C10Probability.HypertreeHonest
import C10Probability.C10SigningReplay
import C10Probability.C10Keygen
import C10Probability.C10Verify

/-! Whole structured C10 honest-signature correctness under the actual
key-generation result. Successful bounded signing is a premise about execution,
not a guarantee of success. Verification reuses the same consistent cache;
no hash injectivity, collision exclusion or fresh-grinder assumption is used. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_c10_honest_verification (encode : WotsQuery → K) (table : Memo K Digest)
    (publicSeed : Digest) (key : ByteKey × ByteKey) (random message shuffle : ByteKey)
    (m n : ℕ) (rBound : m ≤ 2 ^ 32) (wBound : n ≤ 2 ^ 32) (sig : C10Signature)
    (keygen : replayProgram table (c10KeygenProgram encode publicSeed) = some key)
    (signed : replayProgram table
      (c10SignProgram encode random message key.1 key.2 shuffle m n rBound wBound) = some (some sig)) :
    replayProgram table (c10VerifyProgram (fun input => encode (.inl input))
      key.1 key.2 message sig) = some true := by
  rw [c10KeygenProgram] at keygen
  obtain ⟨root, generated, keyValue⟩ := replay_program_map_witness table _ _ _ keygen
  subst key
  obtain ⟨trial, digest, forest, top, randomizer, forestSigned, secrets, auths, layers⟩ :=
    replay_c10_sign_witness encode table random message
      (nodeBlock (randomizerOfDigest publicSeed)) (nodeBlock root) shuffle m n rBound wBound sig signed
  obtain ⟨_, hmsg, accepted⟩ := replay_randomizer_under_success encode table random message
    (nodeBlock (randomizerOfDigest publicSeed)) (nodeBlock root) m rBound trial sig.randomizer digest randomizer
  have forestRecovery := replay_forest_sign_recovery encode table
    (nodeBlock (randomizerOfDigest publicSeed)) (hypertreeIndex digest) digest shuffle forest forestSigned
  have layerRecovery := replay_hypertree_sign_recovery encode table
    (nodeBlock (randomizerOfDigest publicSeed)) shuffle n wBound (hypertreeIndex digest)
    forest.pk top sig.layers layers
  have rootValue := replay_hypertree_sign_keygen_root encode table
    (nodeBlock (randomizerOfDigest publicSeed)) shuffle n wBound digest forest.pk top root
    sig.layers layers generated
  rw [c10VerifyProgram, replay_program_cached table _ _ digest hmsg,
    c10VerifyAfterProgram, if_pos accepted, replay_program_bind, secrets, auths,
    forestRecovery, Option.bind_some, replay_program_map_return, layerRecovery, Option.map_some]
  simp only [rootValue, decide_true]

theorem c10_honest_verification_support [DecidableEq K] (encode : WotsQuery → K)
    (initial : Memo K Digest) (publicSeed : Digest) (key : (ByteKey × ByteKey) × Memo K Digest)
    (random message shuffle : ByteKey) (m n : ℕ) (rBound : m ≤ 2 ^ 32) (wBound : n ≤ 2 ^ 32)
    (sig : C10Signature) (after : Memo K Digest)
    (keygen : key ∈ (c10Keygen encode initial publicSeed).support)
    (signed : (some sig, after) ∈
      (c10Sign encode key.2 random message key.1.1 key.1.2 shuffle m n rBound wBound).support) :
    c10Verify (fun input => encode (.inl input)) after key.1.1 key.1.2 message sig =
      PMF.pure (true, after) := by
  have keyReplay := eval_program_replay digestDraw (c10KeygenProgram encode publicSeed)
    initial key (by rwa [c10_keygen_eval])
  have signSupport : (some sig, after) ∈ (evalProgram digestDraw
      (c10SignProgram encode random message key.1.1 key.1.2 shuffle m n rBound wBound) key.2).support := by
    rwa [c10_sign_eval]
  have extension := eval_program_extends digestDraw _ key.2 (some sig, after) signSupport
  have laterKey := replay_program_extends _ key.2 after key.1 extension keyReplay
  have signReplay := eval_program_replay digestDraw _ key.2 (some sig, after) signSupport
  rw [← c10_verify_eval]
  exact replay_program_eval digestDraw _ after true
    (replay_c10_honest_verification encode after publicSeed key.1 random message shuffle
      m n rBound wBound sig laterKey signReplay)

theorem c10_honest_verification_extends [DecidableEq K] (encode : WotsQuery → K)
    (table later : Memo K Digest) (publicSeed : Digest) (key : ByteKey × ByteKey)
    (random message shuffle : ByteKey) (m n : ℕ) (rBound : m ≤ 2 ^ 32) (wBound : n ≤ 2 ^ 32)
    (sig : C10Signature)
    (keygen : replayProgram table (c10KeygenProgram encode publicSeed) = some key)
    (signed : replayProgram table
      (c10SignProgram encode random message key.1 key.2 shuffle m n rBound wBound) = some (some sig))
    (extension : MemoExtends table later) :
    c10Verify (fun input => encode (.inl input)) later key.1 key.2 message sig =
      PMF.pure (true, later) := by
  rw [← c10_verify_eval]
  exact replay_program_eval digestDraw _ later true
    (replay_program_extends _ table later true extension
      (replay_c10_honest_verification encode table publicSeed key random message shuffle
        m n rBound wBound sig keygen signed))

end
end C10Probability
