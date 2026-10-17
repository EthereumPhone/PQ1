import C10Probability.C10Access
import C10Probability.C10Verify
import C10Probability.C10Keygen
import C10Probability.TreeCached
import C10Probability.ForestCached

/-! Inhabited complete cached executions, including successful signing and
verification, grinder/layer failure and all retained cache entries. These are
arbitrary-table witnesses, not fresh-oracle probabilities or honest correctness. -/
namespace C10Probability
noncomputable section

variable {K α R : Type*}

theorem eval_program_full_cache [DecidableEq K] (p : PMF α) {n : ℕ}
    (program : QueryProgram K α R n) (reply : α) :
    ∃ value, evalProgram p program (fun _ => some reply) = PMF.pure (value, fun _ => some reply) := by
  induction program with
  | done value => exact ⟨value, rfl⟩
  | query key next ih =>
    rw [evalProgram, memoQuery, PMF.pure_bind]
    exact ih reply

theorem layer_recover_full_cache [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (layer tree leaf : ℕ) (message : Randomizer) (sig : LayerSignature) (reply : Digest) :
    layerRecover encode (fun _ => some reply) seed layer tree leaf message sig =
      PMF.pure (randomizerOfDigest reply, fun _ => some reply) := by
  obtain ⟨pk, hpk⟩ := eval_program_full_cache digestDraw
    (wotsRecoveryUnderProgram encode seed layer tree leaf (nodeValueBytes message) sig.sigma sig.count) reply
  rw [wots_recovery_under_eval] at hpk
  rw [layerRecover, hpk, PMF.pure_bind, merkle_recover_cached]

theorem hypertree_recover_full_cache [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (signatures : List LayerSignature) (steps layer index : ℕ)
    (current : Randomizer) (reply : Digest) :
    hypertreeRecover encode seed signatures (steps + 1) layer index current (fun _ => some reply) =
      PMF.pure (randomizerOfDigest reply, fun _ => some reply) := by
  induction steps generalizing layer index current with
  | zero => simp only [hypertreeRecover, layer_recover_full_cache, PMF.pure_bind]
  | succ steps ih =>
    rw [hypertreeRecover, layer_recover_full_cache, PMF.pure_bind]
    exact ih _ _ _

theorem c10_verify_full_cache [DecidableEq K] (encode : ByteKey → K)
    (seed root message : ByteKey) (sig : C10Signature) (reply : Digest) :
    c10Verify encode (fun _ => some reply) seed root message sig =
      PMF.pure (forsAccept (forsOfDigest reply) && decide (nodeBlock (randomizerOfDigest reply) = root),
        fun _ => some reply) := by
  cases ha : forsAccept (forsOfDigest reply) <;>
    simp only [c10Verify, memoQuery, PMF.pure_bind, c10VerifyAfter, ha,
      Bool.false_eq_true, ↓reduceIte, forest_recover_cached, hypertree_recover_full_cache,
      PMF.pure_map, Bool.false_and, Bool.true_and]

theorem c10_keygen_full_cache [DecidableEq K] (encode : WotsQuery → K)
    (publicSeed reply : Digest) :
    c10Keygen encode (fun _ => some reply) publicSeed =
      PMF.pure ((nodeBlock (randomizerOfDigest publicSeed), nodeBlock (randomizerOfDigest reply)),
        fun _ => some reply) := by
  rw [c10Keygen, subtree_root_cached, PMF.pure_map]

theorem wots_sign_full_cache_accept [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (layer tree leaf : ℕ) (message shuffle : ByteKey) (reply : Digest)
    (accept : wotsAccept (wotsOfDigest reply) = true) :
    wotsSign encode (fun _ => some reply) seed layer tree leaf message shuffle 1 (by decide) =
      PMF.pure (some ((fun _ => randomizerOfDigest reply), 0), fun _ => some reply) := by
  have hn : ((counterSchedule (wotsCountStem seed layer tree leaf message) 0 1
      (by decide)).map (fun key => encode (.inl key))) ≠ [] := by
    intro he
    have hl := congrArg List.length he
    simp only [List.length_map, counter_schedule_length, List.length_nil] at hl
    omega
  obtain ⟨order, horder⟩ := eval_program_full_cache digestDraw
    (wotsShuffleProgram (fun key => encode (.inl key)) shuffle) reply
  rw [wots_shuffle_eval] at horder
  have hc := memoGrind_cached_accept
    ((counterSchedule (wotsCountStem seed layer tree leaf message) 0 1 (by decide)).map
      (fun key => encode (.inl key))) 0 reply (wotsAccept ∘ wotsOfDigest) hn
        (by simpa only [Function.comp_apply] using accept)
  rw [wotsSign, wotsCountUnder, hc,
    PMF.pure_bind, wotsSignAfter, horder, PMF.pure_bind, wots_fill_cached_complete, PMF.pure_map]

theorem layer_sign_full_cache_accept [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer) (shuffle : ByteKey)
    (reply : Digest) (accept : wotsAccept (wotsOfDigest reply) = true) :
    ∃ auth, layerSign encode (fun _ => some reply) seed layer tree leaf message shuffle 1 (by decide) =
      PMF.pure (some (⟨fun _ => randomizerOfDigest reply, 0, auth⟩, randomizerOfDigest reply),
        fun _ => some reply) := by
  obtain ⟨built, hbuilt⟩ := eval_program_full_cache digestDraw
    (merkleBuildProgram encode seed layer tree leaf) reply
  rw [merkle_build_eval] at hbuilt
  obtain ⟨subseed, hsubseed⟩ := eval_program_full_cache digestDraw
    (shuffleDeriveProgram (fun key => encode (.inl key)) shuffle (layerShuffleLabel layer)) reply
  rw [shuffle_derive_eval] at hsubseed
  refine ⟨built.1, ?_⟩
  rw [layerSign, hbuilt, PMF.pure_bind, hsubseed, PMF.pure_bind,
    wots_sign_full_cache_accept _ _ _ _ _ _ _ reply accept, PMF.pure_bind,
    layerSignAfter, layer_recover_full_cache, PMF.pure_map]

theorem hypertree_sign_full_cache_accept [DecidableEq K] (encode : WotsQuery → K)
    (seed shuffle : ByteKey) (steps layer index : ℕ) (current : Randomizer)
    (signatures : List LayerSignature) (reply : Digest)
    (accept : wotsAccept (wotsOfDigest reply) = true) :
    ∃ result, hypertreeSign encode seed shuffle 1 (by decide) steps layer index current signatures
      (fun _ => some reply) = PMF.pure (some result, fun _ => some reply) := by
  induction steps generalizing layer index current signatures with
  | zero => exact ⟨(signatures, current), rfl⟩
  | succ steps ih =>
    obtain ⟨auth, hauth⟩ := layer_sign_full_cache_accept encode seed layer
      (hypertreeParent index) (hypertreeLeaf index) current shuffle reply accept
    rw [hypertreeSign, hauth, PMF.pure_bind]
    exact ih _ _ _ _

theorem c10_finish_full_cache_accept [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (reply : Digest) (accept : wotsAccept (wotsOfDigest reply) = true) :
    ∃ sig, c10Finish encode (fun _ => some reply) seed randomizer digest shuffle 1 (by decide) =
      PMF.pure (some sig, fun _ => some reply) := by
  obtain ⟨forest, hforest⟩ := eval_program_full_cache digestDraw
    (forestSignProgram encode seed (hypertreeIndex digest) digest shuffle) reply
  rw [forest_sign_eval] at hforest
  obtain ⟨signed, hsigned⟩ := hypertree_sign_full_cache_accept encode seed shuffle 2 0
    (hypertreeIndex digest) forest.pk [] reply accept
  refine ⟨⟨randomizer, forest.secrets, forest.auths, signed.1⟩, ?_⟩
  rw [c10Finish, hforest, PMF.pure_bind, hsigned, PMF.pure_map]
  rfl

theorem c10_sign_full_cache_accept [DecidableEq K] (encode : WotsQuery → K)
    (random message seed root shuffle : ByteKey) :
    ∃ sig, c10Sign encode (fun _ => some recoveryAcceptedDigest) random message seed root shuffle
      1 1 (by decide) (by decide) = PMF.pure (some sig, fun _ => some recoveryAcceptedDigest) := by
  have ha : forsAccept (forsOfDigest recoveryAcceptedDigest) = true := by decide +kernel
  have hr : randomizerUnder encode (fun _ => some recoveryAcceptedDigest) random message seed root
      1 (by decide) = PMF.pure
        (some (0, randomizerOfDigest recoveryAcceptedDigest, recoveryAcceptedDigest),
          fun _ => some recoveryAcceptedDigest) := by
    simp [randomizerUnder, counterSchedule, derivedMemoGrind, memoQuery, PMF.pure_bind, ha]
  rw [c10Sign, hr, PMF.pure_bind, c10SignAfter]
  exact c10_finish_full_cache_accept _ _ _ _ _ _ recovery_digest_accepted

theorem layer_sign_full_cache_reject [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (hn : n ≤ 2 ^ 32) (reply : Digest)
    (reject : wotsAccept (wotsOfDigest reply) = false) :
    layerSign encode (fun _ => some reply) seed layer tree leaf message shuffle n hn =
      PMF.pure (none, fun _ => some reply) := by
  obtain ⟨built, hbuilt⟩ := eval_program_full_cache digestDraw
    (merkleBuildProgram encode seed layer tree leaf) reply
  rw [merkle_build_eval] at hbuilt
  obtain ⟨subseed, hsubseed⟩ := eval_program_full_cache digestDraw
    (shuffleDeriveProgram (fun key => encode (.inl key)) shuffle (layerShuffleLabel layer)) reply
  rw [shuffle_derive_eval] at hsubseed
  have hc := memoGrind_cached_reject
    ((counterSchedule (wotsCountStem seed layer tree leaf (nodeValueBytes message)) 0 n
      (by simpa using hn)).map (fun key => encode (.inl key))) 0 reply
      (wotsAccept ∘ wotsOfDigest) (by simpa only [Function.comp_apply] using reject)
  rw [layerSign, hbuilt, PMF.pure_bind, hsubseed, PMF.pure_bind, wotsSign, wotsCountUnder,
    hc,
    PMF.pure_bind, wotsSignAfter, PMF.pure_bind]
  rfl

theorem c10_finish_full_cache_reject [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (hn : n ≤ 2 ^ 32) (reply : Digest)
    (reject : wotsAccept (wotsOfDigest reply) = false) :
    c10Finish encode (fun _ => some reply) seed randomizer digest shuffle n hn =
      PMF.pure (none, fun _ => some reply) := by
  obtain ⟨forest, hforest⟩ := eval_program_full_cache digestDraw
    (forestSignProgram encode seed (hypertreeIndex digest) digest shuffle) reply
  rw [forest_sign_eval] at hforest
  rw [c10Finish, hforest, PMF.pure_bind, hypertreeSign,
    layer_sign_full_cache_reject _ _ _ _ _ _ _ _ _ reply reject, PMF.pure_bind, PMF.pure_map]
  rfl

end
end C10Probability
