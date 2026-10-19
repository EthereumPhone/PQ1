import C10Probability.C10FinishOpening
import C10Probability.QueryReplay

/-! The complete signer preserves R-grinding exhaustion and later WOTS
failure. A new opening is accompanied by a returned signature and a replayable
selected signing digest in the final memo table. -/
namespace C10Probability
noncomputable section

def c10SignAfterOpening (target : ForsTarget) (seed shuffle : ByteKey)
    (n : ℕ) (hn : n ≤ 2 ^ 32) (found : Option (ℕ × Randomizer × Digest)) :
    OpeningProgram WotsQuery ByteKey Digest Digest (Option C10Signature) (2 * n + 435045) :=
  match found with
  | none => .done none
  | some (_, randomizer, digest) => c10FinishOpening target seed randomizer digest shuffle n hn

def c10SignOpening (target : ForsTarget) (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    OpeningProgram WotsQuery ByteKey Digest Digest (Option C10Signature) (2 * m + 2 * n + 435045) :=
  castOpening (by omega)
    (bindOpening (liftOpening (randomizerUnderProgram id random message seed root m hm))
      (c10SignAfterOpening target seed shuffle n hn))

attribute [irreducible] c10SignOpening

theorem c10_sign_opening_refines (target : ForsTarget) (secret : Digest)
    (random message seed root shuffle : ByteKey) (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret id
      (c10SignOpening target random message seed root shuffle m n hm hn)
      (c10SignProgram id random message seed root shuffle m n hm hn) := by
  rw [c10SignOpening, c10SignProgram]
  apply opening_refines_cast
  apply opening_refines_bind digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret id id _ _ _ _
    (opening_refines_lift digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret _)
  intro found
  cases found with
  | none => exact opening_refines_done _ _ _ _ _ id none _ _
  | some value => exact c10_finish_opening_refines target secret seed value.2.1 value.2.2 shuffle n hn

theorem c10_sign_opening_avoids (target : ForsTarget) (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    OpeningAvoids (forsTargetKey target) (c10SignOpening target random message seed root shuffle m n hm hn) := by
  rw [c10SignOpening, opening_avoids_cast]
  apply opening_avoids_bind _ _ _ (opening_sealed_avoids _ _
    (query_exclusion_sealed _ _ (randomizer_fors_excluded target random message seed root m hm)))
  intro found
  cases found with
  | none => trivial
  | some value => exact c10_finish_opening_avoids target seed value.2.1 value.2.2 shuffle n hn

theorem c10_sign_opening_budget (target : ForsTarget) (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (c10SignOpening target random message seed root shuffle m n hm hn)) 408408 := by
  rw [c10SignOpening, redact_opening_cast, selectedBudget_cast]
  apply opening_selected_bind _ _ _ 0 408408
    (opening_lift_variable_budget _ _ (randomizer_variable_budget random message seed root m hm))
  intro found
  cases found with
  | none => trivial
  | some value => exact c10_finish_opening_budget target seed value.2.1 value.2.2 shuffle n hn

theorem c10_release_opened (secret : Digest) (randomizer : Randomizer)
    (forest : DeferredForestOutput) (signed : HypertreeSigned) (table : Memo WotsQuery Digest)
    (out : OpeningOutput WotsQuery Digest (Option C10Signature))
    (supported : out ∈ (evalOpening digestDraw nodeCommitEncode randomizerOfDigest secret
      (c10ReleaseOpening randomizer forest signed) table false).support) (opened : out.opened = true) :
    ∃ signature, out.value = some signature ∧ signature.randomizer = randomizer ∧ none ∈ forest.secrets := by
  cases signed with
  | none =>
    have equal : out = ⟨none, table, false⟩ := by simpa only [c10_release_failure_retains,
      PMF.mem_support_pure_iff] using supported
    simp only [equal, Bool.false_eq_true] at opened
  | some result =>
    by_cases selected : none ∈ forest.secrets
    · let signature : C10Signature := ⟨randomizer, (deferredForestOutput secret forest).secrets,
        forest.auths, result.1⟩
      have equal : out = ⟨some signature, table, true⟩ := by
        simpa only [c10ReleaseOpening, selected, ↓reduceIte, evalOpening,
          c10FinishOutput, Option.map_some, PMF.mem_support_pure_iff] using supported
      exact ⟨signature, congrArg OpeningOutput.value equal, rfl, selected⟩
    · have flag : out.opened = false := by
        have equal : out = ⟨c10FinishOutput randomizer (deferredForestOutput 0 forest)
            (some result), table, false⟩ := by
          simpa only [c10ReleaseOpening, selected, ↓reduceIte, evalOpening,
            PMF.mem_support_pure_iff] using supported
        exact congrArg OpeningOutput.opened equal
      simp only [flag, Bool.false_eq_true] at opened

theorem c10_finish_opened (target : ForsTarget) (secret : Digest) (seed : ByteKey)
    (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey) (n : ℕ) (hn : n ≤ 2 ^ 32)
    (table : Memo WotsQuery Digest) (out : OpeningOutput WotsQuery Digest (Option C10Signature))
    (supported : out ∈ (evalOpening digestDraw nodeCommitEncode randomizerOfDigest secret
      (c10FinishOpening target seed randomizer digest shuffle n hn) table false).support)
    (opened : out.opened = true) :
    ∃ signature, out.value = some signature ∧ signature.randomizer = randomizer ∧
      ForestSelected target (hypertreeIndex digest) digest := by
  rw [c10FinishOpening, eval_opening_cast, eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨forest, forestSupport, supported⟩ := supported
  have forestFlag := opening_sealed_flag digestDraw nodeCommitEncode randomizerOfDigest secret
    (forsTargetKey target) _ (forest_sign_opening_sealed target seed (hypertreeIndex digest) digest shuffle)
    table false forest forestSupport
  have marked := opening_post_support digestDraw nodeCommitEncode randomizerOfDigest secret _ _
    (forest_sign_opening_marked target seed (hypertreeIndex digest) digest shuffle)
    table false forest forestSupport
  rw [eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨signed, signedSupport, supported⟩ := supported
  have signedFlag := opening_sealed_flag digestDraw nodeCommitEncode randomizerOfDigest secret
    (forsTargetKey target) _ (query_exclusion_sealed _ _
      (hypertree_sign_fors_excluded target seed shuffle n hn 2 0 (hypertreeIndex digest) forest.value.pk []))
    forest.cache forest.opened signed signedSupport
  rw [signedFlag, forestFlag] at supported
  obtain ⟨signature, equal, randomizerEqual, selected⟩ :=
    c10_release_opened secret randomizer forest.value signed.value signed.cache out supported opened
  exact ⟨signature, equal, randomizerEqual, marked selected⟩

theorem c10_sign_opened (target : ForsTarget) (secret : Digest)
    (random message seed root shuffle : ByteKey) (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32)
    (table : Memo WotsQuery Digest) (out : OpeningOutput WotsQuery Digest (Option C10Signature))
    (supported : out ∈ (evalOpening digestDraw nodeCommitEncode randomizerOfDigest secret
      (c10SignOpening target random message seed root shuffle m n hm hn) table false).support)
    (opened : out.opened = true) :
    ∃ trial signature digest, out.value = some signature ∧
      replayProgram out.cache (randomizerUnderProgram id random message seed root m hm) =
        some (some (trial, signature.randomizer, digest)) ∧
      ForestSelected target (hypertreeIndex digest) digest := by
  rw [c10SignOpening, eval_opening_cast, eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨found, foundSupport, supported⟩ := supported
  rw [eval_opening_lift, PMF.mem_support_map_iff] at foundSupport
  obtain ⟨first, firstSupport, rfl⟩ := foundSupport
  have recorded := eval_program_replay digestDraw
    (randomizerUnderProgram id random message seed root m hm) table first firstSupport
  have extension : MemoExtends first.2 out.cache := by
    intro key value cached
    exact eval_opening_preserves digestDraw nodeCommitEncode randomizerOfDigest secret
      (c10SignAfterOpening target seed shuffle n hn first.1) first.2 false key value cached out supported
  have replayed := replay_program_extends (randomizerUnderProgram id random message seed root m hm)
    first.2 out.cache first.1 extension recorded
  cases foundValue : first.1 with
  | none =>
    have equal : out = ⟨none, first.2, false⟩ := by
      simpa only [foundValue, c10SignAfterOpening, evalOpening, PMF.mem_support_pure_iff] using supported
    simp only [equal, Bool.false_eq_true] at opened
  | some value =>
    rcases value with ⟨trial, randomizer, digest⟩
    rw [foundValue] at supported replayed
    obtain ⟨signature, equal, randomizerEqual, selected⟩ := c10_finish_opened target secret seed
      randomizer digest shuffle n hn first.2 out supported opened
    exact ⟨trial, signature, digest, equal, randomizerEqual ▸ replayed, selected⟩

end
end C10Probability
