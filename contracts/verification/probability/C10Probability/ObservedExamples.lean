import C10Probability.ObservedBranches
import C10Probability.ObservedOutput
import C10Probability.SessionExamples

/-! Concrete passive-history checks. Constant populated tables witness branch
behavior only; they do not establish a probability in an empty-table game. -/
namespace C10Probability
noncomputable section

theorem replay_repeat_example :
    replayProgram (fun _ : ℕ => some (7 : ℕ))
      (.query 1 (fun first => .query 1 (fun second => .done (first, second))) :
        QueryProgram ℕ ℕ (ℕ × ℕ) 2) = some (7, 7) := rfl

theorem replay_missing_example :
    replayProgram (fun _ : ℕ => (none : Option ℕ))
      (.query 1 (fun reply => .done reply) : QueryProgram ℕ ℕ ℕ 1) = none := rfl

theorem replay_overwrite_not_extension :
    ¬ MemoExtends (fun _ : ℕ => some (7 : ℕ)) (fun _ => some 8) := by
  intro h
  have impossible := h 0 7 rfl
  cases impossible

theorem observed_hash_cap_default (table : Memo WotsQuery Digest) :
    c10ObservedSession id sessionExampleConfig
      (.hash [7] (fun reply => .done reply) : C10Client Digest 1)
      0 4 emptySessionLedger table =
        PMF.pure (⟨⟨0, emptySessionLedger, 0, 4⟩, [], []⟩, table) := rfl

theorem observed_sign_cap_default (table : Memo WotsQuery Digest) :
    c10ObservedSession id sessionExampleConfig
      (.sign sessionExampleRequest (fun reply => .done reply.isNone) : C10Client Bool 1)
      3 0 emptySessionLedger table =
        PMF.pure (⟨⟨true, emptySessionLedger, 3, 0⟩, [], []⟩, table) := rfl

theorem observed_bad_request_keeps_cap (table : Memo WotsQuery Digest) :
    c10ObservedSession id sessionExampleConfig
      (.sign ⟨[], [], []⟩ (fun reply => .done reply.isNone) : C10Client Bool 1)
      3 2 emptySessionLedger table =
        PMF.pure (⟨⟨true, emptySessionLedger, 3, 2⟩, [], []⟩, table) := by
  rw [c10_observed_sign_refused _ _ _ _ _ _ _ _ (by decide +kernel)]
  rfl

theorem observed_repeated_hash (cfg : C10SessionConfig) (key : ByteKey) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo WotsQuery Digest) :
    c10ObservedSession id cfg
      (.hash key (fun first => .hash key (fun second => .done (first, second))) :
        C10Client (Digest × Digest) 2) (qr + 2) qs ledger table =
      (memoQuery digestDraw table (.inl key)).map
        (fun reply => (⟨⟨(reply.1, reply.1), ledger, qr, qs⟩, [], [key, key]⟩, reply.2)) := by
  simp only [c10ObservedSession, id_eq]
  rw [PMF.map]
  apply pmf_bind_support_congr
  intro reply hr
  rw [memoQuery_cached digestDraw reply.2 (.inl key) reply.1 (memoQuery_stores _ _ _ _ hr),
    PMF.pure_bind, PMF.pure_map, PMF.pure_map]
  rfl

theorem observed_hash_order (table : Memo WotsQuery Digest)
    (first : table (.inl [1]) = some 11) (second : table (.inl [2]) = some 22) :
    c10ObservedSession id sessionExampleConfig
      (.hash [1] (fun a => .hash [2] (fun b => .done (a, b))) : C10Client (Digest × Digest) 2)
      2 3 emptySessionLedger table =
        PMF.pure (⟨⟨(11, 22), emptySessionLedger, 0, 3⟩, [], [[1], [2]]⟩, table) := by
  simp only [c10ObservedSession, id_eq, memoQuery_cached _ _ _ _ first,
    memoQuery_cached _ _ _ _ second, PMF.pure_bind, PMF.pure_map, observeHash]

theorem observed_hash_after_failure (table : Memo WotsQuery Digest)
    (cached : table (.inl [7]) = some 42) :
    c10ObservedSession id sessionExampleConfig
      (.hash [7] (fun reply => .done reply) : C10Client Digest 1)
      1 4 ⟨[[9]], true⟩ table = PMF.pure (⟨⟨42, ⟨[[9]], true⟩, 0, 4⟩, [], [[7]]⟩, table) := by
  simp only [c10ObservedSession, id_eq, memoQuery_cached _ _ _ _ cached,
    PMF.pure_bind, PMF.pure_map, observeHash]

theorem observed_zero_r_absorbs (table : Memo WotsQuery Digest) :
    c10ObservedSession id { sessionExampleConfig with rTrials := 0, rBound := by decide }
      (.sign sessionExampleRequest (fun first => .sign sessionExampleRequest
        (fun second => .done (first.isNone, second.isNone))) : C10Client (Bool × Bool) 2)
      3 2 emptySessionLedger table =
        PMF.pure (⟨⟨(true, true), ⟨[], true⟩, 3, 1⟩, [], []⟩, table) := by
  have ha : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  rw [c10_observed_sign_exhausted _ _ _ _ 3 1 _ table table ha
    (c10_sign_zero_r_budget _ _ _ _ _ _ _ _ _ _)]
  rw [c10_observed_sign_refused _ _ _ _ _ _ _ _ (session_failed_refuses _ _ rfl)]
  rfl

theorem observed_two_cached_signatures :
    ∃ sig, c10ObservedSession id sessionExampleConfig
      (.sign sessionExampleRequest (fun first => .sign sessionExampleRequest
        (fun second => .done (first, second))) : C10Client (Option C10Signature × Option C10Signature) 2)
      3 2 emptySessionLedger (fun _ => some recoveryAcceptedDigest) =
        PMF.pure (⟨⟨(some sig, some sig),
          ⟨[List.replicate 32 0, List.replicate 32 0], false⟩, 3, 0⟩,
          [⟨sessionExampleRequest, sig⟩, ⟨sessionExampleRequest, sig⟩], []⟩,
          fun _ => some recoveryAcceptedDigest) := by
  obtain ⟨sig, execution⟩ := c10_sign_full_cache_accept id sessionExampleRequest.random
    sessionExampleRequest.message sessionExampleConfig.seed sessionExampleConfig.root sessionExampleRequest.shuffle
  refine ⟨sig, ?_⟩
  have h0 : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  have h1 : sessionAdmits
      ⟨emptySessionLedger.signedMessages ++ [sessionExampleRequest.message], emptySessionLedger.failed⟩
      sessionExampleRequest = true := by decide +kernel
  rw [c10_observed_sign_returned _ _ _ _ 3 1 _ _ _ sig h0 execution]
  rw [c10_observed_sign_returned _ _ _ _ 3 0 _ _ _ sig h1 execution]
  simp only [c10ObservedSession, PMF.pure_map]
  rfl

theorem observed_successful_replay_rejected :
    ∃ sig, c10ObservedDriver id sessionExampleConfig
      (.sign sessionExampleRequest (fun signed => .done
        (sessionExampleRequest.message, signed.getD sessionExampleSignature)) : C10Client C10Forgery 1)
      0 1 (fun _ => some recoveryAcceptedDigest) =
        PMF.pure (⟨⟨⟨(sessionExampleRequest.message, sig),
          ⟨[sessionExampleRequest.message], false⟩, 0, 0⟩, [⟨sessionExampleRequest, sig⟩], []⟩, false⟩,
          fun _ => some recoveryAcceptedDigest) := by
  obtain ⟨sig, execution⟩ := c10_sign_full_cache_accept id sessionExampleRequest.random
    sessionExampleRequest.message sessionExampleConfig.seed sessionExampleConfig.root sessionExampleRequest.shuffle
  refine ⟨sig, ?_⟩
  have ha : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  rw [c10ObservedDriver, c10_observed_sign_returned _ _ _ _ 0 0 _ _ _ sig ha execution]
  simp only [c10ObservedSession, PMF.pure_map, PMF.pure_bind, Option.getD_some, observeSign]
  rw [c10_final_refused _ _ _ _ (c10_final_recorded_refuses _ (by simp [emptySessionLedger]))]
  rw [PMF.pure_map]
  rfl

theorem observed_malformed_signature_refused (table : Memo WotsQuery Digest) :
    c10ObservedDriver id sessionExampleConfig
      (.done (List.replicate 32 0, ⟨0, [], [], []⟩) : C10Client C10Forgery 0) 0 0 table =
        PMF.pure (⟨⟨⟨(List.replicate 32 0, ⟨0, [], [], []⟩), emptySessionLedger, 0, 0⟩,
          [], []⟩, false⟩, table) := by
  simp only [c10ObservedDriver, c10ObservedSession, PMF.pure_bind]
  rw [c10_final_refused _ _ _ _ (by decide +kernel), PMF.pure_map]

theorem observed_cached_initialized_accept (cfg : C10SessionConfig) (publicSeed : Digest) :
    c10ObservedGame id cfg publicSeed (fun _ _ => (.done
      (List.replicate 32 0, sessionExampleSignature) : C10Client C10Forgery 0))
      0 0 (fun _ => some (2 ^ 128)) =
        PMF.pure (⟨(nodeBlock (randomizerOfDigest publicSeed), nodeBlock 1),
          ⟨⟨⟨(List.replicate 32 0, sessionExampleSignature), emptySessionLedger, 0, 0⟩,
            [], []⟩, true⟩⟩, fun _ => some (2 ^ 128)) := by
  rw [c10ObservedGame, c10_keygen_full_cache, PMF.pure_bind]
  simp only [c10ObservedDriver, c10ObservedSession, PMF.pure_bind]
  have ha : sessionFinalAdmits
      (⟨(List.replicate 32 0, sessionExampleSignature), emptySessionLedger, 0, 0⟩) = true := by decide +kernel
  rw [c10Final, if_pos ha, c10_verify_full_cache]
  have accept : forsAccept (forsOfDigest (2 ^ 128)) = true := by decide +kernel
  simp only [accept, sessionConfigAt, decide_true, Bool.and_self, PMF.pure_map]
  have project : randomizerOfDigest (2 ^ 128) = 1 := by decide +kernel
  rw [project]

end
end C10Probability
