import C10Probability.C10RBranches
import C10Probability.C10RNumeric
import C10Probability.SessionExamples

/-! Independent direct-execution witnesses distinguish R exhaustion, later
WOTS failure, refusals and cached success. Constant-cache witnesses describe
arbitrary-table executions, not probabilities of such tables after keygen. -/
namespace C10Probability
noncomputable section

theorem c10_r_sign_cached_success (random message seed root shuffle : ByteKey) :
    ∃ sig, c10RSign id (fun _ => some recoveryAcceptedDigest) random message seed root shuffle
      1 1 (by decide) (by decide) =
        PMF.pure ((some sig, false), fun _ => some recoveryAcceptedDigest) := by
  have accepted : forsAccept (forsOfDigest recoveryAcceptedDigest) = true := by decide +kernel
  have searched : randomizerUnder id (fun _ => some recoveryAcceptedDigest) random message seed root
      1 (by decide) = PMF.pure
        (some (0, randomizerOfDigest recoveryAcceptedDigest, recoveryAcceptedDigest),
          fun _ => some recoveryAcceptedDigest) := by
    simp [randomizerUnder, counterSchedule, derivedMemoGrind, memoQuery, PMF.pure_bind, accepted]
  obtain ⟨sig, finished⟩ := c10_finish_full_cache_accept id seed
    (randomizerOfDigest recoveryAcceptedDigest) recoveryAcceptedDigest shuffle
    recoveryAcceptedDigest recovery_digest_accepted
  refine ⟨sig, ?_⟩
  rw [c10RSign, searched, PMF.pure_bind, c10SignAfter, finished, PMF.pure_map]
  rfl

theorem c10_r_sign_wots_failure (random message seed root shuffle : ByteKey) :
    c10RSign id (fun _ => some (2 ^ 128)) random message seed root shuffle
      1 1 (by decide) (by decide) =
        PMF.pure ((none, false), fun _ => some (2 ^ 128)) := by
  have accepted : forsAccept (forsOfDigest (2 ^ 128)) = true := by decide +kernel
  have rejected : wotsAccept (wotsOfDigest (2 ^ 128)) = false := by decide +kernel
  have searched : randomizerUnder id (fun _ => some (2 ^ 128)) random message seed root
      1 (by decide) = PMF.pure
        (some (0, randomizerOfDigest (2 ^ 128), 2 ^ 128), fun _ => some (2 ^ 128)) := by
    simp [randomizerUnder, counterSchedule, derivedMemoGrind, memoQuery, PMF.pure_bind, accepted]
  rw [c10RSign, searched, PMF.pure_bind, c10SignAfter,
    c10_finish_full_cache_reject _ _ _ _ _ _ _ _ rejected, PMF.pure_map]
  rfl

theorem c10_r_hash_cap_default (table : Memo WotsQuery Digest) :
    c10RSession id sessionExampleConfig (.hash [7] (fun reply => .done reply) : C10Client Digest 1)
      0 4 emptySessionLedger table = PMF.pure ((⟨0, emptySessionLedger, 0, 4⟩, false), table) := by rfl

theorem c10_r_sign_cap_default (table : Memo WotsQuery Digest) :
    c10RSession id sessionExampleConfig
      (.sign sessionExampleRequest (fun reply => .done reply.isNone) : C10Client Bool 1)
      3 0 emptySessionLedger table = PMF.pure ((⟨true, emptySessionLedger, 3, 0⟩, false), table) := by rfl

theorem c10_r_bad_request_keeps_cap (table : Memo WotsQuery Digest) :
    c10RSession id sessionExampleConfig
      (.sign ⟨[], [], []⟩ (fun reply => .done reply.isNone) : C10Client Bool 1)
      3 2 emptySessionLedger table = PMF.pure ((⟨true, emptySessionLedger, 3, 2⟩, false), table) := by
  rw [c10_r_session_sign_refused _ _ _ _ _ _ _ _ (by decide +kernel)]
  rfl

theorem c10_r_zero_trials_absorb (table : Memo WotsQuery Digest) :
    c10RSession id { sessionExampleConfig with rTrials := 0, rBound := by decide }
      (.sign sessionExampleRequest (fun first => .sign sessionExampleRequest
        (fun second => .done (first.isNone, second.isNone))) : C10Client (Bool × Bool) 2)
      3 2 emptySessionLedger table =
        PMF.pure ((⟨(true, true), ⟨[], true⟩, 3, 1⟩, true), table) := by
  have admitted : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  rw [c10_r_session_sign_observed _ _ _ _ 3 1 _ table table none true admitted
    (c10_r_sign_zero _ _ _ _ _ _ _ _ _ _)]
  rw [c10_r_session_sign_refused _ _ _ _ _ _ _ _ (session_failed_refuses _ _ rfl)]
  rw [c10RSession, PMF.pure_map]
  rfl

theorem c10_r_wots_failure_absorbs :
    c10RSession id sessionExampleConfig
      (.sign sessionExampleRequest (fun first => .sign sessionExampleRequest
        (fun second => .done (first.isNone, second.isNone))) : C10Client (Bool × Bool) 2)
      3 2 emptySessionLedger (fun _ => some (2 ^ 128)) =
        PMF.pure ((⟨(true, true), ⟨[], true⟩, 3, 1⟩, false), fun _ => some (2 ^ 128)) := by
  have admitted : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  rw [c10_r_session_sign_observed _ _ _ _ 3 1 _ _ _ none false admitted
    (c10_r_sign_wots_failure _ _ _ _ _)]
  rw [c10_r_session_sign_refused _ _ _ _ _ _ _ _ (session_failed_refuses _ _ rfl)]
  rw [c10RSession, PMF.pure_map]
  rfl

theorem c10_r_hash_after_failure (table : Memo WotsQuery Digest) (cached : table (.inl [7]) = some 42) :
    c10RSession id sessionExampleConfig (.hash [7] (fun reply => .done reply) : C10Client Digest 1)
      1 4 ⟨[[9]], true⟩ table = PMF.pure ((⟨42, ⟨[[9]], true⟩, 0, 4⟩, false), table) := by
  simp only [c10RSession, id_eq, memoQuery_cached digestDraw table (.inl [7]) 42 cached, PMF.pure_bind]

theorem c10_r_two_cached_signatures :
    ∃ sig, c10RSession id sessionExampleConfig
      (.sign sessionExampleRequest (fun first => .sign sessionExampleRequest
        (fun second => .done (first, second))) : C10Client (Option C10Signature × Option C10Signature) 2)
      3 2 emptySessionLedger (fun _ => some recoveryAcceptedDigest) =
        PMF.pure ((⟨(some sig, some sig), ⟨[List.replicate 32 0, List.replicate 32 0], false⟩,
          3, 0⟩, false), fun _ => some recoveryAcceptedDigest) := by
  obtain ⟨sig, executed⟩ := c10_r_sign_cached_success sessionExampleRequest.random
    sessionExampleRequest.message sessionExampleConfig.seed sessionExampleConfig.root sessionExampleRequest.shuffle
  refine ⟨sig, ?_⟩
  have first : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  have second : sessionAdmits
      (sessionAfterSign emptySessionLedger sessionExampleRequest.message (some sig))
      sessionExampleRequest = true := by
    change sessionAdmits ⟨[sessionExampleRequest.message], false⟩ sessionExampleRequest = true
    decide +kernel
  rw [c10_r_session_sign_observed _ _ _ _ 3 1 _ _ _ (some sig) false first executed]
  rw [c10_r_session_sign_observed _ _ _ _ 3 0 _ _ _ (some sig) false second executed]
  rw [c10RSession, PMF.pure_map, PMF.pure_map]
  rfl

theorem c10_r_zero_sign_cap_exhaustion (cfg : C10SessionConfig) (publicSeed : Digest)
    {fuel : ℕ} (adversaries : PMF (C10Adversary fuel)) (qr : ℕ) :
    ((c10RIndependent cfg publicSeed adversaries qr 0).map c10RFailure) true = 0 := by
  apply le_antisymm _ (zero_le _)
  simpa only [Nat.cast_zero, zero_mul] using
    c10_r_independent_exhaustion cfg publicSeed adversaries qr 0

theorem c10_r_zero_trial_sign_event (cfg : C10SessionConfig)
    (table : Memo WotsQuery Digest) {R : Type*} (value : R) :
    (c10RSession id {cfg with rTrials := 0, rBound := by decide}
      (.sign sessionExampleRequest (fun _ => .done value) : C10Client R 1)
      0 1 emptySessionLedger table).map (fun out => out.1.2) = PMF.pure true := by
  have admitted : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  rw [c10_r_session_sign_observed _ _ _ _ 0 0 _ table table none true admitted
    (c10_r_sign_zero _ _ _ _ _ _ _ _ _ _)]
  rw [c10RSession, PMF.pure_map, PMF.pure_map]
  rfl

theorem c10_r_initialized_zero_trials (cfg : C10SessionConfig) (publicSeed : Digest) :
    (c10RGame id {cfg with rTrials := 0, rBound := by decide} publicSeed
      (fun _ _ => (.sign sessionExampleRequest (fun _ => .done
        (List.replicate 32 0, sessionExampleSignature)) : C10Client C10Forgery 1))
      0 1 (fun _ => none)).map (fun out => c10RFailure out.1) = PMF.pure true := by
  simp only [c10RGame, PMF.map_bind, c10_r_driver_failure]
  have branch (key : (ByteKey × ByteKey) × Memo WotsQuery Digest) :
      (c10RSession id
        (sessionConfigAt {cfg with rTrials := 0, rBound := by decide} key.1)
        (.sign sessionExampleRequest (fun _ => .done
          (List.replicate 32 0, sessionExampleSignature)) : C10Client C10Forgery 1)
        0 1 emptySessionLedger key.2).map (fun out => out.1.2) = PMF.pure true := by
    exact c10_r_zero_trial_sign_event (sessionConfigAt cfg key.1) key.2 _
  simp only [branch, PMF.bind_const]

end
end C10Probability
