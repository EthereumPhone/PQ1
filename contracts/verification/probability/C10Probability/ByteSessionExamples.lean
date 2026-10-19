import C10Probability.ByteDriver
import C10Probability.SessionExamples

/-! Direct byte-session boundary consumers. The populated constant cache is
an explicit functional witness, not an empty-cache random-oracle event. -/
namespace C10Probability
noncomputable section

theorem byte_session_hash_after_failure (table : Memo WotsQuery Digest)
    (cached : table (.inl [7]) = some 42) :
    c10ByteSession id sessionExampleConfig
      (.hash [7] (fun reply => .done reply) : C10ByteClient Digest 1)
      1 4 ⟨[[9]], true⟩ table = PMF.pure (⟨42, ⟨[[9]], true⟩, 0, 4⟩, table) := by
  simp only [c10ByteSession, id_eq, memoQuery_cached digestDraw table (.inl [7]) 42 cached,
    PMF.pure_bind]

theorem byte_session_hash_cap_default (table : Memo WotsQuery Digest) :
    c10ByteSession id sessionExampleConfig
      (.hash [7] (fun reply => .done reply) : C10ByteClient Digest 1)
      0 4 emptySessionLedger table = PMF.pure (⟨0, emptySessionLedger, 0, 4⟩, table) := rfl

theorem byte_session_repeated_hash (cfg : C10SessionConfig) (key : ByteKey) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo WotsQuery Digest) :
    c10ByteSession id cfg (.hash key (fun first => .hash key (fun second => .done (first, second))) :
      C10ByteClient (Digest × Digest) 2) (qr + 2) qs ledger table =
      (memoQuery digestDraw table (.inl key)).map
        (fun reply => (⟨(reply.1, reply.1), ledger, qr, qs⟩, reply.2)) := by
  simp only [c10ByteSession, id_eq]
  rw [PMF.map]
  apply pmf_bind_support_congr
  intro reply supported
  rw [memoQuery_cached digestDraw reply.2 (.inl key) reply.1
    (memoQuery_stores _ _ _ _ supported), PMF.pure_bind]
  rfl

theorem byte_session_bad_request_keeps_cap (table : Memo WotsQuery Digest) :
    c10ByteSession id sessionExampleConfig
      (.sign ⟨[], [], []⟩ (fun reply => .done reply.isNone) : C10ByteClient Bool 1)
      3 2 emptySessionLedger table = PMF.pure (⟨true, emptySessionLedger, 3, 2⟩, table) := by
  have refused : sessionAdmits emptySessionLedger ⟨[], [], []⟩ = false := by decide +kernel
  simp only [c10ByteSession, refused, Bool.false_eq_true, ↓reduceIte, Option.isNone_none]

theorem byte_session_sign_cap_default (table : Memo WotsQuery Digest) :
    c10ByteSession id sessionExampleConfig
      (.sign sessionExampleRequest (fun reply => .done reply.isNone) : C10ByteClient Bool 1)
      3 0 emptySessionLedger table = PMF.pure (⟨true, emptySessionLedger, 3, 0⟩, table) := rfl

theorem byte_session_zero_r_absorbs (table : Memo WotsQuery Digest) :
    c10ByteSession id { sessionExampleConfig with rTrials := 0, rBound := by decide }
      (.sign sessionExampleRequest (fun first => .sign sessionExampleRequest
        (fun second => .done (first.isNone, second.isNone))) : C10ByteClient (Bool × Bool) 2)
      3 2 emptySessionLedger table = PMF.pure (⟨(true, true), ⟨[], true⟩, 3, 1⟩, table) := by
  have admitted : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  rw [c10ByteSession, if_pos admitted, c10SignBytes, c10_sign_zero_r_budget,
    PMF.pure_map, PMF.pure_bind]
  simp only [byte_sign_reply_none, byteAfterSign, emptySessionLedger, c10ByteSession,
    session_failed_refuses ⟨[], true⟩ sessionExampleRequest rfl,
    Bool.false_eq_true, ↓reduceIte, Option.isNone_none]

theorem byte_session_two_cached_signatures :
    ∃ bytes, bytes.length = 4008 ∧ c10ByteSession id sessionExampleConfig
      (.sign sessionExampleRequest (fun first => .sign sessionExampleRequest
        (fun second => .done (first, second))) : C10ByteClient (Option ByteKey × Option ByteKey) 2)
      3 2 emptySessionLedger (fun _ => some recoveryAcceptedDigest) =
        PMF.pure (⟨(some bytes, some bytes),
          ⟨[List.replicate 32 0, List.replicate 32 0], false⟩, 3, 0⟩,
          fun _ => some recoveryAcceptedDigest) := by
  obtain ⟨sig, execution⟩ := c10_sign_full_cache_accept id sessionExampleRequest.random
    sessionExampleRequest.message sessionExampleConfig.seed sessionExampleConfig.root sessionExampleRequest.shuffle
  have shape : C10SignatureWellFormed sig :=
    c10_sign_signature_shape id (fun _ => some recoveryAcceptedDigest) sessionExampleRequest.random
      sessionExampleRequest.message sessionExampleConfig.seed sessionExampleConfig.root sessionExampleRequest.shuffle
      1 1 (by decide) (by decide) (some sig, fun _ => some recoveryAcceptedDigest)
      (by rw [execution]; simp)
  change c10Sign id (fun _ => some recoveryAcceptedDigest) sessionExampleRequest.random
    sessionExampleRequest.message sessionExampleConfig.seed sessionExampleConfig.root sessionExampleRequest.shuffle
    sessionExampleConfig.rTrials sessionExampleConfig.wTrials sessionExampleConfig.rBound
    sessionExampleConfig.wBound = PMF.pure (some sig, fun _ => some recoveryAcceptedDigest) at execution
  refine ⟨wireEncode (wireSignatureFromStructured sig shape), wire_encode_length _, ?_⟩
  have first : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  have second : sessionAdmits ⟨[sessionExampleRequest.message], false⟩ sessionExampleRequest = true :=
    by decide +kernel
  rw [c10ByteSession, if_pos first, c10SignBytes, execution, PMF.pure_map, PMF.pure_bind,
    byte_sign_reply_some sig shape]
  change c10ByteSession id sessionExampleConfig _ 3 1
    ⟨[sessionExampleRequest.message], false⟩ (fun _ => some recoveryAcceptedDigest) = _
  rw [c10ByteSession, if_pos second, c10SignBytes, execution, PMF.pure_map, PMF.pure_bind,
    byte_sign_reply_some sig shape]
  rfl

theorem byte_driver_malformed_keeps_cache (table : Memo WotsQuery Digest) :
    c10ByteDriver id sessionExampleConfig
      (.done (List.replicate 32 0, []) : C10ByteClient C10ByteForgery 0) 0 0 table =
        PMF.pure (false, table) := by
  rw [c10ByteDriver, c10ByteSession, PMF.pure_bind]
  apply c10_byte_final_bad_length
  change (0 : ℕ) ≠ 4008
  decide

theorem byte_final_replay_refused (cfg : C10SessionConfig) (message bytes : ByteKey)
    (qr qs : ℕ) (table : Memo WotsQuery Digest) :
    c10ByteFinal id cfg ⟨(message, bytes), ⟨[message], false⟩, qr, qs⟩ table =
      PMF.pure (false, table) := by
  have refused : byteFinalAdmits ⟨(message, bytes), ⟨[message], false⟩, qr, qs⟩ = false := by
    simp [byteFinalAdmits]
  rw [c10ByteFinal, refused, if_neg Bool.false_ne_true]

end
end C10Probability
