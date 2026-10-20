import C10Probability.ByteAvailabilityReal
import C10Probability.ByteSessionExamples
import C10Probability.C10RExamples

/-! Direct byte-observer witnesses distinguish admitted R/WOTS failure,
malformed/capped refusal and successful cached signing. Populated constant
caches are functional examples, not claimed initialized oracle histories. -/
namespace C10Probability
noncomputable section

theorem byte_signing_failure_event_branches (value : C10ByteForgery) :
    c10ByteSigningFailure (false, ⟨value, ⟨[], true⟩, 3, 2⟩) = true ∧
      c10ByteSigningFailure (true, ⟨value, ⟨[], false⟩, 3, 2⟩) = false := by
  exact ⟨rfl, rfl⟩

theorem byte_observed_done_bad_length (cfg : C10SessionConfig) (value : C10ByteForgery)
    (qr qs : ℕ) (table : Memo WotsQuery Digest) (width : value.2.length ≠ 4008) :
    c10ByteObservedDriver id cfg (.done value : C10ByteClient C10ByteForgery 0)
      qr qs table = PMF.pure ((false, ⟨value, emptySessionLedger, qr, qs⟩), table) := by
  rw [c10ByteObservedDriver, c10ByteSession, PMF.pure_bind,
    c10_byte_final_bad_length id cfg _ table width, PMF.pure_map]

theorem byte_observed_bad_request_failure (table : Memo WotsQuery Digest) :
    (c10ByteObservedDriver id sessionExampleConfig
      (.sign ⟨[], [], []⟩ (fun _ => .done ([], [])) : C10ByteClient C10ByteForgery 1)
      3 2 table).map (fun out => c10ByteSigningFailure out.1) = PMF.pure false := by
  rw [c10_byte_observed_driver_failure]
  have refused : sessionAdmits emptySessionLedger ⟨[], [], []⟩ = false := by decide +kernel
  simp only [c10ByteSession, refused, Bool.false_eq_true, ↓reduceIte, PMF.pure_map]
  rfl

theorem byte_observed_cap_refusal_failure (table : Memo WotsQuery Digest) :
    (c10ByteObservedDriver id sessionExampleConfig
      (.sign sessionExampleRequest (fun _ => .done ([], [])) : C10ByteClient C10ByteForgery 1)
      3 0 table).map (fun out => c10ByteSigningFailure out.1) = PMF.pure false := by
  rw [c10_byte_observed_driver_failure, c10ByteSession, c10ByteSession, PMF.pure_map]
  rfl

theorem byte_observed_zero_r_failure (table : Memo WotsQuery Digest) :
    (c10ByteObservedDriver id {sessionExampleConfig with rTrials := 0, rBound := by decide}
      (.sign sessionExampleRequest (fun _ => .sign sessionExampleRequest
        (fun _ => .done ([], []))) : C10ByteClient C10ByteForgery 2)
      3 2 table).map (fun out => c10ByteSigningFailure out.1) = PMF.pure true := by
  rw [c10_byte_observed_driver_failure]
  have admitted : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  rw [c10ByteSession, if_pos admitted, c10SignBytes, c10_sign_zero_r_budget,
    PMF.pure_map, PMF.pure_bind]
  simp only [byte_sign_reply_none, byteAfterSign, emptySessionLedger, c10ByteSession,
    session_failed_refuses ⟨[], true⟩ sessionExampleRequest rfl,
    Bool.false_eq_true, ↓reduceIte, PMF.pure_map]

theorem byte_observed_wots_failure :
    (c10ByteObservedDriver id sessionExampleConfig
      (.sign sessionExampleRequest (fun _ => .done ([], [])) : C10ByteClient C10ByteForgery 1)
      3 2 (fun _ => some (2 ^ 128))).map
        (fun out => c10ByteSigningFailure out.1) = PMF.pure true := by
  have failed : c10Sign id (fun _ => some (2 ^ 128)) sessionExampleRequest.random
      sessionExampleRequest.message sessionExampleConfig.seed sessionExampleConfig.root
      sessionExampleRequest.shuffle 1 1 (by decide) (by decide) =
        PMF.pure (none, fun _ => some (2 ^ 128)) := by
    rw [← c10_r_sign_erases, c10_r_sign_wots_failure, PMF.pure_map]
  have admitted : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  rw [c10_byte_observed_driver_failure, c10ByteSession, if_pos admitted, c10SignBytes]
  simp only [sessionExampleConfig] at failed ⊢
  rw [failed, PMF.pure_map, PMF.pure_bind, c10ByteSession, PMF.pure_map]
  rfl

theorem byte_observed_cached_success :
    (c10ByteObservedDriver id sessionExampleConfig
      (.sign sessionExampleRequest (fun reply => .done (sessionExampleRequest.message, reply.getD [])) :
        C10ByteClient C10ByteForgery 1)
      3 2 (fun _ => some recoveryAcceptedDigest)).map
        (fun out => c10ByteSigningFailure out.1) = PMF.pure false := by
  obtain ⟨sig, execution⟩ := c10_sign_full_cache_accept id sessionExampleRequest.random
    sessionExampleRequest.message sessionExampleConfig.seed sessionExampleConfig.root
    sessionExampleRequest.shuffle
  have shape : C10SignatureWellFormed sig :=
    c10_sign_signature_shape id (fun _ => some recoveryAcceptedDigest) sessionExampleRequest.random
      sessionExampleRequest.message sessionExampleConfig.seed sessionExampleConfig.root
      sessionExampleRequest.shuffle 1 1 (by decide) (by decide)
      (some sig, fun _ => some recoveryAcceptedDigest) (by rw [execution]; simp)
  have admitted : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  rw [c10_byte_observed_driver_failure, c10ByteSession, if_pos admitted, c10SignBytes]
  simp only [sessionExampleConfig] at execution ⊢
  rw [execution, PMF.pure_map, PMF.pure_bind, byte_sign_reply_some sig shape,
    c10ByteSession, PMF.pure_map]
  rfl

theorem byte_observed_game_done_healthy {K : Type*} [DecidableEq K]
    (encode : WotsQuery → K) (cfg : C10SessionConfig) (publicSeed : Digest)
    (value : C10ByteForgery) (qr qs : ℕ) (table : Memo K Digest) :
    (c10ByteObservedGame encode cfg publicSeed
      (fun _ _ => .done value : C10ByteAdversary 0) qr qs table).map
        (fun out => c10ByteSigningFailure out.1) = PMF.pure false := by
  simp only [c10ByteObservedGame, PMF.map_bind, c10_byte_observed_driver_failure,
    c10ByteSession, PMF.pure_map, emptySessionLedger, PMF.bind_const]

theorem byte_observed_initialized_pure (cfg : C10SessionConfig) (publicSeed : Digest)
    {fuel : ℕ} (adversary : C10ByteAdversary fuel) (qr qs : ℕ) :
    c10ByteObservedInitializedShared cfg (PMF.pure (publicSeed, adversary)) qr qs =
      c10ByteObservedShared cfg publicSeed (PMF.pure adversary) qr qs := by
  rw [c10ByteObservedInitializedShared, PMF.pure_bind]

end
end C10Probability
