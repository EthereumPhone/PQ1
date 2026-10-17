import C10Probability.SessionBranches
import C10Probability.SessionCharges
import C10Probability.C10Cached

/-! Inhabited admission, cache, exhaustion, replay and initialized-game
witnesses. Populated constant tables are deliberate witnesses, not claims that
these histories occur under the empty-table random-oracle experiment. -/
namespace C10Probability
noncomputable section

def sessionExampleRequest : C10SignRequest := ⟨[], List.replicate 32 0, List.replicate 32 0⟩
def sessionExampleConfig : C10SessionConfig :=
  ⟨List.replicate 32 0, nodeBlock 1, 1, 1, by decide, by decide⟩
def sessionExampleSignature : C10Signature :=
  ⟨0, List.replicate 13 0, List.replicate 12 (List.replicate 11 0),
    List.replicate 2 ⟨fun _ => 0, 0, List.replicate 9 0⟩⟩

theorem session_example_signature_shape : C10SignatureWellFormed sessionExampleSignature := by
  exact (session_signature_width_iff _).mp (by decide +kernel)

theorem session_admission_vectors :
    sessionAdmits emptySessionLedger sessionExampleRequest = true ∧
    sessionAdmits emptySessionLedger { sessionExampleRequest with random := List.replicate 16 7 } = true ∧
    sessionAdmits emptySessionLedger { sessionExampleRequest with random := List.replicate 15 7 } = false ∧
    sessionAdmits emptySessionLedger { sessionExampleRequest with message := List.replicate 31 0 } = false ∧
    sessionAdmits emptySessionLedger { sessionExampleRequest with shuffle := List.replicate 33 0 } = false ∧
    sessionAdmits ⟨[], true⟩ sessionExampleRequest = false := by decide +kernel

theorem session_hash_after_failure (table : Memo WotsQuery Digest) (cached : table (.inl [7]) = some 42) :
    c10Session id sessionExampleConfig (.hash [7] (fun reply => .done reply) : C10Client Digest 1)
      1 4 ⟨[[9]], true⟩ table = PMF.pure (⟨42, ⟨[[9]], true⟩, 0, 4⟩, table) := by
  simp only [c10Session, id_eq, memoQuery_cached digestDraw table (.inl [7]) 42 cached, PMF.pure_bind]

theorem session_hash_cap_default (table : Memo WotsQuery Digest) :
    c10Session id sessionExampleConfig (.hash [7] (fun reply => .done reply) : C10Client Digest 1)
      0 4 emptySessionLedger table = PMF.pure (⟨0, emptySessionLedger, 0, 4⟩, table) := rfl

theorem session_repeated_hash (cfg : C10SessionConfig) (key : ByteKey) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo WotsQuery Digest) :
    c10Session id cfg (.hash key (fun first => .hash key (fun second => .done (first, second))) :
      C10Client (Digest × Digest) 2) (qr + 2) qs ledger table =
      (memoQuery digestDraw table (.inl key)).map
        (fun reply => (⟨(reply.1, reply.1), ledger, qr, qs⟩, reply.2)) := by
  simp only [c10Session, id_eq]
  rw [PMF.map]
  apply pmf_bind_support_congr
  intro reply hr
  rw [memoQuery_cached digestDraw reply.2 (.inl key) reply.1 (memoQuery_stores _ _ _ _ hr),
    PMF.pure_bind]
  rfl

theorem session_bad_request_keeps_cap (table : Memo WotsQuery Digest) :
    c10Session id sessionExampleConfig
      (.sign ⟨[], [], []⟩ (fun reply => .done reply.isNone) : C10Client Bool 1)
      3 2 emptySessionLedger table = PMF.pure (⟨true, emptySessionLedger, 3, 2⟩, table) := by
  have ha : sessionAdmits emptySessionLedger ⟨[], [], []⟩ = false := by decide +kernel
  rw [c10_session_sign_refused _ _ _ _ _ _ _ _ ha]
  rfl

theorem session_zero_r_absorbs (table : Memo WotsQuery Digest) :
    c10Session id { sessionExampleConfig with rTrials := 0, rBound := by decide }
      (.sign sessionExampleRequest (fun first => .sign sessionExampleRequest
        (fun second => .done (first.isNone, second.isNone))) : C10Client (Bool × Bool) 2)
      3 2 emptySessionLedger table = PMF.pure (⟨(true,true), ⟨[],true⟩, 3, 1⟩, table) := by
  have ha : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  rw [c10_session_sign_exhausted _ _ _ _ 3 1 _ table table ha
    (c10_sign_zero_r_budget _ _ _ _ _ _ _ _ _ _)]
  rw [c10_session_sign_refused _ _ _ _ _ _ _ _ (session_failed_refuses _ _ rfl)]
  rfl

theorem session_two_cached_signatures :
    ∃ sig, c10Session id sessionExampleConfig
      (.sign sessionExampleRequest (fun first => .sign sessionExampleRequest
        (fun second => .done (first, second))) : C10Client (Option C10Signature × Option C10Signature) 2)
      3 2 emptySessionLedger (fun _ => some recoveryAcceptedDigest) =
        PMF.pure (⟨(some sig, some sig),
          ⟨[List.replicate 32 0, List.replicate 32 0], false⟩, 3, 0⟩,
          fun _ => some recoveryAcceptedDigest) := by
  obtain ⟨sig, execution⟩ := c10_sign_full_cache_accept id sessionExampleRequest.random
    sessionExampleRequest.message sessionExampleConfig.seed sessionExampleConfig.root sessionExampleRequest.shuffle
  refine ⟨sig, ?_⟩
  have h0 : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  have h1 : sessionAdmits
      ⟨emptySessionLedger.signedMessages ++ [sessionExampleRequest.message], emptySessionLedger.failed⟩
      sessionExampleRequest = true := by decide +kernel
  rw [c10_session_sign_returned _ _ _ _ 3 1 _ _ _ sig h0 execution]
  rw [c10_session_sign_returned _ _ _ _ 3 0 _ _ _ sig h1 execution]
  rfl

theorem session_successful_replay_rejected :
    c10Driver id sessionExampleConfig
      (.sign sessionExampleRequest (fun signed => .done
        (sessionExampleRequest.message, signed.getD sessionExampleSignature)) : C10Client C10Forgery 1)
      0 1 (fun _ => some recoveryAcceptedDigest) =
        PMF.pure (false, fun _ => some recoveryAcceptedDigest) := by
  obtain ⟨sig, execution⟩ := c10_sign_full_cache_accept id sessionExampleRequest.random
    sessionExampleRequest.message sessionExampleConfig.seed sessionExampleConfig.root sessionExampleRequest.shuffle
  have ha : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  rw [c10Driver, c10_session_sign_returned _ _ _ _ 0 0 _ _ _ sig ha execution]
  simp only [c10Session, PMF.pure_bind, Option.getD_some]
  apply c10_final_refused
  apply c10_final_recorded_refuses
  simp [emptySessionLedger]

theorem session_malformed_signature_refused (table : Memo WotsQuery Digest) :
    c10Driver id sessionExampleConfig
      (.done (List.replicate 32 0, ⟨0,[],[],[]⟩) : C10Client C10Forgery 0) 0 0 table =
        PMF.pure (false, table) := by
  simp only [c10Driver, c10Session, PMF.pure_bind]
  apply c10_final_refused
  decide +kernel

theorem session_cached_initialized_accept (cfg : C10SessionConfig) (publicSeed : Digest) :
    c10Game id cfg publicSeed (fun _ _ => (.done
      (List.replicate 32 0, sessionExampleSignature) : C10Client C10Forgery 0))
      0 0 (fun _ => some (2 ^ 128)) = PMF.pure (true, fun _ => some (2 ^ 128)) := by
  rw [c10Game, c10_keygen_full_cache, PMF.pure_bind]
  simp only [c10Driver, c10Session, PMF.pure_bind]
  have ha : sessionFinalAdmits
      (⟨(List.replicate 32 0,sessionExampleSignature),emptySessionLedger,0,0⟩) = true := by decide +kernel
  rw [c10Final, if_pos ha, c10_verify_full_cache]
  have accept : forsAccept (forsOfDigest (2 ^ 128)) = true := by decide +kernel
  simp only [accept, sessionConfigAt, decide_true, Bool.and_self]

theorem session_game_cost_vector :
    let cfg : C10SessionConfig := ⟨[],[],10000000,10000000,by decide,by decide⟩
    sessionGameRaw cfg 2 3 = 121482646 ∧ sessionGamePublic cfg 2 3 = 91248368 ∧
      sessionGameSelected cfg 2 3 = 31482637 := by decide +kernel

end
end C10Probability
