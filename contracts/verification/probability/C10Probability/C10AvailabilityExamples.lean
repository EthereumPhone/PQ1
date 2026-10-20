import C10Probability.C10AvailabilityNumeric
import C10Probability.C10RExamples

/-! Direct branch witnesses for the availability event. The returned failure
ledger is independent of the forgery verdict and distinguishes refusal from
an admitted failed search. Existing complete-session execution examples are
consumed through their actual final ledger. -/
namespace C10Probability
noncomputable section

theorem c10_signing_failure_event_branches (value : C10Forgery) :
    c10SigningFailure (false, ⟨value, ⟨[], true⟩, 3, 2⟩, false) = true ∧
    c10SigningFailure (true, ⟨value, ⟨[], false⟩, 3, 2⟩, true) = false := by
  exact ⟨rfl, rfl⟩

theorem c10_availability_wots_failure_event :
    (c10RSession id sessionExampleConfig
      (.sign sessionExampleRequest (fun first => .sign sessionExampleRequest
        (fun second => .done (first.isNone, second.isNone))) : C10Client (Bool × Bool) 2)
      3 2 emptySessionLedger (fun _ => some (2 ^ 128))).map
        (fun out => (out.1.1.ledger.failed, out.1.2)) = PMF.pure (true, false) := by
  rw [c10_r_wots_failure_absorbs, PMF.pure_map]

theorem c10_availability_r_failure_event (table : Memo WotsQuery Digest) :
    (c10RSession id {sessionExampleConfig with rTrials := 0, rBound := by decide}
      (.sign sessionExampleRequest (fun first => .sign sessionExampleRequest
        (fun second => .done (first.isNone, second.isNone))) : C10Client (Bool × Bool) 2)
      3 2 emptySessionLedger table).map
        (fun out => (out.1.1.ledger.failed, out.1.2)) = PMF.pure (true, true) := by
  rw [c10_r_zero_trials_absorb, PMF.pure_map]

theorem c10_availability_refusal_event (table : Memo WotsQuery Digest) :
    (c10RSession id sessionExampleConfig
      (.sign ⟨[], [], []⟩ (fun reply => .done reply.isNone) : C10Client Bool 1)
      3 2 emptySessionLedger table).map
        (fun out => (out.1.1.ledger.failed, out.1.1.signRemaining)) = PMF.pure (false, 2) := by
  rw [c10_r_bad_request_keeps_cap, PMF.pure_map]
  rfl

theorem c10_availability_cap_refusal_event (table : Memo WotsQuery Digest) :
    (c10RSession id sessionExampleConfig
      (.sign sessionExampleRequest (fun reply => .done reply.isNone) : C10Client Bool 1)
      3 0 emptySessionLedger table).map (fun out => out.1.1.ledger.failed) = PMF.pure false := by
  rw [c10_r_sign_cap_default, PMF.pure_map]
  rfl

theorem c10_availability_cached_success_event :
    (c10RSession id sessionExampleConfig
      (.sign sessionExampleRequest (fun first => .sign sessionExampleRequest
        (fun second => .done (first, second))) : C10Client (Option C10Signature × Option C10Signature) 2)
      3 2 emptySessionLedger (fun _ => some recoveryAcceptedDigest)).map
        (fun out => (out.1.1.ledger.failed, out.1.1.ledger.signedMessages.length)) =
          PMF.pure (false, 2) := by
  obtain ⟨sig, executed⟩ := c10_r_two_cached_signatures
  rw [executed, PMF.pure_map]
  rfl

end
end C10Probability
