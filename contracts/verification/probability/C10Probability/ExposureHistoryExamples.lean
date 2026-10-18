import C10Probability.TopExposureOpening
import C10Probability.WotsOpeningExamples

/-! Actual duplicate signing and cache-overwrite witnesses. Populated caches
establish satisfiability and necessary premises, not probabilities of these
executions in the initialized empty-cache experiment. -/
namespace C10Probability
noncomputable section
set_option maxRecDepth 4096

theorem exposure_actual_duplicate_history :
    ∃ sig records, C10SigningHistory id (fun _ : WotsQuery => some recoveryAcceptedDigest)
      sessionExampleConfig [⟨sessionExampleRequest, sig⟩, ⟨sessionExampleRequest, sig⟩] records ∧
      records.length = 2 := by
  obtain ⟨sig, execution⟩ := observed_two_cached_signatures
  let client : C10Client (Option C10Signature × Option C10Signature) 2 :=
    .sign sessionExampleRequest (fun first => .sign sessionExampleRequest
      (fun second => .done (first, second)))
  let out : C10ObservedSession (Option C10Signature × Option C10Signature) × Memo WotsQuery Digest :=
    (⟨⟨(some sig, some sig), ⟨[List.replicate 32 0, List.replicate 32 0], false⟩, 3, 0⟩,
      [⟨sessionExampleRequest, sig⟩, ⟨sessionExampleRequest, sig⟩], []⟩,
      fun _ => some recoveryAcceptedDigest)
  have supported : out ∈ (c10ObservedSession id sessionExampleConfig client 3 2
      emptySessionLedger (fun _ => some recoveryAcceptedDigest)).support := by
    change out ∈ (c10ObservedSession id sessionExampleConfig
      (.sign sessionExampleRequest (fun first => .sign sessionExampleRequest
        (fun second => .done (first, second)))) 3 2 emptySessionLedger
        (fun _ => some recoveryAcceptedDigest)).support
    rw [execution]
    exact (PMF.mem_support_pure_iff _ _).mpr rfl
  have each := c10_observed_exposure_support id sessionExampleConfig client 3 2 emptySessionLedger
    (fun _ => some recoveryAcceptedDigest) out supported
  obtain ⟨records, history⟩ := exposure_history_exists id (fun _ => some recoveryAcceptedDigest)
    sessionExampleConfig [⟨sessionExampleRequest, sig⟩, ⟨sessionExampleRequest, sig⟩] each
  refine ⟨sig, records, history, ?_⟩
  exact (exposure_history_length id _ sessionExampleConfig _ records history).symm

theorem exposure_duplicate_history_cannot_drop (sig : C10Signature) (record : C10SigningRecord) :
    ¬ C10SigningHistory id (fun _ : WotsQuery => some recoveryAcceptedDigest)
      sessionExampleConfig [⟨sessionExampleRequest, sig⟩, ⟨sessionExampleRequest, sig⟩] [record] := by
  intro history
  have length := exposure_history_length id _ sessionExampleConfig _ _ history
  contradiction

theorem exposure_overwrite_changes_actual_wots :
    wotsSign id (fun _ : WotsQuery => some recoveryAcceptedDigest) [] 1 0 0 [] [] 1 (by decide) =
      PMF.pure (some ((fun _ => randomizerOfDigest recoveryAcceptedDigest), 0),
        fun _ => some recoveryAcceptedDigest) ∧
    wotsSign id (fun _ : WotsQuery => some (recoveryAcceptedDigest + 2 ^ 129)) [] 1 0 0 [] [] 1 (by decide) =
      PMF.pure (some ((fun _ => randomizerOfDigest (recoveryAcceptedDigest + 2 ^ 129)), 0),
        fun _ => some (recoveryAcceptedDigest + 2 ^ 129)) ∧
    randomizerOfDigest recoveryAcceptedDigest ≠ randomizerOfDigest (recoveryAcceptedDigest + 2 ^ 129) ∧
    ¬ MemoExtends (fun _ : WotsQuery => some recoveryAcceptedDigest)
      (fun _ => some (recoveryAcceptedDigest + 2 ^ 129)) := by
  have accepted : wotsAccept (wotsOfDigest (recoveryAcceptedDigest + 2 ^ 129)) = true := by
    rw [← opening_equal_words_different_digests.1]
    exact recovery_digest_accepted
  refine ⟨wots_sign_full_cache_accept id [] 1 0 0 [] [] recoveryAcceptedDigest recovery_digest_accepted,
    wots_sign_full_cache_accept id [] 1 0 0 [] [] _ accepted, by decide +kernel, ?_⟩
  intro extension
  have equal := Option.some.inj (extension (.inl []) recoveryAcceptedDigest rfl)
  exact opening_equal_words_different_digests.2 equal.symm

end
end C10Probability
