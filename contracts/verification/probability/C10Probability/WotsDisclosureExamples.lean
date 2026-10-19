import C10Probability.WotsCutExamples
import C10Probability.WotsRecoveryExamples

/-! Accepted synthetic internal results exercise release boundaries without
asserting their probability in the initialized game. A known node earlier than
the cut still counts as a release; incomplete C10 signing does not. -/
namespace C10Probability
noncomputable section

def knownWotsResultExample (target : WotsCutTarget) (address : WotsLogicalAddress) :
    WotsDeferredResult target address :=
  ⟨0, recoveryAcceptedDigest, recovery_digest_accepted,
    fun i => knownWotsNode target (address, i) (wotsOfDigest recoveryAcceptedDigest i).val 0⟩

def knownC10ResultExample (target : WotsCutTarget) : WotsDeferredC10 target :=
  ⟨0, 0, ⟨[], [], 0⟩,
    ⟨⟨knownWotsResultExample target (wotsLowerAddress (wotsDigestIndex 0)), []⟩,
      ⟨knownWotsResultExample target (wotsUpperAddress (wotsDigestIndex 0)), []⟩, 0⟩⟩

theorem known_earlier_node_exposes_example :
    WotsResultExposes (knownWotsResultExample ((.inr 0, 29), 3) (.inr 0)) ∧
      (wotsOfDigest recoveryAcceptedDigest (29 : Fin 43)).val = 2 := by
  unfold WotsResultExposes
  decide +kernel

theorem exact_cut_node_exposes_example :
    WotsResultExposes (knownWotsResultExample ((.inr 0, 29), 2) (.inr 0)) := by
  unfold WotsResultExposes
  decide +kernel

theorem later_node_unexposed_example :
    ¬ WotsResultExposes (knownWotsResultExample ((.inr 0, 29), 1) (.inr 0)) := by
  unfold WotsResultExposes
  decide +kernel

theorem other_address_unexposed_example :
    ¬ WotsResultExposes (knownWotsResultExample ((.inr 1, 29), 3) (.inr 0)) := by
  unfold WotsResultExposes
  decide +kernel

theorem known_c10_earlier_release_example (secret : Digest) (table : Memo WotsQuery Digest) :
    evalOpening digestDraw (wotsCutCommit [] ((.inr 0, 29), 3)) randomizerOfDigest secret
      (wotsC10Release (some (knownC10ResultExample ((.inr 0, 29), 3)))) table false =
        PMF.pure ⟨some (wotsDeferredC10Signature secret (knownC10ResultExample ((.inr 0, 29), 3))),
          table, true⟩ := by
  have exposed : WotsHypertreeExposes (knownC10ResultExample ((.inr 0, 29), 3)).signed := by
    unfold WotsHypertreeExposes WotsResultExposes
    decide +kernel
  simp only [wotsC10Release, exposed, ↓reduceIte, evalOpening]

theorem failed_c10_release_retains_example (seed : ByteKey) (target : WotsCutTarget)
    (secret : Digest) (table : Memo WotsQuery Digest) (opened : Bool) :
    evalOpening digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
      (wotsC10Release (target := target) none) table opened = PMF.pure ⟨none, table, opened⟩ := by rfl

theorem failed_upper_retains_no_signature_example (target : WotsCutTarget) (index : Fin (2 ^ 18))
    (lower : WotsDeferredLayer target (wotsLowerAddress index)) :
    wotsDeferredTwoOutput lower none = none := by rfl

theorem wots_duplicate_returned_example (target : WotsCutTarget) (cfg : C10SessionConfig)
    (entry : C10Exposure) (table : Memo WotsQuery Digest) :
    WotsReturned target cfg [entry, entry] table ↔ WotsReturned target cfg [entry] table := by
  simp [WotsReturned]

theorem wots_returned_excluded_example (target : WotsCutTarget) (cfg : C10SessionConfig)
    (out : C10ObservedGame × Memo WotsQuery Digest)
    (returned : WotsReturned target (sessionConfigAt cfg out.1.key) out.1.driver.session.exposures out.2) :
    out ∉ observedWotsSelectedOpening target cfg := by
  simp [observedWotsSelectedOpening, returned]

theorem wots_empty_history_unreturned_example (target : WotsCutTarget) (cfg : C10SessionConfig)
    (table : Memo WotsQuery Digest) : ¬ WotsReturned target cfg [] table := by
  simp [WotsReturned]

theorem wots_missing_layers_candidates_example (out : C10ProbedGame)
    (layers : out.1.driver.session.session.value.2.layers = []) :
    wotsProbeCandidates 0 42 out = {0} := by
  simp [wotsProbeCandidates, prefixCandidates, wotsForgedCoordinate, layers, emptyLayerSignature]

end
end C10Probability
