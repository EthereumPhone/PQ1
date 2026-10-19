import C10Probability.WotsCutSetup

/-! Quantitative transfer for one actual WOTS prefix. The supplied instrumented
client must refine the full client, avoid the selected incoming key, and justify
every disclosure by an explicit excluded event. The budget is structural over
the whole staged context. Concrete C10 consumers must discharge these premises;
this theorem alone does not bound either complete WOTS earlier-opening branch. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem wots_cut_candidate_bound {R : Type*} {n m : ℕ}
    (seed : ByteKey) (target : WotsCutTarget)
    (client : QueryProgram WotsQuery Digest R n)
    (after : Randomizer → OpeningProgram WotsQuery Unit Digest Digest R m)
    (candidates : R → Finset Randomizer) (excluded : R → Memo WotsQuery Digest → Prop)
    (refines : ∀ previous secret,
      OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
        (wotsCutIncoming seed target previous) secret id (after previous) client)
    (avoids : ∀ previous, OpeningAvoids (wotsCutIncoming seed target previous) (after previous))
    (disclosure : ∀ before ∈ (evalProgram digestDraw
      (wotsBeforeCutProgram seed target.1 target.2.val) (fun _ => none)).support,
      ∀ secret out, out ∈ (evalOpening digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
        (after before.1) (Function.update before.2 (wotsCutIncoming seed target before.1)
          (some secret)) false).support → out.opened = true → excluded out.value out.cache)
    (q c : ℕ)
    (budget : SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (bindOpening (liftOpening
        (wotsBeforeCutProgram seed target.1 target.2.val)) after)) q)
    (count : ∀ value, (candidates value).card ≤ c) :
    (evalProgram digestDraw client (fun _ => none)).toOuterMeasure
      (replayedOpeningEvent (wotsSeedChainProgram id seed (wotsTargetLayer target.1)
        (wotsTargetTree target.1) (wotsTargetKp target.1) target.1.2.val target.2.val)
          candidates excluded) ≤ ((q + 2 + c : ℕ) : ℝ≥0∞) / 2 ^ 128 := by
  let prelude := wotsBeforeCutProgram seed target.1 target.2.val
  let context := bindOpening (liftOpening prelude) after
  have comparison := staged_opening_comparison digestDraw (wotsCutCommit seed target)
    randomizerOfDigest prelude (wotsCutIncoming seed target) client after candidates excluded
    (wots_before_cut_fresh seed target) refines avoids
    (fun secret previous label => wots_cut_commit_ne_incoming seed target
      (randomizerOfDigest secret) previous label) disclosure
  change (evalProgram digestDraw client (fun _ => none)).toOuterMeasure
    (replayedOpeningEvent (wotsCutSetup seed target) candidates excluded) ≤
      (openingGame digestDraw digestDraw (wotsCutCommit seed target) randomizerOfDigest
        (PMF.pure context)).toOuterMeasure (candidateEvent (openingCandidates candidates)) at comparison
  rw [wots_cut_setup_event] at comparison
  refine comparison.trans ?_
  have bound := opening_variable_candidate_bound digestDraw digestDraw
    (wotsCutCommit seed target) nodeQueryDecode randomizerOfDigest randomizer_uniform
    (wots_cut_commit_decodes seed target) (wots_cut_commit_labels_injective seed target)
    (PMF.pure context) fixedNodeCandidates q c ?_ candidates count
  · simpa only [fixed_node_candidates_card, Randomizer, Fintype.card_fin,
      Nat.cast_pow, Nat.cast_ofNat] using bound
  · intro program supported
    have equal : program = context := by simpa only [PMF.mem_support_pure_iff] using supported
    simpa only [equal] using budget

end
end C10Probability
