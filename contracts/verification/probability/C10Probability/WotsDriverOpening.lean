import C10Probability.WotsSessionDisclosure

/-! Final verification retains every query and marks incoming-key reads.
Both raw-session and verifier disclosures remain separate from successful
signing exposures and can be charged to the preceding cut. -/
namespace C10Probability
noncomputable section

def wotsProbedDriverOpening (target : WotsCutTarget) (previous : Randomizer) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    OpeningProgram WotsQuery Unit Digest Digest C10ProbedDriver
      (361 + (qr + qs * (sessionSignCost cfg + 1))) :=
  bindOpening (wotsObservedSessionOpening target previous cfg client qr qs emptySessionLedger)
    (fun observed => mapOpeningReturn (fun final => (⟨observed, final.1⟩, final.2))
      (revealLift (wotsCutIncoming cfg.seed target previous)
        (probeProgram (c10FinalProgram id cfg observed.session))))

theorem wots_probed_driver_refines (target : WotsCutTarget) (previous : Randomizer)
    (secret : Digest) (cfg : C10SessionConfig) {fuel : ℕ}
    (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    OpeningRefines digestDraw (wotsCutCommit cfg.seed target) randomizerOfDigest
      (wotsCutIncoming cfg.seed target previous) secret id
      (wotsProbedDriverOpening target previous cfg client qr qs)
      (c10ProbedDriverProgram cfg client qr qs) := by
  apply opening_refines_bind digestDraw (wotsCutCommit cfg.seed target) randomizerOfDigest
    (wotsCutIncoming cfg.seed target previous) secret id id _ _ _ _
    (wots_observed_session_refines target previous secret cfg client qr qs emptySessionLedger)
  intro observed
  exact opening_refines_map digestDraw (wotsCutCommit cfg.seed target) randomizerOfDigest
    (wotsCutIncoming cfg.seed target previous) secret id id
    (fun final : Bool × List WotsQuery => ((⟨observed, final.1⟩ : C10ObservedDriver), final.2))
    (fun final : Bool × List WotsQuery => ((⟨observed, final.1⟩ : C10ObservedDriver), final.2))
    (fun _ => rfl) _ _ (reveal_lift_refines _ _ _ _ _ _)

theorem wots_probed_driver_avoids (target : WotsCutTarget) (previous : Randomizer)
    (cfg : C10SessionConfig) (seedWidth : cfg.seed.length = 32) (rootWidth : cfg.root.length = 32)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    OpeningAvoids (wotsCutIncoming cfg.seed target previous)
      (wotsProbedDriverOpening target previous cfg client qr qs) := by
  apply opening_avoids_bind _ _ _
    (wots_observed_session_avoids target previous cfg seedWidth rootWidth client qr qs emptySessionLedger)
  intro observed
  rw [opening_avoids_map]
  exact reveal_lift_avoids _ _

theorem wots_probed_driver_budget (target : WotsCutTarget) (previous : Randomizer)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsProbedDriverOpening target previous cfg client qr qs))
      (qr + qs * 364076 + 361) := by
  apply opening_selected_bind _ _ _ (qr + qs * 364076) 361
    (wots_observed_session_budget target previous cfg client qr qs emptySessionLedger)
  intro observed
  rw [redact_opening_mapReturn, selectedBudget_mapReturn]
  exact reveal_lift_selected _ _ _ 361 (selectedBudget_total _ _)

theorem wots_probed_driver_opened (target : WotsCutTarget) (previous : Randomizer)
    (secret : Digest) (cfg : C10SessionConfig) (seedWidth : cfg.seed.length = 32)
    (rootWidth : cfg.root.length = 32) {fuel : ℕ} (client : C10Client C10Forgery fuel)
    (qr qs : ℕ) (table : Memo WotsQuery Digest)
    (cached : table (wotsCutIncoming cfg.seed target previous) = some secret)
    (out : OpeningOutput WotsQuery Digest C10ProbedDriver)
    (supported : out ∈ (evalOpening digestDraw (wotsCutCommit cfg.seed target) randomizerOfDigest secret
      (wotsProbedDriverOpening target previous cfg client qr qs) table false).support)
    (opened : out.opened = true) :
    WotsReturned target cfg out.value.1.session.exposures out.cache ∨
      wotsCutIncoming cfg.seed target previous ∈ out.value.1.session.queries.map Sum.inl ++ out.value.2 := by
  rw [wotsProbedDriverOpening, eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨session, sessionSupport, supported⟩ := supported
  rw [eval_opening_mapReturn, PMF.mem_support_map_iff] at supported
  obtain ⟨final, finalSupport, rfl⟩ := supported
  have extension : MemoExtends session.cache final.cache := by
    intro key value present
    exact eval_opening_preserves digestDraw (wotsCutCommit cfg.seed target) randomizerOfDigest secret
      _ session.cache session.opened key value present final finalSupport
  cases sessionFlag : session.opened
  · rw [sessionFlag] at finalSupport
    exact Or.inr (List.mem_append_right _ (reveal_probe_opened digestDraw (wotsCutCommit cfg.seed target)
      randomizerOfDigest (wotsCutIncoming cfg.seed target previous) secret
      (c10FinalProgram id cfg session.value.session) session.cache final finalSupport opened))
  · rcases wots_observed_session_opened target previous secret cfg seedWidth rootWidth client
      qr qs emptySessionLedger table cached session sessionSupport sessionFlag with returned | queried
    · exact Or.inl (wots_returned_extends target cfg session.value.exposures
        session.cache final.cache extension returned)
    · exact Or.inr (List.mem_append_left _ queried)

end
end C10Probability
