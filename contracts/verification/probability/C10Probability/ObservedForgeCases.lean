import C10Probability.ObservedWotsExposure
import C10Probability.ObservedForestOpening
import C10Probability.ObservedCoverage

/-! Six exhaustive alternatives for actual supported initialized forgeries.
The events can overlap. Their probabilities are composed separately. -/
namespace C10Probability
noncomputable section

theorem observed_repeated_forest_cases (cfg : C10SessionConfig)
    (out : C10ObservedGame × Memo WotsQuery Digest)
    (win : out.1.driver.accepted = true)
    (repeated : ObservedRepeatedLowerForest cfg out) :
    ObservedForestOpening cfg out ∨ ObservedForestCoverage cfg out := by
  obtain ⟨records, history, top, lower, valid, _, repeated⟩ := repeated
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, covered | unmatched⟩ := repeated
  · exact Or.inr ⟨win, top.digest, records, valid.digest, covered⟩
  · exact Or.inl ⟨top.digest, records, history, unmatched⟩

theorem c10_initialized_forge_cases (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (out : C10ObservedGame × Memo WotsQuery Digest)
    (supported : out ∈ (c10ObservedInitializedIndependent cfg sampler qr qs).support)
    (win : out.1.driver.accepted = true) :
    ¬ PublicNodeCollisionFree Sum.inl out.2 ∨ PublicNodeZero (fun key => out.2 (.inl key)) ∨
      AcceptedWotsCollision (fun key => out.2 (.inl key)) ∨
      ObservedWotsEarlierExposure cfg out ∨ ObservedForestOpening cfg out ∨
      ObservedForestCoverage cfg out := by
  rcases c10_initialized_wots_descent cfg sampler qr qs out supported win with
    collision | zero | accepted | earlier | repeated
  · exact Or.inl collision
  · exact Or.inr (Or.inl zero)
  · exact Or.inr (Or.inr (Or.inl accepted))
  · exact Or.inr (Or.inr (Or.inr (Or.inl earlier)))
  · exact Or.inr (Or.inr (Or.inr (Or.inr (observed_repeated_forest_cases cfg out win repeated))))

end
end C10Probability
