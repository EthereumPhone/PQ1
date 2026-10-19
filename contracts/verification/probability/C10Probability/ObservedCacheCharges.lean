import C10Probability.TaggedCacheCharges
import C10Probability.ObservedInitialized

/-! Exact erasure keeps the entire tagged cache, so syntactic game budgets
charge the observed initialized experiment without a cache transfer premise. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem c10_observed_initialized_cache_erases (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).map
      (fun out => (out.1.driver.accepted, out.2)) =
      randomizedProgram digestDraw (c10GameMixtureProgram cfg sampler qr qs) (fun _ => none) := by
  simp only [c10ObservedInitializedIndependent, PMF.map_bind, c10_observed_game_erases,
    randomizedProgram, c10GameMixtureProgram, PMF.bind_map, Function.comp_def, c10_game_eval]

theorem c10_observed_initialized_cache_event (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) (event : Set (Memo WotsQuery Digest)) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure {out | out.2 ∈ event} =
      (randomizedProgram digestDraw (c10GameMixtureProgram cfg sampler qr qs)
        (fun _ => none)).toOuterMeasure {out | out.2 ∈ event} := by
  rw [← c10_observed_initialized_cache_erases, PMF.toOuterMeasure_map_apply]
  rfl

theorem c10_observed_node_collision_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | ¬ PublicNodeCollisionFree Sum.inl out.2} ≤
        ((sessionGameSelected cfg qr qs).choose 2 : ℝ≥0∞) / 2 ^ 128 := by
  rw [show {out : C10ObservedGame × Memo WotsQuery Digest | ¬ PublicNodeCollisionFree Sum.inl out.2} =
    {out | out.2 ∈ {table | ¬ PublicNodeCollisionFree Sum.inl table}} from rfl,
    c10_observed_initialized_cache_event]
  exact tagged_program_node_collision_bound (c10GameMixtureProgram cfg sampler qr qs)
    (sessionGameSelected cfg qr qs) (c10_independent_mixture_selected cfg sampler qr qs)

theorem c10_observed_zero_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | PublicNodeZero (fun key => out.2 (.inl key))} ≤
        (sessionGameRaw cfg qr qs : ℝ≥0∞) / 2 ^ 128 := by
  rw [show {out : C10ObservedGame × Memo WotsQuery Digest | PublicNodeZero (fun key => out.2 (.inl key))} =
    {out | out.2 ∈ {table | PublicNodeZero (fun key => table (.inl key))}} from rfl,
    c10_observed_initialized_cache_event]
  have size : 361 + (qr + qs * sessionSignCost cfg) + 177151 = sessionGameRaw cfg qr qs := by
    unfold sessionGameRaw
    omega
  simpa only [size] using tagged_program_zero_bound (c10GameMixtureProgram cfg sampler qr qs)

theorem c10_observed_accepted_collision_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | AcceptedWotsCollision (fun key => out.2 (.inl key))} ≤
        acceptedWotsGameCharge (sessionGameRaw cfg qr qs) := by
  rw [show {out : C10ObservedGame × Memo WotsQuery Digest | AcceptedWotsCollision (fun key => out.2 (.inl key))} =
    {out | out.2 ∈ {table | AcceptedWotsCollision (fun key => table (.inl key))}} from rfl,
    c10_observed_initialized_cache_event]
  have size : 361 + (qr + qs * sessionSignCost cfg) + 177151 = sessionGameRaw cfg qr qs := by
    unfold sessionGameRaw
    omega
  simpa only [size] using tagged_program_accepted_bound (c10GameMixtureProgram cfg sampler qr qs)

end
end C10Probability
