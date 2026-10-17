import C10Probability.ObservedGame
import C10Probability.SessionCharges

/-! Initialized observed experiments retain their respective complete caches.
Only returned-Boolean events inherit the existing shared/independent transfer;
no comparison of cache-visible events is asserted. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem c10_observed_game_result {K : Type*} [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo K Digest) :
    (c10ObservedGame encode cfg publicSeed adversary qr qs table).map
      (fun out => out.1.driver.accepted) =
      (c10Game encode cfg publicSeed adversary qr qs table).map Prod.fst := by
  have h := congrArg (fun p => p.map Prod.fst)
    (c10_observed_game_erases encode cfg publicSeed adversary qr qs table)
  simpa only [PMF.map_comp, Function.comp_def] using h

def c10ObservedInitializedShared (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    PMF (C10ObservedGame × Memo ByteKey Digest) :=
  digestDraw.bind (fun secret => sampler.bind (fun input =>
    c10ObservedGame (privateKey prefixedPrivateInput secret) cfg input.1 input.2 qr qs (fun _ => none)))

def c10ObservedInitializedIndependent (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    PMF (C10ObservedGame × Memo WotsQuery Digest) :=
  sampler.bind (fun input => c10ObservedGame id cfg input.1 input.2 qr qs (fun _ => none))

theorem c10_observed_initialized_shared_erases (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedShared cfg sampler qr qs).map (fun out => out.1.driver.accepted) =
      c10InitializedShared cfg sampler qr qs := by
  simp only [c10ObservedInitializedShared, c10InitializedShared, PMF.map_bind,
    c10_observed_game_result]

theorem c10_observed_initialized_independent_erases (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).map (fun out => out.1.driver.accepted) =
      c10InitializedIndependent cfg sampler qr qs := by
  simp only [c10ObservedInitializedIndependent, c10InitializedIndependent, PMF.map_bind,
    c10_observed_game_result]

theorem c10_observed_initialized_shared_event (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) (event : Set Bool) :
    (c10ObservedInitializedShared cfg sampler qr qs).toOuterMeasure
      {out | out.1.driver.accepted ∈ event} =
      (c10InitializedShared cfg sampler qr qs).toOuterMeasure event := by
  rw [← c10_observed_initialized_shared_erases cfg sampler qr qs,
    PMF.toOuterMeasure_map_apply]
  rfl

theorem c10_observed_initialized_independent_event (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) (event : Set Bool) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | out.1.driver.accepted ∈ event} =
      (c10InitializedIndependent cfg sampler qr qs).toOuterMeasure event := by
  rw [← c10_observed_initialized_independent_erases cfg sampler qr qs,
    PMF.toOuterMeasure_map_apply]
  rfl

theorem c10_observed_initialized_forge_transfer_real (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    ((c10ObservedInitializedShared cfg sampler qr qs).toOuterMeasure
      {out | out.1.driver.accepted = true}).toReal ≤
    ((c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | out.1.driver.accepted = true}).toReal +
      (sessionGamePublic cfg qr qs : ℝ) / 2 ^ 256 := by
  change ((c10ObservedInitializedShared cfg sampler qr qs).toOuterMeasure
      {out | out.1.driver.accepted ∈ ({true} : Set Bool)}).toReal ≤
    ((c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | out.1.driver.accepted ∈ ({true} : Set Bool)}).toReal + _
  rw [c10_observed_initialized_shared_event, c10_observed_initialized_independent_event]
  exact c10_initialized_forge_transfer_real cfg sampler qr qs

theorem c10_observed_initialized_independent_support (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (out : C10ObservedGame × Memo WotsQuery Digest)
    (ho : out ∈ (c10ObservedInitializedIndependent cfg sampler qr qs).support) :
    ∃ input ∈ sampler.support,
      out ∈ (c10ObservedGame id cfg input.1 input.2 qr qs (fun _ => none)).support := by
  rw [c10ObservedInitializedIndependent, PMF.mem_support_bind_iff] at ho
  exact ho

theorem c10_observed_initialized_shared_support (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (out : C10ObservedGame × Memo ByteKey Digest)
    (ho : out ∈ (c10ObservedInitializedShared cfg sampler qr qs).support) :
    ∃ secret ∈ digestDraw.support, ∃ input ∈ sampler.support,
      out ∈ (c10ObservedGame (privateKey prefixedPrivateInput secret) cfg input.1 input.2
        qr qs (fun _ => none)).support := by
  rw [c10ObservedInitializedShared, PMF.mem_support_bind_iff] at ho
  obtain ⟨secret, hs, ho⟩ := ho
  rw [PMF.mem_support_bind_iff] at ho
  obtain ⟨input, hi, ho⟩ := ho
  exact ⟨secret, hs, input, hi, ho⟩

end
end C10Probability
