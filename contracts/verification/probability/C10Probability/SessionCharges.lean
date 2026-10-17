import C10Probability.SessionGame
import C10Probability.DomainNodeCharges

/-! Charges for the initialized adaptive game, including keygen and final
verification. Prefix transfer bounds a residual game event; it is not a proof
that the residual forgery probability is small. Sampler randomness is independent
of the uniform hidden secret; all oracle histories start empty and then persist. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def sessionGameRaw (cfg : C10SessionConfig) (qr qs : ℕ) : ℕ :=
  qr + qs * sessionSignCost cfg + 177512

def sessionGamePublic (cfg : C10SessionConfig) (qr qs : ℕ) : ℕ :=
  qr + qs * sessionSignPublic cfg + 155496

def sessionGameSelected (cfg : C10SessionConfig) (qr qs : ℕ) : ℕ :=
  qr + qs * sessionSignSelected cfg + 177509

def c10GameMixtureProgram (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    PMF (QueryProgram WotsQuery Digest Bool ((361 + (qr + qs * sessionSignCost cfg)) + 177151)) :=
  sampler.map (fun input => c10GameProgram id cfg input.1 input.2 qr qs)

def c10InitializedShared (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) : PMF Bool :=
  digestDraw.bind (fun secret => sampler.bind (fun input =>
    (c10Game (privateKey prefixedPrivateInput secret) cfg input.1 input.2 qr qs
      (fun _ => none)).map Prod.fst))

def c10InitializedIndependent (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) : PMF Bool :=
  sampler.bind (fun input =>
    (c10Game id cfg input.1 input.2 qr qs (fun _ => none)).map Prod.fst)

theorem c10_initialized_shared_eq (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    privateShared digestDraw digestDraw prefixedPrivateInput (c10GameMixtureProgram cfg sampler qr qs) =
      c10InitializedShared cfg sampler qr qs := by
  simp only [privateShared, privateSharedAt, c10GameMixtureProgram, PMF.bind_map,
    Function.comp_def, c10_game_map, id_eq, c10_game_eval, c10InitializedShared]

theorem c10_initialized_independent_eq (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    privateIndependent digestDraw (c10GameMixtureProgram cfg sampler qr qs) =
      c10InitializedIndependent cfg sampler qr qs := by
  simp only [privateIndependent, c10GameMixtureProgram, randomizedProgram, PMF.bind_map,
    Function.comp_def, c10_game_eval, PMF.map_bind, c10InitializedIndependent]

theorem c10_game_mixture_public (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (program : QueryProgram WotsQuery Digest Bool ((361 + (qr + qs * sessionSignCost cfg)) + 177151))
    (hp : program ∈ (c10GameMixtureProgram cfg sampler qr qs).support) :
    PublicBudget program (sessionGamePublic cfg qr qs) := by
  rw [c10GameMixtureProgram, PMF.mem_support_map_iff] at hp
  obtain ⟨input, _, rfl⟩ := hp
  rw [show sessionGamePublic cfg qr qs = 155135 + (qr + qs * sessionSignPublic cfg + 361) by
    unfold sessionGamePublic; omega]
  exact c10_game_public cfg input.1 input.2 qr qs

theorem c10_initialized_prefix_bounds (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) (event : Set Bool) :
    (c10InitializedShared cfg sampler qr qs).toOuterMeasure event ≤
      (c10InitializedIndependent cfg sampler qr qs).toOuterMeasure event +
        (sessionGamePublic cfg qr qs : ℝ≥0∞) / 2 ^ 256 ∧
    (c10InitializedIndependent cfg sampler qr qs).toOuterMeasure event ≤
      (c10InitializedShared cfg sampler qr qs).toOuterMeasure event +
        (sessionGamePublic cfg qr qs : ℝ≥0∞) / 2 ^ 256 := by
  rw [← c10_initialized_shared_eq, ← c10_initialized_independent_eq]
  exact private_secret_event_bounds _ _ (c10_game_mixture_public cfg sampler qr qs) event

theorem c10_initialized_prefix_error_real (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) (event : Set Bool) :
    |((c10InitializedShared cfg sampler qr qs).toOuterMeasure event).toReal -
      ((c10InitializedIndependent cfg sampler qr qs).toOuterMeasure event).toReal| ≤
        (sessionGamePublic cfg qr qs : ℝ) / 2 ^ 256 := by
  rw [← c10_initialized_shared_eq, ← c10_initialized_independent_eq]
  exact private_secret_event_error_real _ _ (c10_game_mixture_public cfg sampler qr qs) event

theorem c10_initialized_forge_transfer_real (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    ((c10InitializedShared cfg sampler qr qs).toOuterMeasure {true}).toReal ≤
      ((c10InitializedIndependent cfg sampler qr qs).toOuterMeasure {true}).toReal +
        (sessionGamePublic cfg qr qs : ℝ) / 2 ^ 256 := by
  have h := (abs_le.mp (c10_initialized_prefix_error_real cfg sampler qr qs {true})).2
  linarith

theorem c10_game_domain_bad_bound (secret : Digest) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    (c10Game (privateKey prefixedPrivateInput secret) cfg publicSeed adversary qr qs
      (fun _ => none)).toOuterMeasure {out | DomainNodeBad out.2} ≤
        ((Nat.choose (sessionGameSelected cfg qr qs) 2 + sessionGameRaw cfg qr qs : ℕ) : ℝ≥0∞) /
          2 ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (c10GameProgram (privateKey prefixedPrivateInput secret) cfg publicSeed adversary qr qs))
    (sessionGameSelected cfg qr qs) (by
      intro program hp
      have he : program = c10GameProgram (privateKey prefixedPrivateInput secret)
          cfg publicSeed adversary qr qs := by simpa using hp
      rw [he]
      rw [show sessionGameSelected cfg qr qs = 177151 + (qr + qs * sessionSignSelected cfg + 358) by
        unfold sessionGameSelected; omega]
      exact c10_game_selected secret cfg publicSeed adversary qr qs)
  simpa only [randomizedProgram_pure, c10_game_eval,
    show 361 + (qr + qs * sessionSignCost cfg) + 177151 = sessionGameRaw cfg qr qs by
      unfold sessionGameRaw; omega] using h

end
end C10Probability
