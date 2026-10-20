import C10Probability.C10RGame
import C10Probability.PrivateSecret

/-! Transfer the returned R-exhaustion observation for actual initialized C10
games. The public seed, configuration and randomized adversary are selected
independently of the hidden uniform prefix. No cache-visible event is exported. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {fuel : ℕ}

def c10RIndependent (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) : PMF C10RGameOutput :=
  (adversaries.bind (fun adversary =>
    c10RGame id cfg publicSeed adversary qr qs (fun _ => none))).map Prod.fst

def c10RSharedAt (secret : Digest) (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) : PMF C10RGameOutput :=
  (adversaries.bind (fun adversary =>
    c10RGame (privateKey prefixedPrivateInput secret) cfg publicSeed adversary qr qs
      (fun _ => none))).map Prod.fst

def c10RShared (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) : PMF C10RGameOutput :=
  digestDraw.bind (fun secret => c10RSharedAt secret cfg publicSeed adversaries qr qs)

def c10RPrograms (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    PMF (QueryProgram WotsQuery Digest C10RGameOutput
      ((361 + (qr + qs * sessionSignCost cfg)) + 177151)) :=
  adversaries.map (fun adversary => c10RGameProgram id cfg publicSeed adversary qr qs)

theorem c10_r_programs_public (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    ∀ program ∈ (c10RPrograms cfg publicSeed adversaries qr qs).support,
      PublicBudget program (c10RPublicCalls cfg qr qs) := by
  intro program supported
  rw [c10RPrograms, PMF.mem_support_map_iff] at supported
  obtain ⟨adversary, _, rfl⟩ := supported
  exact c10_r_game_public cfg publicSeed adversary qr qs

theorem c10_r_independent_refinement (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    privateIndependent digestDraw (c10RPrograms cfg publicSeed adversaries qr qs) =
      c10RIndependent cfg publicSeed adversaries qr qs := by
  simp only [privateIndependent, randomizedProgram, c10RPrograms, PMF.bind_map,
    Function.comp_def, c10_r_game_eval, c10RIndependent]

theorem c10_r_shared_at_refinement (secret : Digest) (cfg : C10SessionConfig)
    (publicSeed : Digest) (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    privateSharedAt digestDraw prefixedPrivateInput secret
      (c10RPrograms cfg publicSeed adversaries qr qs) =
      c10RSharedAt secret cfg publicSeed adversaries qr qs := by
  simp only [privateSharedAt, c10RPrograms, PMF.bind_map, Function.comp_def,
    c10_r_game_map, id_eq, c10_r_game_eval, c10RSharedAt, PMF.map_bind]

theorem c10_r_shared_refinement (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    privateShared digestDraw digestDraw prefixedPrivateInput
      (c10RPrograms cfg publicSeed adversaries qr qs) =
      c10RShared cfg publicSeed adversaries qr qs := by
  simp only [privateShared, c10_r_shared_at_refinement, c10RShared]

theorem c10_r_returned_event_bounds (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) (event : Set C10RGameOutput) :
    (c10RShared cfg publicSeed adversaries qr qs).toOuterMeasure event ≤
      (c10RIndependent cfg publicSeed adversaries qr qs).toOuterMeasure event +
        (c10RPublicCalls cfg qr qs : ℝ≥0∞) / 2 ^ 256 ∧
    (c10RIndependent cfg publicSeed adversaries qr qs).toOuterMeasure event ≤
      (c10RShared cfg publicSeed adversaries qr qs).toOuterMeasure event +
        (c10RPublicCalls cfg qr qs : ℝ≥0∞) / 2 ^ 256 := by
  simpa only [c10_r_independent_refinement, c10_r_shared_refinement] using
    private_secret_event_bounds (c10RPrograms cfg publicSeed adversaries qr qs)
      (c10RPublicCalls cfg qr qs) (c10_r_programs_public cfg publicSeed adversaries qr qs) event

theorem c10_r_failure_event (p : PMF C10RGameOutput) :
    p.toOuterMeasure {out | c10RFailure out = true} = (p.map c10RFailure) true := by
  rw [← PMF.toOuterMeasure_apply_singleton, PMF.toOuterMeasure_map_apply]
  rfl

theorem c10_r_independent_exhaustion (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    ((c10RIndependent cfg publicSeed adversaries qr qs).map c10RFailure) true ≤
      (qs : ℝ≥0∞) * rExhaustionCharge (c10RHistoryCap cfg qr qs) cfg.rTrials := by
  simp only [c10RIndependent, PMF.map_comp, Function.comp_def]
  apply r_bind_flag_bound
  intro adversary _
  exact c10_r_game_initialized_exhaustion cfg publicSeed adversary qr qs

def c10RCharge (cfg : C10SessionConfig) (qr qs : ℕ) : ℝ≥0∞ :=
  (qs : ℝ≥0∞) * rExhaustionCharge (c10RHistoryCap cfg qr qs) cfg.rTrials +
    (c10RPublicCalls cfg qr qs : ℝ≥0∞) / 2 ^ 256

theorem c10_r_shared_exhaustion (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    ((c10RShared cfg publicSeed adversaries qr qs).map c10RFailure) true ≤ c10RCharge cfg qr qs := by
  have transfer := (c10_r_returned_event_bounds cfg publicSeed adversaries qr qs
    {out | c10RFailure out = true}).1
  rw [c10_r_failure_event, c10_r_failure_event] at transfer
  exact transfer.trans (add_le_add
    (c10_r_independent_exhaustion cfg publicSeed adversaries qr qs) le_rfl)

theorem c10_r_shared_exhaustion_capped (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    ((c10RShared cfg publicSeed adversaries qr qs).map c10RFailure) true ≤
      min 1 (c10RCharge cfg qr qs) := by
  exact le_min (PMF.coe_le_one _ true) (c10_r_shared_exhaustion cfg publicSeed adversaries qr qs)

end
end C10Probability
