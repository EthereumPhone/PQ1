import C10Probability.RSessionExhaustion
import C10Probability.PrivateSecret

/-! The direct initialized session on one secret-prefixed shared oracle.
The transfer concerns returned results, including the failure flag. It does
not reveal or transfer cache-visible events. Clients and fixed session
parameters are selected independently of the sampled private-prefix secret. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {R : Type*} {fuel : ℕ}

def rIndependentSession (cfg : RSessionConfig) (clients : PMF (RGrindClient R fuel))
    (qr qs : ℕ) : PMF (RGrindResult R) :=
  (clients.bind (fun client =>
    rSession id cfg client qr qs emptyRGrindLedger (fun _ => none))).map Prod.fst

def rSharedSessionAt (secret : Digest) (cfg : RSessionConfig)
    (clients : PMF (RGrindClient R fuel)) (qr qs : ℕ) : PMF (RGrindResult R) :=
  (clients.bind (fun client =>
    rSession (privateKey prefixedPrivateInput secret) cfg client qr qs
      emptyRGrindLedger (fun _ => none))).map Prod.fst

def rSharedSession (cfg : RSessionConfig) (clients : PMF (RGrindClient R fuel))
    (qr qs : ℕ) : PMF (RGrindResult R) :=
  digestDraw.bind (fun secret => rSharedSessionAt secret cfg clients qr qs)

def rSessionPrograms (cfg : RSessionConfig) (clients : PMF (RGrindClient R fuel))
    (qr qs : ℕ) :
    PMF (QueryProgram (Sum ByteKey ByteKey) Digest (RGrindResult R)
      (qr + qs * (2 * cfg.trials))) :=
  clients.map (fun client => rSessionProgram id cfg client qr qs emptyRGrindLedger)

theorem r_session_programs_public (cfg : RSessionConfig)
    (clients : PMF (RGrindClient R fuel)) (qr qs : ℕ) :
    ∀ program ∈ (rSessionPrograms cfg clients qr qs).support,
      PublicBudget program (qr + qs * cfg.trials) := by
  intro program supported
  rw [rSessionPrograms, PMF.mem_support_map_iff] at supported
  obtain ⟨client, _, rfl⟩ := supported
  exact r_session_public cfg client qr qs emptyRGrindLedger

theorem r_independent_session_refinement (cfg : RSessionConfig)
    (clients : PMF (RGrindClient R fuel)) (qr qs : ℕ) :
    privateIndependent digestDraw (rSessionPrograms cfg clients qr qs) =
      rIndependentSession cfg clients qr qs := by
  simp only [privateIndependent, randomizedProgram, rSessionPrograms, PMF.bind_map,
    Function.comp_def, r_session_eval, rIndependentSession]

theorem r_shared_session_at_refinement (secret : Digest) (cfg : RSessionConfig)
    (clients : PMF (RGrindClient R fuel)) (qr qs : ℕ) :
    privateSharedAt digestDraw prefixedPrivateInput secret (rSessionPrograms cfg clients qr qs) =
      rSharedSessionAt secret cfg clients qr qs := by
  simp only [privateSharedAt, rSessionPrograms, PMF.bind_map, Function.comp_def,
    r_session_map, id_eq, r_session_eval, rSharedSessionAt, PMF.map_bind]

theorem r_shared_session_refinement (cfg : RSessionConfig)
    (clients : PMF (RGrindClient R fuel)) (qr qs : ℕ) :
    privateShared digestDraw digestDraw prefixedPrivateInput
      (rSessionPrograms cfg clients qr qs) = rSharedSession cfg clients qr qs := by
  simp only [privateShared, r_shared_session_at_refinement, rSharedSession]

theorem r_session_returned_event_bounds (cfg : RSessionConfig)
    (clients : PMF (RGrindClient R fuel)) (qr qs : ℕ) (event : Set (RGrindResult R)) :
    (rSharedSession cfg clients qr qs).toOuterMeasure event ≤
      (rIndependentSession cfg clients qr qs).toOuterMeasure event +
        ((qr + qs * cfg.trials : ℕ) : ℝ≥0∞) / 2 ^ 256 ∧
    (rIndependentSession cfg clients qr qs).toOuterMeasure event ≤
      (rSharedSession cfg clients qr qs).toOuterMeasure event +
        ((qr + qs * cfg.trials : ℕ) : ℝ≥0∞) / 2 ^ 256 := by
  simpa only [r_independent_session_refinement, r_shared_session_refinement] using
    private_secret_event_bounds (rSessionPrograms cfg clients qr qs)
      (qr + qs * cfg.trials) (r_session_programs_public cfg clients qr qs) event

theorem r_session_failure_event (p : PMF (RGrindResult R)) :
    p.toOuterMeasure {out | rSessionFailure out = true} =
      (p.map rSessionFailure) true := by
  rw [← PMF.toOuterMeasure_apply_singleton, PMF.toOuterMeasure_map_apply]
  rfl

theorem r_independent_session_exhaustion (cfg : RSessionConfig)
    (clients : PMF (RGrindClient R fuel)) (qr qs : ℕ) :
    ((rIndependentSession cfg clients qr qs).map rSessionFailure) true ≤
      (qs : ℝ≥0∞) * rExhaustionCharge (qr + qs * cfg.trials) cfg.trials := by
  simpa only [rIndependentSession, PMF.map_comp, Function.comp_def] using
    r_session_randomized_exhaustion cfg clients qr qs

def rSessionCharge (cfg : RSessionConfig) (qr qs : ℕ) : ℝ≥0∞ :=
  (qs : ℝ≥0∞) * rExhaustionCharge (qr + qs * cfg.trials) cfg.trials +
    ((qr + qs * cfg.trials : ℕ) : ℝ≥0∞) / 2 ^ 256

theorem r_shared_session_exhaustion (cfg : RSessionConfig)
    (clients : PMF (RGrindClient R fuel)) (qr qs : ℕ) :
    ((rSharedSession cfg clients qr qs).map rSessionFailure) true ≤ rSessionCharge cfg qr qs := by
  have transfer := (r_session_returned_event_bounds cfg clients qr qs
    {out | rSessionFailure out = true}).1
  rw [r_session_failure_event, r_session_failure_event] at transfer
  exact transfer.trans (add_le_add (r_independent_session_exhaustion cfg clients qr qs) le_rfl)

theorem r_shared_session_exhaustion_capped (cfg : RSessionConfig)
    (clients : PMF (RGrindClient R fuel)) (qr qs : ℕ) :
    ((rSharedSession cfg clients qr qs).map rSessionFailure) true ≤
      min 1 (rSessionCharge cfg qr qs) := by
  exact le_min (PMF.coe_le_one _ true) (r_shared_session_exhaustion cfg clients qr qs)

end
end C10Probability
