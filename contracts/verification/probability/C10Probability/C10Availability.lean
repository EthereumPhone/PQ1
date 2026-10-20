import C10Probability.C10FailureGame
import C10Probability.C10RTransfer
import C10Probability.WotsDomainReal

/-! Signing availability in one initialized physical shared-oracle experiment.
The returned failed ledger is covered by R exhaustion or a fully rejected
WOTS schedule. The latter is bounded directly in the physical cache, without
transferring a cache-visible event through the private-prefix theorem. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {fuel : ℕ}

def c10SigningTrace (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    PMF (C10RGameOutput × Memo ByteKey Digest) :=
  digestDraw.bind (fun secret => adversaries.bind (fun adversary =>
    c10RGame (privateKey prefixedPrivateInput secret) cfg publicSeed adversary qr qs (fun _ => none)))

theorem c10_signing_trace_refinement (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    (c10SigningTrace cfg publicSeed adversaries qr qs).map Prod.fst =
      c10RShared cfg publicSeed adversaries qr qs := by
  simp only [c10SigningTrace, PMF.map_bind, c10RShared, c10RSharedAt]

theorem c10_signing_trace_failure_cases (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ)
    (out : C10RGameOutput × Memo ByteKey Digest)
    (supported : out ∈ (c10SigningTrace cfg publicSeed adversaries qr qs).support)
    (failed : c10SigningFailure out.1 = true) :
    c10RFailure out.1 = true ∨ WotsDomainExhausted (nodeBlock (randomizerOfDigest publicSeed))
      cfg.wTrials cfg.wBound out.2 := by
  rw [c10SigningTrace, PMF.mem_support_bind_iff] at supported
  obtain ⟨secret, _, supported⟩ := supported
  rw [PMF.mem_support_bind_iff] at supported
  obtain ⟨adversary, _, supported⟩ := supported
  exact c10_r_game_failure_cases (privateKey prefixedPrivateInput secret) (fun _ => rfl)
    cfg publicSeed adversary qr qs (fun _ => none) out supported failed

theorem c10_signing_trace_wots_bound (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    (c10SigningTrace cfg publicSeed adversaries qr qs).toOuterMeasure
      {out | WotsDomainExhausted (nodeBlock (randomizerOfDigest publicSeed))
        cfg.wTrials cfg.wBound out.2} ≤ wotsDomainCharge cfg.wTrials := by
  rw [c10SigningTrace, PMF.toOuterMeasure_bind_apply]
  calc
    _ ≤ ∑' secret, digestDraw secret * wotsDomainCharge cfg.wTrials := by
      apply pmf_weighted_bound
      intro secret _
      have bound := randomized_wots_domain_bound
        (adversaries.map (fun adversary => c10RGameProgram
          (privateKey prefixedPrivateInput secret) cfg publicSeed adversary qr qs))
        (nodeBlock (randomizerOfDigest publicSeed)) cfg.wTrials cfg.wBound
      simpa only [randomizedProgram, PMF.bind_map, Function.comp_def, c10_r_game_eval] using bound
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

def c10SigningCharge (cfg : C10SessionConfig) (qr qs : ℕ) : ℝ≥0∞ :=
  c10RCharge cfg qr qs + wotsDomainCharge cfg.wTrials

theorem c10_signing_failure_event (p : PMF C10RGameOutput) :
    p.toOuterMeasure {out | c10SigningFailure out = true} = (p.map c10SigningFailure) true := by
  rw [← PMF.toOuterMeasure_apply_singleton, PMF.toOuterMeasure_map_apply]
  rfl

theorem c10_shared_signing_failure_bound (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    ((c10RShared cfg publicSeed adversaries qr qs).map c10SigningFailure) true ≤
      c10SigningCharge cfg qr qs := by
  rw [← c10_signing_failure_event, ← c10_signing_trace_refinement, PMF.toOuterMeasure_map_apply]
  let trace := c10SigningTrace cfg publicSeed adversaries qr qs
  have cover : {out | c10SigningFailure out.1 = true} ∩ trace.support ⊆
      {out | c10RFailure out.1 = true} ∪
      {out | WotsDomainExhausted (nodeBlock (randomizerOfDigest publicSeed))
        cfg.wTrials cfg.wBound out.2} := by
    intro out hit
    exact c10_signing_trace_failure_cases cfg publicSeed adversaries qr qs out hit.2 hit.1
  have rbound : trace.toOuterMeasure {out | c10RFailure out.1 = true} ≤ c10RCharge cfg qr qs := by
    change trace.toOuterMeasure (Prod.fst ⁻¹' {out | c10RFailure out = true}) ≤ _
    rw [← PMF.toOuterMeasure_map_apply, c10_signing_trace_refinement, c10_r_failure_event]
    exact c10_r_shared_exhaustion cfg publicSeed adversaries qr qs
  exact (trace.toOuterMeasure_mono cover).trans
    ((MeasureTheory.measure_union_le _ _).trans
      (add_le_add rbound (c10_signing_trace_wots_bound cfg publicSeed adversaries qr qs)))

theorem c10_shared_signing_failure_capped (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    ((c10RShared cfg publicSeed adversaries qr qs).map c10SigningFailure) true ≤
      min 1 (c10SigningCharge cfg qr qs) := by
  exact le_min (PMF.coe_le_one _ true) (c10_shared_signing_failure_bound cfg publicSeed adversaries qr qs)

end
end C10Probability
