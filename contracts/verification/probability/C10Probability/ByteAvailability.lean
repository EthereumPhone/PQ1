import C10Probability.ByteObservedGame
import C10Probability.C10Availability

/-! Signing availability of the actual finite byte game. The public seed and
byte adversary may have any joint distribution independent of the hidden
uniform prefix. Exact observation refinement adds no probability loss. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {fuel : ℕ}

def c10ByteObservedShared (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10ByteAdversary fuel)) (qr qs : ℕ) : PMF C10ByteGameOutput :=
  digestDraw.bind (fun secret =>
    (adversaries.bind (fun adversary =>
      c10ByteObservedGame (privateKey prefixedPrivateInput secret) cfg publicSeed adversary qr qs
        (fun _ => none))).map Prod.fst)

def c10ByteObservedInitializedShared (cfg : C10SessionConfig)
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) : PMF C10ByteGameOutput :=
  sampler.bind (fun input => c10ByteObservedShared cfg input.1 (PMF.pure input.2) qr qs)

theorem c10_byte_shared_signing_failure_eq (cfg : C10SessionConfig) (publicSeed : Digest)
    (adversaries : PMF (C10ByteAdversary fuel)) (qr qs : ℕ) :
    (c10RShared cfg publicSeed (adversaries.map byteAdversaryToStructured) qr qs).map
      c10SigningFailure =
      (c10ByteObservedShared cfg publicSeed adversaries qr qs).map c10ByteSigningFailure := by
  simp only [c10RShared, c10RSharedAt, c10ByteObservedShared, PMF.map_bind,
    PMF.bind_map, PMF.map_comp, Function.comp_def]
  congr 1
  funext secret
  congr 1
  funext adversary
  exact c10_byte_observed_game_failure (privateKey prefixedPrivateInput secret)
    cfg publicSeed adversary qr qs (fun _ => none)

theorem c10_byte_observed_initialized_erases (cfg : C10SessionConfig)
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) :
    (c10ByteObservedInitializedShared cfg sampler qr qs).map Prod.fst =
      c10ByteInitializedShared cfg sampler qr qs := by
  simp only [c10ByteObservedInitializedShared, c10ByteObservedShared, PMF.map_bind,
    PMF.pure_bind, PMF.map_comp, Function.comp_def, c10_byte_observed_game_verdict,
    c10ByteInitializedShared]
  exact PMF.bind_comm _ _ _

theorem c10_byte_initialized_signing_failure_eq (cfg : C10SessionConfig)
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) :
    (c10ByteObservedInitializedShared cfg sampler qr qs).map c10ByteSigningFailure =
      sampler.bind (fun input =>
        (c10RShared cfg input.1 (PMF.pure (byteAdversaryToStructured input.2)) qr qs).map
          c10SigningFailure) := by
  simp only [c10ByteObservedInitializedShared, PMF.map_bind,
    ← c10_byte_shared_signing_failure_eq, PMF.pure_map]

theorem c10_byte_signing_failure_event (p : PMF C10ByteGameOutput) :
    p.toOuterMeasure {out | c10ByteSigningFailure out = true} =
      (p.map c10ByteSigningFailure) true := by
  rw [← PMF.toOuterMeasure_apply_singleton, PMF.toOuterMeasure_map_apply]
  rfl

theorem c10_byte_shared_signing_failure_bound (cfg : C10SessionConfig)
    (publicSeed : Digest) (adversaries : PMF (C10ByteAdversary fuel)) (qr qs : ℕ) :
    ((c10ByteObservedShared cfg publicSeed adversaries qr qs).map c10ByteSigningFailure) true ≤
      c10SigningCharge cfg qr qs := by
  rw [← c10_byte_shared_signing_failure_eq]
  exact c10_shared_signing_failure_bound cfg publicSeed
    (adversaries.map byteAdversaryToStructured) qr qs

theorem c10_byte_initialized_signing_failure_bound (cfg : C10SessionConfig)
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) :
    ((c10ByteObservedInitializedShared cfg sampler qr qs).map c10ByteSigningFailure) true ≤
      c10SigningCharge cfg qr qs := by
  rw [c10ByteObservedInitializedShared, PMF.map_bind, PMF.bind_apply]
  calc
    _ ≤ ∑' input, sampler input * c10SigningCharge cfg qr qs := by
      apply pmf_weighted_bound
      intro input _
      exact c10_byte_shared_signing_failure_bound cfg input.1 (PMF.pure input.2) qr qs
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

theorem c10_byte_initialized_signing_failure_capped (cfg : C10SessionConfig)
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) :
    ((c10ByteObservedInitializedShared cfg sampler qr qs).map c10ByteSigningFailure) true ≤
      min 1 (c10SigningCharge cfg qr qs) := by
  exact le_min (PMF.coe_le_one _ true)
    (c10_byte_initialized_signing_failure_bound cfg sampler qr qs)

end
end C10Probability
