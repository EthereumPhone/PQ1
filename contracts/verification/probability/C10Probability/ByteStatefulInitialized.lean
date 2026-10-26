import C10Probability.ByteStatefulGame
import C10Probability.ByteForgeBound
import C10Probability.ByteAvailability

/-! Initialized finite-cutoff bounds for the direct stateful byte game. The
public seed and client initializer may be correlated under an arbitrary PMF;
both remain independent of the hidden uniformly drawn prefix. Exact compiler
equalities discharge the finite-game bounds rather than assuming them. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def c10StatefulByteSampler {S : Type*} (step : S → PMF (C10ByteAction S C10ByteForgery))
    (n : ℕ) (sampler : PMF (Digest × C10StatefulByteAdversary S)) :
    PMF (Digest × C10ByteAdversary n) :=
  sampler.bind (fun input => (c10StatefulByteAdversaryCompile step n input.2).map
    (fun client => (input.1, client)))

def c10StatefulByteInitializedCutoff {S : Type*} (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery)) (n : ℕ)
    (sampler : PMF (Digest × C10StatefulByteAdversary S)) (qr qs : ℕ) : PMF C10ByteGameOutput :=
  sampler.bind (fun input => digestDraw.bind (fun secret =>
    (c10StatefulByteCutoffGame (privateKey prefixedPrivateInput secret) cfg input.1 step n input.2
      qr qs (fun _ => none)).map Prod.fst))

theorem c10_stateful_byte_initialized_eq {S : Type*} (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery)) (n : ℕ)
    (sampler : PMF (Digest × C10StatefulByteAdversary S)) (qr qs : ℕ) :
    c10ByteObservedInitializedShared cfg (c10StatefulByteSampler step n sampler) qr qs =
      c10StatefulByteInitializedCutoff cfg step n sampler qr qs := by
  simp only [c10ByteObservedInitializedShared, c10StatefulByteSampler,
    c10StatefulByteInitializedCutoff, c10ByteObservedShared, PMF.bind_bind, PMF.bind_map,
    Function.comp_def, PMF.pure_bind]
  congr 1
  funext input
  rw [PMF.bind_comm]
  apply congrArg (PMF.bind digestDraw)
  funext secret
  calc
    _ = ((c10StatefulByteAdversaryCompile step n input.2).bind (fun client =>
        c10ByteObservedGame (privateKey prefixedPrivateInput secret) cfg input.1 client qr qs
          (fun _ => none))).map Prod.fst := (PMF.map_bind _ _ _).symm
    _ = _ := congrArg (fun p : PMF (C10ByteGameOutput × Memo ByteKey Digest) => p.map Prod.fst)
      (c10_stateful_byte_compiled_game (privateKey prefixedPrivateInput secret)
        cfg input.1 step n input.2 qr qs (fun _ => none))

theorem c10_stateful_byte_cutoff_forge_bound {S : Type*} (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery)) (n : ℕ)
    (sampler : PMF (Digest × C10StatefulByteAdversary S)) (qr qs : ℕ) :
    ((c10StatefulByteInitializedCutoff cfg step n sampler qr qs).map Prod.fst).toOuterMeasure {true} ≤
      min 1 (sharedForgeCharge cfg qr qs) := by
  rw [← c10_stateful_byte_initialized_eq, c10_byte_observed_initialized_erases]
  exact c10_byte_shared_forge_bound_capped cfg (c10StatefulByteSampler step n sampler) qr qs

theorem c10_stateful_byte_cutoff_failure_bound {S : Type*} (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery)) (n : ℕ)
    (sampler : PMF (Digest × C10StatefulByteAdversary S)) (qr qs : ℕ) :
    ((c10StatefulByteInitializedCutoff cfg step n sampler qr qs).map c10ByteSigningFailure) true ≤
      min 1 (c10SigningCharge cfg qr qs) := by
  rw [← c10_stateful_byte_initialized_eq]
  exact c10_byte_initialized_signing_failure_capped cfg (c10StatefulByteSampler step n sampler) qr qs

end
end C10Probability
