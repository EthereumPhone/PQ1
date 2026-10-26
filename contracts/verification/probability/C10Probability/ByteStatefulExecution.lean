import C10Probability.ByteStatefulKernel
import C10Probability.ByteStatefulInitialized

/-! The complete initialized stateful byte execution. Initialization samples
the public input/client pair, hidden prefix and actual keygen cache. Later
steps retain that same prefix, public key, ledger, caps and table. Completion
runs the existing final verifier before returning the observed game result.
The client transition never receives this interpreter-owned state. -/
namespace C10Probability
noncomputable section

inductive C10ByteGameState (S : Type*) where
  | initialize
  | run (secret : Digest) (key : ByteKey × ByteKey) (state : C10ByteExecutionState ByteKey S)

def c10StatefulByteGameStep {S : Type*} (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery))
    (sampler : PMF (Digest × C10StatefulByteAdversary S)) (qr qs : ℕ) :
    C10ByteGameState S → PMF (C10ByteGameOutput ⊕ C10ByteGameState S)
  | .initialize => sampler.bind fun input => digestDraw.bind fun secret =>
      (c10Keygen (privateKey prefixedPrivateInput secret) (fun _ => none) input.1).map fun key =>
        .inr (.run secret key.1 ⟨input.2 key.1.1 key.1.2, qr, qs, emptySessionLedger, key.2⟩)
  | .run secret key state =>
      (c10StatefulByteStep (privateKey prefixedPrivateInput secret) (sessionConfigAt cfg key)
        step state).bind fun result => match result with
        | .inl completed =>
            (c10ByteCutoffFinish (privateKey prefixedPrivateInput secret) (sessionConfigAt cfg key)
              (mapSessionValue some completed.1, completed.2)).map (fun out => .inl out.1)
        | .inr next => PMF.pure (.inr (.run secret key next))

theorem c10_stateful_byte_initial_step {S : Type*} (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery))
    (sampler : PMF (Digest × C10StatefulByteAdversary S)) (qr qs : ℕ) :
    c10StatefulByteGameStep cfg step sampler qr qs .initialize =
      sampler.bind (fun input => digestDraw.bind (fun secret =>
        (c10Keygen (privateKey prefixedPrivateInput secret) (fun _ => none) input.1).map
          (fun key => .inr (.run secret key.1
            ⟨input.2 key.1.1 key.1.2, qr, qs, emptySessionLedger, key.2⟩)))) := by
  rfl

def c10StatefulByteObservation {S : Type*} (qr qs : ℕ) :
    (C10ByteGameOutput ⊕ C10ByteGameState S) → C10ByteGameOutput
  | .inl result => result
  | .inr .initialize => (false, ⟨([], []), emptySessionLedger, qr, qs⟩)
  | .inr (.run _ _ state) =>
      (false, ⟨([], []), state.ledger, state.rawRemaining, state.signRemaining⟩)

theorem c10_stateful_byte_running_cutoff {S : Type*} (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery))
    (sampler : PMF (Digest × C10StatefulByteAdversary S)) (initialQr initialQs : ℕ)
    (secret : Digest) (key : ByteKey × ByteKey) (n : ℕ) (s : S) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo ByteKey Digest) :
    (kernelCutoff (c10StatefulByteGameStep cfg step sampler initialQr initialQs) n
        (.run secret key ⟨s, qr, qs, ledger, table⟩)).map
          (c10StatefulByteObservation initialQr initialQs) =
      ((c10StatefulByteCutoff (privateKey prefixedPrivateInput secret) (sessionConfigAt cfg key)
        step n s qr qs ledger table).bind
          (c10ByteCutoffFinish (privateKey prefixedPrivateInput secret) (sessionConfigAt cfg key))).map
            Prod.fst := by
  induction n generalizing s qr qs ledger table with
  | zero =>
    simp only [kernelCutoff, PMF.pure_map, c10StatefulByteObservation,
      c10StatefulByteCutoff, PMF.pure_bind, c10_byte_cutoff_finish_pending]
  | succ n ih =>
    simp only [kernelCutoff, c10StatefulByteGameStep, c10StatefulByteStep,
      c10StatefulByteCutoff, PMF.bind_bind, PMF.map_bind]
    apply congrArg (PMF.bind (step s))
    funext action
    cases action with
    | done value =>
      simp only [PMF.pure_bind, PMF.bind_map, Function.comp_def, PMF.pure_map,
        c10StatefulByteObservation, mapSessionValue]
      rfl
    | tick next => simp only [PMF.pure_bind, ih, PMF.map_bind]
    | hash first next =>
      cases qr with
      | zero => simp only [PMF.pure_bind, ih, PMF.map_bind]
      | succ qr =>
        simp only [PMF.bind_map, Function.comp_def, PMF.bind_bind, PMF.pure_bind, ih,
          PMF.map_bind]
    | sign req next =>
      cases qs with
      | zero => simp only [PMF.pure_bind, ih, PMF.map_bind]
      | succ qs =>
        by_cases admitted : sessionAdmits ledger req = true
        · simp only [admitted, ↓reduceIte, PMF.bind_map, Function.comp_def, PMF.bind_bind,
            PMF.pure_bind, ih, PMF.map_bind]
        · simp only [admitted, Bool.false_eq_true, ↓reduceIte, PMF.pure_bind, ih, PMF.map_bind]

theorem c10_stateful_byte_execution_cutoff {S : Type*} (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery))
    (sampler : PMF (Digest × C10StatefulByteAdversary S)) (qr qs n : ℕ) :
    (kernelCutoff (c10StatefulByteGameStep cfg step sampler qr qs) (n + 1) .initialize).map
        (c10StatefulByteObservation qr qs) =
      c10StatefulByteInitializedCutoff cfg step n sampler qr qs := by
  simp only [kernelCutoff, c10StatefulByteGameStep, PMF.bind_bind, PMF.bind_map,
    Function.comp_def, PMF.map_bind, c10_stateful_byte_running_cutoff,
    c10StatefulByteInitializedCutoff, c10StatefulByteCutoffGame, c10StatefulByteCutoffDriver]

def C10StatefulByteTerminates {S : Type*} (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery))
    (sampler : PMF (Digest × C10StatefulByteAdversary S)) (qr qs : ℕ) : Prop :=
  KernelTerminatesAlmostSurely (c10StatefulByteGameStep cfg step sampler qr qs) .initialize

def c10StatefulByteInitialized {S : Type*} (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery))
    (sampler : PMF (Digest × C10StatefulByteAdversary S)) (qr qs : ℕ)
    (terminates : C10StatefulByteTerminates cfg step sampler qr qs) : PMF C10ByteGameOutput :=
  kernelTerminalPMF (c10StatefulByteGameStep cfg step sampler qr qs) .initialize terminates

end
end C10Probability
