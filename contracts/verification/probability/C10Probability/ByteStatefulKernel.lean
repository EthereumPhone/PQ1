import C10Probability.ByteStatefulSession
import C10Probability.TerminatingKernel

/-! One-step stateful byte execution. The interpreter owns the caps, ledger
and memo table; the client's transition function sees only its own state.
Its generic absorbing-kernel semantics erases exactly to the independently
defined finite byte-session observation, including unfinished executions. -/
namespace C10Probability
noncomputable section

structure C10ByteExecutionState (K S : Type*) where
  client : S
  rawRemaining : ℕ
  signRemaining : ℕ
  ledger : C10SessionLedger
  table : Memo K Digest

def c10StatefulByteStep {K S R : Type*} [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (step : S → PMF (C10ByteAction S R))
    (state : C10ByteExecutionState K S) :
    PMF ((C10SessionResult R × Memo K Digest) ⊕ C10ByteExecutionState K S) :=
  (step state.client).bind fun action => match action with
    | .done value => PMF.pure (.inl
        (⟨value, state.ledger, state.rawRemaining, state.signRemaining⟩, state.table))
    | .tick next => PMF.pure (.inr {state with client := next})
    | .hash key next => match state.rawRemaining with
      | 0 => PMF.pure (.inr {state with client := next 0})
      | qr + 1 => (memoQuery digestDraw state.table (encode (.inl key))).map fun reply =>
          .inr {state with client := next reply.1, rawRemaining := qr, table := reply.2}
    | .sign req next => match state.signRemaining with
      | 0 => PMF.pure (.inr {state with client := next none})
      | qs + 1 => if sessionAdmits state.ledger req then
          (c10SignBytes encode cfg req state.table).map fun reply =>
            .inr {state with
              client := next reply.1
              signRemaining := qs
              ledger := byteAfterSign state.ledger req.message reply.1
              table := reply.2}
        else PMF.pure (.inr {state with client := next none})

def c10ByteCutoffObservation {K S R : Type*} :
    ((C10SessionResult R × Memo K Digest) ⊕ C10ByteExecutionState K S) →
      C10SessionResult (Option R) × Memo K Digest
  | .inl result => (mapSessionValue some result.1, result.2)
  | .inr state => (⟨none, state.ledger, state.rawRemaining, state.signRemaining⟩, state.table)

theorem c10_stateful_byte_kernel_cutoff {K S R : Type*} [DecidableEq K]
    (encode : WotsQuery → K) (cfg : C10SessionConfig) (step : S → PMF (C10ByteAction S R))
    (n : ℕ) (s : S) (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo K Digest) :
    (kernelCutoff (c10StatefulByteStep encode cfg step) n ⟨s, qr, qs, ledger, table⟩).map
        c10ByteCutoffObservation = c10StatefulByteCutoff encode cfg step n s qr qs ledger table := by
  induction n generalizing s qr qs ledger table with
  | zero => simp only [kernelCutoff, PMF.pure_map, c10ByteCutoffObservation, c10StatefulByteCutoff]
  | succ n ih =>
    simp only [kernelCutoff, c10StatefulByteStep, c10StatefulByteCutoff,
      PMF.map_bind, PMF.bind_bind]
    congr 1
    funext action
    cases action with
    | done value =>
      simp only [PMF.pure_bind, PMF.pure_map, c10ByteCutoffObservation, mapSessionValue]
    | tick next => simp only [PMF.pure_bind, ih]
    | hash key next =>
      cases qr with
      | zero => simp only [PMF.pure_bind, ih]
      | succ qr =>
        simp only [PMF.bind_map, Function.comp_def, ih]
    | sign req next =>
      cases qs with
      | zero => simp only [PMF.pure_bind, ih]
      | succ qs =>
        by_cases admitted : sessionAdmits ledger req = true
        · simp only [admitted, ↓reduceIte, PMF.bind_map, Function.comp_def, ih]
        · simp only [admitted, Bool.false_eq_true, ↓reduceIte, PMF.pure_bind, ih]

end
end C10Probability
