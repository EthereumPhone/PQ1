import C10Probability.ByteStatefulTypes

/-! Direct finite observations of the stateful byte session. Exhaustion returns
`none` while a completed client returns `some value`; both retain the actual
ledger, remaining caps and oracle cache. All existing admission rules remain. -/
namespace C10Probability
noncomputable section

def c10StatefulByteCutoff {K S R : Type*} [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (step : S → PMF (C10ByteAction S R)) :
    ℕ → S → ℕ → ℕ → C10SessionLedger → Memo K Digest →
      PMF (C10SessionResult (Option R) × Memo K Digest)
  | 0, _, qr, qs, ledger, table => PMF.pure (⟨none, ledger, qr, qs⟩, table)
  | n + 1, s, qr, qs, ledger, table => (step s).bind fun action => match action with
    | .done value => PMF.pure (⟨some value, ledger, qr, qs⟩, table)
    | .tick next => c10StatefulByteCutoff encode cfg step n next qr qs ledger table
    | .hash key next => match qr with
      | 0 => c10StatefulByteCutoff encode cfg step n (next 0) 0 qs ledger table
      | qr + 1 => (memoQuery digestDraw table (encode (.inl key))).bind fun reply =>
          c10StatefulByteCutoff encode cfg step n (next reply.1) qr qs ledger reply.2
    | .sign req next => match qs with
      | 0 => c10StatefulByteCutoff encode cfg step n (next none) qr 0 ledger table
      | qs + 1 => if sessionAdmits ledger req then
          (c10SignBytes encode cfg req table).bind fun reply =>
            c10StatefulByteCutoff encode cfg step n (next reply.1) qr qs
              (byteAfterSign ledger req.message reply.1) reply.2
        else c10StatefulByteCutoff encode cfg step n (next none) qr (qs + 1) ledger table

end
end C10Probability
