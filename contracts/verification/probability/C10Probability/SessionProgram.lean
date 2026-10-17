import C10Probability.SessionTypes

/-! Compile the adaptive client through the complete signer. The raw index is
derived from remaining admitted-call caps, independent of attempted-call fuel.
Refused calls return the specified default without touching the oracle. -/
namespace C10Probability
noncomputable section

variable {K L R : Type*}

def c10SessionProgram (encode : WotsQuery → K) (cfg : C10SessionConfig) :
    {fuel : ℕ} → C10Client R fuel → (qr qs : ℕ) → C10SessionLedger →
      QueryProgram K Digest (C10SessionResult R) (qr + qs * sessionSignCost cfg)
  | _, .done value, qr, qs, ledger => .done ⟨value, ledger, qr, qs⟩
  | _, .hash _ next, 0, qs, ledger => c10SessionProgram encode cfg (next 0) 0 qs ledger
  | _, .hash key next, qr + 1, qs, ledger =>
      castProgram (by omega) (.query (encode (.inl key))
        (fun reply => c10SessionProgram encode cfg (next reply) qr qs ledger))
  | _, .sign _ next, qr, 0, ledger => c10SessionProgram encode cfg (next none) qr 0 ledger
  | _, .sign req next, qr, qs + 1, ledger =>
      if sessionAdmits ledger req then
        castProgram (by simp only [Nat.add_mul, Nat.one_mul, sessionSignCost]; omega)
          (bindProgram (c10SignProgram encode req.random req.message cfg.seed cfg.root req.shuffle
            cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound)
            (fun reply => c10SessionProgram encode cfg (next reply) qr qs
              (sessionAfterSign ledger req.message reply)))
      else c10SessionProgram encode cfg (next none) qr (qs + 1) ledger

attribute [irreducible] c10SessionProgram

def c10Session [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig) :
    {fuel : ℕ} → C10Client R fuel → ℕ → ℕ → C10SessionLedger → Memo K Digest →
      PMF (C10SessionResult R × Memo K Digest)
  | _, .done value, qr, qs, ledger, table => PMF.pure (⟨value, ledger, qr, qs⟩, table)
  | _, .hash _ next, 0, qs, ledger, table => c10Session encode cfg (next 0) 0 qs ledger table
  | _, .hash key next, qr + 1, qs, ledger, table =>
      (memoQuery digestDraw table (encode (.inl key))).bind
        (fun reply => c10Session encode cfg (next reply.1) qr qs ledger reply.2)
  | _, .sign _ next, qr, 0, ledger, table =>
      c10Session encode cfg (next none) qr 0 ledger table
  | _, .sign req next, qr, qs + 1, ledger, table =>
      if sessionAdmits ledger req then
        (c10Sign encode table req.random req.message cfg.seed cfg.root req.shuffle
          cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound).bind
          (fun reply => c10Session encode cfg (next reply.1) qr qs
            (sessionAfterSign ledger req.message reply.1) reply.2)
      else c10Session encode cfg (next none) qr (qs + 1) ledger table

theorem c10_session_eval [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ) (ledger : C10SessionLedger)
    (table : Memo K Digest) :
    evalProgram digestDraw (c10SessionProgram encode cfg client qr qs ledger) table =
      c10Session encode cfg client qr qs ledger table := by
  induction client generalizing qr qs ledger table with
  | done value => simp only [c10SessionProgram, c10Session, evalProgram]
  | hash key next ih =>
      cases qr <;> simp only [c10SessionProgram, c10Session, evalProgram_cast, evalProgram, ih]
  | sign req next ih =>
      cases qs with
      | zero => simp only [c10SessionProgram, c10Session, ih]
      | succ qs =>
          cases h : sessionAdmits ledger req <;>
            simp only [c10SessionProgram, c10Session, h, Bool.false_eq_true, ↓reduceIte,
              evalProgram_cast, evalProgram_bind, c10_sign_eval, ih]

theorem c10_session_map (encode : K → L) (labels : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel)
    (qr qs : ℕ) (ledger : C10SessionLedger) :
    mapProgram encode (c10SessionProgram labels cfg client qr qs ledger) =
      c10SessionProgram (encode ∘ labels) cfg client qr qs ledger := by
  induction client generalizing qr qs ledger with
  | done value => simp only [c10SessionProgram, mapProgram]
  | hash key next ih =>
      cases qr <;> simp only [c10SessionProgram, mapProgram_cast, mapProgram, ih, Function.comp_def]
  | sign req next ih =>
      cases qs with
      | zero => simp only [c10SessionProgram, ih]
      | succ qs =>
          cases h : sessionAdmits ledger req <;>
            simp only [c10SessionProgram, h, Bool.false_eq_true, ↓reduceIte, mapProgram_cast,
              mapProgram_bind, c10_sign_map, ih]

end
end C10Probability
