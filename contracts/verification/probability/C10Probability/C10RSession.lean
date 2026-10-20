import C10Probability.C10RSign
import C10Probability.SessionBudget

/-! An R-exhaustion observer of the complete adaptive C10 session. Client
continuations receive exactly the original replies, including refusals and
later WOTS failures. The observer flag is returned only after the client ends. -/
namespace C10Probability
noncomputable section

variable {K L R : Type*}

abbrev C10RSessionResult (R : Type*) := C10SessionResult R × Bool

def addC10RFlag (failed : Bool) (out : C10RSessionResult R) : C10RSessionResult R :=
  (out.1, failed || out.2)

def c10RSessionProgram (encode : WotsQuery → K) (cfg : C10SessionConfig) :
    {fuel : ℕ} → C10Client R fuel → (qr qs : ℕ) → C10SessionLedger →
      QueryProgram K Digest (C10RSessionResult R) (qr + qs * sessionSignCost cfg)
  | _, .done value, qr, qs, ledger => .done (⟨value, ledger, qr, qs⟩, false)
  | _, .hash _ next, 0, qs, ledger => c10RSessionProgram encode cfg (next 0) 0 qs ledger
  | _, .hash key next, qr + 1, qs, ledger =>
      castProgram (by omega) (.query (encode (.inl key))
        (fun reply => c10RSessionProgram encode cfg (next reply) qr qs ledger))
  | _, .sign _ next, qr, 0, ledger => c10RSessionProgram encode cfg (next none) qr 0 ledger
  | _, .sign req next, qr, qs + 1, ledger =>
      if sessionAdmits ledger req then
        castProgram (by simp only [Nat.add_mul, Nat.one_mul, sessionSignCost]; omega)
          (bindProgram (c10RSignProgram encode req.random req.message cfg.seed cfg.root req.shuffle
            cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound)
            (fun reply => mapReturnProgram (addC10RFlag reply.2)
              (c10RSessionProgram encode cfg (next reply.1) qr qs
                (sessionAfterSign ledger req.message reply.1))))
      else c10RSessionProgram encode cfg (next none) qr (qs + 1) ledger

attribute [irreducible] c10RSessionProgram

def c10RSession [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig) :
    {fuel : ℕ} → C10Client R fuel → ℕ → ℕ → C10SessionLedger → Memo K Digest →
      PMF (C10RSessionResult R × Memo K Digest)
  | _, .done value, qr, qs, ledger, table => PMF.pure ((⟨value, ledger, qr, qs⟩, false), table)
  | _, .hash _ next, 0, qs, ledger, table => c10RSession encode cfg (next 0) 0 qs ledger table
  | _, .hash key next, qr + 1, qs, ledger, table =>
      (memoQuery digestDraw table (encode (.inl key))).bind
        (fun reply => c10RSession encode cfg (next reply.1) qr qs ledger reply.2)
  | _, .sign _ next, qr, 0, ledger, table =>
      c10RSession encode cfg (next none) qr 0 ledger table
  | _, .sign req next, qr, qs + 1, ledger, table =>
      if sessionAdmits ledger req then
        (c10RSign encode table req.random req.message cfg.seed cfg.root req.shuffle
          cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound).bind
          (fun reply => (c10RSession encode cfg (next reply.1.1) qr qs
            (sessionAfterSign ledger req.message reply.1.1) reply.2).map
              (fun out => (addC10RFlag reply.1.2 out.1, out.2)))
      else c10RSession encode cfg (next none) qr (qs + 1) ledger table

theorem c10_r_session_eval [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel)
    (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo K Digest) :
    evalProgram digestDraw (c10RSessionProgram encode cfg client qr qs ledger) table =
      c10RSession encode cfg client qr qs ledger table := by
  induction client generalizing qr qs ledger table with
  | done value => simp only [c10RSessionProgram, c10RSession, evalProgram]
  | hash key next ih =>
      cases qr <;> simp only [c10RSessionProgram, c10RSession, evalProgram_cast, evalProgram, ih]
  | sign req next ih =>
      cases qs with
      | zero => simp only [c10RSessionProgram, c10RSession, ih]
      | succ qs =>
          cases h : sessionAdmits ledger req <;>
            simp only [c10RSessionProgram, c10RSession, h, Bool.false_eq_true, ↓reduceIte,
              evalProgram_cast, evalProgram_bind, c10_r_sign_eval, evalProgram_mapReturn, ih]

theorem c10_r_session_erases [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel)
    (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo K Digest) :
    (c10RSession encode cfg client qr qs ledger table).map (fun out => (out.1.1, out.2)) =
      c10Session encode cfg client qr qs ledger table := by
  induction client generalizing qr qs ledger table with
  | done value => simp only [c10RSession, c10Session, PMF.pure_map]
  | hash key next ih =>
      cases qr <;> simp only [c10RSession, c10Session, PMF.map_bind, ih]
  | sign req next ih =>
      cases qs with
      | zero => simp only [c10RSession, c10Session, ih]
      | succ qs =>
          cases h : sessionAdmits ledger req
          · simp only [c10RSession, c10Session, h, Bool.false_eq_true, ↓reduceIte, ih]
          · simp only [c10RSession, c10Session, h, ↓reduceIte, PMF.map_bind,
              PMF.map_comp, Function.comp_def, addC10RFlag, ih]
            rw [← c10_r_sign_erases encode table req.random req.message cfg.seed cfg.root
              req.shuffle cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound, PMF.bind_map]
            rfl

theorem c10_r_session_map (encode : K → L) (labels : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel)
    (qr qs : ℕ) (ledger : C10SessionLedger) :
    mapProgram encode (c10RSessionProgram labels cfg client qr qs ledger) =
      c10RSessionProgram (encode ∘ labels) cfg client qr qs ledger := by
  induction client generalizing qr qs ledger with
  | done value => simp only [c10RSessionProgram, mapProgram]
  | hash key next ih =>
      cases qr <;> simp only [c10RSessionProgram, mapProgram_cast, mapProgram, ih, Function.comp_def]
  | sign req next ih =>
      cases qs with
      | zero => simp only [c10RSessionProgram, ih]
      | succ qs =>
          cases h : sessionAdmits ledger req <;>
            simp only [c10RSessionProgram, h, Bool.false_eq_true, ↓reduceIte, mapProgram_cast,
              mapProgram_bind, c10_r_sign_map, mapProgram_mapReturn, ih]

theorem c10_r_session_public (cfg : C10SessionConfig) {fuel : ℕ}
    (client : C10Client R fuel) (qr qs : ℕ) (ledger : C10SessionLedger) :
    PublicBudget (c10RSessionProgram id cfg client qr qs ledger)
      (qr + qs * sessionSignPublic cfg) := by
  induction client generalizing qr qs ledger with
  | done value => simp only [c10RSessionProgram, PublicBudget]
  | hash key next ih =>
      cases qr with
      | zero => simpa only [c10RSessionProgram] using ih 0 0 qs ledger
      | succ qr =>
          simp only [c10RSessionProgram, publicBudget_cast, id_eq, PublicBudget]
          refine ⟨by omega, fun reply => ?_⟩
          simpa only [show qr + 1 + qs * sessionSignPublic cfg - 1 =
            qr + qs * sessionSignPublic cfg by omega] using ih reply qr qs ledger
  | sign req next ih =>
      cases qs with
      | zero => simpa only [c10RSessionProgram] using ih none qr 0 ledger
      | succ qs =>
          cases h : sessionAdmits ledger req
          · simpa only [c10RSessionProgram, h, Bool.false_eq_true, ↓reduceIte] using
              ih none qr (qs + 1) ledger
          · simp only [c10RSessionProgram, h, ↓reduceIte, publicBudget_cast]
            rw [show qr + (qs + 1) * sessionSignPublic cfg =
              sessionSignPublic cfg + (qr + qs * sessionSignPublic cfg) by ring]
            apply publicBudget_bind _ _ _ _ (c10_r_sign_public _ _ _ _ _ _ _ _ _)
            intro reply
            rw [publicBudget_mapReturn]
            exact ih reply.1 qr qs (sessionAfterSign ledger req.message reply.1)

end
end C10Probability
