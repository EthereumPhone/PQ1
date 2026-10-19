import C10Probability.ObservedGame

/-! Compile the existing passive observed session and initialized game. The
equations preserve exposures, forwarded queries, final output and full cache. -/
namespace C10Probability
noncomputable section
variable {K R : Type*}

def c10ObservedSessionProgram (encode : WotsQuery → K) (cfg : C10SessionConfig) :
    {fuel : ℕ} → C10Client R fuel → (qr qs : ℕ) → C10SessionLedger →
      QueryProgram K Digest (C10ObservedSession R) (qr + qs * sessionSignCost cfg)
  | _, .done value, qr, qs, ledger => .done ⟨⟨value, ledger, qr, qs⟩, [], []⟩
  | _, .hash _ next, 0, qs, ledger => c10ObservedSessionProgram encode cfg (next 0) 0 qs ledger
  | _, .hash key next, qr + 1, qs, ledger =>
      castProgram (by omega) (.query (encode (.inl key)) (fun reply =>
        mapReturnProgram (observeHash key)
          (c10ObservedSessionProgram encode cfg (next reply) qr qs ledger)))
  | _, .sign _ next, qr, 0, ledger => c10ObservedSessionProgram encode cfg (next none) qr 0 ledger
  | _, .sign req next, qr, qs + 1, ledger =>
      if sessionAdmits ledger req then
        castProgram (by simp only [Nat.add_mul, Nat.one_mul, sessionSignCost]; omega)
          (bindProgram (c10SignProgram encode req.random req.message cfg.seed cfg.root req.shuffle
            cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound) (fun reply =>
              mapReturnProgram (observeSign req reply)
                (c10ObservedSessionProgram encode cfg (next reply) qr qs
                  (sessionAfterSign ledger req.message reply))))
      else c10ObservedSessionProgram encode cfg (next none) qr (qs + 1) ledger

attribute [irreducible] c10ObservedSessionProgram

theorem c10_observed_session_program_eval [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest) :
    evalProgram digestDraw (c10ObservedSessionProgram encode cfg client qr qs ledger) table =
      c10ObservedSession encode cfg client qr qs ledger table := by
  induction client generalizing qr qs ledger table with
  | done value => simp only [c10ObservedSessionProgram, c10ObservedSession, evalProgram]
  | hash key next ih =>
    cases qr <;> simp only [c10ObservedSessionProgram, c10ObservedSession,
      evalProgram_cast, evalProgram, evalProgram_mapReturn, ih]
  | sign req next ih =>
    cases qs with
    | zero => simp only [c10ObservedSessionProgram, c10ObservedSession, ih]
    | succ qs =>
      cases admitted : sessionAdmits ledger req <;>
        simp only [c10ObservedSessionProgram, c10ObservedSession, admitted, Bool.false_eq_true,
          ↓reduceIte, evalProgram_cast, evalProgram_bind, c10_sign_eval,
          evalProgram_mapReturn, ih]

def c10ObservedDriverProgram (encode : WotsQuery → K) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    QueryProgram K Digest C10ObservedDriver (361 + (qr + qs * sessionSignCost cfg)) :=
  bindProgram (c10ObservedSessionProgram encode cfg client qr qs emptySessionLedger)
    (fun observed => mapReturnProgram (fun accepted => ⟨observed, accepted⟩)
      (c10FinalProgram encode cfg observed.session))

theorem c10_observed_driver_program_eval [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) :
    evalProgram digestDraw (c10ObservedDriverProgram encode cfg client qr qs) table =
      c10ObservedDriver encode cfg client qr qs table := by
  simp only [c10ObservedDriverProgram, evalProgram_bind, c10_observed_session_program_eval,
    evalProgram_mapReturn, c10_final_eval, c10ObservedDriver]

def c10ObservedGameProgram (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    QueryProgram K Digest C10ObservedGame ((361 + (qr + qs * sessionSignCost cfg)) + 177151) :=
  bindProgram (c10KeygenProgram encode publicSeed) (fun key =>
    mapReturnProgram (fun driver => ⟨key, driver⟩)
      (c10ObservedDriverProgram encode (sessionConfigAt cfg key) (adversary key.1 key.2) qr qs))

theorem c10_observed_game_program_eval [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo K Digest) :
    evalProgram digestDraw (c10ObservedGameProgram encode cfg publicSeed adversary qr qs) table =
      c10ObservedGame encode cfg publicSeed adversary qr qs table := by
  simp only [c10ObservedGameProgram, evalProgram_bind, c10_keygen_eval,
    evalProgram_mapReturn, c10ObservedGame]
  congr 1
  funext key
  exact congrArg (PMF.map (fun out : C10ObservedDriver × Memo K Digest =>
    (C10ObservedGame.mk key.1 out.1, out.2)))
    (c10_observed_driver_program_eval encode (sessionConfigAt cfg key.1)
      (adversary key.1.1 key.1.2) qr qs key.2)

end
end C10Probability
