import C10Probability.RSessionTypes

/-! Independent direct interpreter and query-program compiler for the adaptive
R session. Their equality includes the full output, ordered ledger, remaining
caps, and memo table. No positivity premise excludes zero-trial searches. -/
namespace C10Probability
noncomputable section

variable {K L R : Type*}

def rSessionProgram (encode : Sum ByteKey ByteKey → K) (cfg : RSessionConfig) :
    {fuel : ℕ} → RGrindClient R fuel → (qr qs : ℕ) → RGrindLedger →
      QueryProgram K Digest (RGrindResult R) (qr + qs * (2 * cfg.trials))
  | _, .done value, qr, qs, ledger => .done ⟨value, ledger, qr, qs⟩
  | _, .hash _ next, 0, qs, ledger => rSessionProgram encode cfg (next 0) 0 qs ledger
  | _, .hash key next, qr + 1, qs, ledger =>
      castProgram (by omega) (.query (encode (.inl key))
        (fun reply => rSessionProgram encode cfg (next reply) qr qs ledger))
  | _, .grind _ next, qr, 0, ledger => rSessionProgram encode cfg (next none) qr 0 ledger
  | _, .grind context next, qr, qs + 1, ledger =>
      if rSessionAdmits ledger context then
        castProgram (by simp only [Nat.add_mul, Nat.one_mul]; omega)
          (bindProgram (randomizerUnderProgram encode context.1 context.2 cfg.seed cfg.root
            cfg.trials cfg.bound)
            (fun reply => rSessionProgram encode cfg (next reply) qr qs
              (rSessionAfterGrind ledger context reply)))
      else rSessionProgram encode cfg (next none) qr (qs + 1) ledger

attribute [irreducible] rSessionProgram

def rSession [DecidableEq K] (encode : Sum ByteKey ByteKey → K) (cfg : RSessionConfig) :
    {fuel : ℕ} → RGrindClient R fuel → ℕ → ℕ → RGrindLedger → Memo K Digest →
      PMF (RGrindResult R × Memo K Digest)
  | _, .done value, qr, qs, ledger, table => PMF.pure (⟨value, ledger, qr, qs⟩, table)
  | _, .hash _ next, 0, qs, ledger, table => rSession encode cfg (next 0) 0 qs ledger table
  | _, .hash key next, qr + 1, qs, ledger, table =>
      (memoQuery digestDraw table (encode (.inl key))).bind
        (fun reply => rSession encode cfg (next reply.1) qr qs ledger reply.2)
  | _, .grind _ next, qr, 0, ledger, table =>
      rSession encode cfg (next none) qr 0 ledger table
  | _, .grind context next, qr, qs + 1, ledger, table =>
      if rSessionAdmits ledger context then
        (randomizerUnder encode table context.1 context.2 cfg.seed cfg.root
          cfg.trials cfg.bound).bind
          (fun reply => rSession encode cfg (next reply.1) qr qs
            (rSessionAfterGrind ledger context reply.1) reply.2)
      else rSession encode cfg (next none) qr (qs + 1) ledger table

theorem r_session_eval [DecidableEq K] (encode : Sum ByteKey ByteKey → K)
    (cfg : RSessionConfig) {fuel : ℕ} (client : RGrindClient R fuel)
    (qr qs : ℕ) (ledger : RGrindLedger) (table : Memo K Digest) :
    evalProgram digestDraw (rSessionProgram encode cfg client qr qs ledger) table =
      rSession encode cfg client qr qs ledger table := by
  induction client generalizing qr qs ledger table with
  | done value => simp only [rSessionProgram, rSession, evalProgram]
  | hash key next ih =>
      cases qr <;> simp only [rSessionProgram, rSession, evalProgram_cast, evalProgram, ih]
  | grind context next ih =>
      cases qs with
      | zero => simp only [rSessionProgram, rSession, ih]
      | succ qs =>
          cases h : rSessionAdmits ledger context <;>
            simp only [rSessionProgram, rSession, h, Bool.false_eq_true, ↓reduceIte,
              evalProgram_cast, evalProgram_bind, randomizer_under_eval, ih]

theorem r_session_map (encode : K → L) (labels : Sum ByteKey ByteKey → K)
    (cfg : RSessionConfig) {fuel : ℕ} (client : RGrindClient R fuel)
    (qr qs : ℕ) (ledger : RGrindLedger) :
    mapProgram encode (rSessionProgram labels cfg client qr qs ledger) =
      rSessionProgram (encode ∘ labels) cfg client qr qs ledger := by
  induction client generalizing qr qs ledger with
  | done value => simp only [rSessionProgram, mapProgram]
  | hash key next ih =>
      cases qr <;> simp only [rSessionProgram, mapProgram_cast, mapProgram, ih, Function.comp_def]
  | grind context next ih =>
      cases qs with
      | zero => simp only [rSessionProgram, ih]
      | succ qs =>
          cases h : rSessionAdmits ledger context <;>
            simp only [rSessionProgram, h, Bool.false_eq_true, ↓reduceIte, mapProgram_cast,
              mapProgram_bind, randomizer_under_map, ih]

theorem r_session_public (cfg : RSessionConfig) {fuel : ℕ}
    (client : RGrindClient R fuel) (qr qs : ℕ) (ledger : RGrindLedger) :
    PublicBudget (rSessionProgram id cfg client qr qs ledger) (qr + qs * cfg.trials) := by
  induction client generalizing qr qs ledger with
  | done value => simp only [rSessionProgram, PublicBudget]
  | hash key next ih =>
      cases qr with
      | zero => simpa only [rSessionProgram] using ih 0 0 qs ledger
      | succ qr =>
          simp only [rSessionProgram, publicBudget_cast, id_eq, PublicBudget]
          refine ⟨by omega, fun reply => ?_⟩
          simpa only [show qr + 1 + qs * cfg.trials - 1 =
            qr + qs * cfg.trials by omega] using ih reply qr qs ledger
  | grind context next ih =>
      cases qs with
      | zero => simpa only [rSessionProgram] using ih none qr 0 ledger
      | succ qs =>
          cases h : rSessionAdmits ledger context
          · simpa only [rSessionProgram, h, Bool.false_eq_true, ↓reduceIte] using
              ih none qr (qs + 1) ledger
          · simp only [rSessionProgram, h, ↓reduceIte, publicBudget_cast]
            rw [show qr + (qs + 1) * cfg.trials =
              cfg.trials + (qr + qs * cfg.trials) by ring]
            apply publicBudget_bind _ _ _ _ (randomizer_under_public _ _ _ _ _ _)
            intro reply
            exact ih reply qr qs (rSessionAfterGrind ledger context reply)

theorem randomizer_under_independent (table : Memo (Sum ByteKey ByteKey) Digest)
    (context : RContext) (cfg : RSessionConfig) :
    randomizerUnder id table context.1 context.2 cfg.seed cfg.root cfg.trials cfg.bound =
      privateRandomizerSearch table context.1 context.2 cfg.seed cfg.root cfg.trials
        (by simpa using cfg.bound) := by
  rw [← randomizer_under_eval, randomizerUnderProgram, mapProgram_id,
    privateRandomizerProgram_independent]

end
end C10Probability
