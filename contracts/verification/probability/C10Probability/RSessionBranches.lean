import C10Probability.RSessionState

/-! Exact cache-preserving branch equations for the adaptive R session.
They expose the admission boundary independently of the recursive compiler. -/
namespace C10Probability
noncomputable section

variable {K R : Type*}

theorem r_session_hash_capped [DecidableEq K] (encode : Sum ByteKey ByteKey → K)
    (cfg : RSessionConfig) {fuel : ℕ} (key : ByteKey) (next : Digest → RGrindClient R fuel)
    (qs : ℕ) (ledger : RGrindLedger) (table : Memo K Digest) :
    rSession encode cfg (.hash key next) 0 qs ledger table =
      rSession encode cfg (next 0) 0 qs ledger table := by
  exact rfl

theorem r_session_hash_live [DecidableEq K] (encode : Sum ByteKey ByteKey → K)
    (cfg : RSessionConfig) {fuel : ℕ} (key : ByteKey) (next : Digest → RGrindClient R fuel)
    (qr qs : ℕ) (ledger : RGrindLedger) (table : Memo K Digest) :
    rSession encode cfg (.hash key next) (qr + 1) qs ledger table =
      (memoQuery digestDraw table (encode (.inl key))).bind
        (fun reply => rSession encode cfg (next reply.1) qr qs ledger reply.2) := by
  exact rfl

theorem r_session_grind_capped [DecidableEq K] (encode : Sum ByteKey ByteKey → K)
    (cfg : RSessionConfig) {fuel : ℕ} (req : RContext)
    (next : Option RSearchResult → RGrindClient R fuel) (qr : ℕ)
    (ledger : RGrindLedger) (table : Memo K Digest) :
    rSession encode cfg (.grind req next) qr 0 ledger table =
      rSession encode cfg (next none) qr 0 ledger table := by
  exact rfl

theorem r_session_grind_refused [DecidableEq K] (encode : Sum ByteKey ByteKey → K)
    (cfg : RSessionConfig) {fuel : ℕ} (req : RContext)
    (next : Option RSearchResult → RGrindClient R fuel) (qr qs : ℕ)
    (ledger : RGrindLedger) (table : Memo K Digest) (ha : rSessionAdmits ledger req = false) :
    rSession encode cfg (.grind req next) qr qs ledger table =
      rSession encode cfg (next none) qr qs ledger table := by
  cases qs <;> simp only [rSession, ha, Bool.false_eq_true, ↓reduceIte]

theorem r_session_grind_exhausted [DecidableEq K] (encode : Sum ByteKey ByteKey → K)
    (cfg : RSessionConfig) {fuel : ℕ} (req : RContext)
    (next : Option RSearchResult → RGrindClient R fuel) (qr qs : ℕ)
    (ledger : RGrindLedger) (table finalTable : Memo K Digest)
    (ha : rSessionAdmits ledger req = true)
    (execution : randomizerUnder encode table req.1 req.2 cfg.seed cfg.root cfg.trials cfg.bound = PMF.pure (none, finalTable)) :
    rSession encode cfg (.grind req next) qr (qs + 1) ledger table =
      rSession encode cfg (next none) qr qs ⟨ledger.contexts, true⟩ finalTable := by
  simp only [rSession, ha, ↓reduceIte, execution, PMF.pure_bind, rSessionAfterGrind]

theorem r_session_grind_returned [DecidableEq K] (encode : Sum ByteKey ByteKey → K)
    (cfg : RSessionConfig) {fuel : ℕ} (req : RContext)
    (next : Option RSearchResult → RGrindClient R fuel) (qr qs : ℕ)
    (ledger : RGrindLedger) (table finalTable : Memo K Digest) (sig : RSearchResult)
    (ha : rSessionAdmits ledger req = true)
    (execution : randomizerUnder encode table req.1 req.2 cfg.seed cfg.root cfg.trials cfg.bound = PMF.pure (some sig, finalTable)) :
    rSession encode cfg (.grind req next) qr (qs + 1) ledger table =
      rSession encode cfg (next (some sig)) qr qs
        ⟨ledger.contexts ++ [req], ledger.failed⟩ finalTable := by
  simp only [rSession, ha, ↓reduceIte, execution, PMF.pure_bind, rSessionAfterGrind]

end
end C10Probability
