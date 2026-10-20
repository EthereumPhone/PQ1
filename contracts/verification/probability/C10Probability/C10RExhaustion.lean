import C10Probability.C10RSession
import C10Probability.C10RInvariant
import C10Probability.RSessionMass

/-! First R-search exhaustion in the actual complete adaptive C10 session.
Other signing failures stop subsequent signing but do not set the R flag.
The bound uses actual public-history coverage and cached successful replay. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {R : Type*}

theorem c10_r_session_exhaustion (cfg : C10SessionConfig) {fuel : ℕ}
    (client : C10Client R fuel) (qr qs : ℕ) (contexts : Finset RContext)
    (ledger : C10SessionLedger) (history total : ℕ) (table : Memo WotsQuery Digest)
    (invariant : C10RInvariant cfg contexts ledger history table)
    (budget : history + qr + qs * sessionSignPublic cfg ≤ total) :
    ((c10RSession id cfg client qr qs ledger table).map (fun out => out.1.2)) true ≤
      (qs : ℝ≥0∞) * rExhaustionCharge total cfg.rTrials := by
  induction client generalizing qr qs contexts ledger history table with
  | done value => simp [c10RSession, PMF.pure_map]
  | hash key next ih =>
      cases qr with
      | zero => exact ih 0 0 qs contexts ledger history table invariant budget
      | succ qr =>
          simp only [c10RSession]
          apply r_bind_flag_bound
          intro reply supported
          exact ih reply.1 qr qs contexts ledger (history + 1) reply.2
            (c10_r_invariant_query cfg contexts ledger history table invariant key reply supported)
            (by omega)
  | sign req next ih =>
      cases qs with
      | zero => exact ih none qr 0 contexts ledger history table invariant budget
      | succ qs =>
          cases admitted : sessionAdmits ledger req
          · simp only [c10RSession, admitted, Bool.false_eq_true, ↓reduceIte]
            exact ih none qr (qs + 1) contexts ledger history table invariant budget
          · simp only [c10RSession, admitted, ↓reduceIte, c10RSign,
              PMF.bind_bind, PMF.bind_map]
            obtain ⟨healthy, message, random, _⟩ := (session_admits_iff ledger req).mp admitted
            have single :
                ((randomizerUnder id table req.random req.message cfg.seed cfg.root
                  cfg.rTrials cfg.rBound).map Prod.fst) none ≤
                    rExhaustionCharge total cfg.rTrials := by
              rw [c10_randomizer_independent]
              exact (r_context_exhaustion_bound contexts table (req.random, req.message)
                ⟨message, random⟩ cfg.seed cfg.root cfg.rTrials (by simpa using cfg.rBound)
                history (invariant.2 healthy).1 (invariant.2 healthy).2 invariant.1).trans
                  (r_exhaustion_charge_mono history total cfg.rTrials (by omega))
            have step := r_bind_first_none_bound
              (randomizerUnder id table req.random req.message cfg.seed cfg.root
                cfg.rTrials cfg.rBound)
              (fun found => (c10SignAfter id found.2 cfg.seed req.shuffle cfg.wTrials
                cfg.wBound found.1).bind (fun reply =>
                  (c10RSession id cfg (next reply.1) qr qs
                    (sessionAfterSign ledger req.message reply.1) reply.2).map
                    (fun out => (addC10RFlag found.1.isNone out.1, out.2))))
              (fun out => out.1.2)
              ((qs : ℝ≥0∞) * rExhaustionCharge total cfg.rTrials) ?_
            · calc
                _ ≤ _ := step
                _ ≤ rExhaustionCharge total cfg.rTrials +
                    (qs : ℝ≥0∞) * rExhaustionCharge total cfg.rTrials :=
                  add_le_add single le_rfl
                _ = ((qs + 1 : ℕ) : ℝ≥0∞) * rExhaustionCharge total cfg.rTrials := by
                  rw [Nat.cast_add, Nat.cast_one, add_mul, one_mul, add_comm]
            · intro found middle searched
              apply r_bind_flag_bound
              intro reply finished
              simp only [PMF.map_comp, Function.comp_def, addC10RFlag,
                Option.isNone_some, Bool.false_or]
              apply ih reply.1 qr qs (insert (req.random, req.message) contexts)
                (sessionAfterSign ledger req.message reply.1)
                (history + sessionSignPublic cfg) reply.2
              · exact c10_r_invariant_after_found cfg contexts ledger history table invariant
                  req admitted found middle searched reply finished
              · simp only [Nat.add_mul, Nat.one_mul] at budget
                omega

end
end C10Probability
