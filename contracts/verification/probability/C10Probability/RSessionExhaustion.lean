import C10Probability.RSessionInvariant
import C10Probability.RSessionMass
import C10Probability.RContextExhaustion

/-! First exhaustion in a finite adaptive session. The initialized endpoint
derives all private-input freshness and public-history premises from execution.
Caps bound admitted calls, independently of attempted-call fuel. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {R : Type*}

def rSessionFailure (out : RGrindResult R) : Bool := out.ledger.failed

theorem r_session_exhaustion_bound (cfg : RSessionConfig) {fuel : ℕ}
    (client : RGrindClient R fuel) (qr qs : ℕ) (ledger : RGrindLedger)
    (history total : ℕ) (table : Memo (Sum ByteKey ByteKey) Digest)
    (invariant : RSessionInvariant cfg ledger history table)
    (healthy : ledger.failed = false)
    (budget : history + qr + qs * cfg.trials ≤ total) :
    ((rSession id cfg client qr qs ledger table).map
      (fun out => rSessionFailure out.1)) true ≤
        (qs : ℝ≥0∞) * rExhaustionCharge total cfg.trials := by
  induction client generalizing qr qs ledger history table with
  | done value => simp [rSession, PMF.pure_map, rSessionFailure, healthy]
  | hash key next ih =>
      cases qr with
      | zero => exact ih 0 0 qs ledger history table invariant healthy budget
      | succ qr =>
          simp only [rSession]
          apply r_bind_flag_bound
          intro reply supported
          exact ih reply.1 qr qs ledger (history + 1) reply.2
            (r_session_invariant_query cfg ledger history table invariant key reply supported)
            healthy (by omega)
  | grind context next ih =>
      cases qs with
      | zero => exact ih none qr 0 ledger history table invariant healthy budget
      | succ qs =>
          cases admitted : rSessionAdmits ledger context
          · simp only [rSession, admitted, Bool.false_eq_true, ↓reduceIte]
            exact ih none qr (qs + 1) ledger history table invariant healthy budget
          · simp only [rSession, admitted, ↓reduceIte]
            have valid := ((r_session_admits_iff ledger context).mp admitted).2
            have single :
                ((randomizerUnder id table context.1 context.2 cfg.seed cfg.root
                  cfg.trials cfg.bound).map Prod.fst) none ≤
                    rExhaustionCharge total cfg.trials := by
              rw [randomizer_under_independent table context cfg]
              exact (r_context_exhaustion_bound ledger.contexts.toFinset table context valid
                cfg.seed cfg.root cfg.trials (by simpa using cfg.bound) history
                (invariant.2 healthy).1 (invariant.2 healthy).2 invariant.1).trans
                  (r_exhaustion_charge_mono history total cfg.trials (by omega))
            have step := r_bind_first_none_bound
              (randomizerUnder id table context.1 context.2 cfg.seed cfg.root cfg.trials cfg.bound)
              (fun reply => rSession id cfg (next reply.1) qr qs
                (rSessionAfterGrind ledger context reply.1) reply.2)
              (fun out => rSessionFailure out.1)
              ((qs : ℝ≥0∞) * rExhaustionCharge total cfg.trials) ?_
            · calc
                _ ≤ _ := step
                _ ≤ rExhaustionCharge total cfg.trials +
                    (qs : ℝ≥0∞) * rExhaustionCharge total cfg.trials :=
                  add_le_add single le_rfl
                _ = ((qs + 1 : ℕ) : ℝ≥0∞) * rExhaustionCharge total cfg.trials := by
                  rw [Nat.cast_add, Nat.cast_one, add_mul, one_mul, add_comm]
            · intro result after supported
              apply ih (some result) qr qs (rSessionAfterGrind ledger context (some result))
                (history + cfg.trials) after
              · exact r_session_invariant_search cfg ledger history table invariant context admitted
                  (some result, after) supported
              · exact healthy
              · simp only [Nat.add_mul, Nat.one_mul] at budget
                omega

theorem r_session_initialized_exhaustion (cfg : RSessionConfig) {fuel : ℕ}
    (client : RGrindClient R fuel) (qr qs : ℕ) :
    ((rSession id cfg client qr qs emptyRGrindLedger (fun _ => none)).map
      (fun out => rSessionFailure out.1)) true ≤
        (qs : ℝ≥0∞) * rExhaustionCharge (qr + qs * cfg.trials) cfg.trials := by
  exact r_session_exhaustion_bound cfg client qr qs emptyRGrindLedger
    0 (qr + qs * cfg.trials) (fun _ => none)
    (r_session_invariant_empty cfg) rfl (by omega)

theorem r_session_randomized_exhaustion (cfg : RSessionConfig) {fuel : ℕ}
    (clients : PMF (RGrindClient R fuel)) (qr qs : ℕ) :
    ((clients.bind (fun client =>
      rSession id cfg client qr qs emptyRGrindLedger (fun _ => none))).map
      (fun out => rSessionFailure out.1)) true ≤
        (qs : ℝ≥0∞) * rExhaustionCharge (qr + qs * cfg.trials) cfg.trials := by
  apply r_bind_flag_bound
  intro client _
  exact r_session_initialized_exhaustion cfg client qr qs

end
end C10Probability
