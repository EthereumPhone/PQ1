import C10Probability.RContextReplay
import C10Probability.RandomizerUnder

/-! Finite adaptive R-grinding clients. Attempted interactions, admitted public
calls, and admitted searches have separate bounds. Successful contexts are
recorded chronologically, including repetitions. Exhaustion is persistent. -/
namespace C10Probability
noncomputable section

structure RSessionConfig where
  seed : ByteKey
  root : ByteKey
  trials : ℕ
  bound : trials ≤ 2 ^ 32

structure RGrindLedger where
  contexts : List RContext
  failed : Bool
  deriving DecidableEq

def emptyRGrindLedger : RGrindLedger := ⟨[], false⟩

def rSessionAdmits (ledger : RGrindLedger) (context : RContext) : Bool :=
  !ledger.failed && decide (context.2.length = 32 ∧
    (context.1.length = 0 ∨ context.1.length = 16))

def rSessionAfterGrind (ledger : RGrindLedger) (context : RContext)
    (reply : Option RSearchResult) : RGrindLedger :=
  match reply with
  | none => ⟨ledger.contexts, true⟩
  | some _ => ⟨ledger.contexts ++ [context], ledger.failed⟩

inductive RGrindClient (R : Type*) : ℕ → Type _ where
  | done {fuel : ℕ} (value : R) : RGrindClient R fuel
  | hash {fuel : ℕ} (key : ByteKey) (next : Digest → RGrindClient R fuel) :
      RGrindClient R (fuel + 1)
  | grind {fuel : ℕ} (context : RContext)
      (next : Option RSearchResult → RGrindClient R fuel) : RGrindClient R (fuel + 1)

structure RGrindResult (R : Type*) where
  value : R
  ledger : RGrindLedger
  rawRemaining : ℕ
  grindRemaining : ℕ

theorem r_session_admits_iff (ledger : RGrindLedger) (context : RContext) :
    rSessionAdmits ledger context = true ↔
      ledger.failed = false ∧ validRContext context := by
  simp [rSessionAdmits, validRContext]

theorem r_session_failed_refuses (ledger : RGrindLedger) (context : RContext)
    (failed : ledger.failed = true) : rSessionAdmits ledger context = false := by
  simp [rSessionAdmits, failed]

theorem r_session_malformed_refuses (ledger : RGrindLedger) (context : RContext)
    (invalid : ¬ validRContext context) : rSessionAdmits ledger context = false := by
  cases admitted : rSessionAdmits ledger context with
  | false => rfl
  | true => exact (invalid ((r_session_admits_iff ledger context).mp admitted).2).elim

theorem r_session_none_absorbs (ledger : RGrindLedger) (context : RContext) :
    (rSessionAfterGrind ledger context none).failed = true ∧
      (rSessionAfterGrind ledger context none).contexts = ledger.contexts := by
  exact ⟨rfl, rfl⟩

theorem r_session_some_records (ledger : RGrindLedger) (context : RContext)
    (result : RSearchResult) :
    (rSessionAfterGrind ledger context (some result)).contexts = ledger.contexts ++ [context] ∧
      (rSessionAfterGrind ledger context (some result)).failed = ledger.failed := by
  exact ⟨rfl, rfl⟩

end
end C10Probability
