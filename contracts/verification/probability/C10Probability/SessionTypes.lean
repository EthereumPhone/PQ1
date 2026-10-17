import C10Probability.C10Sign
import C10Probability.C10Access

/-! Finite adaptive structured clients. The index bounds attempted interactions,
including refused calls; accepted hash/sign caps are separate. Remaining caps
represent nonnegative FullSession limits minus admitted-call counters. -/
namespace C10Probability
noncomputable section

structure C10SignRequest where
  random : ByteKey
  message : ByteKey
  shuffle : ByteKey

structure C10SessionConfig where
  seed : ByteKey
  root : ByteKey
  rTrials : ℕ
  wTrials : ℕ
  rBound : rTrials ≤ 2 ^ 32
  wBound : wTrials ≤ 2 ^ 32

def sessionSignCost (cfg : C10SessionConfig) : ℕ :=
  2 * cfg.rTrials + 2 * cfg.wTrials + 435044

def sessionSignPublic (cfg : C10SessionConfig) : ℕ :=
  cfg.rTrials + 2 * cfg.wTrials + 364290

def sessionSignSelected (cfg : C10SessionConfig) : ℕ := cfg.rTrials + 435042

structure C10SessionLedger where
  signedMessages : List ByteKey
  failed : Bool
  deriving DecidableEq

def emptySessionLedger : C10SessionLedger := ⟨[], false⟩

def sessionAdmits (ledger : C10SessionLedger) (req : C10SignRequest) : Bool :=
  !ledger.failed && decide (req.message.length = 32 ∧
    (req.random.length = 0 ∨ req.random.length = 16) ∧ req.shuffle.length = 32)

def sessionAfterSign (ledger : C10SessionLedger) (message : ByteKey)
    (reply : Option C10Signature) : C10SessionLedger :=
  match reply with
  | none => ⟨ledger.signedMessages, true⟩
  | some _ => ⟨ledger.signedMessages ++ [message], ledger.failed⟩

inductive C10Client (R : Type*) : ℕ → Type _ where
  | done {fuel : ℕ} (value : R) : C10Client R fuel
  | hash {fuel : ℕ} (key : ByteKey) (next : Digest → C10Client R fuel) : C10Client R (fuel + 1)
  | sign {fuel : ℕ} (req : C10SignRequest)
      (next : Option C10Signature → C10Client R fuel) : C10Client R (fuel + 1)

structure C10SessionResult (R : Type*) where
  value : R
  ledger : C10SessionLedger
  rawRemaining : ℕ
  signRemaining : ℕ

theorem session_admits_iff (ledger : C10SessionLedger) (req : C10SignRequest) :
    sessionAdmits ledger req = true ↔ ledger.failed = false ∧ req.message.length = 32 ∧
      (req.random.length = 0 ∨ req.random.length = 16) ∧ req.shuffle.length = 32 := by
  simp [sessionAdmits]

theorem session_failed_refuses (ledger : C10SessionLedger) (req : C10SignRequest)
    (failed : ledger.failed = true) : sessionAdmits ledger req = false := by
  simp [sessionAdmits, failed]

theorem session_none_absorbs (ledger : C10SessionLedger) (message : ByteKey) :
    (sessionAfterSign ledger message none).failed = true ∧
      (sessionAfterSign ledger message none).signedMessages = ledger.signedMessages := by
  exact ⟨rfl, rfl⟩

theorem session_some_records (ledger : C10SessionLedger) (message : ByteKey)
    (sig : C10Signature) :
    (sessionAfterSign ledger message (some sig)).signedMessages = ledger.signedMessages ++ [message] ∧
      (sessionAfterSign ledger message (some sig)).failed = ledger.failed := by
  exact ⟨rfl, rfl⟩

theorem session_sign_cost_positive (cfg : C10SessionConfig) : 0 < sessionSignCost cfg := by
  unfold sessionSignCost
  omega

end
end C10Probability
