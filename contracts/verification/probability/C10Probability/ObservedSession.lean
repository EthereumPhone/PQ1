import C10Probability.SessionState
import C10Probability.QueryReplay

/-! Passive records of actual client-visible signing returns and forwarded
raw queries. Refused requests are not recorded. Repeats remain in order, and
the observer never changes the reply delivered to the adaptive client. -/
namespace C10Probability
noncomputable section

variable {K R : Type*}

structure C10Exposure where
  request : C10SignRequest
  signature : C10Signature

structure C10ObservedSession (R : Type*) where
  session : C10SessionResult R
  exposures : List C10Exposure
  queries : List ByteKey

def observeHash (key : ByteKey) (out : C10ObservedSession R) : C10ObservedSession R :=
  { out with queries := key :: out.queries }

def observeSign (req : C10SignRequest) (reply : Option C10Signature)
    (out : C10ObservedSession R) : C10ObservedSession R :=
  match reply with
  | none => out
  | some sig => { out with exposures := ⟨req, sig⟩ :: out.exposures }

theorem observe_hash_session (key : ByteKey) (out : C10ObservedSession R) :
    (observeHash key out).session = out.session := rfl

theorem observe_sign_session (req : C10SignRequest) (reply : Option C10Signature)
    (out : C10ObservedSession R) : (observeSign req reply out).session = out.session := by
  cases reply <;> rfl

theorem observe_sign_none (req : C10SignRequest) (out : C10ObservedSession R) :
    observeSign req none out = out := rfl

theorem observe_sign_some (req : C10SignRequest) (sig : C10Signature)
    (out : C10ObservedSession R) :
    (observeSign req (some sig) out).exposures = ⟨req, sig⟩ :: out.exposures := rfl

def c10ObservedSession [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig) :
    {fuel : ℕ} → C10Client R fuel → ℕ → ℕ → C10SessionLedger → Memo K Digest →
      PMF (C10ObservedSession R × Memo K Digest)
  | _, .done value, qr, qs, ledger, table =>
      PMF.pure (⟨⟨value, ledger, qr, qs⟩, [], []⟩, table)
  | _, .hash _ next, 0, qs, ledger, table =>
      c10ObservedSession encode cfg (next 0) 0 qs ledger table
  | _, .hash key next, qr + 1, qs, ledger, table =>
      (memoQuery digestDraw table (encode (.inl key))).bind (fun reply =>
        (c10ObservedSession encode cfg (next reply.1) qr qs ledger reply.2).map
          (fun out => (observeHash key out.1, out.2)))
  | _, .sign _ next, qr, 0, ledger, table =>
      c10ObservedSession encode cfg (next none) qr 0 ledger table
  | _, .sign req next, qr, qs + 1, ledger, table =>
      if sessionAdmits ledger req then
        (c10Sign encode table req.random req.message cfg.seed cfg.root req.shuffle
          cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound).bind (fun reply =>
            (c10ObservedSession encode cfg (next reply.1) qr qs
              (sessionAfterSign ledger req.message reply.1) reply.2).map
                (fun out => (observeSign req reply.1 out.1, out.2)))
      else c10ObservedSession encode cfg (next none) qr (qs + 1) ledger table

theorem c10_observed_session_erases [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest) :
    (c10ObservedSession encode cfg client qr qs ledger table).map
      (fun out => (out.1.session, out.2)) = c10Session encode cfg client qr qs ledger table := by
  induction client generalizing qr qs ledger table with
  | done value => simp only [c10ObservedSession, c10Session, PMF.pure_map]
  | hash key next ih =>
    cases qr <;> simp only [c10ObservedSession, c10Session, PMF.map_bind, PMF.map_comp,
      Function.comp_def, observe_hash_session, ih]
  | sign req next ih =>
    cases qs with
    | zero => simp only [c10ObservedSession, c10Session, ih]
    | succ qs =>
      cases ha : sessionAdmits ledger req <;>
        simp only [c10ObservedSession, c10Session, ha, Bool.false_eq_true, ↓reduceIte,
          PMF.map_bind, PMF.map_comp, Function.comp_def, observe_sign_session, ih]

theorem c10_observed_session_support [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest)
    (out : C10ObservedSession R × Memo K Digest)
    (ho : out ∈ (c10ObservedSession encode cfg client qr qs ledger table).support) :
    (out.1.session, out.2) ∈ (c10Session encode cfg client qr qs ledger table).support := by
  rw [← c10_observed_session_erases encode cfg client qr qs ledger table,
    PMF.mem_support_map_iff]
  exact ⟨out, ho, rfl⟩

theorem c10_observed_session_extends [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest)
    (out : C10ObservedSession R × Memo K Digest)
    (ho : out ∈ (c10ObservedSession encode cfg client qr qs ledger table).support) :
    MemoExtends table out.2 := by
  apply eval_program_extends digestDraw (c10SessionProgram encode cfg client qr qs ledger)
    table (out.1.session, out.2)
  rw [c10_session_eval]
  exact c10_observed_session_support encode cfg client qr qs ledger table out ho

end
end C10Probability
