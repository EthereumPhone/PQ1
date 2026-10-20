import C10Probability.RSessionProgram
import C10Probability.RContextHistory
import C10Probability.RPublicHistory

/-! Search freshness and successful replay are session invariants derived from
actual cache updates. They are only required before the first exhaustion;
public-history accounting continues after failure, when raw calls still run. -/
namespace C10Probability
noncomputable section

def RSessionInvariant (cfg : RSessionConfig) (ledger : RGrindLedger)
    (history : ℕ) (table : Memo (Sum ByteKey ByteKey) Digest) : Prop :=
  BoundedRPublicHistory history table ∧
    (ledger.failed = false →
      RContextHistory ledger.contexts.toFinset table ∧
      AcceptedRContexts ledger.contexts.toFinset table cfg.seed cfg.root cfg.trials
        (by simpa using cfg.bound))

theorem r_session_invariant_empty (cfg : RSessionConfig) :
    RSessionInvariant cfg emptyRGrindLedger 0 (fun _ => none) := by
  refine ⟨r_public_history_empty, fun _ => ?_⟩
  constructor
  · exact r_context_history_empty
  · exact accepted_r_contexts_empty _ _ _ _ _

theorem r_session_invariant_mono (cfg : RSessionConfig) (ledger : RGrindLedger)
    (before after : ℕ) (table : Memo (Sum ByteKey ByteKey) Digest)
    (bound : before ≤ after) (invariant : RSessionInvariant cfg ledger before table) :
    RSessionInvariant cfg ledger after table := by
  exact ⟨r_public_history_mono before after table bound invariant.1, invariant.2⟩

theorem r_session_invariant_query (cfg : RSessionConfig) (ledger : RGrindLedger)
    (history : ℕ) (table : Memo (Sum ByteKey ByteKey) Digest)
    (invariant : RSessionInvariant cfg ledger history table) (key : ByteKey)
    (out : Digest × Memo (Sum ByteKey ByteKey) Digest)
    (supported : out ∈ (memoQuery digestDraw table (.inl key)).support) :
    RSessionInvariant cfg ledger (history + 1) out.2 := by
  refine ⟨r_public_history_query history table invariant.1 key out supported, ?_⟩
  intro healthy
  obtain ⟨origins, accepted⟩ := invariant.2 healthy
  exact ⟨r_context_history_public_query _ table key origins out supported,
    accepted_r_contexts_extend _ table out.2 _ _ _ _ accepted
      (memo_query_extends digestDraw table (.inl key) out supported)⟩

theorem r_session_invariant_search (cfg : RSessionConfig) (ledger : RGrindLedger)
    (history : ℕ) (table : Memo (Sum ByteKey ByteKey) Digest)
    (invariant : RSessionInvariant cfg ledger history table) (context : RContext)
    (admitted : rSessionAdmits ledger context = true)
    (out : Option RSearchResult × Memo (Sum ByteKey ByteKey) Digest)
    (supported : out ∈ (randomizerUnder id table context.1 context.2
      cfg.seed cfg.root cfg.trials cfg.bound).support) :
    RSessionInvariant cfg (rSessionAfterGrind ledger context out.1)
      (history + cfg.trials) out.2 := by
  rw [randomizer_under_independent table context cfg] at supported
  obtain ⟨healthy, valid⟩ := (r_session_admits_iff ledger context).mp admitted
  obtain ⟨origins, accepted⟩ := invariant.2 healthy
  refine ⟨r_public_history_search history table invariant.1 _ _ _ _ _ _ out supported, ?_⟩
  rcases out with ⟨reply, after⟩
  cases reply with
  | none => simp [rSessionAfterGrind]
  | some result =>
      intro _
      have newOrigins := r_context_history_search ledger.contexts.toFinset context valid
        cfg.seed cfg.root cfg.trials (by simpa using cfg.bound) table origins
        (some result, after) supported
      have newAccepted := accepted_r_contexts_insert_success ledger.contexts.toFinset table
        after context cfg.seed cfg.root cfg.trials (by simpa using cfg.bound)
        result accepted supported
      simpa [rSessionAfterGrind, List.toFinset_append, Finset.union_comm] using
        And.intro newOrigins newAccepted

theorem r_session_preserves_invariant (cfg : RSessionConfig) {R : Type*} {fuel : ℕ}
    (client : RGrindClient R fuel) (qr qs : ℕ) (ledger : RGrindLedger)
    (history : ℕ) (table : Memo (Sum ByteKey ByteKey) Digest)
    (invariant : RSessionInvariant cfg ledger history table)
    (out : RGrindResult R × Memo (Sum ByteKey ByteKey) Digest)
    (supported : out ∈ (rSession id cfg client qr qs ledger table).support) :
    RSessionInvariant cfg out.1.ledger (history + qr + qs * cfg.trials) out.2 := by
  induction client generalizing qr qs ledger history table with
  | done value =>
      have equal : out = (⟨value, ledger, qr, qs⟩, table) := by
        simpa only [rSession, PMF.mem_support_pure_iff] using supported
      subst out
      exact r_session_invariant_mono cfg ledger _ _ table (by omega) invariant
  | hash key next ih =>
      cases qr with
      | zero =>
          simpa only [Nat.add_zero] using
            ih 0 0 qs ledger history table invariant supported
      | succ qr =>
          simp only [rSession, PMF.mem_support_bind_iff] at supported
          obtain ⟨reply, replySupport, childSupport⟩ := supported
          have child := ih reply.1 qr qs ledger (history + 1) reply.2
            (r_session_invariant_query cfg ledger history table invariant key reply replySupport)
            childSupport
          simpa only [show history + 1 + qr + qs * cfg.trials =
            history + (qr + 1) + qs * cfg.trials by omega] using child
  | grind context next ih =>
      cases qs with
      | zero => exact ih none qr 0 ledger history table invariant supported
      | succ qs =>
          cases admitted : rSessionAdmits ledger context
          · simp only [rSession, admitted, Bool.false_eq_true, ↓reduceIte] at supported
            exact ih none qr (qs + 1) ledger history table invariant supported
          · simp only [rSession, admitted, ↓reduceIte, PMF.mem_support_bind_iff] at supported
            obtain ⟨reply, replySupport, childSupport⟩ := supported
            have child := ih reply.1 qr qs (rSessionAfterGrind ledger context reply.1)
              (history + cfg.trials) reply.2
              (r_session_invariant_search cfg ledger history table invariant context admitted
                reply replySupport) childSupport
            simpa only [show history + cfg.trials + qr + qs * cfg.trials =
              history + qr + (qs + 1) * cfg.trials by ring] using child

end
end C10Probability
