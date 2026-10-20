import C10Probability.RForeignSign
import C10Probability.RContextExhaustion
import C10Probability.SessionTypes

/-! Actual C10 execution discharges the R-origin and replay premises while
signing remains enabled. Public history is bounded even after either kind of
signing failure. The proof context set is not exposed to the client. -/
namespace C10Probability
noncomputable section

def C10RInvariant (cfg : C10SessionConfig) (contexts : Finset RContext)
    (ledger : C10SessionLedger) (history : ℕ) (table : Memo WotsQuery Digest) : Prop :=
  BoundedRPublicHistory history table ∧
    (ledger.failed = false →
      RContextHistory contexts table ∧
      AcceptedRContexts contexts table cfg.seed cfg.root cfg.rTrials
        (by simpa using cfg.rBound))

theorem bounded_r_history_execution {R : Type*} {fuel : ℕ}
    (program : QueryProgram WotsQuery Digest R fuel) (calls : ℕ)
    (budget : PublicBudget program calls) (history : ℕ) (table : Memo WotsQuery Digest)
    (covered : BoundedRPublicHistory history table) (out : R × Memo WotsQuery Digest)
    (supported : out ∈ (evalProgram digestDraw program table).support) :
    BoundedRPublicHistory (history + calls) out.2 := by
  obtain ⟨seen, size, cover⟩ := covered
  obtain ⟨after, afterSize, afterCover⟩ := r_public_history_execution
    program calls budget seen table cover out supported
  exact ⟨after, afterSize.trans (Nat.add_le_add_right size calls), afterCover⟩

theorem c10_r_invariant_keygen (cfg : C10SessionConfig) (publicSeed : Digest)
    (out : (ByteKey × ByteKey) × Memo WotsQuery Digest)
    (supported : out ∈ (c10Keygen id (fun _ => none) publicSeed).support) :
    C10RInvariant cfg ∅ emptySessionLedger 155135 out.2 := by
  refine ⟨?_, fun _ => ⟨c10_keygen_r_history publicSeed out supported,
    accepted_r_contexts_empty _ _ _ _ _⟩⟩
  apply bounded_r_history_execution (c10KeygenProgram id publicSeed) 155135
    (c10_keygen_public publicSeed) 0 (fun _ => none) r_public_history_empty out
  rwa [c10_keygen_eval]

theorem c10_r_invariant_mono (cfg : C10SessionConfig) (contexts : Finset RContext)
    (ledger : C10SessionLedger) (before after : ℕ) (table : Memo WotsQuery Digest)
    (bound : before ≤ after) (invariant : C10RInvariant cfg contexts ledger before table) :
    C10RInvariant cfg contexts ledger after table := by
  exact ⟨r_public_history_mono before after table bound invariant.1, invariant.2⟩

theorem c10_r_invariant_query (cfg : C10SessionConfig) (contexts : Finset RContext)
    (ledger : C10SessionLedger) (history : ℕ) (table : Memo WotsQuery Digest)
    (invariant : C10RInvariant cfg contexts ledger history table) (key : ByteKey)
    (out : Digest × Memo WotsQuery Digest)
    (supported : out ∈ (memoQuery digestDraw table (.inl key)).support) :
    C10RInvariant cfg contexts ledger (history + 1) out.2 := by
  refine ⟨r_public_history_query history table invariant.1 key out supported, ?_⟩
  intro healthy
  obtain ⟨origins, accepted⟩ := invariant.2 healthy
  exact ⟨r_context_history_public_query _ table key origins out supported,
    accepted_r_contexts_extend _ table out.2 _ _ _ _ accepted
      (memo_query_extends digestDraw table (.inl key) out supported)⟩

theorem c10_randomizer_independent (table : Memo WotsQuery Digest)
    (random message seed root : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32) :
    randomizerUnder id table random message seed root n bound =
      privateRandomizerSearch table random message seed root n (by simpa using bound) := by
  rw [← randomizer_under_eval, randomizerUnderProgram, mapProgram_id,
    privateRandomizerProgram_independent]

theorem c10_r_invariant_after_found (cfg : C10SessionConfig) (contexts : Finset RContext)
    (ledger : C10SessionLedger) (history : ℕ) (table : Memo WotsQuery Digest)
    (invariant : C10RInvariant cfg contexts ledger history table) (req : C10SignRequest)
    (admitted : sessionAdmits ledger req = true) (found : RSearchResult)
    (middle : Memo WotsQuery Digest)
    (searched : (some found, middle) ∈ (randomizerUnder id table req.random req.message
      cfg.seed cfg.root cfg.rTrials cfg.rBound).support)
    (out : Option C10Signature × Memo WotsQuery Digest)
    (finished : out ∈ (c10SignAfter id middle cfg.seed req.shuffle cfg.wTrials cfg.wBound
      (some found)).support) :
    C10RInvariant cfg (insert (req.random, req.message) contexts)
      (sessionAfterSign ledger req.message out.1) (history + sessionSignPublic cfg) out.2 := by
  have full : out ∈ (c10Sign id table req.random req.message cfg.seed cfg.root req.shuffle
      cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound).support := by
    rw [c10Sign, PMF.mem_support_bind_iff]
    exact ⟨(some found, middle), searched, finished⟩
  have historyBound := bounded_r_history_execution
    (c10SignProgram id req.random req.message cfg.seed cfg.root req.shuffle
      cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound)
    (sessionSignPublic cfg) (c10_sign_public _ _ _ _ _ _ _ _ _)
    history table invariant.1 out (by rwa [c10_sign_eval])
  refine ⟨historyBound, fun _ => ?_⟩
  obtain ⟨healthy, message, random, _⟩ := (session_admits_iff ledger req).mp admitted
  obtain ⟨origins, accepted⟩ := invariant.2 healthy
  rw [c10_randomizer_independent] at searched
  have newOrigins := r_context_history_search contexts (req.random, req.message)
    ⟨message, random⟩ cfg.seed cfg.root cfg.rTrials (by simpa using cfg.rBound)
    table origins (some found, middle) searched
  have newAccepted := accepted_r_contexts_insert_success contexts table middle
    (req.random, req.message) cfg.seed cfg.root cfg.rTrials (by simpa using cfg.rBound)
    found accepted searched
  refine ⟨c10_sign_after_r_history cfg.seed req.shuffle cfg.wTrials cfg.wBound
    (some found) _ middle newOrigins out finished, ?_⟩
  apply accepted_r_contexts_extend _ middle out.2 _ _ _ _ newAccepted
  apply eval_program_extends digestDraw
    (c10SignAfterProgram id cfg.seed req.shuffle cfg.wTrials cfg.wBound (some found)) middle out
  rwa [c10_sign_after_eval]

theorem c10_r_invariant_sign (cfg : C10SessionConfig) (contexts : Finset RContext)
    (ledger : C10SessionLedger) (history : ℕ) (table : Memo WotsQuery Digest)
    (invariant : C10RInvariant cfg contexts ledger history table) (req : C10SignRequest)
    (admitted : sessionAdmits ledger req = true)
    (out : Option C10Signature × Memo WotsQuery Digest)
    (supported : out ∈ (c10Sign id table req.random req.message cfg.seed cfg.root req.shuffle
      cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound).support) :
    C10RInvariant cfg (insert (req.random, req.message) contexts)
      (sessionAfterSign ledger req.message out.1) (history + sessionSignPublic cfg) out.2 := by
  have historyBound := bounded_r_history_execution
    (c10SignProgram id req.random req.message cfg.seed cfg.root req.shuffle
      cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound)
    (sessionSignPublic cfg) (c10_sign_public _ _ _ _ _ _ _ _ _)
    history table invariant.1 out (by rwa [c10_sign_eval])
  rw [c10Sign, PMF.mem_support_bind_iff] at supported
  obtain ⟨⟨found, middle⟩, searched, finished⟩ := supported
  cases found with
  | none =>
      have equal : out = (none, middle) := by simpa [c10SignAfter] using finished
      subst out
      exact ⟨historyBound, by simp [sessionAfterSign]⟩
  | some found =>
      exact c10_r_invariant_after_found cfg contexts ledger history table invariant req
        admitted found middle searched out finished

end
end C10Probability
