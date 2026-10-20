import C10Probability.RContextHistory
import C10Probability.SelectedComposition
import C10Probability.ForsInputs
import C10Probability.WotsPrivate

/-! A conservative selector for private R inputs. The actual WOTS and FORS
private callers have different tail widths. Zero selected-call budgets preserve
the entire selected part of the memo table, including absence of entries. -/
namespace C10Probability
noncomputable section

def rPrivateQuery : WotsQuery → Bool
  | .inl _ => false
  | .inr tail => decide (tail.length = 71 ∨ tail.length = 87)

theorem r_private_query_public (key : ByteKey) :
    rPrivateQuery (.inl key) = false := by rfl

theorem r_private_query_context (context : RContext) (nonce : Counter)
    (valid : validRContext context) :
    rPrivateQuery (.inr (rContextTail context nonce)) = true := by
  simpa only [rPrivateQuery, decide_eq_true_eq] using
    r_context_tail_width context nonce valid

theorem r_private_query_wots (layer tree kp index : ℕ) :
    rPrivateQuery (.inr (wotsPrivateTail layer tree kp index)) = false := by
  simp [rPrivateQuery, wots_private_tail_length]

theorem r_private_query_fors (ht tree leaf : ℕ) :
    rPrivateQuery (.inr (forsPrivateTail ht tree leaf)) = false := by
  simp [rPrivateQuery, fors_private_tail_length]

variable {K L α R : Type*}

theorem selectedBudget_map_none (select : L → Bool) (encode : K → L)
    (unselected : ∀ key, select (encode key) = false) {n : ℕ}
    (program : QueryProgram K α R n) :
    SelectedBudget select (mapProgram encode program) 0 := by
  induction program with
  | done value => trivial
  | query key next ih =>
    simpa only [mapProgram, SelectedBudget, unselected, Bool.false_eq_true, ↓reduceIte]
      using ih

theorem memo_query_other_exact [DecidableEq K] (p : PMF α)
    (table : Memo K α) (queried key : K) (different : key ≠ queried)
    (out : α × Memo K α) (supported : out ∈ (memoQuery p table queried).support) :
    out.2 key = table key := by
  cases cached : table queried with
  | none =>
    rw [memoQuery, cached, PMF.mem_support_map_iff] at supported
    obtain ⟨reply, _, rfl⟩ := supported
    simp [different]
  | some value =>
    have equal : out = (value, table) := by simpa [memoQuery, cached] using supported
    simp [equal]

theorem selected_zero_cache_exact [DecidableEq K] (p : PMF α) (select : K → Bool)
    {n : ℕ} (program : QueryProgram K α R n)
    (budget : SelectedBudget select program 0) (table : Memo K α)
    (key : K) (selected : select key = true) (out : R × Memo K α)
    (supported : out ∈ (evalProgram p program table).support) :
    out.2 key = table key := by
  induction program generalizing table out with
  | done value =>
    have equal : out = (value, table) := by simpa [evalProgram] using supported
    simp [equal]
  | query queried next ih =>
    cases chosen : select queried with
    | true => simp [SelectedBudget, chosen] at budget
    | false =>
      simp only [SelectedBudget, chosen, Bool.false_eq_true, ↓reduceIte] at budget
      rw [evalProgram, PMF.mem_support_bind_iff] at supported
      obtain ⟨reply, querySupport, restSupport⟩ := supported
      have different : key ≠ queried := by
        intro equal
        simp [equal, chosen] at selected
      exact (ih reply.1 (budget reply.1) reply.2 out restSupport).trans
        (memo_query_other_exact p table queried key different reply querySupport)

theorem r_context_history_foreign {n : ℕ}
    (program : QueryProgram WotsQuery Digest R n)
    (budget : SelectedBudget rPrivateQuery program 0)
    (contexts : Finset RContext) (table : Memo WotsQuery Digest)
    (history : RContextHistory contexts table) (out : R × Memo WotsQuery Digest)
    (supported : out ∈ (evalProgram digestDraw program table).support) :
    RContextHistory contexts out.2 := by
  intro context nonce value valid stored
  have same := selected_zero_cache_exact digestDraw rPrivateQuery program budget
    table (.inr (rContextTail context nonce)) (r_private_query_context context nonce valid)
    out supported
  exact history context nonce value valid (same ▸ stored)

end
end C10Probability
