import C10Probability.AdaptivePresample
import C10Probability.QueryReplay

/-! A replay of the precomputed program in the restored cache ensures that
all precomputed entries used by that program are retained. This converts the
exact restored-cache law into full-cache preservation on replay-backed events. -/
namespace C10Probability
noncomputable section
variable {K α R T : Type*} [DecidableEq K]

theorem memo_query_covered (p : PMF α) (table view : Memo K α) (key : K)
    (reply : α × Memo K α) (supported : reply ∈ (memoQuery p table key).support)
    (before : MemoExtends table view) (stored : view key = some reply.1) :
    MemoExtends reply.2 view := by
  intro other value cached
  rcases memoQuery_origin p table key other value reply supported cached with old | equal
  · exact before other value old
  · subst other
    have same := memoQuery_stores p table key reply supported
    have eq := Option.some.inj (cached.symm.trans same)
    simpa only [eq] using stored

/-- A replay in a subcache of the same later memo must contain every entry
inserted by the original execution, as well as the supplied baseline. -/
theorem eval_program_replay_cache (p : PMF α) {n : ℕ} (program : QueryProgram K α R n)
    (table : Memo K α) (warm : R × Memo K α)
    (supported : warm ∈ (evalProgram p program table).support)
    (view full : Memo K α) (base : MemoExtends table view)
    (warmFull : MemoExtends warm.2 full) (viewFull : MemoExtends view full)
    (value : R) (replayed : replayProgram view program = some value) :
    MemoExtends warm.2 view := by
  induction program generalizing table warm with
  | done result =>
    have equal : warm = (result, table) := by simpa only [evalProgram, PMF.mem_support_pure_iff] using supported
    simpa only [equal] using base
  | query key next ih =>
    rw [evalProgram, PMF.mem_support_bind_iff] at supported
    obtain ⟨reply, hr, later⟩ := supported
    cases cached : view key with
    | none => simp only [replayProgram, cached, Option.bind_none] at replayed; cases replayed
    | some actual =>
      have preserved := evalProgram_preserves p (next reply.1) reply.2 key reply.1
        (memoQuery_stores p table key reply hr) warm later
      have same := Option.some.inj ((warmFull key reply.1 preserved).symm.trans
        (viewFull key actual cached))
      have current : view key = some reply.1 := by simpa only [← same] using cached
      rw [replay_program_cached view key next reply.1 current] at replayed
      exact ih reply.1 reply.2 warm later
        (memo_query_covered p table view key reply hr base current) warmFull replayed

theorem restore_queries_extends (table : Memo K α) (out : TraceOutput K α R)
    (extension : MemoExtends table out.cache) :
    MemoExtends table (restoreQueries table out).cache ∧
      MemoExtends (restoreQueries table out).cache out.cache := by
  constructor
  · intro key value cached
    change (if key ∈ out.queries then out.cache key else table key) = some value
    split
    · exact extension key value cached
    · exact cached
  · intro key value cached
    change (if key ∈ out.queries then out.cache key else table key) = some value at cached
    split at cached
    · exact cached
    · exact extension key value cached

omit [DecidableEq K] in
theorem memo_extends_antisymm (first second : Memo K α)
    (forward : MemoExtends first second) (backward : MemoExtends second first) : first = second := by
  funext key
  cases left : first key with
  | some value => exact (forward key value left).symm
  | none =>
    cases right : second key with
    | none => rfl
    | some value => have impossible := backward key value right; simp [left] at impossible

theorem precompute_restore_replay (p : PMF α) {m n : ℕ}
    (setup : QueryProgram K α T m) (client : QueryProgram K α R n) (table : Memo K α)
    (warm : T × Memo K α) (hw : warm ∈ (evalProgram p setup table).support)
    (out : TraceOutput K α R) (ho : out ∈ (traceProgram p client warm.2).support)
    (value : T) (replayed : replayProgram (restoreQueries table out).cache setup = some value) :
    restoreQueries table out = out := by
  have erased : (out.value, out.cache) ∈ (evalProgram p client warm.2).support := by
    rw [← traceProgram_erases, PMF.mem_support_map_iff]
    exact ⟨out, ho, rfl⟩
  have warmFull := eval_program_extends p client warm.2 (out.value, out.cache) erased
  have baseFull := memo_extends_trans (eval_program_extends p setup table warm hw) warmFull
  obtain ⟨baseView, viewFull⟩ := restore_queries_extends table out baseFull
  have warmView := eval_program_replay_cache p setup table warm hw
    (restoreQueries table out).cache out.cache baseView warmFull viewFull value replayed
  have same : out.cache = (restoreQueries table out).cache := by
    apply memo_extends_antisymm _ _ _ viewFull
    intro key digest cached
    rcases traceProgram_origin p client warm.2 out ho key digest cached with old | queried
    · exact warmView key digest old
    · simpa only [restoreQueries, queried, ↓reduceIte] using cached
  cases out
  simpa only [restoreQueries] using congrArg
    (fun cache => TraceOutput.mk _ cache _) same.symm


end
end C10Probability
