import C10Probability.MemoPresample
import C10Probability.DerivedGrind
import C10Probability.WotsPrivate

/-! Adaptive memo precomputation preserves the later client's full result,
query trace and cache after restoring entries that client never queried.
Precomputation may repeat inputs and start from an arbitrary cache. Its result
is not supplied to the client. The final theorem consumes the actual WOTS
seed-chain program; no freshness or transcript-independence premise is added. -/
namespace C10Probability
noncomputable section
variable {K α R T : Type*} [DecidableEq K]

def restoreTraceTarget (target : K) (out : TraceOutput K α R) : TraceOutput K α R :=
  ⟨out.value, (restoreTarget target out).2, out.queries⟩

theorem restore_trace_target_selected (target : K) (out : TraceOutput K α R) :
    restoreTraceTarget target ⟨out.value, out.cache, target :: out.queries⟩ =
      ⟨out.value, out.cache, target :: out.queries⟩ := by
  simp [restoreTraceTarget, restoreTarget]

theorem restore_trace_target_other (target key : K) (different : key ≠ target)
    (out : TraceOutput K α R) :
    restoreTraceTarget target ⟨out.value, out.cache, key :: out.queries⟩ =
      ⟨(restoreTraceTarget target out).value, (restoreTraceTarget target out).cache,
        key :: (restoreTraceTarget target out).queries⟩ := by
  simp [restoreTraceTarget, restoreTarget, Ne.symm different]

theorem trace_program_presample (p : PMF α) (target : K) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) (fresh : table target = none) :
    traceProgram p program table = p.bind fun secret =>
      (traceProgram p program (Function.update table target (some secret))).map
        (restoreTraceTarget target) := by
  induction program generalizing table with
  | done value =>
    simp only [traceProgram, PMF.pure_map, restoreTraceTarget, restoreTarget,
      List.not_mem_nil, ↓reduceIte, Function.update_idem]
    have same : Function.update table target none = table := by
      rw [← fresh, Function.update_eq_self]
    simp only [same, PMF.bind_const]
  | query key next ih =>
    by_cases selected : key = target
    · subst key
      rw [traceProgram, memoQuery_fresh p table target fresh, PMF.bind_map]
      congr 1
      funext secret
      rw [traceProgram, memoQuery_cached p _ target secret (by simp),
        PMF.pure_bind, PMF.map_comp]
      simp only [Function.comp_def, restore_trace_target_selected]
    · cases cached : table key with
      | some value =>
        rw [traceProgram, memoQuery_cached p table key value cached, PMF.pure_bind,
          ih value table fresh, PMF.map_bind]
        congr 1
        funext secret
        rw [traceProgram, memoQuery_cached p _ key value (by simp [selected, cached]),
          PMF.pure_bind, PMF.map_comp, PMF.map_comp]
        simp only [Function.comp_def, restore_trace_target_other target key selected]
      | none =>
        rw [traceProgram, memoQuery_fresh p table key cached, PMF.bind_map]
        have later (reply : α) := ih reply (Function.update table key (some reply))
          (by simp [Ne.symm selected, fresh])
        simp only [Function.comp_def, later, PMF.map_bind]
        rw [PMF.bind_comm]
        congr 1
        funext secret
        rw [traceProgram, memoQuery_fresh p _ key (by simp [selected, cached]),
          PMF.bind_map, PMF.map_bind]
        simp only [Function.comp_def]
        congr 1
        funext reply
        rw [Function.update_comm selected, PMF.map_comp, PMF.map_comp]
        simp only [Function.comp_def, restore_trace_target_other target key selected]

def restoreQueries (baseline : Memo K α) (out : TraceOutput K α R) : TraceOutput K α R :=
  ⟨out.value, fun key => if key ∈ out.queries then out.cache key else baseline key, out.queries⟩

theorem trace_program_unqueried (p : PMF α) {n : ℕ} (program : QueryProgram K α R n)
    (table : Memo K α) (out : TraceOutput K α R)
    (supported : out ∈ (traceProgram p program table).support) (key : K)
    (absent : key ∉ out.queries) : out.cache key = table key := by
  cases cached : out.cache key with
  | some value =>
    have original := (traceProgram_origin p program table out supported key value cached).resolve_right absent
    exact original.symm
  | none =>
    cases original : table key with
    | none => rfl
    | some value =>
      have supported' : (out.value, out.cache) ∈ (evalProgram p program table).support := by
        rw [← traceProgram_erases, PMF.mem_support_map_iff]
        exact ⟨out, supported, rfl⟩
      have kept := evalProgram_preserves p program table key value original
        (out.value, out.cache) supported'
      simp [cached] at kept

theorem restore_queries_supported (p : PMF α) {n : ℕ} (program : QueryProgram K α R n)
    (table : Memo K α) (out : TraceOutput K α R)
    (supported : out ∈ (traceProgram p program table).support) :
    restoreQueries table out = out := by
  have same : (fun key => if key ∈ out.queries then out.cache key else table key) = out.cache := by
    funext key
    by_cases member : key ∈ out.queries
    · simp [member]
    · simp [member, trace_program_unqueried p program table out supported key member]
  cases out
  simp only [restoreQueries, same]

theorem restore_queries_absorb (first second : Memo K α) (out : TraceOutput K α R) :
    restoreQueries first (restoreQueries second out) = restoreQueries first out := by
  simp only [restoreQueries]
  congr 1
  funext key
  split <;> simp_all

theorem trace_program_restore (p : PMF α) {n : ℕ} (program : QueryProgram K α R n)
    (table : Memo K α) :
    (traceProgram p program table).map (restoreQueries table) = traceProgram p program table := by
  calc
    _ = (traceProgram p program table).map id := by
      simp only [PMF.map]
      apply bind_eq_of_support
      intro out supported
      simp only [Function.comp_def, id_eq]
      rw [restore_queries_supported p program table out supported]
    _ = _ := PMF.map_id _

theorem restore_queries_presampled (p : PMF α) {n : ℕ} (program : QueryProgram K α R n)
    (table : Memo K α) (target : K) (secret : α) (fresh : table target = none)
    (out : TraceOutput K α R)
    (supported : out ∈ (traceProgram p program (Function.update table target (some secret))).support) :
    restoreQueries table out = restoreTraceTarget target out := by
  unfold restoreQueries restoreTraceTarget restoreTarget
  dsimp only
  congr 1
  funext key
  by_cases same : key = target
  · subst key
    by_cases queried : target ∈ out.queries <;> simp [queried, fresh]
  · have right : (if target ∈ out.queries then out.cache else
        Function.update out.cache target none) key = out.cache key := by
      split <;> simp_all
    rw [right]
    by_cases queried : key ∈ out.queries
    · simp [queried]
    · have unchanged := trace_program_unqueried p program
        (Function.update table target (some secret)) out supported key queried
      simp [queried, unchanged, same]

theorem trace_program_presample_all (p : PMF α) (target : K) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) (fresh : table target = none) :
    traceProgram p program table = p.bind fun secret =>
      (traceProgram p program (Function.update table target (some secret))).map
        (restoreQueries table) := by
  rw [trace_program_presample p target program table fresh]
  congr 1
  funext secret
  simp only [PMF.map]
  apply bind_eq_of_support
  intro out supported
  simp only [Function.comp_def]
  rw [restore_queries_presampled p program table target secret fresh out supported]

/-- The setup may query adaptively, repeat inputs, and encounter prior cached
entries. Its returned value is not given to the later client. Restoring entries
that the client never queried preserves its entire result, trace and cache. -/
theorem trace_program_precompute (p : PMF α) {m n : ℕ}
    (setup : QueryProgram K α T m) (client : QueryProgram K α R n) (table : Memo K α) :
    traceProgram p client table = (evalProgram p setup table).bind fun warm =>
      (traceProgram p client warm.2).map (restoreQueries table) := by
  induction setup generalizing table with
  | done value =>
    rw [evalProgram, PMF.pure_bind, trace_program_restore]
  | query key next ih =>
    calc
      _ = (memoQuery p table key).bind (fun reply =>
          (traceProgram p client reply.2).map (restoreQueries table)) := by
        cases cached : table key with
        | some value =>
          rw [memoQuery_cached p table key value cached, PMF.pure_bind, trace_program_restore]
        | none =>
          rw [memoQuery_fresh p table key cached, PMF.bind_map]
          exact trace_program_presample_all p key client table cached
      _ = _ := by
        rw [evalProgram, PMF.bind_bind]
        apply bind_eq_of_support
        intro reply _
        have later := congrArg (fun law : PMF (TraceOutput K α R) =>
          law.map (restoreQueries table)) (ih reply.1 reply.2)
        simpa only [PMF.map_bind, PMF.map_comp, Function.comp_def,
          restore_queries_absorb] using later


theorem wots_seed_chain_precompute {n : ℕ} (client : QueryProgram WotsQuery Digest R n)
    (table : Memo WotsQuery Digest) (seed : ByteKey) (layer tree kp index steps : ℕ) :
    traceProgram digestDraw client table =
      (wotsSeedChain id table seed layer tree kp index steps).bind fun warm =>
        (traceProgram digestDraw client warm.2).map (restoreQueries table) := by
  rw [← wots_seed_chain_eval]
  exact trace_program_precompute digestDraw
    (wotsSeedChainProgram id seed layer tree kp index steps) client table


end
end C10Probability
