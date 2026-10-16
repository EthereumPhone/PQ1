import C10Probability.QueryProgram

/-! Observers for adaptive lazy sampling. The executed cache remains the
ordinary memo table. The observer records projected fresh replies and a flag;
erasure preserves the complete returned result and final cache distribution. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

structure CollisionView (K α V : Type*) where
  cache : Memo K α
  seen : Finset V
  bad : Bool

variable {K α V R : Type*}

def recordReply [DecidableEq K] [DecidableEq V] (project : α → V) (state : CollisionView K α V) (key : K) (value : α) :
    CollisionView K α V :=
  ⟨Function.update state.cache key (some value), insert (project value) state.seen,
    state.bad || decide (project value ∈ state.seen)⟩

def observedQuery [DecidableEq K] [DecidableEq V] (p : PMF α) (project : α → V) (state : CollisionView K α V)
    (key : K) : PMF (α × CollisionView K α V) :=
  match state.cache key with
  | some value => PMF.pure (value, state)
  | none => p.map fun value => (value, recordReply project state key value)

def observeProgram [DecidableEq K] [DecidableEq V] (p : PMF α) (project : α → V) : {n : ℕ} → QueryProgram K α R n →
    CollisionView K α V → PMF (R × CollisionView K α V)
  | _, .done value, state => PMF.pure (value, state)
  | _, .query key next, state => (observedQuery p project state key).bind fun out =>
      observeProgram p project (next out.1) out.2

theorem observedQuery_erases [DecidableEq K] [DecidableEq V] (p : PMF α) (project : α → V)
    (state : CollisionView K α V) (key : K) :
    (observedQuery p project state key).map (fun out => (out.1, out.2.cache)) =
      memoQuery p state.cache key := by
  cases h : state.cache key <;>
    simp [observedQuery, memoQuery, h, PMF.map_comp, PMF.pure_map, Function.comp_def, recordReply]

theorem observeProgram_erases [DecidableEq K] [DecidableEq V] (p : PMF α) (project : α → V) {n : ℕ}
    (program : QueryProgram K α R n) (state : CollisionView K α V) :
    (observeProgram p project program state).map (fun out => (out.1, out.2.cache)) =
      evalProgram p program state.cache := by
  induction program generalizing state with
  | done value => simp [observeProgram, evalProgram, PMF.pure_map]
  | query key next ih =>
    rw [observeProgram, PMF.map_bind, evalProgram,
      ← observedQuery_erases p project state key, PMF.bind_map]
    congr 1
    funext out
    exact ih out.1 out.2

def SeenCovers (project : α → V) (cache : Memo K α) (seen : Finset V) : Prop :=
  ∀ key value, cache key = some value → project value ∈ seen

def CollisionFree (project : α → V) (cache : Memo K α) : Prop :=
  ∀ key other value reply, cache key = some value → cache other = some reply →
    project value = project reply → key = other

def ViewValid (project : α → V) (state : CollisionView K α V) : Prop :=
  SeenCovers project state.cache state.seen ∧
    (state.bad = false → CollisionFree project state.cache)

def emptyView : CollisionView K α V := ⟨fun _ => none, ∅, false⟩

theorem emptyView_valid (project : α → V) : ViewValid project (emptyView : CollisionView K α V) := by
  simp [ViewValid, SeenCovers, CollisionFree, emptyView]

theorem recordReply_valid [DecidableEq K] [DecidableEq V] (project : α → V) (state : CollisionView K α V)
    (hv : ViewValid project state) (key : K) (value : α) :
    ViewValid project (recordReply project state key value) := by
  constructor
  · intro other reply hr
    by_cases hk : other = key
    · have he : reply = value := by simpa [recordReply, hk] using hr.symm
      simp [recordReply, he]
    · have ho : state.cache other = some reply := by simpa [recordReply, hk] using hr
      exact Finset.mem_insert_of_mem (hv.1 other reply ho)
  · intro hb left right a b hl hr he
    have hparts : state.bad = false ∧ project value ∉ state.seen := by
      simpa [recordReply] using hb
    by_cases hleft : left = key
    · by_cases hright : right = key
      · exact hleft.trans hright.symm
      · have ha : a = value := by simpa [recordReply, hleft] using hl.symm
        have hcache : state.cache right = some b := by simpa [recordReply, hright] using hr
        apply False.elim
        apply hparts.2
        rw [← ha, he]
        exact hv.1 right b hcache
    · by_cases hright : right = key
      · have hb : b = value := by simpa [recordReply, hright] using hr.symm
        have hcache : state.cache left = some a := by simpa [recordReply, hleft] using hl
        apply False.elim
        apply hparts.2
        rw [← hb, ← he]
        exact hv.1 left a hcache
      · exact hv.2 hparts.1 left right a b
          (by simpa [recordReply, hleft] using hl)
          (by simpa [recordReply, hright] using hr) he

theorem observedQuery_cached [DecidableEq K] [DecidableEq V] (p : PMF α) (project : α → V)
    (state : CollisionView K α V) (key : K) (value : α)
    (h : state.cache key = some value) :
    observedQuery p project state key = PMF.pure (value, state) := by
  simp [observedQuery, h]

theorem observedQuery_valid [DecidableEq K] [DecidableEq V] (p : PMF α) (project : α → V)
    (state : CollisionView K α V) (hv : ViewValid project state) (key : K)
    (out : α × CollisionView K α V) (ho : out ∈ (observedQuery p project state key).support) :
    ViewValid project out.2 := by
  cases h : state.cache key with
  | none =>
    simp only [observedQuery, h, PMF.mem_support_map_iff] at ho
    obtain ⟨value, _, rfl⟩ := ho
    exact recordReply_valid project state hv key value
  | some value =>
    have he : out = (value, state) := by simpa [observedQuery, h] using ho
    simpa [he] using hv

theorem observeProgram_valid [DecidableEq K] [DecidableEq V] (p : PMF α) (project : α → V) {n : ℕ}
    (program : QueryProgram K α R n) (state : CollisionView K α V)
    (hv : ViewValid project state) (out : R × CollisionView K α V)
    (ho : out ∈ (observeProgram p project program state).support) : ViewValid project out.2 := by
  induction program generalizing state out with
  | done value =>
    have he : out = (value, state) := by simpa [observeProgram] using ho
    simpa [he] using hv
  | query key next ih =>
    rw [observeProgram, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, hr, ho⟩ := ho
    exact ih reply.1 reply.2 (observedQuery_valid p project state hv key reply hr) out ho

theorem observeProgram_collision_flag [DecidableEq K] [DecidableEq V] (p : PMF α) (project : α → V) {n : ℕ}
    (program : QueryProgram K α R n) (state : CollisionView K α V)
    (hv : ViewValid project state) (out : R × CollisionView K α V)
    (ho : out ∈ (observeProgram p project program state).support)
    (hc : ¬ CollisionFree project out.2.cache) : out.2.bad = true := by
  have hvalid := observeProgram_valid p project program state hv out ho
  cases hb : out.2.bad
  · exact False.elim (hc (hvalid.2 hb))
  · rfl

theorem observedQuery_bad_persists [DecidableEq K] [DecidableEq V] (p : PMF α) (project : α → V)
    (state : CollisionView K α V) (hb : state.bad = true) (key : K)
    (out : α × CollisionView K α V) (ho : out ∈ (observedQuery p project state key).support) :
    out.2.bad = true := by
  cases h : state.cache key with
  | none =>
    simp only [observedQuery, h, PMF.mem_support_map_iff] at ho
    obtain ⟨value, _, rfl⟩ := ho
    simp [recordReply, hb]
  | some value =>
    have he : out = (value, state) := by simpa [observedQuery, h] using ho
    simpa [he] using hb

theorem observeProgram_bad_persists [DecidableEq K] [DecidableEq V] (p : PMF α) (project : α → V) {n : ℕ}
    (program : QueryProgram K α R n) (state : CollisionView K α V)
    (hb : state.bad = true) (out : R × CollisionView K α V)
    (ho : out ∈ (observeProgram p project program state).support) : out.2.bad = true := by
  induction program generalizing state out with
  | done value =>
    have he : out = (value, state) := by simpa [observeProgram] using ho
    simpa [he] using hb
  | query key next ih =>
    rw [observeProgram, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, hr, ho⟩ := ho
    exact ih reply.1 reply.2 (observedQuery_bad_persists p project state hb key reply hr) out ho

end
end C10Probability
