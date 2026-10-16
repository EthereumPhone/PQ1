import C10Probability.CollisionObserver

/-! The observer retains every cached reply. Only fresh selected inputs insert
their projections into `seen` and set the collision flag. Unselected replies
still reach the client and can affect later selected inputs. -/
namespace C10Probability
noncomputable section

variable {K α V R : Type*}

def selectedCache (select : K → Bool) (table : Memo K α) : Memo K α :=
  fun key => if select key then table key else none

def selectedView (select : K → Bool) (state : CollisionView K α V) : CollisionView K α V :=
  ⟨selectedCache select state.cache, state.seen, state.bad⟩

def recordSelected [DecidableEq K] [DecidableEq V] (select : K → Bool) (project : α → V)
    (state : CollisionView K α V) (key : K) (value : α) : CollisionView K α V :=
  if select key then recordReply project state key value
  else ⟨Function.update state.cache key (some value), state.seen, state.bad⟩

def selectedQuery [DecidableEq K] [DecidableEq V] (p : PMF α) (select : K → Bool)
    (project : α → V) (state : CollisionView K α V) (key : K) :
    PMF (α × CollisionView K α V) :=
  match state.cache key with
  | some value => PMF.pure (value, state)
  | none => p.map fun value => (value, recordSelected select project state key value)

def observeSelected [DecidableEq K] [DecidableEq V] (p : PMF α) (select : K → Bool)
    (project : α → V) : {n : ℕ} → QueryProgram K α R n →
    CollisionView K α V → PMF (R × CollisionView K α V)
  | _, .done value, state => PMF.pure (value, state)
  | _, .query key next, state => (selectedQuery p select project state key).bind fun out =>
      observeSelected p select project (next out.1) out.2

theorem selectedCache_empty (select : K → Bool) :
    selectedCache select (fun _ => (none : Option α)) = fun _ => none := by
  funext key
  simp [selectedCache]

theorem selectedCache_update [DecidableEq K] (select : K → Bool) (table : Memo K α)
    (key : K) (value : α) :
    selectedCache select (Function.update table key (some value)) =
      if select key then Function.update (selectedCache select table) key (some value)
      else selectedCache select table := by
  funext other
  by_cases he : other = key
  · subst other
    cases hs : select key <;> simp [selectedCache, hs]
  · cases select key <;> simp [selectedCache, he]

theorem selectedView_record [DecidableEq K] [DecidableEq V] (select : K → Bool)
    (project : α → V) (state : CollisionView K α V) (key : K) (value : α) :
    selectedView select (recordSelected select project state key value) =
      if select key then recordReply project (selectedView select state) key value
      else selectedView select state := by
  cases hs : select key <;>
    simp [recordSelected, hs, selectedView, recordReply, selectedCache_update]
  rfl

theorem selectedQuery_erases [DecidableEq K] [DecidableEq V] (p : PMF α)
    (select : K → Bool) (project : α → V) (state : CollisionView K α V) (key : K) :
    (selectedQuery p select project state key).map (fun out => (out.1, out.2.cache)) =
      memoQuery p state.cache key := by
  cases h : state.cache key <;> cases hs : select key <;>
    simp [selectedQuery, memoQuery, h, PMF.map_comp, PMF.pure_map, Function.comp_def,
      recordSelected, hs, recordReply]

theorem observeSelected_erases [DecidableEq K] [DecidableEq V] (p : PMF α)
    (select : K → Bool) (project : α → V) {n : ℕ} (program : QueryProgram K α R n)
    (state : CollisionView K α V) :
    (observeSelected p select project program state).map (fun out => (out.1, out.2.cache)) =
      evalProgram p program state.cache := by
  induction program generalizing state with
  | done value => simp [observeSelected, evalProgram, PMF.pure_map]
  | query key next ih =>
    rw [observeSelected, PMF.map_bind, evalProgram,
      ← selectedQuery_erases p select project state key, PMF.bind_map]
    congr 1
    funext out
    exact ih out.1 out.2

theorem selectedView_empty (select : K → Bool) :
    selectedView select (emptyView : CollisionView K α V) = emptyView := by
  simp [selectedView, emptyView, selectedCache_empty]

theorem recordSelected_valid [DecidableEq K] [DecidableEq V] (select : K → Bool)
    (project : α → V) (state : CollisionView K α V)
    (hv : ViewValid project (selectedView select state)) (key : K) (value : α) :
    ViewValid project (selectedView select (recordSelected select project state key value)) := by
  rw [selectedView_record]
  cases hs : select key
  · simpa [hs] using hv
  · simpa [hs] using recordReply_valid project (selectedView select state) hv key value

theorem selectedQuery_valid [DecidableEq K] [DecidableEq V] (p : PMF α)
    (select : K → Bool) (project : α → V) (state : CollisionView K α V)
    (hv : ViewValid project (selectedView select state)) (key : K)
    (out : α × CollisionView K α V)
    (ho : out ∈ (selectedQuery p select project state key).support) :
    ViewValid project (selectedView select out.2) := by
  cases h : state.cache key with
  | none =>
    simp only [selectedQuery, h, PMF.mem_support_map_iff] at ho
    obtain ⟨value, _, rfl⟩ := ho
    exact recordSelected_valid select project state hv key value
  | some value =>
    have he : out = (value, state) := by simpa [selectedQuery, h] using ho
    simpa [he] using hv

theorem observeSelected_valid [DecidableEq K] [DecidableEq V] (p : PMF α)
    (select : K → Bool) (project : α → V) {n : ℕ} (program : QueryProgram K α R n)
    (state : CollisionView K α V) (hv : ViewValid project (selectedView select state))
    (out : R × CollisionView K α V)
    (ho : out ∈ (observeSelected p select project program state).support) :
    ViewValid project (selectedView select out.2) := by
  induction program generalizing state out with
  | done value =>
    have he : out = (value, state) := by simpa [observeSelected] using ho
    simpa [he] using hv
  | query key next ih =>
    rw [observeSelected, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, hr, ho⟩ := ho
    exact ih reply.1 reply.2 (selectedQuery_valid p select project state hv key reply hr) out ho

theorem observeSelected_collision_flag [DecidableEq K] [DecidableEq V] (p : PMF α)
    (select : K → Bool) (project : α → V) {n : ℕ} (program : QueryProgram K α R n)
    (state : CollisionView K α V) (hv : ViewValid project (selectedView select state))
    (out : R × CollisionView K α V)
    (ho : out ∈ (observeSelected p select project program state).support)
    (hc : ¬ CollisionFree project (selectedCache select out.2.cache)) : out.2.bad = true := by
  have hvalid := observeSelected_valid p select project program state hv out ho
  cases hb : out.2.bad
  · exact False.elim (hc (hvalid.2 hb))
  · rfl

end
end C10Probability
