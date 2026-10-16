import C10Probability.CollisionObserver

/-! Acceptance-filtered observation of the existing adaptive interpreter.
Every fresh reply is stored in the ordinary cache. Only accepted projections
enter the observed set or raise the collision flag. Erasure preserves the full
returned value and final cache, including rejected and cached replies. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K α V R : Type*}

def recordAcceptedReply [DecidableEq K] [DecidableEq V]
    (project : α → V) (accept : V → Bool) (state : CollisionView K α V)
    (key : K) (value : α) : CollisionView K α V :=
  ⟨Function.update state.cache key (some value),
    if accept (project value) then insert (project value) state.seen else state.seen,
    state.bad || (accept (project value) && decide (project value ∈ state.seen))⟩

def acceptedQuery [DecidableEq K] [DecidableEq V] (p : PMF α)
    (project : α → V) (accept : V → Bool) (state : CollisionView K α V)
    (key : K) : PMF (α × CollisionView K α V) :=
  match state.cache key with
  | some value => PMF.pure (value, state)
  | none => p.map fun value => (value, recordAcceptedReply project accept state key value)

def observeAcceptedProgram [DecidableEq K] [DecidableEq V] (p : PMF α)
    (project : α → V) (accept : V → Bool) : {n : ℕ} → QueryProgram K α R n →
      CollisionView K α V → PMF (R × CollisionView K α V)
  | _, .done value, state => PMF.pure (value, state)
  | _, .query key next, state => (acceptedQuery p project accept state key).bind fun out =>
      observeAcceptedProgram p project accept (next out.1) out.2

theorem acceptedQuery_erases [DecidableEq K] [DecidableEq V] (p : PMF α)
    (project : α → V) (accept : V → Bool) (state : CollisionView K α V) (key : K) :
    (acceptedQuery p project accept state key).map (fun out => (out.1, out.2.cache)) =
      memoQuery p state.cache key := by
  cases h : state.cache key <;>
    simp [acceptedQuery, memoQuery, h, PMF.map_comp, PMF.pure_map,
      Function.comp_def, recordAcceptedReply]

theorem observeAcceptedProgram_erases [DecidableEq K] [DecidableEq V] (p : PMF α)
    (project : α → V) (accept : V → Bool) {n : ℕ}
    (program : QueryProgram K α R n) (state : CollisionView K α V) :
    (observeAcceptedProgram p project accept program state).map
      (fun out => (out.1, out.2.cache)) = evalProgram p program state.cache := by
  induction program generalizing state with
  | done value => simp [observeAcceptedProgram, evalProgram, PMF.pure_map]
  | query key next ih =>
    rw [observeAcceptedProgram, PMF.map_bind, evalProgram,
      ← acceptedQuery_erases p project accept state key, PMF.bind_map]
    congr 1
    funext out
    exact ih out.1 out.2

def AcceptedSeenCovers (project : α → V) (accept : V → Bool)
    (cache : Memo K α) (seen : Finset V) : Prop :=
  ∀ key value, cache key = some value → accept (project value) = true → project value ∈ seen

/-- Equality of the projections also makes the second reply accepted. -/
def AcceptedCollisionFree (project : α → V) (accept : V → Bool) (cache : Memo K α) : Prop :=
  ∀ key other value reply, cache key = some value → cache other = some reply →
    accept (project value) = true → project value = project reply → key = other

def AcceptedViewValid (project : α → V) (accept : V → Bool)
    (state : CollisionView K α V) : Prop :=
  AcceptedSeenCovers project accept state.cache state.seen ∧
    (state.bad = false → AcceptedCollisionFree project accept state.cache)

theorem emptyAcceptedView_valid (project : α → V) (accept : V → Bool) :
    AcceptedViewValid project accept (emptyView : CollisionView K α V) := by
  simp [AcceptedViewValid, AcceptedSeenCovers, AcceptedCollisionFree, emptyView]

theorem recordAcceptedReply_valid [DecidableEq K] [DecidableEq V]
    (project : α → V) (accept : V → Bool) (state : CollisionView K α V)
    (hv : AcceptedViewValid project accept state) (key : K) (value : α) :
    AcceptedViewValid project accept (recordAcceptedReply project accept state key value) := by
  constructor
  · intro other reply hr ha
    by_cases hk : other = key
    · have he : reply = value := by simpa [recordAcceptedReply, hk] using hr.symm
      simp [recordAcceptedReply, ← he, ha]
    · have ho : state.cache other = some reply := by simpa [recordAcceptedReply, hk] using hr
      have hm := hv.1 other reply ho ha
      cases h : accept (project value) <;> simp [recordAcceptedReply, h, hm]
  · intro hb left right a b hl hr ha he
    have hparts : state.bad = false ∧
        (accept (project value) = true → project value ∉ state.seen) := by
      simpa [recordAcceptedReply] using hb
    by_cases hleft : left = key
    · by_cases hright : right = key
      · exact hleft.trans hright.symm
      · have hav : a = value := by simpa [recordAcceptedReply, hleft] using hl.symm
        have hcache : state.cache right = some b := by simpa [recordAcceptedReply, hright] using hr
        apply False.elim
        apply hparts.2 (by simpa [← hav] using ha)
        rw [← hav, he]
        exact hv.1 right b hcache (by simpa [← he] using ha)
    · by_cases hright : right = key
      · have hbvalue : b = value := by simpa [recordAcceptedReply, hright] using hr.symm
        have hcache : state.cache left = some a := by simpa [recordAcceptedReply, hleft] using hl
        apply False.elim
        apply hparts.2 (by simpa [← hbvalue, ← he] using ha)
        rw [← hbvalue, ← he]
        exact hv.1 left a hcache ha
      · exact hv.2 hparts.1 left right a b
          (by simpa [recordAcceptedReply, hleft] using hl)
          (by simpa [recordAcceptedReply, hright] using hr) ha he

theorem acceptedQuery_cached [DecidableEq K] [DecidableEq V] (p : PMF α)
    (project : α → V) (accept : V → Bool) (state : CollisionView K α V)
    (key : K) (value : α) (h : state.cache key = some value) :
    acceptedQuery p project accept state key = PMF.pure (value, state) := by
  simp [acceptedQuery, h]

theorem acceptedQuery_valid [DecidableEq K] [DecidableEq V] (p : PMF α)
    (project : α → V) (accept : V → Bool) (state : CollisionView K α V)
    (hv : AcceptedViewValid project accept state) (key : K)
    (out : α × CollisionView K α V) (ho : out ∈ (acceptedQuery p project accept state key).support) :
    AcceptedViewValid project accept out.2 := by
  cases h : state.cache key with
  | none =>
    simp only [acceptedQuery, h, PMF.mem_support_map_iff] at ho
    obtain ⟨value, _, rfl⟩ := ho
    exact recordAcceptedReply_valid project accept state hv key value
  | some value =>
    have he : out = (value, state) := by simpa [acceptedQuery, h] using ho
    simpa [he] using hv

theorem observeAcceptedProgram_valid [DecidableEq K] [DecidableEq V] (p : PMF α)
    (project : α → V) (accept : V → Bool) {n : ℕ}
    (program : QueryProgram K α R n) (state : CollisionView K α V)
    (hv : AcceptedViewValid project accept state) (out : R × CollisionView K α V)
    (ho : out ∈ (observeAcceptedProgram p project accept program state).support) :
    AcceptedViewValid project accept out.2 := by
  induction program generalizing state out with
  | done value =>
    have he : out = (value, state) := by simpa [observeAcceptedProgram] using ho
    simpa [he] using hv
  | query key next ih =>
    rw [observeAcceptedProgram, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, hr, ho⟩ := ho
    exact ih reply.1 reply.2 (acceptedQuery_valid p project accept state hv key reply hr) out ho

theorem observeAcceptedProgram_collision_flag [DecidableEq K] [DecidableEq V] (p : PMF α)
    (project : α → V) (accept : V → Bool) {n : ℕ}
    (program : QueryProgram K α R n) (state : CollisionView K α V)
    (hv : AcceptedViewValid project accept state) (out : R × CollisionView K α V)
    (ho : out ∈ (observeAcceptedProgram p project accept program state).support)
    (hc : ¬ AcceptedCollisionFree project accept out.2.cache) : out.2.bad = true := by
  have hvalid := observeAcceptedProgram_valid p project accept program state hv out ho
  cases hb : out.2.bad
  · exact False.elim (hc (hvalid.2 hb))
  · rfl

theorem acceptedQuery_bad_persists [DecidableEq K] [DecidableEq V] (p : PMF α)
    (project : α → V) (accept : V → Bool) (state : CollisionView K α V)
    (hb : state.bad = true) (key : K) (out : α × CollisionView K α V)
    (ho : out ∈ (acceptedQuery p project accept state key).support) : out.2.bad = true := by
  cases h : state.cache key with
  | none =>
    simp only [acceptedQuery, h, PMF.mem_support_map_iff] at ho
    obtain ⟨value, _, rfl⟩ := ho
    simp [recordAcceptedReply, hb]
  | some value =>
    have he : out = (value, state) := by simpa [acceptedQuery, h] using ho
    simpa [he] using hb

theorem observeAcceptedProgram_bad_persists [DecidableEq K] [DecidableEq V] (p : PMF α)
    (project : α → V) (accept : V → Bool) {n : ℕ}
    (program : QueryProgram K α R n) (state : CollisionView K α V)
    (hb : state.bad = true) (out : R × CollisionView K α V)
    (ho : out ∈ (observeAcceptedProgram p project accept program state).support) :
    out.2.bad = true := by
  induction program generalizing state out with
  | done value =>
    have he : out = (value, state) := by simpa [observeAcceptedProgram] using ho
    simpa [he] using hb
  | query key next ih =>
    rw [observeAcceptedProgram, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, hr, ho⟩ := ho
    exact ih reply.1 reply.2
      (acceptedQuery_bad_persists p project accept state hb key reply hr) out ho

end
end C10Probability
