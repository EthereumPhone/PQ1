import C10Probability.DigestGrind
import C10Probability.Boundaries

/-! Stateful lazy sampling. A repeated key returns its stored value; only an
absent key draws. The search retains the resulting table even on exhaustion.
This is a manually transcribed PMF model, not an imported EasyCrypt theorem. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K α : Type*} [DecidableEq K]

abbrev Memo (K α : Type*) := K → Option α

def memoQuery (p : PMF α) (table : Memo K α) (key : K) : PMF (α × Memo K α) :=
  match table key with
  | some x => PMF.pure (x, table)
  | none => p.map fun x => (x, Function.update table key (some x))

theorem memoQuery_cached (p : PMF α) (table : Memo K α) (key : K) (x : α)
    (h : table key = some x) : memoQuery p table key = PMF.pure (x, table) := by
  simp [memoQuery, h]

theorem memoQuery_fresh (p : PMF α) (table : Memo K α) (key : K)
    (h : table key = none) :
    memoQuery p table key = p.map (fun x => (x, Function.update table key (some x))) := by
  simp [memoQuery, h]

theorem memoQuery_stores (p : PMF α) (table : Memo K α) (key : K)
    (out : α × Memo K α) (h : out ∈ (memoQuery p table key).support) :
    out.2 key = some out.1 := by
  cases ht : table key with
  | none =>
    rw [memoQuery_fresh p table key ht, PMF.mem_support_map_iff] at h
    obtain ⟨x, _, rfl⟩ := h
    simp
  | some x =>
    rw [memoQuery_cached p table key x ht] at h
    simpa using (show out = (x, table) from by simpa using h) ▸ ht

theorem memoQuery_other (p : PMF α) (table : Memo K α) (key other : K)
    (hne : other ≠ key) (out : α × Memo K α)
    (h : out ∈ (memoQuery p table key).support) : out.2 other = table other := by
  cases ht : table key with
  | none =>
    rw [memoQuery_fresh p table key ht, PMF.mem_support_map_iff] at h
    obtain ⟨x, _, rfl⟩ := h
    simp [hne]
  | some x =>
    rw [memoQuery_cached p table key x ht] at h
    have : out = (x, table) := by simpa using h
    simp [this]

theorem memoQuery_preserves (p : PMF α) (table : Memo K α) (key other : K)
    (x : α) (hx : table other = some x) (out : α × Memo K α)
    (h : out ∈ (memoQuery p table key).support) : out.2 other = some x := by
  by_cases he : other = key
  · subst other
    rw [memoQuery_cached p table key x hx] at h
    have : out = (x, table) := by simpa using h
    simp [this, hx]
  · rw [memoQuery_other p table key other he out h, hx]

def memoGrind (p : PMF α) (accept : α → Bool) (table : Memo K α) (start : ℕ) :
    List K → PMF (Option (ℕ × α) × Memo K α)
  | [] => PMF.pure (none, table)
  | key :: keys => (memoQuery p table key).bind fun out =>
      if accept out.1 then PMF.pure (some (start, out.1), out.2)
      else memoGrind p accept out.2 (start + 1) keys

theorem memoGrind_preserves (p : PMF α) (accept : α → Bool) (table : Memo K α)
    (start : ℕ) (keys : List K) (key : K) (x : α) (hx : table key = some x)
    (out : Option (ℕ × α) × Memo K α)
    (ho : out ∈ (memoGrind p accept table start keys).support) :
    out.2 key = some x := by
  induction keys generalizing table start out with
  | nil =>
    have he : out = (none, table) := by simpa [memoGrind] using ho
    simpa [he] using hx
  | cons first rest ih =>
    rw [memoGrind, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, hr, ho⟩ := ho
    have hp := memoQuery_preserves p table first key x hx reply hr
    cases ha : accept reply.1
    · simp only [ha, Bool.false_eq_true, ↓reduceIte] at ho
      exact ih reply.2 (start + 1) hp out ho
    · simp only [ha, ↓reduceIte] at ho
      have he : out = (some (start, reply.1), reply.2) := by simpa using ho
      simpa [he] using hp

/-- Both absence from the initial history and distinctness within this schedule
are required. The conclusion retains exhaustion, index and full reply. -/
theorem memoGrind_fresh (p : PMF α) (accept : α → Bool) (table : Memo K α)
    (start : ℕ) (keys : List K) (hd : keys.Nodup)
    (hf : ∀ key ∈ keys, table key = none) :
    (memoGrind p accept table start keys).map Prod.fst =
      grind p accept start keys.length := by
  induction keys generalizing table start with
  | nil => simp [memoGrind, grind, PMF.pure_map]
  | cons key keys ih =>
    obtain ⟨hk, hd⟩ := List.nodup_cons.mp hd
    rw [memoGrind, memoQuery_fresh p table key (hf key (by simp)),
      PMF.bind_map, PMF.map_bind]
    simp only [grind, Function.comp_def]
    congr 1
    funext x
    cases ha : accept x
    · simp only [Bool.false_eq_true, ↓reduceIte]
      apply ih _ _ hd
      intro other ho
      have hne : other ≠ key := by intro h; subst other; exact hk ho
      simpa [hne] using hf other (by simp [ho])
    · simp [PMF.pure_map]

/-- Empty history is an explicit satisfiable initial-history premise. -/
theorem memoGrind_empty (p : PMF α) (accept : α → Bool) (start : ℕ)
    (keys : List K) (hd : keys.Nodup) :
    (memoGrind p accept (fun _ => none) start keys).map Prod.fst =
      grind p accept start keys.length :=
  memoGrind_fresh p accept _ start keys hd (by simp)

theorem memoGrind_repeat (p : PMF α) (accept : α → Bool) (key : K) :
    (memoGrind p accept (fun _ => none) 0 [key, key]).map Prod.fst =
      cached p accept 2 := by
  simp only [memoGrind, memoQuery, PMF.bind_map, Function.comp_def,
    Function.update_self, PMF.pure_bind, PMF.map_bind, cached]
  congr 1
  funext x
  cases ha : accept x <;> simp [ha, grind, PMF.pure_bind, PMF.pure_map]

theorem memo_repeat_two_failure (key : K) :
    ((memoGrind fairReply id (fun _ => none) 0 [key, key]).map Prod.fst) none =
      (2 : ℝ≥0∞)⁻¹ := by
  rw [memoGrind_repeat, cached_two_failure]

theorem memo_prefilled_reject (p : PMF α) (accept : α → Bool) (key : K)
    (x : α) (hx : accept x = false) :
    (memoGrind p accept (fun _ => some x) 0 [key]).map Prod.fst = PMF.pure none := by
  simp [memoGrind, memoQuery, hx, PMF.pure_bind, PMF.pure_map]

end
end C10Probability
