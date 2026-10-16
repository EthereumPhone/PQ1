import C10Probability.LabelledGrind

/-! Two sequential queries through one persistent table per attempt. The first
reply determines the label and hence the second query. The observation theorem
derives independent label sampling from fresh first-query inputs. -/
namespace C10Probability
noncomputable section

variable {K L α β : Type*}

theorem bind_eq_of_support (p : PMF α) (f g : α → PMF β)
    (h : ∀ x ∈ p.support, f x = g x) : p.bind f = p.bind g := by
  apply PMF.ext
  intro y
  simp only [PMF.bind_apply]
  apply tsum_congr
  intro x
  by_cases hx : x ∈ p.support
  · rw [h x hx]
  · rw [(p.apply_eq_zero_iff x).mpr hx]
    simp

def derivedMemoGrind [DecidableEq K] (p : PMF α) (derive : α → L) (encode : L → K)
    (accept : α → Bool) (table : Memo K α) (start : ℕ) :
    List K → PMF (Option (ℕ × L × α) × Memo K α)
  | [] => PMF.pure (none, table)
  | key :: keys => (memoQuery p table key).bind fun first =>
      (memoQuery p first.2 (encode (derive first.1))).bind fun second =>
        if accept second.1 then PMF.pure (some (start, derive first.1, second.1), second.2)
        else derivedMemoGrind p derive encode accept second.2 (start + 1) keys

theorem derivedMemoGrind_refines [DecidableEq K] (p : PMF α) (derive : α → L)
    (encode : L → K) (accept : α → Bool) (hidden : K → Bool)
    (visible : ∀ label, hidden (encode label) = false)
    (table : Memo K α) (start : ℕ) (keys : List K) (hd : keys.Nodup)
    (hf : ∀ key ∈ keys, table key = none)
    (hh : ∀ key ∈ keys, hidden key = true) :
    (derivedMemoGrind p derive encode accept table start keys).map
      (fun out => (out.1, eraseMemo hidden out.2)) =
        labelledMemoGrind (p.map derive) p encode accept
          (eraseMemo hidden table) start keys.length := by
  induction keys generalizing table start with
  | nil => simp [derivedMemoGrind, labelledMemoGrind, PMF.pure_map]
  | cons key keys ih =>
    obtain ⟨hk, hd⟩ := List.nodup_cons.mp hd
    have hkey := hh key (by simp)
    rw [derivedMemoGrind, memoQuery_fresh p table key (hf key (by simp)),
      PMF.bind_map, PMF.map_bind]
    simp only [labelledMemoGrind, PMF.bind_map, Function.comp_def]
    congr 1
    funext value
    rw [← eraseMemo_update_hidden hidden table key (some value) hkey,
      memoQuery_erase p hidden (Function.update table key (some value))
        (encode (derive value)) (visible (derive value)), PMF.bind_map, PMF.map_bind]
    simp only [Function.comp_def]
    apply bind_eq_of_support
    intro out hout
    cases ha : accept out.1
    · simp only [Bool.false_eq_true, ↓reduceIte]
      apply ih out.2 (start + 1) hd
      · intro other ho
        have hother := hh other (by simp [ho])
        have hneq : other ≠ encode (derive value) := by
          intro he
          rw [he, visible] at hother
          cases hother
        rw [memoQuery_other p (Function.update table key (some value))
          (encode (derive value)) other hneq out hout]
        have hnk : other ≠ key := by intro he; subst other; exact hk ho
        simpa [hnk] using hf other (by simp [ho])
      · intro other ho
        exact hh other (by simp [ho])
    · simp [PMF.pure_map]

theorem derivedMemoGrind_result [DecidableEq K] (p : PMF α) (derive : α → L)
    (encode : L → K) (accept : α → Bool) (hidden : K → Bool)
    (visible : ∀ label, hidden (encode label) = false)
    (table : Memo K α) (start : ℕ) (keys : List K) (hd : keys.Nodup)
    (hf : ∀ key ∈ keys, table key = none)
    (hh : ∀ key ∈ keys, hidden key = true) :
    (derivedMemoGrind p derive encode accept table start keys).map
      (fun out => forgetLabel out.1) =
        (randomMemoGrind ((p.map derive).map encode) p accept table start keys.length).map
          Prod.fst := by
  have h := derivedMemoGrind_refines p derive encode accept hidden visible table start
    keys hd hf hh
  rw [labelledMemoGrind_erase _ _ _ _ hidden visible] at h
  have ho := congrArg (PMF.map (fun out : Option (ℕ × L × α) × Memo K α =>
    forgetLabel out.1)) h
  rw [← labelledMemoGrind_projection]
  simpa only [PMF.map_comp, Function.comp_def] using ho

theorem derived_prefilled_label :
    (derivedMemoGrind (PMF.pure false) id (fun _ => true) (fun _ => true)
      (fun key : Bool => if key then none else some true) 0 [false]).map Prod.fst =
        PMF.pure (some (0, true, false)) := by
  simp [derivedMemoGrind, memoQuery, PMF.pure_map, PMF.pure_bind]

theorem derived_immediate_state :
    derivedMemoGrind (PMF.pure true) id (fun _ => (1 : ℕ)) id (fun _ => none) 0 [0, 2] =
      PMF.pure (some (0, true, true),
        Function.update (Function.update (fun _ => none) 0 (some true)) 1 (some true)) := by
  simp [derivedMemoGrind, memoQuery, PMF.pure_map, PMF.pure_bind]

theorem derived_cached_hmsg_failure :
    (derivedMemoGrind (PMF.pure true) id (fun _ => true) id
      (fun key : Bool => if key then some false else none) 0 [false]).map Prod.fst =
        PMF.pure none := by
  simp [derivedMemoGrind, memoQuery, PMF.pure_map, PMF.pure_bind]

theorem derived_prefilled_differs :
    (derivedMemoGrind (PMF.pure false) id (fun _ => true) (fun _ => true)
      (fun key : Bool => if key then none else some true) 0 [false]).map Prod.fst ≠
    (labelledMemoGrind (PMF.pure false) (PMF.pure false) (fun _ => true) (fun _ => true)
      (fun key : Bool => if key then none else some true) 0 1).map Prod.fst := by
  rw [derived_prefilled_label]
  simp [labelledMemoGrind, memoQuery, PMF.pure_map, PMF.pure_bind]
  intro he
  have h := congrArg (fun p : PMF (Option (ℕ × Bool × Bool)) => p (some (0, true, false))) he
  simp [PMF.pure_apply] at h

end
end C10Probability
