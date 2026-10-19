import C10Probability.ReplyBudget
import C10Probability.TreeRun
import C10Probability.StateFold
import C10Probability.CountProgram

/-! Structural exclusion with a result predicate. Keeping the result predicate
lets later compression calls use the array widths actually produced by a loop. -/
namespace C10Probability
noncomputable section
variable {K α R T I S N : Type*}

def QueryExclusion (select : K → Bool) (post : R → Prop) :
    {n : ℕ} → QueryProgram K α R n → Prop
  | _, .done value => post value
  | _, .query key next => select key = false ∧ ∀ reply, QueryExclusion select post (next reply)

theorem queryExclusion_cast (select : K → Bool) (post : R → Prop) {n m : ℕ}
    (h : n = m) (program : QueryProgram K α R n) :
    QueryExclusion select post (castProgram h program) = QueryExclusion select post program := by
  subst m
  rfl

theorem queryExclusion_reserve (select : K → Bool) (post : R → Prop) (extra : ℕ)
    {n : ℕ} (program : QueryProgram K α R n) :
    QueryExclusion select post (reserveProgram extra program) = QueryExclusion select post program := by
  induction program with
  | done value => rfl
  | query key next ih => simp only [reserveProgram, QueryExclusion, ih]

theorem queryExclusion_mapReturn (select : K → Bool) (post : T → Prop) (f : R → T)
    {n : ℕ} (program : QueryProgram K α R n) :
    QueryExclusion select post (mapReturnProgram f program) =
      QueryExclusion select (post ∘ f) program := by
  induction program with
  | done value => rfl
  | query key next ih => simp only [mapReturnProgram, QueryExclusion, ih]

theorem queryExclusion_bind (select : K → Bool) (middle : R → Prop) (post : T → Prop)
    {n m : ℕ} (program : QueryProgram K α R n) (after : R → QueryProgram K α T m)
    (first : QueryExclusion select middle program)
    (later : ∀ value, middle value → QueryExclusion select post (after value)) :
    QueryExclusion select post (bindProgram program after) := by
  induction program with
  | done value =>
    simpa only [bindProgram, queryExclusion_cast, queryExclusion_reserve] using later value first
  | query key next ih => exact ⟨first.1, fun reply => ih reply (first.2 reply)⟩

theorem queryExclusion_budget (select : K → Bool) (post : R → Prop)
    {n : ℕ} (program : QueryProgram K Digest R n)
    (excluded : QueryExclusion select post program) :
    ReplyBudget (hmsgReplyCharge select) program 0 := by
  induction program with
  | done value => trivial
  | query key next ih =>
    intro value
    simp only [hmsgReplyCharge, excluded.1, Bool.false_and, Bool.false_eq_true, ↓reduceIte]
    exact ih value (excluded.2 value)

theorem queryExclusion_map {L : Type*} (select : L → Bool) (post : R → Prop)
    (encode : K → L) {n : ℕ} (program : QueryProgram K α R n) :
    QueryExclusion select post (mapProgram encode program) =
      QueryExclusion (select ∘ encode) post program := by
  induction program with
  | done value => rfl
  | query key next ih => simp only [mapProgram, QueryExclusion, Function.comp_apply, ih]

theorem queryExclusion_reply_bind (select : K → Bool) (middle : R → Prop)
    {n m : ℕ} (program : QueryProgram K Digest R n)
    (after : R → QueryProgram K Digest T m) (q : ℕ)
    (first : QueryExclusion select middle program)
    (later : ∀ value, middle value → ReplyBudget (hmsgReplyCharge select) (after value) q) :
    ReplyBudget (hmsgReplyCharge select) (bindProgram program after) q := by
  induction program with
  | done value =>
    simpa only [bindProgram, replyBudget_cast, replyBudget_reserve] using later value first
  | query key next ih =>
    intro reply
    simp only [hmsgReplyCharge, first.1, Bool.false_and, Bool.false_eq_true, ↓reduceIte]
    exact ih reply (first.2 reply)

theorem queryExclusion_chain (select : K → Bool) (input : ℕ → N → K) (project : α → N)
    (excluded : ∀ pos value, select (input pos value) = false)
    (start steps : ℕ) (current : N) :
    QueryExclusion select (fun _ => True) (chainProgram input project start steps current) := by
  induction steps generalizing start current with
  | zero => trivial
  | succ steps ih => exact ⟨excluded start current, fun reply => ih (start + 1) (project reply)⟩

theorem queryExclusion_stateFold (select : K → Bool) (post : S → Prop) (cost : I → ℕ)
    (step : (i : I) → S → QueryProgram K α S (cost i))
    (excluded : ∀ i state, post state → QueryExclusion select post (step i state))
    (indices : List I) (state : S) (valid : post state) :
    QueryExclusion select post (stateFoldProgram cost step indices state) := by
  induction indices generalizing state with
  | nil => exact valid
  | cons i rest ih =>
    rw [stateFoldProgram, queryExclusion_cast]
    exact queryExclusion_bind select post post _ _ (excluded i state valid) ih

theorem queryExclusion_collection (select : K → Bool) (input : I → ℕ → N → K)
    (project : α → N) (starts steps : I → ℕ) (values : I → N)
    (excluded : ∀ i pos value, select (input i pos value) = false) (indices : List I)
    (count : ℕ) (length : indices.length = count) :
    QueryExclusion select (fun out => out.length = count)
      (chainCollectionProgram input project starts steps values indices) := by
  subst count
  induction indices with
  | nil => rfl
  | cons i rest ih =>
    rw [chainCollectionProgram, queryExclusion_cast]
    apply queryExclusion_bind select (fun _ => True) _ _ _
      (queryExclusion_chain select (input i) project (excluded i) _ _ _)
    intro current _
    simpa only [queryExclusion_mapReturn, Function.comp_def, List.length_cons,
      Nat.add_right_cancel_iff] using ih

theorem queryExclusion_count (select : K → Bool) (accept : α → Bool)
    (start : ℕ) (keys : List K) (excluded : ∀ key ∈ keys, select key = false) :
    QueryExclusion select (fun _ => True) (countProgram accept start keys) := by
  induction keys generalizing start with
  | nil => trivial
  | cons key rest ih =>
    refine ⟨excluded key (by simp), fun reply => ?_⟩
    cases ha : accept reply
    · simp only [ha, Bool.false_eq_true, ↓reduceIte]
      exact ih (start + 1) (fun k hk => excluded k (by simp [hk]))
    · simp only [ha, ↓reduceIte, QueryExclusion]

theorem queryExclusion_treeCast (select : K → Bool) {first second : List ℕ} {n m : ℕ}
    (shapeEq : first = second) (costEq : n = m)
    (program : QueryProgram K α (ShapeStack N first × S) n) :
    QueryExclusion select (fun _ => True) (castTreeProgram shapeEq costEq program) =
      QueryExclusion select (fun _ => True) program := by
  subst second
  subst m
  rfl

theorem queryExclusion_merge (select : K → Bool) (input : ℕ → ℕ → N → N → K)
    (project : α → N) (remember : ℕ → ℕ → N → N → S → S)
    (excluded : ∀ kp h left right, select (input kp h left right) = false)
    (kp : ℕ) (shape : List ℕ) (height : ℕ) (stack : ShapeStack N shape)
    (current : N) (state : S) :
    QueryExclusion select (fun _ => True)
      (mergeProgram input project remember kp shape height stack current state) := by
  induction shape generalizing height current state with
  | nil => trivial
  | cons level rest ih =>
    by_cases same : level = height
    · rw [mergeProgram, dif_pos same, queryExclusion_treeCast]
      exact ⟨excluded _ _ _ _, fun reply => ih _ _ _ _⟩
    · rw [mergeProgram, dif_neg same, queryExclusion_treeCast]
      trivial

theorem queryExclusion_tree (select : K → Bool) (leafCost : ℕ)
    (leaf : ℕ → QueryProgram K α N leafCost)
    (leaves : ∀ kp, QueryExclusion select (fun _ => True) (leaf kp))
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S)
    (excluded : ∀ kp h left right, select (input kp h left right) = false)
    (n start : ℕ) (shape : List ℕ) (stack : ShapeStack N shape) (state : S) :
    QueryExclusion select (fun _ => True)
      (treeProgram leafCost leaf input project remember n start shape stack state) := by
  induction n generalizing start shape state with
  | zero => trivial
  | succ n ih =>
    rw [treeProgram, queryExclusion_cast]
    apply queryExclusion_bind select (fun _ => True) _ _ _ (leaves start)
    intro current _
    apply queryExclusion_bind select (fun _ => True) _ _ _
      (queryExclusion_merge select input project remember excluded _ _ _ _ _ _)
    intro merged _
    exact ih _ _ _ _

end
end C10Probability
