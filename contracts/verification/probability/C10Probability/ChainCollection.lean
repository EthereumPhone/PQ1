import C10Probability.ChainProgram

/-! Ordered collections of reply-dependent chains. The exact sum of their
lengths indexes the compiled client. Every chain shares the full memo table;
there is no independent-chain or freshness assumption. -/
namespace C10Probability
noncomputable section

variable {I K α N R T : Type*}

def mapReturnProgram (f : R → T) : {n : ℕ} → QueryProgram K α R n →
    QueryProgram K α T n
  | _, .done value => .done (f value)
  | _, .query key next => .query key (fun reply => mapReturnProgram f (next reply))

theorem evalProgram_mapReturn [DecidableEq K] (p : PMF α) (f : R → T)
    {n : ℕ} (program : QueryProgram K α R n) (table : Memo K α) :
    evalProgram p (mapReturnProgram f program) table =
      (evalProgram p program table).map (fun out => (f out.1, out.2)) := by
  induction program generalizing table with
  | done value => simp [mapReturnProgram, evalProgram, PMF.pure_map]
  | query key next ih =>
    simp only [mapReturnProgram, evalProgram, PMF.map_bind]
    congr 1
    funext reply
    exact ih reply.1 reply.2

theorem selectedBudget_mapReturn (select : K → Bool) (f : R → T)
    {n : ℕ} (program : QueryProgram K α R n) (q : ℕ) :
    SelectedBudget select (mapReturnProgram f program) q =
      SelectedBudget select program q := by
  induction program generalizing q with
  | done value => rfl
  | query key next ih =>
    cases hs : select key <;>
      simp only [mapReturnProgram, SelectedBudget, hs, Bool.false_eq_true, ↓reduceIte, ih]

def collectionSteps (steps : I → ℕ) (indices : List I) : ℕ :=
  (indices.map steps).sum

def chainCollectionProgram (input : I → ℕ → N → K) (project : α → N)
    (starts steps : I → ℕ) (values : I → N) :
    (indices : List I) → QueryProgram K α (List N) (collectionSteps steps indices)
  | [] => .done []
  | i :: rest => castProgram (by simp [collectionSteps, Nat.add_comm])
      (bindProgram (chainProgram (input i) project (starts i) (steps i) (values i))
        (fun current => mapReturnProgram (List.cons current)
          (chainCollectionProgram input project starts steps values rest)))

def chainCollectionLoop [DecidableEq K] (p : PMF α) (input : I → ℕ → N → K)
    (project : α → N) (starts steps : I → ℕ) (values : I → N) :
    List I → Memo K α → PMF (List N × Memo K α)
  | [], table => PMF.pure ([], table)
  | i :: rest, table =>
      (chainLoop p (input i) project (starts i) (steps i) (values i) table).bind
        (fun current => (chainCollectionLoop p input project starts steps values rest current.2).map
          (fun later => (current.1 :: later.1, later.2)))

theorem evalProgram_chainCollection [DecidableEq K] (p : PMF α)
    (input : I → ℕ → N → K) (project : α → N) (starts steps : I → ℕ)
    (values : I → N) (indices : List I) (table : Memo K α) :
    evalProgram p (chainCollectionProgram input project starts steps values indices) table =
      chainCollectionLoop p input project starts steps values indices table := by
  induction indices generalizing table with
  | nil => rfl
  | cons i rest ih =>
    simp only [chainCollectionProgram, evalProgram_cast, evalProgram_bind,
      evalProgram_chain, evalProgram_mapReturn, ih, chainCollectionLoop]

theorem chainCollectionLoop_length [DecidableEq K] (p : PMF α)
    (input : I → ℕ → N → K) (project : α → N) (starts steps : I → ℕ)
    (values : I → N) (indices : List I) (table : Memo K α)
    (out : List N × Memo K α)
    (ho : out ∈ (chainCollectionLoop p input project starts steps values indices table).support) :
    out.1.length = indices.length := by
  induction indices generalizing table out with
  | nil =>
    have he : out = ([], table) := by simpa [chainCollectionLoop] using ho
    simp [he]
  | cons i rest ih =>
    rw [chainCollectionLoop, PMF.mem_support_bind_iff] at ho
    obtain ⟨current, _, ho⟩ := ho
    rw [PMF.mem_support_map_iff] at ho
    obtain ⟨later, hl, rfl⟩ := ho
    simpa using congrArg Nat.succ (ih current.2 later hl)

theorem chainCollectionLoop_append [DecidableEq K] (p : PMF α)
    (input : I → ℕ → N → K) (project : α → N) (starts steps : I → ℕ)
    (values : I → N) (first later : List I) (table : Memo K α) :
    chainCollectionLoop p input project starts steps values (first ++ later) table =
      (chainCollectionLoop p input project starts steps values first table).bind
        (fun left => (chainCollectionLoop p input project starts steps values later left.2).map
          (fun right => (left.1 ++ right.1, right.2))) := by
  induction first generalizing table with
  | nil =>
    simp only [List.nil_append, chainCollectionLoop, PMF.pure_bind]
    exact (PMF.map_id _).symm
  | cons i rest ih =>
    simp only [List.cons_append, chainCollectionLoop, ih, PMF.bind_bind,
      PMF.bind_map, PMF.map_bind, PMF.map_comp, Function.comp_def, List.cons_append]

theorem chainLoop_constant_cached [DecidableEq K] (p : PMF α)
    (input : ℕ → N → K) (project : α → N) (start steps : ℕ) (reply : α) :
    chainLoop p input project start steps (project reply) (fun _ => some reply) =
      PMF.pure (project reply, fun _ => some reply) := by
  induction steps generalizing start with
  | zero => rfl
  | succ steps ih =>
    simp only [chainLoop, memoQuery, PMF.pure_bind, ih]

theorem chainCollectionLoop_constant_cached [DecidableEq K] (p : PMF α)
    (input : I → ℕ → N → K) (project : α → N) (starts steps : I → ℕ)
    (indices : List I) (reply : α) :
    chainCollectionLoop p input project starts steps (fun _ => project reply)
      indices (fun _ => some reply) =
      PMF.pure (List.replicate indices.length (project reply), fun _ => some reply) := by
  induction indices with
  | nil => rfl
  | cons i rest ih =>
    simp only [chainCollectionLoop, chainLoop_constant_cached, PMF.pure_bind, ih,
      PMF.pure_map, List.length_cons, List.replicate_succ]

end
end C10Probability
