import C10Probability.OpeningCache

/-! Compositional full-cache correspondence. A symbolic result may defer the
selected secret until a successful signature is returned. These equations do
not by themselves assert that the source hides the secret: query avoidance and
the reveal condition are separate obligations of the concrete construction. -/
namespace C10Probability
noncomputable section
variable {K P α S R T U V : Type*} [DecidableEq K]

def openingProject (interpret : R → T) (out : OpeningOutput K α R) : T × Memo K α :=
  (interpret out.value, out.cache)

def OpeningRefines (p : PMF α) (encode : S → P → K) (project : α → S)
    (target : K) (secret : α) (interpret : R → T) {n m : ℕ}
    (instrumented : OpeningProgram K P α α R n) (ordinary : QueryProgram K α T m) : Prop :=
  ∀ table opened, table target = some secret →
    (evalOpening p encode project secret instrumented table opened).map
      (openingProject interpret) = evalProgram p ordinary table

theorem opening_refines_done (p : PMF α) (encode : S → P → K) (project : α → S)
    (target : K) (secret : α) (interpret : R → T) (value : R) (n m : ℕ) :
    OpeningRefines p encode project target secret interpret
      (.done (n := n) value) (.done (n := m) (interpret value)) := by
  intro table opened _
  simp only [evalOpening, PMF.pure_map, openingProject, evalProgram]

theorem opening_refines_lift (p : PMF α) (encode : S → P → K) (project : α → S)
    (target : K) (secret : α) {n : ℕ} (program : QueryProgram K α R n) :
    OpeningRefines p encode project target secret id (liftOpening program) program := by
  intro table opened _
  rw [eval_opening_lift, PMF.map_comp]
  simpa only [Function.comp_def, openingProject, id_eq, Prod.mk.eta] using
    PMF.map_id (evalProgram p program table)

theorem opening_refines_cast (p : PMF α) (encode : S → P → K) (project : α → S)
    (target : K) (secret : α) (interpret : R → T) {n m n' m' : ℕ}
    (hn : n = n') (hm : m = m') (instrumented : OpeningProgram K P α α R n)
    (ordinary : QueryProgram K α T m)
    (refines : OpeningRefines p encode project target secret interpret instrumented ordinary) :
    OpeningRefines p encode project target secret interpret
      (castOpening hn instrumented) (castProgram hm ordinary) := by
  subst n'
  subst m'
  exact refines

theorem opening_refines_reserve (p : PMF α) (encode : S → P → K) (project : α → S)
    (target : K) (secret : α) (interpret : R → T) {n m : ℕ}
    (instrumented : OpeningProgram K P α α R n) (ordinary : QueryProgram K α T m)
    (refines : OpeningRefines p encode project target secret interpret instrumented ordinary)
    (extra left : ℕ) :
    OpeningRefines p encode project target secret interpret
      (reserveOpening extra instrumented) (reserveProgram left ordinary) := by
  intro table opened cached
  rw [eval_opening_reserve, evalProgram_reserve]
  exact refines table opened cached

theorem opening_refines_bind (p : PMF α) (encode : S → P → K) (project : α → S)
    (target : K) (secret : α) (interpret : R → T) (result : U → V)
    {n m a b : ℕ} (instrumented : OpeningProgram K P α α R n)
    (ordinary : QueryProgram K α T m) (after : R → OpeningProgram K P α α U a)
    (next : T → QueryProgram K α V b)
    (first : OpeningRefines p encode project target secret interpret instrumented ordinary)
    (later : ∀ value, OpeningRefines p encode project target secret result
      (after value) (next (interpret value))) :
    OpeningRefines p encode project target secret result
      (bindOpening instrumented after) (bindProgram ordinary next) := by
  intro table opened cached
  rw [eval_opening_bind, PMF.map_bind, evalProgram_bind,
    ← first table opened cached, PMF.bind_map]
  apply bind_eq_of_support
  intro out supported
  exact later out.value out.cache out.opened
    (eval_opening_preserves p encode project secret instrumented table opened
      target secret cached out supported)

theorem opening_refines_map (p : PMF α) (encode : S → P → K) (project : α → S)
    (target : K) (secret : α) (interpret : R → T) (result : U → V)
    (f : R → U) (g : T → V) (compatible : ∀ value, result (f value) = g (interpret value))
    {n m : ℕ} (instrumented : OpeningProgram K P α α R n)
    (ordinary : QueryProgram K α T m)
    (refines : OpeningRefines p encode project target secret interpret instrumented ordinary) :
    OpeningRefines p encode project target secret result
      (mapOpeningReturn f instrumented) (mapReturnProgram g ordinary) := by
  intro table opened cached
  rw [eval_opening_mapReturn, PMF.map_comp, evalProgram_mapReturn,
    ← refines table opened cached, PMF.map_comp]
  congr 1
  funext out
  simp only [Function.comp_def, openingProject, compatible]

theorem opening_refines_query (p : PMF α) (encode : S → P → K) (project : α → S)
    (target : K) (secret : α) (interpret : R → T) {n m : ℕ} (key : K)
    (after : α → OpeningProgram K P α α R n) (next : α → QueryProgram K α T m)
    (later : ∀ value, OpeningRefines p encode project target secret interpret
      (after value) (next value)) :
    OpeningRefines p encode project target secret interpret (.query key after) (.query key next) := by
  intro table opened cached
  rw [evalOpening, PMF.map_bind, evalProgram]
  apply bind_eq_of_support
  intro reply supported
  exact later reply.1 reply.2 opened
    (memoQuery_preserves p table key target secret cached reply supported)

theorem opening_refines_reveal (p : PMF α) (encode : S → P → K) (project : α → S)
    (target : K) (secret : α) (interpret : R → T) {n m : ℕ}
    (after : α → OpeningProgram K P α α R n) (next : α → QueryProgram K α T m)
    (later : OpeningRefines p encode project target secret interpret (after secret) (next secret)) :
    OpeningRefines p encode project target secret interpret (.reveal after) (.query target next) := by
  intro table opened cached
  rw [evalOpening, evalProgram_cached p target next table secret cached]
  exact later table true cached

end
end C10Probability
