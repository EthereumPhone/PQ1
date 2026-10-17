import C10Probability.ForestOne
import C10Probability.ForestShuffle

/-! Twelve actual signing/recovery calls, threaded in the computed order and
written to natural tree positions. All three list arrays and the complete
memo table are retained by the ordinary-loop/compiler equation. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

structure ForestState where
  secrets : List Randomizer
  auths : List (List Randomizer)
  roots : List Randomizer
  deriving DecidableEq

def emptyForestState : ForestState :=
  ⟨List.replicate 13 0, List.replicate 12 (List.replicate 11 0), List.replicate 13 0⟩

def forestWrite (state : ForestState) (tree : ℕ) (out : ForestTreeResult) : ForestState :=
  ⟨state.secrets.set tree out.secret, state.auths.set tree out.auth,
    state.roots.set tree out.root⟩

theorem forest_write_lengths (state : ForestState) (tree : ℕ) (out : ForestTreeResult) :
    (forestWrite state tree out).secrets.length = state.secrets.length ∧
    (forestWrite state tree out).auths.length = state.auths.length ∧
    (forestWrite state tree out).roots.length = state.roots.length := by
  simp [forestWrite]

def forestFillStep (encode : WotsQuery → K) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (tree : Fin 12) (state : ForestState) :
    QueryProgram K Digest ForestState 6156 :=
  mapReturnProgram (forestWrite state tree.val)
    (forestOneProgram encode seed ht tree.val (forestIndex digest tree.val))

def forestFillProgram (encode : WotsQuery → K) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (order : List (Fin 12)) (state : ForestState) :
    QueryProgram K Digest ForestState (collectionSteps (fun _ => 6156) order) :=
  stateFoldProgram (fun _ => 6156) (forestFillStep encode seed ht digest) order state

def forestFillLoop [DecidableEq K] (encode : WotsQuery → K) (seed : ByteKey)
    (ht : ℕ) (digest : Digest) :
    List (Fin 12) → ForestState → Memo K Digest → PMF (ForestState × Memo K Digest)
  | [], state, table => PMF.pure (state, table)
  | tree :: rest, state, table =>
      (forestOne encode table seed ht tree.val (forestIndex digest tree.val)).bind
        (fun out => forestFillLoop encode seed ht digest rest
          (forestWrite state tree.val out.1) out.2)

theorem forest_fill_eval [DecidableEq K] (encode : WotsQuery → K) (seed : ByteKey)
    (ht : ℕ) (digest : Digest) (order : List (Fin 12))
    (state : ForestState) (table : Memo K Digest) :
    evalProgram digestDraw (forestFillProgram encode seed ht digest order state) table =
      forestFillLoop encode seed ht digest order state table := by
  induction order generalizing state table with
  | nil => rfl
  | cons tree rest ih =>
    simp only [forestFillProgram, stateFoldProgram, evalProgram_cast, evalProgram_bind,
      forestFillStep, evalProgram_mapReturn, forest_one_eval, PMF.bind_map,
      forestFillLoop] at ih ⊢
    congr 1
    funext out
    exact ih _ _

theorem forest_fill_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (order : List (Fin 12)) (state : ForestState) :
    mapProgram encode (forestFillProgram labels seed ht digest order state) =
      forestFillProgram (encode ∘ labels) seed ht digest order state := by
  simp only [forestFillProgram, mapProgram_stateFold, forestFillStep,
    mapProgram_mapReturn, forest_one_map]
  rfl

theorem forest_fill_public (seed : ByteKey) (ht : ℕ) (digest : Digest)
    (order : List (Fin 12)) (state : ForestState) :
    PublicBudget (forestFillProgram id seed ht digest order state)
      (collectionSteps (fun _ => 4107) order) := by
  apply publicBudget_stateFold
  intro tree state
  rw [forestFillStep, publicBudget_mapReturn]
  exact forest_one_public _ _ _ _

theorem collection_steps_constant {I : Type*} (charge : ℕ) (indices : List I) :
    collectionSteps (fun _ => charge) indices = charge * indices.length := by
  induction indices with
  | nil => simp [collectionSteps]
  | cons i rest ih =>
    simp only [collectionSteps, List.map_cons, List.sum_cons, List.length_cons] at ih ⊢
    rw [ih, Nat.mul_add, Nat.mul_one]
    omega

theorem forest_fill_raw_calls (order : ForestOrder) :
    collectionSteps (fun _ => 6156) order.val = 73872 := by
  rw [collection_steps_constant, forest_order_length]

theorem forest_fill_public_calls (order : ForestOrder) :
    collectionSteps (fun _ => 4107) order.val = 49284 := by
  rw [collection_steps_constant, forest_order_length]

def forestOrderedProgram (encode : WotsQuery → K) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (order : ForestOrder) : QueryProgram K Digest ForestState 73872 :=
  castProgram (forest_fill_raw_calls order)
    (forestFillProgram encode seed ht digest order.val emptyForestState)

attribute [irreducible] forestOrderedProgram

theorem forest_ordered_eval [DecidableEq K] (encode : WotsQuery → K) (seed : ByteKey)
    (ht : ℕ) (digest : Digest) (order : ForestOrder) (table : Memo K Digest) :
    evalProgram digestDraw (forestOrderedProgram encode seed ht digest order) table =
      forestFillLoop encode seed ht digest order.val emptyForestState table := by
  rw [forestOrderedProgram, evalProgram_cast, forest_fill_eval]

theorem forest_ordered_map (encode : K → L) (labels : WotsQuery → K) (seed : ByteKey)
    (ht : ℕ) (digest : Digest) (order : ForestOrder) :
    mapProgram encode (forestOrderedProgram labels seed ht digest order) =
      forestOrderedProgram (encode ∘ labels) seed ht digest order := by
  simp only [forestOrderedProgram, mapProgram_cast, forest_fill_map]

theorem forest_ordered_public (seed : ByteKey) (ht : ℕ) (digest : Digest)
    (order : ForestOrder) :
    PublicBudget (forestOrderedProgram id seed ht digest order) 49284 := by
  rw [forestOrderedProgram, publicBudget_cast, ← forest_fill_public_calls order]
  exact forest_fill_public _ _ _ _ _

end
end C10Probability
