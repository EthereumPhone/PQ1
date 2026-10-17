import C10Probability.MerkleExamples

/-! A complete cached subtree is an inhabited execution, including all512 WOTS
leaves. Every cache entry survives; no hidden freshness assumption is needed. -/
namespace C10Probability
noncomputable section

variable {K α N : Type*}

theorem merge_loop_constant_cached [DecidableEq K] (p : PMF α)
    (input : ℕ → ℕ → N → N → K) (project : α → N) (reply : α)
    (kp height : ℕ) (shape : List ℕ) :
    mergeLoop p input project (fun _ _ _ _ (_ : Unit) => ()) kp
      (shape.map (fun h => (project reply,h))) height (project reply) () (fun _ => some reply) =
      PMF.pure (((mergedShape height shape).map (fun h => (project reply,h)),()),
        fun _ => some reply) := by
  induction shape generalizing height with
  | nil => simp [mergeLoop, mergedShape, mergeShape]
  | cons level rest ih =>
    by_cases he : level = height
    · simp only [List.map_cons, mergeLoop, he, ↓reduceIte, memoQuery, PMF.pure_bind, ih]
      simp only [mergedShape, mergeShape, ↓reduceIte]
    · simp [List.map_cons, mergeLoop, he, mergedShape, mergeShape]

theorem tree_loop_constant_cached [DecidableEq K] (p : PMF α)
    (input : ℕ → ℕ → N → N → K) (project : α → N) (reply : α)
    (n start : ℕ) (shape : List ℕ) :
    treeLoop p (fun _ table => PMF.pure (project reply,table)) input project
      (fun _ _ _ _ (_ : Unit) => ()) n start (shape.map (fun h => (project reply,h))) ()
      (fun _ => some reply) =
      PMF.pure (((runShape n shape).map (fun h => (project reply,h)),()), fun _ => some reply) := by
  induction n generalizing start shape with
  | zero => rfl
  | succ n ih =>
    rw [treeLoop, PMF.pure_bind, merge_loop_constant_cached, PMF.pure_bind, ih]
    rfl

theorem subtree_root_cached [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (layer tree : ℕ) (reply : Digest) :
    subtreeRoot encode (fun _ => some reply) seed layer tree =
      PMF.pure (randomizerOfDigest reply, fun _ => some reply) := by
  unfold subtreeRoot subtreeLoop
  have loop : treeLoop digestDraw
      (fun kp table => wotsLeaf encode table seed layer tree kp)
      (fun kp h l r => encode (.inl (treePairInput seed layer tree kp h l r)))
      randomizerOfDigest (fun _ _ _ _ (_ : Unit) => ()) 512 0 [] () (fun _ => some reply) =
      PMF.pure (([(randomizerOfDigest reply,9)],()), fun _ => some reply) := by
    have general (n start : ℕ) (shape : List ℕ) : treeLoop digestDraw
        (fun kp table => wotsLeaf encode table seed layer tree kp)
        (fun kp h l r => encode (.inl (treePairInput seed layer tree kp h l r)))
        randomizerOfDigest (fun _ _ _ _ (_ : Unit) => ()) n start
        (shape.map (fun h => (randomizerOfDigest reply,h))) () (fun _ => some reply) =
        PMF.pure (((runShape n shape).map (fun h => (randomizerOfDigest reply,h)),()),
          fun _ => some reply) := by
      induction n generalizing start shape with
      | zero => rfl
      | succ n ih =>
        rw [treeLoop, wots_leaf_cached, PMF.pure_bind,
          merge_loop_constant_cached, PMF.pure_bind, ih]
        rfl
    simpa only [subtree_shape, List.map_nil, List.map_cons] using general 512 0 []
  rw [loop, PMF.pure_map]
  rfl

end
end C10Probability
