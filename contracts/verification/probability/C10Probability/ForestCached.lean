import C10Probability.ForsExamples
import C10Probability.ForestCharges

/-! Inhabited complete cached executions retain every memo entry. These are
witnesses of the actual procedures, not fresh-draw or general correctness
claims. The helper also instantiates to finite key spaces. -/
namespace C10Probability
noncomputable section

variable {K α N S : Type*}

theorem fors_remember_zero (target leaf height : ℕ) :
    forsRemember target leaf height 0 0 (List.replicate 11 0) = List.replicate 11 0 := by
  simp only [forsRemember, List.set_replicate_self, ite_self]

theorem merge_loop_fixed_state_cached [DecidableEq K] (p : PMF α)
    (input : ℕ → ℕ → N → N → K) (project : α → N) (reply : α)
    (remember : ℕ → ℕ → N → N → S → S) (state : S)
    (fixed : ∀ kp height, remember kp height (project reply) (project reply) state = state)
    (kp height : ℕ) (shape : List ℕ) :
    mergeLoop p input project remember kp
      (shape.map (fun h => (project reply,h))) height (project reply) state (fun _ => some reply) =
      PMF.pure (((mergedShape height shape).map (fun h => (project reply,h)),state),
        fun _ => some reply) := by
  induction shape generalizing height with
  | nil => simp [mergeLoop, mergedShape, mergeShape]
  | cons level rest ih =>
    by_cases he : level = height
    · simp only [List.map_cons, mergeLoop, he, ↓reduceIte, memoQuery,
        PMF.pure_bind, fixed, ih]
      simp only [mergedShape, mergeShape, ↓reduceIte]
    · simp [List.map_cons, mergeLoop, he, mergedShape, mergeShape]

theorem fors_tree_loop_cached_zero [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (ht tree target n start : ℕ) (shape : List ℕ) :
    treeLoop digestDraw (fun leaf table => forsLeaf encode table seed ht tree leaf)
      (fun leaf h l r => encode (.inl (forsTreePairInput seed ht tree leaf h l r)))
      randomizerOfDigest (forsRemember target) n start (shape.map (fun h => (0,h)))
      (List.replicate 11 0) (fun _ => some 0) =
      PMF.pure (((runShape n shape).map (fun h => (0,h)),List.replicate 11 0),
        fun _ => some 0) := by
  have hz : randomizerOfDigest (0 : Digest) = 0 := by decide +kernel
  induction n generalizing start shape with
  | zero => rfl
  | succ n ih =>
    rw [treeLoop, fors_leaf_cached _ _ _ _ _ _ 0 0 rfl rfl, PMF.pure_bind]
    have hm := merge_loop_fixed_state_cached digestDraw
      (fun leaf h l r => encode (.inl (forsTreePairInput seed ht tree leaf h l r)))
      randomizerOfDigest 0 (forsRemember target) (List.replicate 11 0)
      (fun kp height => by simpa only [hz] using fors_remember_zero target kp height)
      start 0 shape
    simp only [hz] at hm ⊢
    rw [hm, PMF.pure_bind, ih]
    rfl

theorem fors_tree_cached_zero [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (ht tree target : ℕ) :
    forsTree encode (fun _ => some 0) seed ht tree target =
      PMF.pure ((0,List.replicate 11 0),fun _ => some 0) := by
  unfold forsTree forsTreeState
  have loop := fors_tree_loop_cached_zero encode seed ht tree target 2048 0 []
  simp only [fors_tree_shape, List.map_nil, List.map_cons] at loop
  rw [loop, PMF.pure_map]
  rfl

theorem fors_root_cached_zero [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (ht tree : ℕ) :
    forsRoot encode (fun _ => some 0) seed ht tree = PMF.pure (0,fun _ => some 0) := by
  rw [forsRoot, fors_tree_cached_zero, PMF.pure_map]

theorem fors_sign_cached_zero [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (ht tree target : ℕ) :
    forsSign encode (fun _ => some 0) seed ht tree target =
      PMF.pure ((0,List.replicate 11 0),fun _ => some 0) := by
  have hz : randomizerOfDigest (0 : Digest) = 0 := by decide +kernel
  simp only [forsSign, memoQuery, PMF.pure_bind, fors_tree_cached_zero, PMF.pure_map, hz]

theorem fors_recovery_loop_cached [DecidableEq K] (encode : ByteKey → K)
    (seed : ByteKey) (ht tree : ℕ) (auth : List Randomizer) (steps height index : ℕ)
    (current : Randomizer) (reply : Digest) :
    forsRecoveryLoop encode seed ht tree auth (steps + 1) height index current
      (fun _ => some reply) = PMF.pure (randomizerOfDigest reply,fun _ => some reply) := by
  induction steps generalizing height index current with
  | zero => simp [forsRecoveryLoop, memoQuery, PMF.pure_bind]
  | succ steps ih =>
    rw [forsRecoveryLoop, memoQuery, PMF.pure_bind]
    exact ih (height + 1) (index / 2) (randomizerOfDigest reply)

theorem fors_recover_cached [DecidableEq K] (encode : ByteKey → K)
    (seed : ByteKey) (ht tree target : ℕ) (secret : Randomizer)
    (auth : List Randomizer) (reply : Digest) :
    forsRecover encode (fun _ => some reply) seed ht tree target secret auth =
      PMF.pure (randomizerOfDigest reply,fun _ => some reply) := by
  rw [forsRecover, memoQuery, PMF.pure_bind]
  exact fors_recovery_loop_cached _ _ _ _ _ 10 _ _ _ _

theorem forest_one_cached_zero [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (ht tree target : ℕ) :
    forestOne encode (fun _ => some 0) seed ht tree target =
      PMF.pure (⟨0,List.replicate 11 0,0⟩,fun _ => some 0) := by
  have hz : randomizerOfDigest (0 : Digest) = 0 := by decide +kernel
  simp only [forestOne, fors_sign_cached_zero, PMF.pure_bind, fors_recover_cached,
    PMF.pure_map, hz]

theorem forest_fill_cached_zero [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (order : List (Fin 12)) :
    forestFillLoop encode seed ht digest order emptyForestState (fun _ => some 0) =
      PMF.pure (emptyForestState,fun _ => some 0) := by
  induction order with
  | nil => rfl
  | cons tree rest ih =>
    rw [forestFillLoop, forest_one_cached_zero, PMF.pure_bind]
    have hw : forestWrite emptyForestState tree.val ⟨0,List.replicate 11 0,0⟩ =
        emptyForestState := by simp only [forestWrite, emptyForestState, List.set_replicate_self]
    rw [hw, ih]

theorem forest_finish_cached_zero [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (ht : ℕ) :
    forestFinish encode (fun _ => some 0) seed ht emptyForestState =
      PMF.pure (⟨List.replicate 13 0,List.replicate 12 (List.replicate 11 0),0⟩,
        fun _ => some 0) := by
  have hz : randomizerOfDigest (0 : Digest) = 0 := by decide +kernel
  simp only [forestFinish, fors_root_cached_zero, PMF.pure_bind, forestLast,
    memoQuery, PMF.pure_map, hz, emptyForestState, List.set_replicate_self]

theorem forest_sign_cached_zero [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) :
    forestSign encode (fun _ => some 0) seed ht digest (List.replicate 32 0) =
      PMF.pure (⟨List.replicate 13 0,List.replicate 12 (List.replicate 11 0),0⟩,
        fun _ => some 0) := by
  simp only [forestSign, forest_shuffle_zero, PMF.pure_bind,
    forest_fill_cached_zero, forest_finish_cached_zero]

theorem forest_recovery_loop_cached [DecidableEq K] (encode : ByteKey → K)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (indices : List (Fin 12)) (roots : List Randomizer)
    (reply : Digest) :
    forestRecoveryLoop encode seed ht digest secrets auths indices roots (fun _ => some reply) =
      PMF.pure (roots ++ List.replicate indices.length (randomizerOfDigest reply),
        fun _ => some reply) := by
  induction indices generalizing roots with
  | nil => simp [forestRecoveryLoop]
  | cons tree rest ih =>
    simp only [forestRecoveryLoop, fors_recover_cached, PMF.pure_bind, ih,
      List.length_cons, List.replicate_succ, List.append_assoc, List.singleton_append]

theorem forest_recover_cached [DecidableEq K] (encode : ByteKey → K)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (reply : Digest) :
    forestRecover encode (fun _ => some reply) seed ht digest secrets auths =
      PMF.pure (randomizerOfDigest reply,fun _ => some reply) := by
  simp only [forestRecover, forest_recovery_loop_cached, PMF.pure_bind, memoQuery, PMF.pure_map]

end
end C10Probability
