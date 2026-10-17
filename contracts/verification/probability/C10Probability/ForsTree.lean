import C10Probability.ForsLeaf
import C10Probability.ForsShape

/-! The actual FORS tree loop remembers authentication siblings before each
ordered merge. Unlike Merkle.build, FORS has no kept flags: each matching merge
writes the path slot. The compiler retains the whole final memo table. -/
namespace C10Probability
noncomputable section

variable {K L S : Type*}

def forsRemember (target leaf height : ℕ) (left right : Randomizer)
    (auth : List Randomizer) : List Randomizer :=
  let sibling := siblingIndex (target / 2 ^ height)
  let leftStart := (leaf / 2 ^ (height + 1)) * 2 ^ (height + 1)
  let rightStart := leftStart + 2 ^ height
  if sibling % 2 = 0 then
    if sibling * 2 ^ height = leftStart then auth.set height left else auth
  else if sibling * 2 ^ height = rightStart then auth.set height right else auth

theorem fors_remember_length (target leaf height : ℕ) (left right : Randomizer)
    (auth : List Randomizer) :
    (forsRemember target leaf height left right auth).length = auth.length := by
  unfold forsRemember
  dsimp only
  split <;> split <;> simp

def forsTreeStateProgram (encode : WotsQuery → K) (seed : ByteKey) (ht tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    QueryProgram K Digest (List (Randomizer × ℕ) × S) 6143 :=
  castProgram fors_tree_raw_calls (mapReturnProgram (eraseTreeState (runShape 2048 []))
    (treeProgram 2 (forsLeafProgram encode seed ht tree)
      (fun leaf h l r => encode (.inl (forsTreePairInput seed ht tree leaf h l r)))
      randomizerOfDigest remember 2048 0 [] PUnit.unit initial))

attribute [irreducible] forsTreeStateProgram

def forsTreeState [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    PMF ((List (Randomizer × ℕ) × S) × Memo K Digest) :=
  treeLoop digestDraw (fun leaf memo => forsLeaf encode memo seed ht tree leaf)
    (fun leaf h l r => encode (.inl (forsTreePairInput seed ht tree leaf h l r)))
    randomizerOfDigest remember 2048 0 [] initial table

theorem fors_tree_state_eval [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (ht tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    evalProgram digestDraw (forsTreeStateProgram encode seed ht tree remember initial) table =
      forsTreeState encode table seed ht tree remember initial := by
  rw [forsTreeStateProgram, evalProgram_cast, evalProgram_mapReturn]
  change (evalProgram digestDraw _ table).map (eraseTreeOutput (runShape 2048 [])) = _
  rw [tree_program_eval]
  simp only [fors_leaf_eval, eraseStack, forsTreeState]

theorem fors_tree_state_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (ht tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    mapProgram encode (forsTreeStateProgram labels seed ht tree remember initial) =
      forsTreeStateProgram (encode ∘ labels) seed ht tree remember initial := by
  simp only [forsTreeStateProgram, mapProgram_cast, mapProgram_mapReturn,
    tree_program_map, fors_leaf_map, Function.comp_def]

set_option maxRecDepth 80000 in
theorem fors_tree_state_public (seed : ByteKey) (ht tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    PublicBudget (forsTreeStateProgram id seed ht tree remember initial) 4095 := by
  rw [forsTreeStateProgram, publicBudget_cast, publicBudget_mapReturn, ← fors_tree_public_calls]
  exact tree_program_public 2 1 _ (fors_leaf_public seed ht tree) _ _ _ _ _ _ _ _

def forsTreeProgram (encode : WotsQuery → K) (seed : ByteKey) (ht tree target : ℕ) :
    QueryProgram K Digest (Randomizer × List Randomizer) 6143 :=
  mapReturnProgram (fun out => (treeRoot out.1, out.2))
    (forsTreeStateProgram encode seed ht tree (forsRemember target) (List.replicate 11 0))

def forsTree [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) :
    PMF ((Randomizer × List Randomizer) × Memo K Digest) :=
  (forsTreeState encode table seed ht tree (forsRemember target) (List.replicate 11 0)).map
    (fun out => ((treeRoot out.1.1, out.1.2), out.2))

theorem fors_tree_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) :
    evalProgram digestDraw (forsTreeProgram encode seed ht tree target) table =
      forsTree encode table seed ht tree target := by
  rw [forsTreeProgram, evalProgram_mapReturn, fors_tree_state_eval]
  rfl

theorem fors_tree_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (ht tree target : ℕ) :
    mapProgram encode (forsTreeProgram labels seed ht tree target) =
      forsTreeProgram (encode ∘ labels) seed ht tree target := by
  simp only [forsTreeProgram, mapProgram_mapReturn, fors_tree_state_map]

theorem fors_tree_public (seed : ByteKey) (ht tree target : ℕ) :
    PublicBudget (forsTreeProgram id seed ht tree target) 4095 := by
  rw [forsTreeProgram, publicBudget_mapReturn]
  exact fors_tree_state_public _ _ _ _ _

theorem fors_tree_auth_length [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (ht tree target : ℕ)
    (out : (Randomizer × List Randomizer) × Memo K Digest)
    (ho : out ∈ (forsTree encode table seed ht tree target).support) :
    out.1.2.length = 11 := by
  rw [forsTree, PMF.mem_support_map_iff] at ho
  obtain ⟨result, hr, rfl⟩ := ho
  exact tree_loop_state_invariant digestDraw _ _ randomizerOfDigest (forsRemember target)
    (fun auth => auth.length = 11)
    (fun leaf h l r auth ha => by
      dsimp only
      rw [fors_remember_length]
      exact ha)
    2048 0 [] (List.replicate 11 0) table (by simp) result hr

def forsRootProgram (encode : WotsQuery → K) (seed : ByteKey) (ht tree : ℕ) :
    QueryProgram K Digest Randomizer 6143 :=
  mapReturnProgram Prod.fst (forsTreeProgram encode seed ht tree 0)

def forsRoot [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree : ℕ) : PMF (Randomizer × Memo K Digest) :=
  (forsTree encode table seed ht tree 0).map (fun out => (out.1.1, out.2))

theorem fors_root_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree : ℕ) :
    evalProgram digestDraw (forsRootProgram encode seed ht tree) table =
      forsRoot encode table seed ht tree := by
  rw [forsRootProgram, evalProgram_mapReturn, fors_tree_eval]
  rfl

theorem fors_root_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (ht tree : ℕ) :
    mapProgram encode (forsRootProgram labels seed ht tree) =
      forsRootProgram (encode ∘ labels) seed ht tree := by
  simp only [forsRootProgram, mapProgram_mapReturn, fors_tree_map]

theorem fors_root_public (seed : ByteKey) (ht tree : ℕ) :
    PublicBudget (forsRootProgram id seed ht tree) 4095 := by
  rw [forsRootProgram, publicBudget_mapReturn]
  exact fors_tree_public _ _ _ _

def forsSignProgram (encode : WotsQuery → K) (seed : ByteKey) (ht tree target : ℕ) :
    QueryProgram K Digest (Randomizer × List Randomizer) 6144 :=
  .query (encode (.inr (forsPrivateTail ht tree target))) (fun secret =>
    mapReturnProgram (fun out => (randomizerOfDigest secret, out.2))
      (forsTreeProgram encode seed ht tree target))

def forsSign [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) :
    PMF ((Randomizer × List Randomizer) × Memo K Digest) :=
  (memoQuery digestDraw table (encode (.inr (forsPrivateTail ht tree target)))).bind
    (fun secret => (forsTree encode secret.2 seed ht tree target).map
      (fun out => ((randomizerOfDigest secret.1, out.1.2), out.2)))

theorem fors_sign_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) :
    evalProgram digestDraw (forsSignProgram encode seed ht tree target) table =
      forsSign encode table seed ht tree target := by
  simp only [forsSignProgram, evalProgram, evalProgram_mapReturn, fors_tree_eval, forsSign]

theorem fors_sign_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (ht tree target : ℕ) :
    mapProgram encode (forsSignProgram labels seed ht tree target) =
      forsSignProgram (encode ∘ labels) seed ht tree target := by
  simp only [forsSignProgram, mapProgram, mapProgram_mapReturn, fors_tree_map, Function.comp_def]

theorem fors_sign_public (seed : ByteKey) (ht tree target : ℕ) :
    PublicBudget (forsSignProgram id seed ht tree target) 4095 := by
  intro secret
  rw [publicBudget_mapReturn]
  exact fors_tree_public _ _ _ _

end
end C10Probability
