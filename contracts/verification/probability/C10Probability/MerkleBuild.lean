import C10Probability.Subtree

/-! Authentication collection preserves the exact keep/kept state, the
pre-hash left/right choice and out-of-range list defaults of RawMerkle.build.
This compiler equality is not a new universal build/recover correctness proof. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

structure AuthKeep where
  nodes : List Randomizer
  kept : List Bool
  deriving DecidableEq

def emptyAuthKeep : AuthKeep := ⟨List.replicate 9 0, List.replicate 9 false⟩

def writeAuthKeep (state : AuthKeep) (height : ℕ) (node : Randomizer) : AuthKeep :=
  ⟨state.nodes.set height node, state.kept.set height true⟩

def authRemember (target kp height : ℕ) (left right : Randomizer) (state : AuthKeep) : AuthKeep :=
  if (state.kept[height]?).getD false then state
  else
    let sibling := siblingIndex (target / 2 ^ height)
    let pairStart := (kp / 2 ^ (height + 1)) * 2 ^ (height + 1)
    let leftIndex := pairStart / 2 ^ height
    if leftIndex = sibling then writeAuthKeep state height left
    else if leftIndex + 1 = sibling then writeAuthKeep state height right
    else state

theorem auth_remember_lengths (target kp height : ℕ) (left right : Randomizer)
    (state : AuthKeep) :
    (authRemember target kp height left right state).nodes.length = state.nodes.length ∧
    (authRemember target kp height left right state).kept.length = state.kept.length := by
  unfold authRemember
  split
  · exact ⟨rfl, rfl⟩
  · dsimp only
    split
    · simp [writeAuthKeep]
    · split <;> simp [writeAuthKeep]

theorem auth_remember_kept (target kp height : ℕ) (left right : Randomizer)
    (state : AuthKeep) (hk : (state.kept[height]?).getD false = true) :
    authRemember target kp height left right state = state := by
  simp [authRemember, hk]

def merkleBuildProgram (encode : WotsQuery → K) (seed : ByteKey) (layer tree target : ℕ) :
    QueryProgram K Digest (List Randomizer × Randomizer) 177151 :=
  mapReturnProgram (fun out => (out.2.nodes, treeRoot out.1))
    (subtreeProgram encode seed layer tree (authRemember target) emptyAuthKeep)

def merkleBuild [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree target : ℕ) :
    PMF ((List Randomizer × Randomizer) × Memo K Digest) :=
  (subtreeLoop encode table seed layer tree (authRemember target) emptyAuthKeep).map
    (fun out => ((out.1.2.nodes, treeRoot out.1.1), out.2))

theorem merkle_build_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree target : ℕ) :
    evalProgram digestDraw (merkleBuildProgram encode seed layer tree target) table =
      merkleBuild encode table seed layer tree target := by
  rw [merkleBuildProgram, evalProgram_mapReturn, subtree_program_eval]
  rfl

theorem merkle_build_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (layer tree target : ℕ) :
    mapProgram encode (merkleBuildProgram labels seed layer tree target) =
      merkleBuildProgram (encode ∘ labels) seed layer tree target := by
  simp only [merkleBuildProgram, mapProgram_mapReturn, subtree_program_map]

theorem merkle_build_public (seed : ByteKey) (layer tree target : ℕ) :
    PublicBudget (merkleBuildProgram id seed layer tree target) 155135 := by
  rw [merkleBuildProgram, publicBudget_mapReturn]
  exact subtree_program_public _ _ _ _ _

end
end C10Probability
