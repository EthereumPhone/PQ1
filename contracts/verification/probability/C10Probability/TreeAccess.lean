import C10Probability.MerkleBuild

/-! Actual merge heights are strictly below9, so the nine-entry authentication
arrays are accessed in range. Remembered array lengths persist through the
ordinary list-stack procedure and every adaptive oracle reply. -/
namespace C10Probability
noncomputable section

variable {K α N S : Type*}

def mergeAccessBound (bound : ℕ) : ℕ → List ℕ → Prop
  | _, [] => True
  | height, level :: rest => if level = height then
      height < bound ∧ mergeAccessBound bound (height + 1) rest else True

theorem merge_access_bound (bound height : ℕ) (shape : List ℕ)
    (hb : (mergeShape height shape).height ≤ bound) : mergeAccessBound bound height shape := by
  induction shape generalizing height with
  | nil => trivial
  | cons level rest ih =>
    by_cases he : level = height
    · simp only [mergeShape, he, ↓reduceIte] at hb
      simp only [mergeAccessBound, he, ↓reduceIte]
      have hm := merge_shape_height_mono (height + 1) rest
      exact ⟨by omega, ih (height + 1) hb⟩
    · simp [mergeAccessBound, he]

def treeAccessBound (bound : ℕ) : ℕ → List ℕ → Prop
  | 0, _ => True
  | n + 1, shape => mergeAccessBound bound 0 shape ∧ treeAccessBound bound n (nextShape shape)

theorem tree_access_bound (bound n : ℕ) (shape : List ℕ)
    (hb : shapeHeightBound bound n shape) : treeAccessBound bound n shape := by
  induction n generalizing shape with
  | zero => trivial
  | succ n ih => exact ⟨merge_access_bound _ _ _ hb.1, ih _ hb.2⟩

theorem subtree_auth_indices : treeAccessBound 9 512 [] :=
  tree_access_bound 9 512 [] subtree_merge_height_bound

theorem merge_loop_state_invariant [DecidableEq K] (p : PMF α)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S) (property : S → Prop)
    (preserves : ∀ kp height left right state, property state →
      property (remember kp height left right state)) (kp : ℕ)
    (stack : List (N × ℕ)) (height : ℕ) (current : N) (state : S) (table : Memo K α)
    (initial : property state) (out : (List (N × ℕ) × S) × Memo K α)
    (ho : out ∈ (mergeLoop p input project remember kp stack height current state table).support) :
    property out.1.2 := by
  induction stack generalizing height current state table out with
  | nil =>
    have he : out = (([(current, height)], state), table) := by simpa [mergeLoop] using ho
    simpa [he] using initial
  | cons top rest ih =>
    rcases top with ⟨left, level⟩
    by_cases he : level = height
    · rw [mergeLoop, if_pos he, PMF.mem_support_bind_iff] at ho
      obtain ⟨reply, _, ho⟩ := ho
      exact ih (height + 1) (project reply.1) _ reply.2
        (preserves kp height left current state initial) out ho
    · have hout : out = (((current, height) :: (left, level) :: rest, state), table) := by
        simpa only [mergeLoop, he, ↓reduceIte, PMF.mem_support_pure_iff] using ho
      simpa [hout] using initial

theorem tree_loop_state_invariant [DecidableEq K] (p : PMF α)
    (leaf : ℕ → Memo K α → PMF (N × Memo K α))
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S) (property : S → Prop)
    (preserves : ∀ kp height left right state, property state →
      property (remember kp height left right state))
    (n start : ℕ) (stack : List (N × ℕ)) (state : S) (table : Memo K α)
    (initial : property state) (out : (List (N × ℕ) × S) × Memo K α)
    (ho : out ∈ (treeLoop p leaf input project remember n start stack state table).support) :
    property out.1.2 := by
  induction n generalizing start stack state table out with
  | zero =>
    have he : out = ((stack, state), table) := by simpa [treeLoop] using ho
    simpa [he] using initial
  | succ n ih =>
    rw [treeLoop, PMF.mem_support_bind_iff] at ho
    obtain ⟨current, _, ho⟩ := ho
    rw [PMF.mem_support_bind_iff] at ho
    obtain ⟨merged, hm, ho⟩ := ho
    exact ih (start + 1) merged.1.1 merged.1.2 merged.2
      (merge_loop_state_invariant p input project remember property preserves
        start stack 0 current.1 state current.2 initial merged hm) out ho

theorem merkle_build_auth_length [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree target : ℕ)
    (out : (List Randomizer × Randomizer) × Memo K Digest)
    (ho : out ∈ (merkleBuild encode table seed layer tree target).support) :
    out.1.1.length = 9 := by
  rw [merkleBuild, PMF.mem_support_map_iff] at ho
  obtain ⟨result, hr, rfl⟩ := ho
  have hi := tree_loop_state_invariant digestDraw _ _ randomizerOfDigest (authRemember target)
    (fun s => s.nodes.length = 9 ∧ s.kept.length = 9)
    (fun kp h l r s hs => by
      dsimp only
      rw [(auth_remember_lengths target kp h l r s).1,
        (auth_remember_lengths target kp h l r s).2]
      exact hs)
    512 0 [] emptyAuthKeep table (by simp [emptyAuthKeep]) result hr
  exact hi.1

end
end C10Probability
