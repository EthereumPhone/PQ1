import C10Probability.TreeCertificate
import C10Probability.MerkleInputs

/-! A collected slot certifies the node actually stored at that array index.
Collection is required only for subtrees containing the selected target. -/
namespace C10Probability
noncomputable section

variable {K α N S : Type*}

def RecordedAuthSlot (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (target : ℕ) (auth : List N) (height : ℕ) : Prop :=
  ∃ value, auth[height]? = some value ∧ RecordedTreeNode table leaf input project
    height ((siblingIndex (target / 2 ^ height) + 1) * 2 ^ height) value

def CollectedTreeNode (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (target : ℕ) (auth : List N) (height edge : ℕ) (root : N) : Prop :=
  RecordedTreeNode table leaf input project height edge root ∧
    (edge - 2 ^ height ≤ target → target < edge →
      ∀ j, j < height → RecordedAuthSlot table leaf input project target auth j)

def CollectedForest (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (target : ℕ) (auth : List N) : ℕ → List (N × ℕ) → Prop
  | _, [] => True
  | edge, (root, height) :: rest =>
      CollectedTreeNode table leaf input project target auth height edge root ∧
        CollectedForest table leaf input project target auth (edge - 2 ^ height) rest

def RememberAuthLaw (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (target bound : ℕ) (nodes : S → List N) (valid : S → Prop)
    (remember : ℕ → ℕ → N → N → S → S) : Prop :=
  ∀ kp height left right state, valid state → height < bound →
    (kp + 1) % 2 ^ (height + 1) = 0 →
    RecordedTreeNode table leaf input project height (kp + 1 - 2 ^ height) left →
    RecordedTreeNode table leaf input project height (kp + 1) right →
    valid (remember kp height left right state) ∧
    (∀ j, RecordedAuthSlot table leaf input project target (nodes state) j →
      RecordedAuthSlot table leaf input project target
        (nodes (remember kp height left right state)) j) ∧
    (kp + 1 - 2 ^ (height + 1) ≤ target → target < kp + 1 →
      RecordedAuthSlot table leaf input project target
        (nodes (remember kp height left right state)) height)

theorem collected_node_mono (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (target : ℕ) (before after : List N)
    (preserves : ∀ j, RecordedAuthSlot table leaf input project target before j →
      RecordedAuthSlot table leaf input project target after j)
    (height edge : ℕ) (root : N)
    (collected : CollectedTreeNode table leaf input project target before height edge root) :
    CollectedTreeNode table leaf input project target after height edge root := by
  exact ⟨collected.1, fun lower upper j hj => preserves j (collected.2 lower upper j hj)⟩

theorem collected_forest_mono (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (target : ℕ) (before after : List N)
    (preserves : ∀ j, RecordedAuthSlot table leaf input project target before j →
      RecordedAuthSlot table leaf input project target after j)
    (edge : ℕ) (stack : List (N × ℕ))
    (collected : CollectedForest table leaf input project target before edge stack) :
    CollectedForest table leaf input project target after edge stack := by
  induction stack generalizing edge with
  | nil => trivial
  | cons entry rest ih =>
    exact ⟨collected_node_mono table leaf input project target before after preserves
      _ _ _ collected.1, ih _ collected.2⟩

theorem collected_node_pair (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (target : ℕ) (auth : List N) (height edge : ℕ) (left right : N) (reply : α)
    (hl : CollectedTreeNode table leaf input project target auth height (edge - 2 ^ height) left)
    (hr : CollectedTreeNode table leaf input project target auth height edge right)
    (lookup : table (input (edge - 1) height left right) = some reply)
    (collected : edge - 2 ^ (height + 1) ≤ target → target < edge →
      RecordedAuthSlot table leaf input project target auth height) :
    CollectedTreeNode table leaf input project target auth (height + 1) edge (project reply) := by
  refine ⟨.pair height edge left right reply hl.1 hr.1 lookup, ?_⟩
  intro lower upper j hj
  by_cases he : j = height
  · subst j; exact collected lower upper
  · have hj' : j < height := by omega
    by_cases side : target < edge - 2 ^ height
    · apply hl.2 _ side j hj'
      have hp : 2 ^ (height + 1) = 2 ^ height + 2 ^ height := by rw [pow_succ]; omega
      simpa only [Nat.sub_sub, ← hp] using lower
    · exact hr.2 (by omega) upper j hj'

theorem recorded_tree_node_unique (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    {height edge : ℕ} {first second : N}
    (one : RecordedTreeNode table leaf input project height edge first)
    (two : RecordedTreeNode table leaf input project height edge second) : first = second := by
  induction one generalizing second with
  | leaf kp value recorded =>
    cases two with
    | leaf _ other otherRecorded => exact Option.some.inj (recorded.symm.trans otherRecorded)
  | pair height edge left right reply hl hr hd ihl ihr =>
    cases two with
    | pair _ _ left' right' reply' hl' hr' hd' =>
      have el := ihl hl'
      have er := ihr hr'
      subst left'
      subst right'
      exact congrArg project (Option.some.inj (hd.symm.trans hd'))

end
end C10Probability
