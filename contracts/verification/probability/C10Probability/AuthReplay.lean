import C10Probability.AuthCertificate
import C10Probability.AuthSchedule

/-! The loop theorem threads actual authentication state through every merge.
The collector law is instantiated separately for the unchanged Merkle/FORS
callbacks; it is not an assumption in their final returned-array theorems. -/
namespace C10Probability
noncomputable section

variable {K α N S : Type*}

theorem replay_merge_collected (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (target bound : ℕ) (nodes : S → List N) (valid : S → Prop)
    (remember : ℕ → ℕ → N → N → S → S)
    (law : RememberAuthLaw table leaf input project target bound nodes valid remember)
    (kp : ℕ) (stack : List (N × ℕ)) (height : ℕ) (current : N) (state : S)
    (out : List (N × ℕ) × S)
    (initial : valid state)
    (schedule : mergeAuthSchedule bound kp height (stack.map Prod.snd))
    (prior : CollectedForest table leaf input project target (nodes state)
      (kp + 1 - 2 ^ height) stack)
    (node : CollectedTreeNode table leaf input project target (nodes state) height (kp + 1) current)
    (recorded : replayMerge table input project remember kp stack height current state = some out) :
    valid out.2 ∧ CollectedForest table leaf input project target (nodes out.2) (kp + 1) out.1 := by
  induction stack generalizing height current state out with
  | nil =>
    have he : out = ([(current, height)], state) := Option.some.inj recorded.symm
    exact he ▸ ⟨initial, node, trivial⟩
  | cons entry rest ih =>
    obtain ⟨left, level⟩ := entry
    by_cases he : level = height
    · subst level
      simp only [replayMerge, ↓reduceIte] at recorded
      simp only [List.map_cons, mergeAuthSchedule, ↓reduceIte] at schedule
      cases hd : table (input kp height left current) with
      | none => simp only [hd, Option.bind_none] at recorded; cases recorded
      | some reply =>
        simp only [hd, Option.bind_some] at recorded
        obtain ⟨nextValid, preserves, selected⟩ := law kp height left current state
          initial schedule.1 schedule.2.1 prior.1.1 node.1
        have nextLeft := collected_node_mono table leaf input project target _ _ preserves
          height (kp + 1 - 2 ^ height) left prior.1
        have nextRight := collected_node_mono table leaf input project target _ _ preserves
          height (kp + 1) current node
        have parent := collected_node_pair table leaf input project target _ height
          (kp + 1) left current reply nextLeft nextRight (by simpa using hd) selected
        have restCollected := collected_forest_mono table leaf input project target _ _
          preserves _ rest prior.2
        have hp : 2 ^ (height + 1) = 2 ^ height + 2 ^ height := by rw [pow_succ]; omega
        apply ih (height + 1) (project reply) (remember kp height left current state)
          out nextValid schedule.2.2 _ parent recorded
        simpa only [hp, Nat.sub_sub] using restCollected
    · simp only [replayMerge, he, ↓reduceIte, Option.some.injEq] at recorded
      subst out
      exact ⟨initial, node, prior⟩

theorem replay_tree_collected (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (target bound : ℕ) (nodes : S → List N) (valid : S → Prop)
    (remember : ℕ → ℕ → N → N → S → S)
    (law : RememberAuthLaw table leaf input project target bound nodes valid remember)
    (n start : ℕ) (stack : List (N × ℕ)) (state : S) (out : List (N × ℕ) × S)
    (initial : valid state)
    (schedule : treeAuthSchedule bound n start (stack.map Prod.snd))
    (prior : CollectedForest table leaf input project target (nodes state) start stack)
    (recorded : replayTree table leaf input project remember n start stack state = some out) :
    valid out.2 ∧ CollectedForest table leaf input project target (nodes out.2) (start + n) out.1 := by
  induction n generalizing start stack state out with
  | zero =>
    have he : out = (stack, state) := Option.some.inj recorded.symm
    simpa only [he, Nat.add_zero] using And.intro initial prior
  | succ n ih =>
    rw [replayTree] at recorded
    cases hl : leaf start with
    | none => simp only [hl, Option.bind_none] at recorded; cases recorded
    | some current =>
      simp only [hl, Option.bind_some] at recorded
      cases hm : replayMerge table input project remember start stack 0 current state with
      | none => simp only [hm, Option.bind_none] at recorded; cases recorded
      | some merged =>
        simp only [hm, Option.bind_some] at recorded
        have mergedCollected := replay_merge_collected table leaf input project target bound
          nodes valid remember law start stack 0 current state merged initial schedule.1
          (by simpa using prior) ⟨.leaf start current hl, by simp⟩ hm
        have nextSchedule : treeAuthSchedule bound n (start + 1) (merged.1.map Prod.snd) := by
          rw [replay_merge_shape table input project remember start stack 0 current state merged hm]
          exact schedule.2
        simpa only [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using
          ih (start + 1) merged.1 merged.2 out mergedCollected.1 nextSchedule mergedCollected.2 recorded

theorem tree_program_collected (table : Memo K α)
    (leafCost : ℕ) (leaf : ℕ → QueryProgram K α N leafCost)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (target bound : ℕ) (nodes : S → List N) (valid : S → Prop)
    (remember : ℕ → ℕ → N → N → S → S)
    (law : RememberAuthLaw table (fun kp => replayProgram table (leaf kp)) input project
      target bound nodes valid remember)
    (n start : ℕ) (shape : List ℕ) (stack : ShapeStack N shape) (state : S)
    (out : ShapeStack N (runShape n shape) × S)
    (initial : valid state) (schedule : treeAuthSchedule bound n start shape)
    (prior : CollectedForest table (fun kp => replayProgram table (leaf kp)) input project
      target (nodes state) start (eraseStack shape stack))
    (recorded : replayProgram table
      (treeProgram leafCost leaf input project remember n start shape stack state) = some out) :
    valid out.2 ∧ CollectedForest table (fun kp => replayProgram table (leaf kp)) input project
      target (nodes out.2) (start + n) (eraseStack (runShape n shape) out.1) := by
  have hr := congrArg (Option.map (eraseTreeState (runShape n shape))) recorded
  rw [replay_tree_program] at hr
  exact replay_tree_collected table _ input project target bound nodes valid remember law
    n start _ state _ initial (by simpa only [erased_stack_shape] using schedule) prior hr

theorem collected_erased_root (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (target : ℕ) (auth : List N) (edge height : ℕ)
    (shape : List ℕ) (stack : ShapeStack N shape) (fallback : N)
    (complete : shape = [height])
    (collected : CollectedForest table leaf input project target auth edge (eraseStack shape stack)) :
    CollectedTreeNode table leaf input project target auth height edge
      ((eraseStack shape stack).headD (fallback, 0)).1 := by
  subst shape
  exact collected.1

theorem replay_complete_tree_collected (table : Memo K α)
    (leafCost : ℕ) (leaf : ℕ → QueryProgram K α N leafCost)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (target bound : ℕ) (nodes : S → List N) (valid : S → Prop)
    (remember : ℕ → ℕ → N → N → S → S)
    (law : RememberAuthLaw table (fun kp => replayProgram table (leaf kp)) input project
      target bound nodes valid remember)
    (n height : ℕ) (state : S) (fallback : N) (out : List (N × ℕ) × S)
    (initial : valid state) (schedule : treeAuthSchedule bound n 0 [])
    (complete : runShape n [] = [height])
    (recorded : (replayProgram table
      (treeProgram leafCost leaf input project remember n 0 [] PUnit.unit state)).map
        (eraseTreeState (runShape n [])) = some out) :
    valid out.2 ∧ CollectedTreeNode table (fun kp => replayProgram table (leaf kp)) input project
      target (nodes out.2) height n (out.1.headD (fallback, 0)).1 := by
  cases hx : replayProgram table
      (treeProgram leafCost leaf input project remember n 0 [] PUnit.unit state) with
  | none => simp only [hx, Option.map_none] at recorded; cases recorded
  | some value =>
    simp only [hx, Option.map_some, Option.some.injEq] at recorded
    subst out
    have collected := tree_program_collected table leafCost leaf input project target bound
      nodes valid remember law n 0 [] PUnit.unit state value initial schedule trivial hx
    refine ⟨collected.1, ?_⟩
    exact collected_erased_root table _ input project target _ n height _ value.1
      fallback complete (by simpa only [Nat.zero_add] using collected.2)

end
end C10Probability
