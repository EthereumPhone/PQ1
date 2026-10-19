import C10Probability.OpeningPost
import C10Probability.ForestSignOpening

/-! A deferred slot can occur only at a coordinate selected by this signing
digest. No marker is introduced by a tree commitment, failed lookup default,
shuffle or the special thirteenth transmitted root. -/
namespace C10Probability
noncomputable section

def ForestSelected (target : ForsTarget) (ht : ℕ) (digest : Digest) : Prop :=
  ∃ tree : Fin 12, (.inr (forsPrivateTail ht tree.val (forestIndex digest tree.val)) : WotsQuery) =
    forsTargetKey target

def ForestMarked (target : ForsTarget) (ht : ℕ) (digest : Digest)
    (state : DeferredForestState) : Prop := none ∈ state.secrets → ForestSelected target ht digest

theorem fors_secret_opening_marked (target : ForsTarget) (ht tree leaf : ℕ) :
    OpeningPost (fun node => node = none →
      (.inr (forsPrivateTail ht tree leaf) : WotsQuery) = forsTargetKey target)
      (forsSecretOpening target ht tree leaf) := by
  unfold forsSecretOpening
  split
  next matched => exact fun _ => matched
  next different =>
    intro value impossible
    cases impossible

theorem fors_sign_opening_marked (target : ForsTarget) (seed : ByteKey) (ht tree leaf : ℕ) :
    OpeningPost (fun out => out.1 = none →
      (.inr (forsPrivateTail ht tree leaf) : WotsQuery) = forsTargetKey target)
      (forsSignOpening target seed ht tree leaf) := by
  apply opening_post_bind _ _ _ _ (fors_secret_opening_marked target ht tree leaf)
  intro node marked
  rw [opening_post_map]
  exact opening_post_constant _ marked _

theorem forest_one_opening_marked (target : ForsTarget) (seed : ByteKey) (ht tree leaf : ℕ) :
    OpeningPost (fun out => out.secret = none →
      (.inr (forsPrivateTail ht tree leaf) : WotsQuery) = forsTargetKey target)
      (forestOneOpening target seed ht tree leaf) := by
  apply opening_post_bind _ _ _ _ (fors_sign_opening_marked target seed ht tree leaf)
  intro sig marked
  rw [opening_post_map]
  exact opening_post_constant _ marked _

theorem forest_fill_opening_marked (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (order : List (Fin 12)) (state : DeferredForestState)
    (valid : ForestMarked target ht digest state) :
    OpeningPost (ForestMarked target ht digest) (forestFillOpening target seed ht digest order state) := by
  apply opening_post_fold (ForestMarked target ht digest) _ _ _ order state valid
  intro tree state before
  rw [forestFillStepOpening, opening_post_map]
  apply opening_post_bind
    (fun out : Option Randomizer × List Randomizer => out.1 = none →
      (.inr (forsPrivateTail ht tree.val (forestIndex digest tree.val)) : WotsQuery) = forsTargetKey target)
    _ _ _ (fors_sign_opening_marked target seed ht tree.val (forestIndex digest tree.val))
  intro sig marked
  rw [opening_post_map]
  change OpeningPost (fun _ => none ∈ state.secrets.set tree.val sig.1 → ForestSelected target ht digest) _
  apply opening_post_constant
  intro present
  rcases List.mem_or_eq_of_mem_set present with prior | chosen
  · exact before prior
  · exact ⟨tree, marked chosen.symm⟩

theorem forest_ordered_opening_marked (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (order : ForestOrder) :
    OpeningPost (ForestMarked target ht digest) (forestOrderedOpening target seed ht digest order) := by
  rw [forestOrderedOpening, opening_post_cast]
  apply forest_fill_opening_marked
  intro present
  simp [emptyDeferredForest] at present

theorem forest_finish_opening_marked (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (state : DeferredForestState) (valid : ForestMarked target ht digest state) :
    OpeningPost (fun out => none ∈ out.secrets → ForestSelected target ht digest)
      (forestFinishOpening target seed ht state) := by
  apply opening_post_bind (fun _ => True) _ _ _ (opening_post_constant True True.intro _)
  intro last _ leaf reply present
  rcases List.mem_or_eq_of_mem_set present with prior | impossible
  · exact valid prior
  · cases impossible

theorem forest_sign_opening_marked (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (shuffle : ByteKey) :
    OpeningPost (fun out => none ∈ out.secrets → ForestSelected target ht digest)
      (forestSignOpening target seed ht digest shuffle) := by
  rw [forestSignOpening]
  apply opening_post_bind (fun _ => True) _ _ _ (opening_post_constant True True.intro _)
  intro order _
  exact opening_post_bind (ForestMarked target ht digest) _ _ _
    (forest_ordered_opening_marked target seed ht digest order)
    (forest_finish_opening_marked target seed ht digest)

theorem deferred_nodes_known (secret other : Digest) (nodes : List (Option Randomizer))
    (known : none ∉ nodes) : nodes.map (deferredNode secret) = nodes.map (deferredNode other) := by
  apply List.map_congr_left
  intro node member
  cases node with
  | none => exact False.elim (known member)
  | some value => rfl

theorem deferred_forest_known (secret other : Digest) (forest : DeferredForestOutput)
    (known : none ∉ forest.secrets) : deferredForestOutput secret forest = deferredForestOutput other forest := by
  exact congrArg (fun values => ForestOutput.mk values forest.auths forest.pk)
    (deferred_nodes_known secret other forest.secrets known)

end
end C10Probability
