import C10Probability.WotsTwoLayers

/-! Both actual signing layers are composed before any signature disclosure.
Each deferred array retains its own address and accepted word. An exhausted
upper layer discards the lower signature result without opening its nodes. -/
namespace C10Probability
noncomputable section

structure WotsDeferredHypertree (target : WotsCutTarget) (index : Fin (2 ^ 18)) where
  lower : WotsDeferredLayer target (wotsLowerAddress index)
  upper : WotsDeferredLayer target (wotsUpperAddress index)
  root : Randomizer

def wotsDeferredHypertreeSigned (secret : Digest) {target : WotsCutTarget} {index : Fin (2 ^ 18)}
    (signed : Option (WotsDeferredHypertree target index)) : HypertreeSigned :=
  signed.map (fun result => ([wotsDeferredLayerSignature secret result.lower,
    wotsDeferredLayerSignature secret result.upper], result.root))

def wotsDeferredTwoOutput {target : WotsCutTarget} {index : Fin (2 ^ 18)}
    (lower : WotsDeferredLayer target (wotsLowerAddress index))
    (upper : Option (WotsDeferredLayer target (wotsUpperAddress index) × Randomizer)) :
    Option (WotsDeferredHypertree target index) :=
  upper.map (fun value => ⟨lower, value.1, value.2⟩)

theorem wots_deferred_two_output (secret : Digest) {target : WotsCutTarget} {index : Fin (2 ^ 18)}
    (lower : WotsDeferredLayer target (wotsLowerAddress index))
    (upper : Option (WotsDeferredLayer target (wotsUpperAddress index) × Randomizer)) :
    wotsDeferredHypertreeSigned secret (wotsDeferredTwoOutput lower upper) =
      wotsTwoLayerOutput (wotsDeferredLayerSignature secret lower) (wotsDeferredLayerSigned secret upper) := by
  cases upper <;> rfl

def wotsHypertreeOpening (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32) (index : Fin (2 ^ 18)) (current : Randomizer) :
    OpeningProgram WotsQuery Unit Digest Digest (Option (WotsDeferredHypertree target index))
      (2 * (n + 177511)) :=
  castOpening (by omega)
    (bindOpening (wotsLayerOpening seed target previous (wotsLowerAddress index) current shuffle n bound)
      (fun lower => match lower with
        | none => .done none
        | some (sig, root) => mapOpeningReturn (wotsDeferredTwoOutput sig)
            (wotsLayerOpening seed target previous (wotsUpperAddress index) root shuffle n bound)))

attribute [irreducible] wotsHypertreeOpening

theorem wots_hypertree_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32)
    (index : Fin (2 ^ 18)) (current : Randomizer) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredHypertreeSigned secret)
      (wotsHypertreeOpening seed target previous shuffle n bound index current)
      (hypertreeSignProgram id seed shuffle n bound 2 0 index.val current []) := by
  have compared : OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredHypertreeSigned secret)
      (wotsHypertreeOpening seed target previous shuffle n bound index current)
      (wotsTwoLayerProgram seed shuffle n bound index current) := by
    rw [wotsHypertreeOpening, wotsTwoLayerProgram]
    apply opening_refines_cast
    apply opening_refines_bind digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredLayerSigned secret)
      (wotsDeferredHypertreeSigned secret) _ _ _ _
      (wots_layer_opening_refines seed target previous (wotsLowerAddress index) current shuffle n bound secret)
    intro lower
    cases lower with
    | none =>
      exact opening_refines_done _ _ _ _ _ (wotsDeferredHypertreeSigned secret) none _ _
    | some value =>
      obtain ⟨sig, root⟩ := value
      exact opening_refines_map digestDraw (wotsCutCommit seed target) randomizerOfDigest
        (wotsCutIncoming seed target previous) secret (wotsDeferredLayerSigned secret)
        (wotsDeferredHypertreeSigned secret) (wotsDeferredTwoOutput sig)
        (wotsTwoLayerOutput (wotsDeferredLayerSignature secret sig))
        (wots_deferred_two_output secret sig) _ _
        (wots_layer_opening_refines seed target previous (wotsUpperAddress index) root shuffle n bound secret)
  intro table opened cached
  rw [wots_two_layer_eval]
  exact compared table opened cached

theorem wots_hypertree_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (shuffle : ByteKey) (width : shuffle.length = 32)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (index : Fin (2 ^ 18)) (current : Randomizer) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsHypertreeOpening seed target previous shuffle n bound index current) := by
  rw [wotsHypertreeOpening, opening_sealed_cast]
  apply opening_sealed_bind _ _ _
    (wots_layer_opening_sealed seed target previous (wotsLowerAddress index) current shuffle width n bound)
  intro lower
  cases lower with
  | none => trivial
  | some value =>
    obtain ⟨sig, root⟩ := value
    rw [opening_sealed_map]
    exact wots_layer_opening_sealed seed target previous (wotsUpperAddress index) root shuffle width n bound

theorem wots_hypertree_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32)
    (index : Fin (2 ^ 18)) (current : Randomizer) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsHypertreeOpening seed target previous shuffle n bound index current)) 310690 := by
  rw [wotsHypertreeOpening, redact_opening_cast, selectedBudget_cast]
  apply opening_selected_bind _ _ _ 155345 155345
    (wots_layer_opening_budget seed target previous (wotsLowerAddress index) current shuffle n bound)
  intro lower
  cases lower with
  | none => trivial
  | some value =>
    obtain ⟨sig, root⟩ := value
    rw [redact_opening_mapReturn, selectedBudget_mapReturn]
    exact wots_layer_opening_budget seed target previous (wotsUpperAddress index) root shuffle n bound

end
end C10Probability
