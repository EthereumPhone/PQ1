import C10Probability.WotsAuxOpening
import C10Probability.OpeningTreeBounds

/-! The tree builder visits all512 legal leaf coordinates. Its natural-index
interface remains total; the unused out-of-range branch executes the ordinary
leaf. Sealing and budget facts are required only on the proved visited range. -/
namespace C10Probability
noncomputable section

def wotsAddressWithKp (address : WotsLogicalAddress) (kp : Fin 512) : WotsLogicalAddress :=
  match address with
  | .inl lower => .inl (lower.1, kp)
  | .inr _ => .inr kp

theorem wots_address_with_kp_fields (address : WotsLogicalAddress) (kp : Fin 512)
    (index : Fin 43) :
    wotsTargetLayer (wotsAddressWithKp address kp, index) = wotsTargetLayer (address, 0) ∧
      wotsTargetTree (wotsAddressWithKp address kp, index) = wotsTargetTree (address, 0) ∧
      wotsTargetKp (wotsAddressWithKp address kp, index) = kp.val := by
  cases address <;> exact ⟨rfl, rfl, rfl⟩

def wotsTreeLeafOpening (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (address : WotsLogicalAddress) (kp : ℕ) :
    OpeningProgram WotsQuery Unit Digest Digest Randomizer 345 :=
  if bound : kp < 512 then
    wotsLeafOpening seed target previous (wotsAddressWithKp address ⟨kp, bound⟩)
  else liftOpening (wotsLeafProgram id seed (wotsTargetLayer (address, 0))
    (wotsTargetTree (address, 0)) kp)

theorem wots_tree_leaf_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (kp : ℕ) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret id
      (wotsTreeLeafOpening seed target previous address kp)
      (wotsLeafProgram id seed (wotsTargetLayer (address, 0))
        (wotsTargetTree (address, 0)) kp) := by
  unfold wotsTreeLeafOpening
  split
  next bound =>
    have fields := wots_address_with_kp_fields address ⟨kp, bound⟩ 0
    have refines := wots_leaf_opening_refines seed target previous
      (wotsAddressWithKp address ⟨kp, bound⟩) secret
    simpa only [fields.1, fields.2.1, fields.2.2] using refines
  next _ => exact opening_refines_lift _ _ _ _ _ _

theorem wots_tree_leaf_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (kp : ℕ) (bound : kp < 512) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsTreeLeafOpening seed target previous address kp) := by
  rw [wotsTreeLeafOpening, dif_pos bound]
  exact wots_leaf_opening_sealed seed target previous _

theorem wots_tree_leaf_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (kp : ℕ) (bound : kp < 512) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsTreeLeafOpening seed target previous address kp)) 302 := by
  rw [wotsTreeLeafOpening, dif_pos bound]
  exact wots_leaf_opening_budget seed target previous _

theorem merkle_pair_ne_wots_incoming (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (layer tree height parent : ℕ) (left right : Randomizer) :
    (.inl (merklePairInput seed layer tree height parent left right) : WotsQuery) ≠
      wotsCutIncoming seed target previous := by
  apply wots_public_width_ne_incoming
  simp only [merklePairInput, List.length_append, c10_address_length, node_block_length]
  omega

end
end C10Probability
