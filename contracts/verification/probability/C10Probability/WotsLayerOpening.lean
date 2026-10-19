import C10Probability.WotsSubtreeOpening
import C10Probability.WotsShuffleOpening
import C10Probability.LayerCachedRecovery

/-! One full honest layer keeps the actual builder, shuffle and bounded WOTS
signer. Recovery is the proved cached replay, so its complete result/cache law
equals the original layer. The symbolic signature is still not disclosed. -/
namespace C10Probability
noncomputable section

structure WotsDeferredLayer (target : WotsCutTarget) (address : WotsLogicalAddress) where
  wots : WotsDeferredResult target address
  auth : List Randomizer

def wotsDeferredLayerSignature (secret : Digest) {target : WotsCutTarget} {address : WotsLogicalAddress}
    (sig : WotsDeferredLayer target address) : LayerSignature :=
  ⟨wotsDeferredSigmaValue secret sig.wots.sigma, sig.wots.count, sig.auth⟩

def wotsDeferredLayerSigned (secret : Digest) {target : WotsCutTarget} {address : WotsLogicalAddress}
    (signed : Option (WotsDeferredLayer target address × Randomizer)) : LayerSigned :=
  signed.map (fun value => (wotsDeferredLayerSignature secret value.1, value.2))

def wotsLayerCachedOutput {target : WotsCutTarget} {address : WotsLogicalAddress}
    (built : List Randomizer × Randomizer) (signed : Option (WotsDeferredResult target address)) :
    Option (WotsDeferredLayer target address × Randomizer) :=
  signed.map (fun value => (⟨value, built.1⟩, built.2))

theorem wots_layer_cached_output (secret : Digest) {target : WotsCutTarget} {address : WotsLogicalAddress}
    (built : List Randomizer × Randomizer) (signed : Option (WotsDeferredResult target address)) :
    wotsDeferredLayerSigned secret (wotsLayerCachedOutput built signed) =
      layerCachedOutput built (wotsDeferredSignature secret signed) := by
  cases signed <;> rfl

def wotsLayerOpening (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (address : WotsLogicalAddress) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) : OpeningProgram WotsQuery Unit Digest Digest
      (Option (WotsDeferredLayer target address × Randomizer)) (n + 177511) :=
  castOpening (by omega)
    (bindOpening (wotsMerkleBuildOpening seed target previous address (wotsTargetKp (address, 0)))
      (fun built => bindOpening
        (liftOpening (shuffleDeriveProgram Sum.inl shuffle (layerShuffleLabel (wotsTargetLayer (address, 0)))))
        (fun subseed => bindOpening
          (wotsSignOpening seed target previous address (nodeValueBytes message) subseed n bound)
          (fun signed => .done (n := 107) (wotsLayerCachedOutput built signed)))))

attribute [irreducible] wotsLayerOpening

theorem wots_layer_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredLayerSigned secret)
      (wotsLayerOpening seed target previous address message shuffle n bound)
      (layerSignProgram id seed (wotsTargetLayer (address, 0)) (wotsTargetTree (address, 0))
        (wotsTargetKp (address, 0)) message shuffle n bound) := by
  have compared : OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredLayerSigned secret)
      (wotsLayerOpening seed target previous address message shuffle n bound)
      (layerCachedProgram id seed (wotsTargetLayer (address, 0)) (wotsTargetTree (address, 0))
        (wotsTargetKp (address, 0)) message shuffle n bound) := by
    rw [wotsLayerOpening, layerCachedProgram]
    apply opening_refines_cast
    apply opening_refines_bind digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret id (wotsDeferredLayerSigned secret) _ _ _ _
      (wots_merkle_build_opening_refines seed target previous address _ secret)
    intro built
    apply opening_refines_bind digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret id (wotsDeferredLayerSigned secret) _ _ _ _
      (opening_refines_lift _ _ _ _ _ _)
    intro subseed
    apply opening_refines_bind digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredSignature secret)
      (wotsDeferredLayerSigned secret) _ _ _ _
      (wots_sign_opening_refines seed target previous address _ subseed n bound secret)
    intro signed
    simpa only [wots_layer_cached_output] using
      opening_refines_done digestDraw (wotsCutCommit seed target) randomizerOfDigest
        (wotsCutIncoming seed target previous) secret (wotsDeferredLayerSigned secret)
        (wotsLayerCachedOutput built signed) 107 107
  intro table opened cached
  rw [layer_sign_cached_eval id table seed _ _ _ message shuffle n bound
    (wots_target_bounds (address, 0)).2.2.1]
  exact compared table opened cached

theorem wots_layer_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (message : Randomizer) (shuffle : ByteKey)
    (width : shuffle.length = 32) (n : ℕ) (bound : n ≤ 2 ^ 32) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsLayerOpening seed target previous address message shuffle n bound) := by
  rw [wotsLayerOpening, opening_sealed_cast]
  apply opening_sealed_bind _ _ _ (wots_merkle_build_opening_sealed seed target previous address _)
  intro built
  apply opening_sealed_lift_bind _ _ (fun out => out.length = 32)
    (shuffle_derive_wots_cut_excluded seed shuffle _ target previous width
      (by rw [layer_shuffle_label_length]; decide))
  intro subseed subseedWidth
  exact opening_sealed_bind _ _ _
    (wots_sign_opening_sealed seed target previous address _ subseed subseedWidth n bound)
    (fun _ => trivial)

theorem wots_layer_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsLayerOpening seed target previous address message shuffle n bound)) 155345 := by
  rw [wotsLayerOpening, redact_opening_cast, selectedBudget_cast]
  apply opening_selected_bind _ _ _ 155135 210
    (wots_merkle_build_opening_budget seed target previous address _)
  intro built
  apply opening_selected_bind _ _ _ 1 209 (selectedBudget_total _ _)
  intro subseed
  exact opening_selected_bind _ _ _ 209 0
    (wots_sign_opening_budget seed target previous address _ subseed n bound)
    (fun _ => trivial)

end
end C10Probability
