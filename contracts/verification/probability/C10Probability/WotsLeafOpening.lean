import C10Probability.WotsFillOpening

/-! The complete WOTS key-generation leaf retains all43 endpoints and their
ordered compression. Position7 is public and cannot be the selected cut, so
the final array is concrete without a disclosure of the selected node. -/
namespace C10Probability
noncomputable section

def wotsKnownSigma {target : WotsCutTarget} {address : WotsLogicalAddress}
    (sigma : WotsDeferredSigma target address (fun _ => 7)) : WotsSigma :=
  fun i => wotsKnownValue (sigma i)

theorem wots_known_sigma (secret : Digest) {target : WotsCutTarget}
    {address : WotsLogicalAddress} (sigma : WotsDeferredSigma target address (fun _ => 7)) :
    wotsKnownSigma sigma = wotsDeferredSigmaValue secret sigma := by
  funext i
  exact wots_deferred_endpoint secret (sigma i)

def wotsLeafFillOpening (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (address : WotsLogicalAddress) : OpeningProgram WotsQuery Unit Digest Digest WotsSigma 344 :=
  castOpening wots_leaf_fill_cost (mapOpeningReturn wotsKnownSigma
    (wotsFillOpening seed target previous address (fun _ => 7) (fun _ => Nat.le_refl 7)
      wotsIndices (wotsZeroDeferredSigma target address (fun _ => 7))))

theorem wots_leaf_fill_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret id
      (wotsLeafFillOpening seed target previous address)
      (wotsLeafFillProgram id seed (wotsTargetLayer (address, 0))
        (wotsTargetTree (address, 0)) (wotsTargetKp (address, 0))) := by
  rw [wotsLeafFillOpening, wotsLeafFillProgram]
  apply opening_refines_cast
  have compared := opening_refines_map digestDraw (wotsCutCommit seed target) randomizerOfDigest
    (wotsCutIncoming seed target previous) secret (wotsDeferredSigmaValue secret) id
    wotsKnownSigma id (wots_known_sigma secret) _ _
    (wots_fill_opening_refines seed target previous address (fun _ => 7) (fun _ => Nat.le_refl 7)
      wotsIndices (wotsZeroDeferredSigma target address (fun _ => 7)) secret)
  intro table opened cached
  simpa only [evalProgram_mapReturn, wots_zero_deferred_sigma,
    show (fun out : WotsSigma × Memo WotsQuery Digest => (id out.1, out.2)) = id from rfl,
    PMF.map_id] using compared table opened cached

theorem wots_leaf_fill_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsLeafFillOpening seed target previous address) := by
  rw [wotsLeafFillOpening, opening_sealed_cast, opening_sealed_map]
  exact wots_fill_opening_sealed seed target previous address (fun _ => 7) (fun _ => Nat.le_refl 7)
    wotsIndices (wotsZeroDeferredSigma target address (fun _ => 7))

theorem wots_leaf_fill_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsLeafFillOpening seed target previous address)) 301 := by
  rw [wotsLeafFillOpening, redact_opening_cast, selectedBudget_cast,
    redact_opening_mapReturn, selectedBudget_mapReturn, ← wots_leaf_public_cost]
  exact wots_fill_opening_budget seed target previous address (fun _ => 7) (fun _ => Nat.le_refl 7)
    wotsIndices (wotsZeroDeferredSigma target address (fun _ => 7))

theorem wots_pk_ne_cut_incoming (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (layer tree kp : ℕ) (values : List Randomizer)
    (width : values.length = 43) :
    (.inl (wotsPkInput seed layer tree kp values) : WotsQuery) ≠
      wotsCutIncoming seed target previous := by
  intro equal
  by_cases zero : target.2.val = 0
  · rw [wots_cut_incoming_zero seed target previous zero] at equal
    exact wots_target_not_public target.1 _ equal
  · rw [wots_cut_incoming_positive seed target previous (by omega)] at equal
    have lengths := congrArg List.length (Sum.inl.inj equal)
    simp only [wotsPkInput, wotsChainInput, List.length_append, c10_address_length,
      node_blocks_length, width, List.length_ofFn, List.length_replicate] at lengths
    omega

def wotsLeafOpening (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (address : WotsLogicalAddress) : OpeningProgram WotsQuery Unit Digest Digest Randomizer 345 :=
  bindOpening (wotsLeafFillOpening seed target previous address) (fun sigma =>
    .query (.inl (wotsPkInput seed (wotsTargetLayer (address, 0))
      (wotsTargetTree (address, 0)) (wotsTargetKp (address, 0)) (List.ofFn sigma)))
      (fun reply => .done (randomizerOfDigest reply)))

theorem wots_leaf_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret id (wotsLeafOpening seed target previous address)
      (wotsLeafProgram id seed (wotsTargetLayer (address, 0))
        (wotsTargetTree (address, 0)) (wotsTargetKp (address, 0))) := by
  apply opening_refines_bind digestDraw (wotsCutCommit seed target) randomizerOfDigest
    (wotsCutIncoming seed target previous) secret id id _ _ _ _
    (wots_leaf_fill_opening_refines seed target previous address secret)
  intro sigma
  exact opening_refines_query _ _ _ _ _ id _ _ _
    (fun reply => opening_refines_done _ _ _ _ _ id (randomizerOfDigest reply) 0 0)

theorem wots_leaf_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) :
    OpeningSealed (wotsCutIncoming seed target previous) (wotsLeafOpening seed target previous address) := by
  apply opening_sealed_bind _ _ _ (wots_leaf_fill_opening_sealed seed target previous address)
  intro sigma
  exact ⟨wots_pk_ne_cut_incoming seed target previous _ _ _ (List.ofFn sigma)
    (by simp), fun _ => trivial⟩

theorem wots_leaf_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsLeafOpening seed target previous address)) 302 := by
  exact opening_selected_bind _ _ _ 301 1 (wots_leaf_fill_opening_budget seed target previous address)
    (fun _ => selectedBudget_total _ _)

end
end C10Probability
