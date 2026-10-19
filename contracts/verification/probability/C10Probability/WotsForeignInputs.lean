import C10Probability.WotsShuffleOpening

/-! Concrete foreign-query separation from a WOTS cut. Addressed public
inputs use their encoded nonzero kind, even when payload lengths coincide.
Private inputs use the independent interface tag and their full tail widths. -/
namespace C10Probability
noncomputable section

theorem wots_foreign_address_ne_incoming (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (layer tree kind kp index position hashAddress : ℕ)
    (tail : ByteKey) (bound : kind < 2 ^ 32) (different : kind ≠ 0) :
    (.inl (seed ++ c10Address layer tree kind kp index position hashAddress ++ tail) : WotsQuery) ≠
      wotsCutIncoming seed target previous := by
  intro equal
  by_cases zero : target.2.val = 0
  · rw [wots_cut_incoming_zero seed target previous zero] at equal
    exact wots_target_not_public target.1 _ equal
  · rw [wots_cut_incoming_positive seed target previous (by omega)] at equal
    have bytes := Sum.inl.inj equal
    simp only [wotsChainInput, List.append_assoc] at bytes
    have joined := List.append_cancel_left bytes
    have addresses := List.append_inj_left joined
      (by rw [c10_address_length, c10_address_length])
    have fields := congrArg (fun key : ByteKey => (key.drop 12).take 4) addresses
    dsimp only at fields
    rw [c10_address_kind, c10_address_kind] at fields
    exact different (be_bytes_four_injective bound (by decide) fields)

theorem wots_foreign_private_ne_incoming (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (tail : ByteKey) (width : tail.length ≠ 48) :
    (.inr tail : WotsQuery) ≠ wotsCutIncoming seed target previous := by
  intro equal
  by_cases zero : target.2.val = 0
  · rw [wots_cut_incoming_zero seed target previous zero] at equal
    have lengths := congrArg List.length (Sum.inr.inj equal)
    rw [wots_private_tail_length] at lengths
    exact width lengths
  · rw [wots_cut_incoming_positive seed target previous (by omega)] at equal
    cases equal

theorem fors_private_ne_wots_incoming (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (ht tree leaf : ℕ) :
    (.inr (forsPrivateTail ht tree leaf) : WotsQuery) ≠ wotsCutIncoming seed target previous := by
  apply wots_foreign_private_ne_incoming
  rw [fors_private_tail_length]
  decide

theorem fors_leaf_ne_wots_incoming (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (ht tree leaf : ℕ) (node : Randomizer) :
    (.inl (forsLeafInput seed ht tree leaf node) : WotsQuery) ≠ wotsCutIncoming seed target previous := by
  exact wots_foreign_address_ne_incoming seed target previous 0 ht 3 tree 0 0 leaf
    (nodeBlock node) (by decide) (by decide)

theorem fors_pair_ne_wots_incoming (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (ht tree height parent : ℕ) (left right : Randomizer) :
    (.inl (forsPairInput seed ht tree height parent left right) : WotsQuery) ≠
      wotsCutIncoming seed target previous := by
  simpa only [forsPairInput, List.append_assoc] using
    wots_foreign_address_ne_incoming seed target previous 0 ht 3 tree 0 (height + 1) parent
      (nodeBlock left ++ nodeBlock right) (by decide) (by decide)

theorem fors_pk_ne_wots_incoming (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (ht : ℕ) (roots : List Randomizer) :
    (.inl (forsPkInput seed ht roots) : WotsQuery) ≠ wotsCutIncoming seed target previous := by
  exact wots_foreign_address_ne_incoming seed target previous 0 ht 4 0 0 0 0
    (roots.flatMap nodeBlock) (by decide) (by decide)

end
end C10Probability
