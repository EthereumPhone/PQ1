import C10Probability.WotsAuxOpening

/-! Actual bounded signing retains the accepted digest, count and positional
symbolic array. The result remains internal until the enclosing C10 signature
succeeds. Count exhaustion and rejected branches preserve their full cache. -/
namespace C10Probability
noncomputable section

structure WotsDeferredResult (target : WotsCutTarget) (address : WotsLogicalAddress) where
  count : ℕ
  digest : Digest
  accepted : wotsAccept (wotsOfDigest digest) = true
  sigma : WotsDeferredSigma target address (fun i => (wotsOfDigest digest i).val)

def wotsDeferredSignature (secret : Digest) {target : WotsCutTarget} {address : WotsLogicalAddress}
    (signed : Option (WotsDeferredResult target address)) : WotsSignature :=
  signed.map (fun result => (wotsDeferredSigmaValue secret result.sigma, result.count))

def wotsAcceptedFillOpening (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (address : WotsLogicalAddress) (word : WotsWord) (accepted : wotsAccept word = true)
    (order : WotsOrder) : OpeningProgram WotsQuery Unit Digest Digest
      (WotsDeferredSigma target address (fun i => (word i).val)) 248 :=
  castOpening (wots_sign_fill_cost word accepted order)
    (wotsFillOpening seed target previous address (fun i => (word i).val)
      (fun i => Nat.le_of_lt_succ (word i).isLt) order.val
      (wotsZeroDeferredSigma target address (fun i => (word i).val)))

theorem wots_accepted_fill_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (word : WotsWord)
    (accepted : wotsAccept word = true) (order : WotsOrder) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredSigmaValue secret)
      (wotsAcceptedFillOpening seed target previous address word accepted order)
      (wotsAcceptedFillProgram id seed (wotsTargetLayer (address, 0)) (wotsTargetTree (address, 0))
        (wotsTargetKp (address, 0)) word accepted order) := by
  rw [wotsAcceptedFillOpening, wotsAcceptedFillProgram]
  apply opening_refines_cast
  exact wots_fill_opening_refines seed target previous address (fun i => (word i).val)
    (fun i => Nat.le_of_lt_succ (word i).isLt) order.val
    (wotsZeroDeferredSigma target address (fun i => (word i).val)) secret

theorem wots_accepted_fill_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (word : WotsWord)
    (accepted : wotsAccept word = true) (order : WotsOrder) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsAcceptedFillOpening seed target previous address word accepted order) := by
  rw [wotsAcceptedFillOpening, opening_sealed_cast]
  exact wots_fill_opening_sealed seed target previous address (fun i => (word i).val)
    (fun i => Nat.le_of_lt_succ (word i).isLt) order.val _

theorem wots_accepted_fill_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (word : WotsWord)
    (accepted : wotsAccept word = true) (order : WotsOrder) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsAcceptedFillOpening seed target previous address word accepted order)) 205 := by
  rw [wotsAcceptedFillOpening, redact_opening_cast, selectedBudget_cast,
    ← wots_order_digit_sum word accepted order]
  exact wots_fill_opening_budget seed target previous address (fun i => (word i).val)
    (fun i => Nat.le_of_lt_succ (word i).isLt) order.val _

def wotsSignAfterOpening (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (address : WotsLogicalAddress) (shuffle : ByteKey) (selected : Option (ℕ × Digest)) :
    OpeningProgram WotsQuery Unit Digest Digest (Option (WotsDeferredResult target address)) 252 :=
  match selected with
  | none => .done none
  | some (count, digest) =>
    if accepted : wotsAccept (wotsOfDigest digest) = true then
      bindOpening (liftOpening (wotsShuffleProgram Sum.inl shuffle)) (fun order =>
        mapOpeningReturn (fun sigma => some ⟨count, digest, accepted, sigma⟩)
          (wotsAcceptedFillOpening seed target previous address (wotsOfDigest digest) accepted order))
    else .done none

attribute [irreducible] wotsSignAfterOpening

theorem wots_sign_after_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (shuffle : ByteKey)
    (selected : Option (ℕ × Digest)) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredSignature secret)
      (wotsSignAfterOpening seed target previous address shuffle selected)
      (wotsSignAfterProgram id seed (wotsTargetLayer (address, 0)) (wotsTargetTree (address, 0))
        (wotsTargetKp (address, 0)) shuffle selected) := by
  cases selected with
  | none =>
    rw [wotsSignAfterOpening, wotsSignAfterProgram]
    exact opening_refines_done _ _ _ _ _ (wotsDeferredSignature secret) none _ _
  | some value =>
    obtain ⟨count, digest⟩ := value
    by_cases accepted : wotsAccept (wotsOfDigest digest) = true
    · rw [wotsSignAfterOpening, wotsSignAfterProgram, dif_pos accepted, dif_pos accepted]
      apply opening_refines_bind digestDraw (wotsCutCommit seed target) randomizerOfDigest
        (wotsCutIncoming seed target previous) secret id (wotsDeferredSignature secret) _ _ _ _
        (opening_refines_lift _ _ _ _ _ _)
      intro order
      exact opening_refines_map digestDraw (wotsCutCommit seed target) randomizerOfDigest
        (wotsCutIncoming seed target previous) secret (wotsDeferredSigmaValue secret)
        (wotsDeferredSignature secret) _ _ (fun _ => rfl) _ _
        (wots_accepted_fill_opening_refines seed target previous address
          (wotsOfDigest digest) accepted order secret)
    · rw [wotsSignAfterOpening, wotsSignAfterProgram, dif_neg accepted, dif_neg accepted]
      exact opening_refines_done _ _ _ _ _ (wotsDeferredSignature secret) none _ _

theorem wots_sign_after_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (shuffle : ByteKey)
    (width : shuffle.length = 32) (selected : Option (ℕ × Digest)) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsSignAfterOpening seed target previous address shuffle selected) := by
  cases selected with
  | none => rw [wotsSignAfterOpening]; trivial
  | some value =>
    obtain ⟨count, digest⟩ := value
    by_cases accepted : wotsAccept (wotsOfDigest digest) = true
    · rw [wotsSignAfterOpening, dif_pos accepted]
      apply opening_sealed_bind _ _ _ (wots_shuffle_opening_sealed seed shuffle target previous width)
      intro order
      rw [opening_sealed_map]
      exact wots_accepted_fill_opening_sealed seed target previous address (wotsOfDigest digest) accepted order
    · rw [wotsSignAfterOpening, dif_neg accepted]
      trivial

theorem wots_sign_after_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (shuffle : ByteKey)
    (selected : Option (ℕ × Digest)) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsSignAfterOpening seed target previous address shuffle selected)) 209 := by
  cases selected with
  | none => rw [wotsSignAfterOpening]; trivial
  | some value =>
    obtain ⟨count, digest⟩ := value
    by_cases accepted : wotsAccept (wotsOfDigest digest) = true
    · rw [wotsSignAfterOpening, dif_pos accepted]
      apply opening_selected_bind _ _ _ 4 205 (selectedBudget_total _ _)
      intro order
      rw [redact_opening_mapReturn, selectedBudget_mapReturn]
      exact wots_accepted_fill_opening_budget seed target previous address (wotsOfDigest digest) accepted order
    · rw [wotsSignAfterOpening, dif_neg accepted]
      trivial

def wotsSignOpening (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (address : WotsLogicalAddress) (message shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32) :
    OpeningProgram WotsQuery Unit Digest Digest (Option (WotsDeferredResult target address)) (n + 252) :=
  castOpening (Nat.add_comm 252 n)
    (bindOpening (liftOpening (mapProgram Sum.inl (wotsCountProgram seed (wotsTargetLayer (address, 0))
      (wotsTargetTree (address, 0)) (wotsTargetKp (address, 0)) message 0 n (by simpa using bound))))
      (wotsSignAfterOpening seed target previous address shuffle))

theorem wots_sign_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (message shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredSignature secret)
      (wotsSignOpening seed target previous address message shuffle n bound)
      (wotsSignProgram id seed (wotsTargetLayer (address, 0)) (wotsTargetTree (address, 0))
        (wotsTargetKp (address, 0)) message shuffle n bound) := by
  rw [wotsSignOpening, wotsSignProgram]
  apply opening_refines_cast
  exact opening_refines_bind digestDraw (wotsCutCommit seed target) randomizerOfDigest
    (wotsCutIncoming seed target previous) secret id (wotsDeferredSignature secret) _ _ _ _
    (opening_refines_lift _ _ _ _ _ _)
    (fun selected => wots_sign_after_opening_refines seed target previous address shuffle selected secret)

theorem wots_sign_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (message shuffle : ByteKey)
    (width : shuffle.length = 32) (n : ℕ) (bound : n ≤ 2 ^ 32) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsSignOpening seed target previous address message shuffle n bound) := by
  rw [wotsSignOpening, opening_sealed_cast]
  exact opening_sealed_bind _ _ _ (wots_count_opening_sealed seed target previous _ _ _ message 0 n _)
    (wots_sign_after_opening_sealed seed target previous address shuffle width)

theorem wots_sign_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (message shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsSignOpening seed target previous address message shuffle n bound)) 209 := by
  rw [wotsSignOpening, redact_opening_cast, selectedBudget_cast]
  exact opening_selected_bind _ _ _ 0 209 (wots_count_opening_budget seed _ _ _ message 0 n _)
    (wots_sign_after_opening_budget seed target previous address shuffle)

end
end C10Probability
