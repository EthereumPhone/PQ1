import C10Probability.WotsOrdinaryOpening
import C10Probability.WotsReleaseOpening

/-! Full C10 signing before client-visible release. The ordinary R search and
forest are followed by both actual signing layers. Successful metadata retains
the full digests; failed searches return none and retain their entire cache. -/
namespace C10Probability
noncomputable section

def wotsDigestIndex (digest : Digest) : Fin (2 ^ 18) :=
  ⟨hypertreeIndex digest, hypertree_index_bound digest⟩

structure WotsDeferredC10 (target : WotsCutTarget) where
  randomizer : Randomizer
  digest : Digest
  forest : ForestOutput
  signed : WotsDeferredHypertree target (wotsDigestIndex digest)

def wotsDeferredC10Signature (secret : Digest) {target : WotsCutTarget}
    (result : WotsDeferredC10 target) : C10Signature :=
  ⟨result.randomizer, result.forest.secrets, result.forest.auths,
    [wotsDeferredLayerSignature secret result.signed.lower,
      wotsDeferredLayerSignature secret result.signed.upper]⟩

def wotsDeferredC10Signed (secret : Digest) {target : WotsCutTarget}
    (signed : Option (WotsDeferredC10 target)) : Option C10Signature :=
  signed.map (wotsDeferredC10Signature secret)

def wotsDeferredFinish {target : WotsCutTarget} (randomizer : Randomizer) (digest : Digest)
    (forest : ForestOutput) (signed : Option (WotsDeferredHypertree target (wotsDigestIndex digest))) :
    Option (WotsDeferredC10 target) :=
  signed.map (fun result => ⟨randomizer, digest, forest, result⟩)

theorem wots_deferred_finish_output (secret : Digest) {target : WotsCutTarget}
    (randomizer : Randomizer) (digest : Digest) (forest : ForestOutput)
    (signed : Option (WotsDeferredHypertree target (wotsDigestIndex digest))) :
    wotsDeferredC10Signed secret (wotsDeferredFinish randomizer digest forest signed) =
      c10FinishOutput randomizer forest (wotsDeferredHypertreeSigned secret signed) := by
  cases signed <;> rfl

def wotsC10FinishDeferred (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) :
    OpeningProgram WotsQuery Unit Digest Digest (Option (WotsDeferredC10 target)) (2 * n + 435044) :=
  castOpening (by omega)
    (bindOpening (liftOpening (forestSignProgram id seed (hypertreeIndex digest) digest shuffle))
      (fun forest => mapOpeningReturn (wotsDeferredFinish randomizer digest forest)
        (wotsHypertreeOpening seed target previous shuffle n bound (wotsDigestIndex digest) forest.pk)))

attribute [irreducible] wotsC10FinishDeferred

theorem wots_c10_finish_deferred_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredC10Signed secret)
      (wotsC10FinishDeferred seed target previous randomizer digest shuffle n bound)
      (c10FinishProgram id seed randomizer digest shuffle n bound) := by
  rw [wotsC10FinishDeferred, c10FinishProgram]
  apply opening_refines_cast
  apply opening_refines_bind digestDraw (wotsCutCommit seed target) randomizerOfDigest
    (wotsCutIncoming seed target previous) secret id (wotsDeferredC10Signed secret) _ _ _ _
    (opening_refines_lift _ _ _ _ _ _)
  intro forest
  exact opening_refines_map digestDraw (wotsCutCommit seed target) randomizerOfDigest
    (wotsCutIncoming seed target previous) secret (wotsDeferredHypertreeSigned secret)
    (wotsDeferredC10Signed secret) (wotsDeferredFinish randomizer digest forest)
    (c10FinishOutput randomizer forest) (wots_deferred_finish_output secret randomizer digest forest)
    _ _ (wots_hypertree_opening_refines seed target previous shuffle n bound _ forest.pk secret)

theorem wots_c10_finish_deferred_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (width : shuffle.length = 32) (n : ℕ) (bound : n ≤ 2 ^ 32) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsC10FinishDeferred seed target previous randomizer digest shuffle n bound) := by
  rw [wotsC10FinishDeferred, opening_sealed_cast]
  apply opening_sealed_bind _ _ _
    (forest_sign_wots_cut_sealed seed target previous _ digest shuffle width)
  intro forest
  rw [opening_sealed_map]
  exact wots_hypertree_opening_sealed seed target previous shuffle width n bound _ forest.pk

theorem wots_c10_finish_deferred_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsC10FinishDeferred seed target previous randomizer digest shuffle n bound))
      364076 := by
  rw [wotsC10FinishDeferred, redact_opening_cast, selectedBudget_cast]
  apply opening_selected_bind _ _ _ 53386 310690 (forest_sign_wots_opening_budget seed _ digest shuffle)
  intro forest
  rw [redact_opening_mapReturn, selectedBudget_mapReturn]
  exact wots_hypertree_opening_budget seed target previous shuffle n bound _ forest.pk

def wotsC10AfterDeferred (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32) (found : Option (ℕ × Randomizer × Digest)) :
    OpeningProgram WotsQuery Unit Digest Digest (Option (WotsDeferredC10 target)) (2 * n + 435044) :=
  match found with
  | none => .done none
  | some (_, randomizer, digest) =>
      wotsC10FinishDeferred seed target previous randomizer digest shuffle n bound

def wotsC10SignDeferred (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (random message root shuffle : ByteKey) (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    OpeningProgram WotsQuery Unit Digest Digest (Option (WotsDeferredC10 target))
      (2 * m + 2 * n + 435044) :=
  castOpening (by omega)
    (bindOpening (liftOpening (randomizerUnderProgram id random message seed root m hm))
      (wotsC10AfterDeferred seed target previous shuffle n hn))

attribute [irreducible] wotsC10SignDeferred

theorem wots_c10_sign_deferred_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (random message root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredC10Signed secret)
      (wotsC10SignDeferred seed target previous random message root shuffle m n hm hn)
      (c10SignProgram id random message seed root shuffle m n hm hn) := by
  rw [wotsC10SignDeferred, c10SignProgram]
  apply opening_refines_cast
  apply opening_refines_bind digestDraw (wotsCutCommit seed target) randomizerOfDigest
    (wotsCutIncoming seed target previous) secret id (wotsDeferredC10Signed secret) _ _ _ _
    (opening_refines_lift _ _ _ _ _ _)
  intro found
  cases found with
  | none => exact opening_refines_done _ _ _ _ _ _ none _ _
  | some value => exact wots_c10_finish_deferred_refines seed target previous _ _ shuffle n hn secret

theorem wots_c10_sign_deferred_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (random message root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32)
    (seedWidth : seed.length = 32) (rootWidth : root.length = 32)
    (messageWidth : message.length = 32) (shuffleWidth : shuffle.length = 32) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsC10SignDeferred seed target previous random message root shuffle m n hm hn) := by
  rw [wotsC10SignDeferred, opening_sealed_cast]
  apply opening_sealed_bind _ _ _
    (randomizer_wots_opening_sealed seed target previous random message root m hm
      seedWidth rootWidth messageWidth)
  intro found
  cases found with
  | none => trivial
  | some value => exact wots_c10_finish_deferred_sealed seed target previous _ _ shuffle shuffleWidth n hn

theorem wots_c10_sign_deferred_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (random message root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsC10SignDeferred seed target previous random message root shuffle m n hm hn))
      364076 := by
  rw [wotsC10SignDeferred, redact_opening_cast, selectedBudget_cast]
  apply opening_selected_bind _ _ _ 0 364076 (randomizer_wots_opening_budget random message seed root m hm)
  intro found
  cases found with
  | none => trivial
  | some value => exact wots_c10_finish_deferred_budget seed target previous _ _ shuffle n hn

end
end C10Probability
