import C10Probability.WotsC10Deferred
import C10Probability.C10FinishOpening

/-! Client-visible release occurs only after complete signing succeeds. The
extra opening flag is passive; erasing it gives the actual result and cache. -/
namespace C10Probability
noncomputable section

local instance {target : WotsCutTarget} {address : WotsLogicalAddress}
    (result : WotsDeferredResult target address) : Decidable (WotsResultExposes result) := by
  unfold WotsResultExposes
  infer_instance

local instance {target : WotsCutTarget} {index : Fin (2 ^ 18)}
    (result : WotsDeferredHypertree target index) : Decidable (WotsHypertreeExposes result) := by
  unfold WotsHypertreeExposes
  infer_instance

theorem wots_c10_unexposed_known (first other : Digest) {target : WotsCutTarget}
    (result : WotsDeferredC10 target) (unexposed : ¬ WotsHypertreeExposes result.signed) :
    wotsDeferredC10Signature first result = wotsDeferredC10Signature other result := by
  have lower : ¬ WotsResultExposes result.signed.lower.wots := fun h => unexposed (Or.inl h)
  have upper : ¬ WotsResultExposes result.signed.upper.wots := fun h => unexposed (Or.inr h)
  simp only [wotsDeferredC10Signature,
    wots_layer_unexposed_known first other result.signed.lower lower,
    wots_layer_unexposed_known first other result.signed.upper upper]

def wotsC10Release {target : WotsCutTarget} (signed : Option (WotsDeferredC10 target)) :
    OpeningProgram WotsQuery Unit Digest Digest (Option C10Signature) 1 :=
  match signed with
  | none => .done none
  | some result => if WotsHypertreeExposes result.signed then
      .reveal (fun secret => .done (some (wotsDeferredC10Signature secret result)))
    else .done (some (wotsDeferredC10Signature 0 result))

theorem wots_c10_release_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (secret : Digest) (signed : Option (WotsDeferredC10 target)) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret id (wotsC10Release signed)
      (.done (n := 0) (wotsDeferredC10Signed secret signed)) := by
  intro table opened _
  cases signed with
  | none =>
    simp only [wotsC10Release, evalOpening, PMF.pure_map, openingProject,
      id_eq, evalProgram, wotsDeferredC10Signed, Option.map_none]
  | some result =>
    by_cases exposed : WotsHypertreeExposes result.signed
    · simp only [wotsC10Release, exposed, ↓reduceIte, evalOpening, PMF.pure_map,
        openingProject, id_eq, evalProgram, wotsDeferredC10Signed, Option.map_some]
    · simp only [wotsC10Release, exposed, ↓reduceIte, evalOpening, PMF.pure_map,
        openingProject, id_eq, evalProgram, wotsDeferredC10Signed, Option.map_some,
        wots_c10_unexposed_known secret 0 result exposed]

theorem wots_c10_release_avoids (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (signed : Option (WotsDeferredC10 target)) :
    OpeningAvoids (wotsCutIncoming seed target previous) (wotsC10Release signed) := by
  cases signed with
  | none => trivial
  | some result =>
    by_cases exposed : WotsHypertreeExposes result.signed
    · simp only [wotsC10Release, exposed, ↓reduceIte, OpeningAvoids]
      exact fun _ => True.intro
    · simp only [wotsC10Release, exposed, ↓reduceIte, OpeningAvoids]

theorem wots_c10_release_budget {target : WotsCutTarget} (signed : Option (WotsDeferredC10 target)) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsC10Release signed)) 0 := by
  cases signed with
  | none => trivial
  | some result =>
    by_cases exposed : WotsHypertreeExposes result.signed <;>
      simp only [wotsC10Release, exposed, ↓reduceIte, redactOpening, SelectedBudget]

theorem wots_c10_release_disclosure (seed : ByteKey) (target : WotsCutTarget)
    (secret : Digest) (signed : Option (WotsDeferredC10 target)) (table : Memo WotsQuery Digest)
    (out : OpeningOutput WotsQuery Digest (Option C10Signature))
    (supported : out ∈ (evalOpening digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
      (wotsC10Release signed) table false).support) (opened : out.opened = true) :
    ∃ result, signed = some result ∧ WotsHypertreeExposes result.signed ∧
      out.value = some (wotsDeferredC10Signature secret result) ∧ out.cache = table := by
  cases signed with
  | none =>
    have equal : out = ⟨none, table, false⟩ := by
      simpa only [wotsC10Release, evalOpening, PMF.mem_support_pure_iff] using supported
    simp only [equal, Bool.false_eq_true] at opened
  | some result =>
    by_cases exposed : WotsHypertreeExposes result.signed
    · have equal : out = ⟨some (wotsDeferredC10Signature secret result), table, true⟩ := by
        simpa only [wotsC10Release, exposed, ↓reduceIte, evalOpening,
          PMF.mem_support_pure_iff] using supported
      exact ⟨result, rfl, exposed, congrArg OpeningOutput.value equal, congrArg OpeningOutput.cache equal⟩
    · have equal : out = ⟨some (wotsDeferredC10Signature 0 result), table, false⟩ := by
        simpa only [wotsC10Release, exposed, ↓reduceIte, evalOpening,
          PMF.mem_support_pure_iff] using supported
      simp only [equal, Bool.false_eq_true] at opened

def wotsC10Opening (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (random message root shuffle : ByteKey) (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    OpeningProgram WotsQuery Unit Digest Digest (Option C10Signature) (2 * m + 2 * n + 435045) :=
  castOpening (by omega) (bindOpening
    (wotsC10SignDeferred seed target previous random message root shuffle m n hm hn) wotsC10Release)

attribute [irreducible] wotsC10Opening

theorem wots_c10_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (random message root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret id
      (wotsC10Opening seed target previous random message root shuffle m n hm hn)
      (c10SignProgram id random message seed root shuffle m n hm hn) := by
  have compared := opening_refines_bind_done digestDraw (wotsCutCommit seed target) randomizerOfDigest
    (wotsCutIncoming seed target previous) secret (wotsDeferredC10Signed secret) id _ _ _
    (wots_c10_sign_deferred_refines seed target previous random message root shuffle m n hm hn secret)
    (wots_c10_release_refines seed target previous secret)
  intro table opened cached
  rw [wotsC10Opening, eval_opening_cast]
  have actual := compared table opened cached
  rw [evalProgram_mapReturn] at actual
  have identity : (fun out : Option C10Signature × Memo WotsQuery Digest => (id out.1, out.2)) = id := by
    funext out
    rfl
  rw [identity, PMF.map_id] at actual
  exact actual

theorem wots_c10_opening_avoids (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (random message root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32)
    (seedWidth : seed.length = 32) (rootWidth : root.length = 32)
    (messageWidth : message.length = 32) (shuffleWidth : shuffle.length = 32) :
    OpeningAvoids (wotsCutIncoming seed target previous)
      (wotsC10Opening seed target previous random message root shuffle m n hm hn) := by
  rw [wotsC10Opening, opening_avoids_cast]
  exact opening_avoids_bind _ _ _
    (opening_sealed_avoids _ _ (wots_c10_sign_deferred_sealed seed target previous
      random message root shuffle m n hm hn seedWidth rootWidth messageWidth shuffleWidth))
    (wots_c10_release_avoids seed target previous)

theorem wots_c10_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (random message root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsC10Opening seed target previous random message root shuffle m n hm hn)) 364076 := by
  rw [wotsC10Opening, redact_opening_cast, selectedBudget_cast]
  exact opening_selected_bind _ _ _ 364076 0
    (wots_c10_sign_deferred_budget seed target previous random message root shuffle m n hm hn)
    wots_c10_release_budget

end
end C10Probability
