import C10Probability.WotsSignProvenance
import C10Probability.WotsLayerOpening

/-! Layer metadata is tied to the executed count search. Full-cache
refinement separately supplies replay of the original layer, including its
cached recovery. Both witnesses survive the enclosing computation. -/
namespace C10Probability
noncomputable section

theorem opening_refines_replay {K P α S R T : Type*} [DecidableEq K]
    (p : PMF α) (encode : S → P → K) (project : α → S) (target : K) (secret : α)
    (interpret : R → T) {n m : ℕ} (instrumented : OpeningProgram K P α α R n)
    (ordinary : QueryProgram K α T m)
    (refines : OpeningRefines p encode project target secret interpret instrumented ordinary)
    (table : Memo K α) (opened : Bool) (cached : table target = some secret)
    (out : OpeningOutput K α R)
    (supported : out ∈ (evalOpening p encode project secret instrumented table opened).support) :
    replayProgram out.cache ordinary = some (interpret out.value) := by
  apply eval_program_replay p ordinary table (openingProject interpret out)
  rw [← refines table opened cached, PMF.mem_support_map_iff]
  exact ⟨out, supported, rfl⟩

def wotsAddressCountProgram (seed : ByteKey) (address : WotsLogicalAddress)
    (message : Randomizer) (n : ℕ) (bound : n ≤ 2 ^ 32) :
    QueryProgram WotsQuery Digest (Option (ℕ × Digest)) n :=
  mapProgram Sum.inl (wotsCountProgram seed (wotsTargetLayer (address, 0))
    (wotsTargetTree (address, 0)) (wotsTargetKp (address, 0))
    (nodeValueBytes message) 0 n (by simpa using bound))

theorem wots_layer_opening_count_replay (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (secret : Digest) (table : Memo WotsQuery Digest)
    (opened : Bool)
    (out : OpeningOutput WotsQuery Digest (Option (WotsDeferredLayer target address × Randomizer)))
    (supported : out ∈ (evalOpening digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
      (wotsLayerOpening seed target previous address message shuffle n bound) table opened).support)
    (sig : WotsDeferredLayer target address) (root : Randomizer)
    (returned : out.value = some (sig, root)) :
    replayProgram out.cache (wotsAddressCountProgram seed address message n bound) =
      some (some (sig.wots.count, sig.wots.digest)) := by
  rw [wotsLayerOpening, eval_opening_cast, eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨built, _, supported⟩ := supported
  rw [eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨subseed, _, supported⟩ := supported
  rw [eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨signed, signSupport, supported⟩ := supported
  have equal : out = ⟨wotsLayerCachedOutput built.value signed.value, signed.cache, signed.opened⟩ := by
    simpa only [evalOpening, PMF.mem_support_pure_iff] using supported
  subst out
  dsimp only at returned ⊢
  cases signedValue : signed.value with
  | none => simp only [wotsLayerCachedOutput, signedValue, Option.map_none] at returned; cases returned
  | some result =>
    have counted := wots_sign_opening_count_replay seed target previous address
      (nodeValueBytes message) subseed.value n bound secret subseed.cache subseed.opened signed
      signSupport result signedValue
    have sigEq : result = sig.wots := by
      simp only [wotsLayerCachedOutput, signedValue, Option.map_some,
        Option.some.injEq, Prod.mk.injEq] at returned
      exact congrArg WotsDeferredLayer.wots returned.1
    rw [sigEq] at counted
    exact counted

theorem wots_layer_opening_replay (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (secret : Digest) (table : Memo WotsQuery Digest)
    (opened : Bool) (cached : table (wotsCutIncoming seed target previous) = some secret)
    (out : OpeningOutput WotsQuery Digest (Option (WotsDeferredLayer target address × Randomizer)))
    (supported : out ∈ (evalOpening digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
      (wotsLayerOpening seed target previous address message shuffle n bound) table opened).support) :
    replayProgram out.cache (layerSignProgram id seed (wotsTargetLayer (address, 0))
      (wotsTargetTree (address, 0)) (wotsTargetKp (address, 0)) message shuffle n bound) =
        some (wotsDeferredLayerSigned secret out.value) := by
  exact opening_refines_replay digestDraw (wotsCutCommit seed target) randomizerOfDigest
    (wotsCutIncoming seed target previous) secret (wotsDeferredLayerSigned secret) _ _
    (wots_layer_opening_refines seed target previous address message shuffle n bound secret)
    table opened cached out supported

end
end C10Probability
