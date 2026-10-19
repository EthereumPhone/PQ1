import C10Probability.WotsSignOpening
import C10Probability.OpeningPost
import C10Probability.CountReplay

/-! Stored signing digests come from the actual bounded count search. These
facts relate deferred metadata to the final memo table, independently of the
erasure equation for the returned signature. -/
namespace C10Probability
noncomputable section

theorem opening_post_all {K P α H R : Type*} (post : R → Prop) (valid : ∀ value, post value)
    {n : ℕ} (program : OpeningProgram K P α H R n) : OpeningPost post program := by
  induction program with
  | done value => exact valid value
  | query key next ih => exact ih
  | commit label next ih => exact ih
  | reveal next ih => exact ih

theorem wots_sign_after_opening_metadata (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (shuffle : ByteKey)
    (selected : Option (ℕ × Digest)) :
    OpeningPost (fun signed => ∀ result, signed = some result →
      selected = some (result.count, result.digest))
      (wotsSignAfterOpening seed target previous address shuffle selected) := by
  cases selected with
  | none =>
    rw [wotsSignAfterOpening]
    intro result equal
    cases equal
  | some value =>
    obtain ⟨count, digest⟩ := value
    by_cases accepted : wotsAccept (wotsOfDigest digest) = true
    · rw [wotsSignAfterOpening, dif_pos accepted]
      apply opening_post_bind (fun _ => True) _ _ _ (opening_post_constant True True.intro _)
      intro order _
      rw [opening_post_map]
      apply opening_post_all
      intro sigma result equal
      cases equal
      rfl
    · rw [wotsSignAfterOpening, dif_neg accepted]
      intro result equal
      cases equal

theorem wots_sign_opening_count_replay (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (message shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (secret : Digest) (table : Memo WotsQuery Digest)
    (opened : Bool) (out : OpeningOutput WotsQuery Digest (Option (WotsDeferredResult target address)))
    (supported : out ∈ (evalOpening digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
      (wotsSignOpening seed target previous address message shuffle n bound) table opened).support)
    (result : WotsDeferredResult target address) (returned : out.value = some result) :
    replayProgram out.cache (mapProgram Sum.inl (wotsCountProgram seed (wotsTargetLayer (address, 0))
      (wotsTargetTree (address, 0)) (wotsTargetKp (address, 0)) message 0 n (by simpa using bound))) =
        some (some (result.count, result.digest)) := by
  rw [wotsSignOpening, eval_opening_cast, eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨found, foundSupport, supported⟩ := supported
  rw [eval_opening_lift, PMF.mem_support_map_iff] at foundSupport
  obtain ⟨first, firstSupport, rfl⟩ := foundSupport
  have metadata := opening_post_support digestDraw (wotsCutCommit seed target) randomizerOfDigest secret _ _
    (wots_sign_after_opening_metadata seed target previous address shuffle first.1)
    first.2 opened out supported result returned
  have recorded := eval_program_replay digestDraw _ table first firstSupport
  have extension : MemoExtends first.2 out.cache := by
    intro key value cached
    exact eval_opening_preserves digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
      (wotsSignAfterOpening seed target previous address shuffle first.1) first.2 opened
      key value cached out supported
  have replayed := replay_program_extends _ first.2 out.cache first.1 extension recorded
  rw [metadata] at replayed
  exact replayed

theorem wots_sign_opening_count_lookup (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (message shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (secret : Digest) (table : Memo WotsQuery Digest)
    (opened : Bool) (out : OpeningOutput WotsQuery Digest (Option (WotsDeferredResult target address)))
    (supported : out ∈ (evalOpening digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
      (wotsSignOpening seed target previous address message shuffle n bound) table opened).support)
    (result : WotsDeferredResult target address) (returned : out.value = some result) :
    result.count < n ∧ out.cache (.inl (wotsRecoverCountInput seed (wotsTargetLayer (address, 0))
      (wotsTargetTree (address, 0)) (wotsTargetKp (address, 0)) message result.count)) = some result.digest := by
  have counted := replay_wots_count_success Sum.inl out.cache seed _ _ _ message 0 n _
    result.count result.digest (wots_sign_opening_count_replay seed target previous address
      message shuffle n bound secret table opened out supported result returned)
  exact ⟨by simpa only [Nat.zero_add] using counted.2.1, counted.2.2.1⟩

end
end C10Probability
