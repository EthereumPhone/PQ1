import C10Probability.WotsCountDomain
import C10Probability.LayerSign

/-! The actual WOTS and layer signers can return no signature only after
count exhaustion. Every public input is unchanged by the supplied labeling;
private inputs may be labeled arbitrarily. Prework caches are unrestricted. -/
namespace C10Probability
noncomputable section

theorem wots_sign_failure_domain (encode : WotsQuery → ByteKey)
    (publicKeys : ∀ key, encode (.inl key) = key) (table final : Memo ByteKey Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message shuffle : ByteKey)
    (width : message.length = 16) (n : ℕ) (bounded : n ≤ 2 ^ 32)
    (failed : (none, final) ∈
      (wotsSign encode table seed layer tree kp message shuffle n bounded).support) :
    WotsDomainExhausted seed n bounded final := by
  rw [wotsSign, PMF.mem_support_bind_iff] at failed
  obtain ⟨⟨found, middle⟩, searched, finished⟩ := failed
  cases found with
  | none =>
    have same : final = middle := by simpa [wotsSignAfter] using finished
    subst final
    apply wots_count_exhaustion_in_domain seed layer tree kp message width n bounded table middle
    have identity : (fun key => encode (.inl key)) = id := funext publicKeys
    simpa only [wotsCountUnder, identity, List.map_id, wotsCountSearch] using searched
  | some value =>
    simp only [wotsSignAfter, PMF.mem_support_bind_iff] at finished
    obtain ⟨order, _, finished⟩ := finished
    simp only [PMF.mem_support_map_iff] at finished
    obtain ⟨out, _, equal⟩ := finished
    simp at equal

theorem layer_sign_failure_domain (encode : WotsQuery → ByteKey)
    (publicKeys : ∀ key, encode (.inl key) = key) (table final : Memo ByteKey Digest)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bounded : n ≤ 2 ^ 32)
    (failed : (none, final) ∈
      (layerSign encode table seed layer tree leaf message shuffle n bounded).support) :
    WotsDomainExhausted seed n bounded final := by
  rw [layerSign, PMF.mem_support_bind_iff] at failed
  obtain ⟨built, _, failed⟩ := failed
  rw [PMF.mem_support_bind_iff] at failed
  obtain ⟨subseed, _, failed⟩ := failed
  rw [PMF.mem_support_bind_iff] at failed
  obtain ⟨⟨signed, middle⟩, signing, finished⟩ := failed
  cases signed with
  | none =>
    have same : final = middle := by simpa [layerSignAfter] using finished
    subst final
    exact wots_sign_failure_domain encode publicKeys subseed.2 middle seed layer tree leaf
      (nodeValueBytes message) subseed.1 (node_value_bytes_length message) n bounded signing
  | some value =>
    simp only [layerSignAfter, PMF.mem_support_map_iff] at finished
    obtain ⟨out, _, equal⟩ := finished
    simp at equal

end
end C10Probability
