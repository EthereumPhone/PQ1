import C10Probability.WotsFailure
import C10Probability.C10RSign

/-! Failure provenance through both actual layers, forest prework and the
complete signer. R exhaustion and WOTS exhaustion remain distinct alternatives.
No freshness or cache-origin premise is required for this deterministic trace
property. -/
namespace C10Probability
noncomputable section

theorem hypertree_sign_failure_domain (encode : WotsQuery → ByteKey)
    (publicKeys : ∀ key, encode (.inl key) = key) (seed shuffle : ByteKey)
    (n : ℕ) (bounded : n ≤ 2 ^ 32) (steps layer index : ℕ)
    (current : Randomizer) (signatures : List LayerSignature) (table final : Memo ByteKey Digest)
    (failed : (none, final) ∈
      (hypertreeSign encode seed shuffle n bounded steps layer index current signatures table).support) :
    WotsDomainExhausted seed n bounded final := by
  induction steps generalizing layer index current signatures table with
  | zero => simp [hypertreeSign] at failed
  | succ steps ih =>
    rw [hypertreeSign, PMF.mem_support_bind_iff] at failed
    obtain ⟨⟨signed, middle⟩, signing, finished⟩ := failed
    cases signed with
    | none =>
      have same : final = middle := by simpa using finished
      subst final
      exact layer_sign_failure_domain encode publicKeys table middle seed layer
        (hypertreeParent index) (hypertreeLeaf index) current shuffle n bounded signing
    | some value => exact ih _ _ _ _ middle finished

theorem c10_finish_failure_domain (encode : WotsQuery → ByteKey)
    (publicKeys : ∀ key, encode (.inl key) = key) (table final : Memo ByteKey Digest)
    (seed : ByteKey) (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (bounded : n ≤ 2 ^ 32)
    (failed : (none, final) ∈
      (c10Finish encode table seed randomizer digest shuffle n bounded).support) :
    WotsDomainExhausted seed n bounded final := by
  rw [c10Finish, PMF.mem_support_bind_iff] at failed
  obtain ⟨forest, _, failed⟩ := failed
  rw [PMF.mem_support_map_iff] at failed
  obtain ⟨⟨signed, middle⟩, signing, equal⟩ := failed
  cases signed with
  | none =>
    have same : middle = final := by simpa [c10FinishOutput] using equal
    subst final
    exact hypertree_sign_failure_domain encode publicKeys seed shuffle n bounded 2 0
      (hypertreeIndex digest) forest.1.pk [] forest.2 middle signing
  | some value => simp [c10FinishOutput] at equal

theorem c10_r_sign_failure_cases (encode : WotsQuery → ByteKey)
    (publicKeys : ∀ key, encode (.inl key) = key) (table : Memo ByteKey Digest)
    (random message seed root shuffle : ByteKey) (m n : ℕ)
    (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) (out : C10RSignReply × Memo ByteKey Digest)
    (supported : out ∈ (c10RSign encode table random message seed root shuffle m n hm hn).support)
    (failed : out.1.1 = none) :
    out.1.2 = true ∨ WotsDomainExhausted seed n hn out.2 := by
  rw [c10RSign, PMF.mem_support_bind_iff] at supported
  obtain ⟨⟨found, middle⟩, _, supported⟩ := supported
  rw [PMF.mem_support_map_iff] at supported
  obtain ⟨⟨reply, final⟩, finished, rfl⟩ := supported
  simp only at failed
  subst reply
  cases found with
  | none => exact Or.inl rfl
  | some value =>
    exact Or.inr (c10_finish_failure_domain encode publicKeys middle final seed value.2.1 value.2.2
      shuffle n hn finished)

end
end C10Probability
