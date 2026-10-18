import C10Probability.C10Honest

/-! Actual key generation, bounded signing and verification composed in the
probability monad. None records signing failure; some false records rejection
of a returned signature. No losslessness premise turns failure into success. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def c10HonestCheck [DecidableEq K] (encode : WotsQuery → K) (initial : Memo K Digest)
    (publicSeed : Digest) (random message shuffle : ByteKey) (m n : ℕ)
    (rBound : m ≤ 2 ^ 32) (wBound : n ≤ 2 ^ 32) : PMF (Option Bool) :=
  (c10Keygen encode initial publicSeed).bind (fun key =>
    (c10Sign encode key.2 random message key.1.1 key.1.2 shuffle m n rBound wBound).bind
      (fun signed => match signed.1 with
        | none => PMF.pure none
        | some sig => (c10Verify (fun input => encode (.inl input)) signed.2
            key.1.1 key.1.2 message sig).map (fun verified => some verified.1)))

theorem c10_honest_check_distribution [DecidableEq K] (encode : WotsQuery → K)
    (initial : Memo K Digest) (publicSeed : Digest) (random message shuffle : ByteKey)
    (m n : ℕ) (rBound : m ≤ 2 ^ 32) (wBound : n ≤ 2 ^ 32) :
    c10HonestCheck encode initial publicSeed random message shuffle m n rBound wBound =
      (c10Keygen encode initial publicSeed).bind (fun key =>
        (c10Sign encode key.2 random message key.1.1 key.1.2 shuffle m n rBound wBound).map
          (fun signed => signed.1.map (fun _ => true))) := by
  unfold c10HonestCheck
  apply pmf_bind_support_congr
  intro key generated
  rw [PMF.map]
  apply pmf_bind_support_congr
  rintro ⟨result, after⟩ signed
  cases result with
  | none => rfl
  | some sig =>
    change (c10Verify (fun input => encode (.inl input)) after key.1.1 key.1.2 message sig).map
      (fun verified => some verified.1) = PMF.pure (some true)
    rw [c10_honest_verification_support encode initial publicSeed key random message shuffle
      m n rBound wBound sig after generated signed, PMF.pure_map]

theorem c10_honest_rejection_mass_zero [DecidableEq K] (encode : WotsQuery → K)
    (initial : Memo K Digest) (publicSeed : Digest) (random message shuffle : ByteKey)
    (m n : ℕ) (rBound : m ≤ 2 ^ 32) (wBound : n ≤ 2 ^ 32) :
    c10HonestCheck encode initial publicSeed random message shuffle m n rBound wBound
      (some false) = 0 := by
  rw [c10_honest_check_distribution]
  apply (PMF.apply_eq_zero_iff _ _).mpr
  intro rejected
  rw [PMF.mem_support_bind_iff] at rejected
  obtain ⟨key, _, rejected⟩ := rejected
  rw [PMF.mem_support_map_iff] at rejected
  obtain ⟨⟨result, after⟩, _, value⟩ := rejected
  cases result <;> simp at value

theorem c10_honest_zero_budget_failure [DecidableEq K] (encode : WotsQuery → K)
    (initial : Memo K Digest) (publicSeed : Digest) (random message shuffle : ByteKey)
    (n : ℕ) (wBound : n ≤ 2 ^ 32) :
    c10HonestCheck encode initial publicSeed random message shuffle 0 n (by decide) wBound =
      PMF.pure none := by
  rw [c10_honest_check_distribution]
  simp only [c10_sign_zero_r_budget, PMF.pure_map, Option.map_none, PMF.bind_const]

end
end C10Probability
