import C10Probability.ObservedInitialized
import C10Probability.RecoveryWitness

/-! A winning observed game supplies one joint witness: actual keygen,
successful signing exposures, forwarded hash inputs, budget accounting and
the actual final verifier all refer to its single resulting cache. This is
support evidence for the later forgery partition, not that partition or its
numerical bound. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

structure ObservedOutputWitness (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) (qr qs : ℕ) (out : C10ObservedGame × Memo K Digest) : Prop where
  seed_width : out.1.key.1.length = 32
  root_width : out.1.key.2.length = 32
  keygen : replayProgram out.2 (c10KeygenProgram encode publicSeed) = some out.1.key
  normalized_seed : out.1.key.1 = nodeBlock (randomizerOfDigest publicSeed)
  keygen_root : ∃ root, replayProgram out.2 (subtreeRootProgram encode out.1.key.1 1 0) = some root ∧
    nodeBlock root = out.1.key.2
  raw_accounting : out.1.driver.session.queries.length +
    out.1.driver.session.session.rawRemaining = qr
  sign_accounting : out.1.driver.session.exposures.length +
    out.1.driver.session.session.signRemaining ≤ qs
  ledger : out.1.driver.session.session.ledger.signedMessages =
    exposureMessages out.1.driver.session.exposures
  exposures : ∀ entry ∈ out.1.driver.session.exposures,
    ExposureSupported encode (sessionConfigAt cfg out.1.key) out.2 entry
  queries : ∀ key ∈ out.1.driver.session.queries, ∃ reply, out.2 (encode (.inl key)) = some reply
  nonfailed : out.1.driver.session.session.ledger.failed = false
  message_width : out.1.driver.session.session.value.1.length = 32
  signature_shape : C10SignatureWellFormed out.1.driver.session.session.value.2
  fresh : ∀ entry ∈ out.1.driver.session.exposures,
    out.1.driver.session.session.value.1 ≠ entry.request.message
  verification : VerificationWitness (encode ∘ Sum.inl) out.2 out.1.key.1 out.1.key.2
    out.1.driver.session.session.value.1 out.1.driver.session.session.value.2

theorem c10_observed_output_witness [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo K Digest)
    (out : C10ObservedGame × Memo K Digest)
    (ho : out ∈ (c10ObservedGame encode cfg publicSeed adversary qr qs table).support)
    (win : out.1.driver.accepted = true) :
    ObservedOutputWitness encode cfg publicSeed qr qs out := by
  obtain ⟨keyTable, _, hd⟩ := c10_observed_game_support encode cfg publicSeed adversary qr qs table out ho
  obtain ⟨hs, hr, hk⟩ := c10_observed_game_keygen encode cfg publicSeed adversary qr qs table out ho
  obtain ⟨hn, hroot⟩ := replay_keygen_witness encode out.2 publicSeed out.1.key hk
  obtain ⟨raw, sign, ledger⟩ := c10_observed_driver_accounting encode (sessionConfigAt cfg out.1.key)
    (adversary out.1.key.1 out.1.key.2) qr qs keyTable (out.1.driver, out.2) hd
  obtain ⟨exposures, queries, _⟩ := c10_observed_driver_history encode (sessionConfigAt cfg out.1.key)
    (adversary out.1.key.1 out.1.key.2) qr qs keyTable (out.1.driver, out.2) hd
  obtain ⟨nonfailed, message, signature, fresh, verified⟩ := c10_observed_driver_true encode
    (sessionConfigAt cfg out.1.key) (adversary out.1.key.1 out.1.key.2) qr qs keyTable
    (out.1.driver, out.2) hd win
  exact ⟨hs, hr, hk, hn, hroot, raw, sign, ledger, exposures, queries,
    nonfailed, message, signature, fresh, verifier_replay_witness _ _ _ _ _ _ verified⟩

theorem c10_observed_initialized_independent_witness (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (out : C10ObservedGame × Memo WotsQuery Digest)
    (ho : out ∈ (c10ObservedInitializedIndependent cfg sampler qr qs).support)
    (win : out.1.driver.accepted = true) :
    ∃ input ∈ sampler.support,
      out ∈ (c10ObservedGame id cfg input.1 input.2 qr qs (fun _ => none)).support ∧
      ObservedOutputWitness id cfg input.1 qr qs out := by
  obtain ⟨input, hi, ho⟩ := c10_observed_initialized_independent_support cfg sampler qr qs out ho
  exact ⟨input, hi, ho, c10_observed_output_witness id cfg input.1 input.2 qr qs _ out ho win⟩

theorem c10_observed_initialized_shared_witness (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (out : C10ObservedGame × Memo ByteKey Digest)
    (ho : out ∈ (c10ObservedInitializedShared cfg sampler qr qs).support)
    (win : out.1.driver.accepted = true) :
    ∃ secret ∈ digestDraw.support, ∃ input ∈ sampler.support,
      out ∈ (c10ObservedGame (privateKey prefixedPrivateInput secret) cfg input.1 input.2
        qr qs (fun _ => none)).support ∧
      ObservedOutputWitness (privateKey prefixedPrivateInput secret) cfg input.1 qr qs out := by
  obtain ⟨secret, hs, input, hi, ho⟩ := c10_observed_initialized_shared_support cfg sampler qr qs out ho
  exact ⟨secret, hs, input, hi, ho, c10_observed_output_witness _ cfg input.1 input.2 qr qs _ out ho win⟩

end
end C10Probability
