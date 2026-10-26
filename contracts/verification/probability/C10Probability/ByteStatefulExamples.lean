import C10Probability.ByteStatefulGeometric
import C10Probability.ByteAvailabilityExamples

/-! Stateful boundary witnesses preserve the complete session state. Constant
populated caches are functional examples, not claims about initialized oracle
histories. The reply-dependent coin is drawn after the hash response. -/
namespace C10Probability
noncomputable section

theorem byte_stateful_cutoff_zero_done (cfg : C10SessionConfig)
    (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo WotsQuery Digest) :
    c10StatefulByteCutoff id cfg (fun _ : Unit => PMF.pure (.done true))
        0 () qr qs ledger table = PMF.pure (⟨none, ledger, qr, qs⟩, table) ∧
      c10StatefulByteCutoff id cfg (fun _ : Unit => PMF.pure (.done true))
        1 () qr qs ledger table = PMF.pure (⟨some true, ledger, qr, qs⟩, table) := by
  simp only [c10StatefulByteCutoff, PMF.pure_bind, and_self]

theorem byte_stateful_tick (cfg : C10SessionConfig) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo WotsQuery Digest) :
    c10StatefulByteStep id cfg (fun _ : ℕ => PMF.pure (.tick 7 : C10ByteAction ℕ Bool))
      ⟨2, qr, qs, ledger, table⟩ = PMF.pure (.inr ⟨7, qr, qs, ledger, table⟩) := by
  simp only [c10StatefulByteStep, PMF.pure_bind]

theorem byte_stateful_hash_cap (cfg : C10SessionConfig) (qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo WotsQuery Digest) :
    c10StatefulByteStep id cfg (fun _ : Digest =>
      PMF.pure (.hash [7] id : C10ByteAction Digest Bool)) ⟨42, 0, qs, ledger, table⟩ =
        PMF.pure (.inr ⟨0, 0, qs, ledger, table⟩) := by
  simp only [c10StatefulByteStep, PMF.pure_bind, id_eq]

theorem byte_stateful_hash_cached_after_failure (cfg : C10SessionConfig)
    (table : Memo WotsQuery Digest) (cached : table (.inl [7]) = some 42) :
    c10StatefulByteStep id cfg (fun _ : Digest =>
      PMF.pure (.hash [7] id : C10ByteAction Digest Bool)) ⟨0, 1, 4, ⟨[[9]], true⟩, table⟩ =
        PMF.pure (.inr ⟨42, 0, 4, ⟨[[9]], true⟩, table⟩) := by
  simp only [c10StatefulByteStep, PMF.pure_bind, id_eq,
    memoQuery_cached digestDraw table (.inl [7]) 42 cached, PMF.pure_map]

theorem byte_stateful_sign_cap (cfg : C10SessionConfig) (qr : ℕ)
    (ledger : C10SessionLedger) (table : Memo WotsQuery Digest) :
    c10StatefulByteStep id cfg (fun _ : Option ByteKey =>
      PMF.pure (.sign sessionExampleRequest id : C10ByteAction (Option ByteKey) Bool))
        ⟨some [9], qr, 0, ledger, table⟩ = PMF.pure (.inr ⟨none, qr, 0, ledger, table⟩) := by
  simp only [c10StatefulByteStep, PMF.pure_bind, id_eq]

theorem byte_stateful_malformed_keeps_cap (table : Memo WotsQuery Digest) :
    c10StatefulByteStep id sessionExampleConfig (fun _ : Option ByteKey =>
      PMF.pure (.sign ⟨[], [], []⟩ id : C10ByteAction (Option ByteKey) Bool))
        ⟨some [9], 3, 2, emptySessionLedger, table⟩ =
          PMF.pure (.inr ⟨none, 3, 2, emptySessionLedger, table⟩) := by
  have refused : sessionAdmits emptySessionLedger ⟨[], [], []⟩ = false := by decide +kernel
  simp only [c10StatefulByteStep, PMF.pure_bind, refused, Bool.false_eq_true, ↓reduceIte, id_eq]

def statefulZeroRConfig : C10SessionConfig :=
  {sessionExampleConfig with rTrials := 0, rBound := by decide}

theorem byte_stateful_zero_r_charged (table : Memo WotsQuery Digest) :
    c10StatefulByteStep id statefulZeroRConfig
      (fun _ : Option ByteKey =>
        PMF.pure (.sign sessionExampleRequest id : C10ByteAction (Option ByteKey) Bool))
          ⟨some [9], 3, 2, emptySessionLedger, table⟩ =
            PMF.pure (.inr ⟨none, 3, 1, ⟨[], true⟩, table⟩) := by
  have admitted : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  simp only [statefulZeroRConfig, c10StatefulByteStep, PMF.pure_bind]
  rw [if_pos admitted, c10SignBytes, c10_sign_zero_r_budget, PMF.pure_map, PMF.pure_map]
  rfl

theorem byte_stateful_failure_absorbs (cfg : C10SessionConfig)
    (table : Memo WotsQuery Digest) :
    c10StatefulByteStep id cfg (fun _ : Option ByteKey =>
      PMF.pure (.sign sessionExampleRequest id : C10ByteAction (Option ByteKey) Bool))
        ⟨some [9], 3, 1, ⟨[[9]], true⟩, table⟩ =
          PMF.pure (.inr ⟨none, 3, 1, ⟨[[9]], true⟩, table⟩) := by
  simp only [c10StatefulByteStep, PMF.pure_bind,
    session_failed_refuses ⟨[[9]], true⟩ sessionExampleRequest rfl,
    Bool.false_eq_true, ↓reduceIte, id_eq]

theorem byte_stateful_wots_failure :
    c10StatefulByteStep id sessionExampleConfig (fun _ : Option ByteKey =>
      PMF.pure (.sign sessionExampleRequest id : C10ByteAction (Option ByteKey) Bool))
        ⟨some [9], 3, 2, emptySessionLedger, fun _ => some (2 ^ 128)⟩ =
          PMF.pure (.inr ⟨none, 3, 1, ⟨[], true⟩, fun _ => some (2 ^ 128)⟩) := by
  have failed : c10Sign id (fun _ => some (2 ^ 128)) sessionExampleRequest.random
      sessionExampleRequest.message sessionExampleConfig.seed sessionExampleConfig.root
      sessionExampleRequest.shuffle 1 1 (by decide) (by decide) =
        PMF.pure (none, fun _ => some (2 ^ 128)) := by
    rw [← c10_r_sign_erases, c10_r_sign_wots_failure, PMF.pure_map]
  have admitted : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  simp only [c10StatefulByteStep, PMF.pure_bind]
  rw [if_pos admitted, c10SignBytes]
  simp only [sessionExampleConfig] at failed ⊢
  rw [failed, PMF.pure_map, PMF.pure_map]
  rfl

theorem byte_stateful_cached_success :
    ∃ bytes, bytes.length = 4008 ∧
      c10StatefulByteStep id sessionExampleConfig (fun _ : Option ByteKey =>
        PMF.pure (.sign sessionExampleRequest id : C10ByteAction (Option ByteKey) Bool))
          ⟨none, 3, 2, emptySessionLedger, fun _ => some recoveryAcceptedDigest⟩ =
            PMF.pure (.inr ⟨some bytes, 3, 1, ⟨[sessionExampleRequest.message], false⟩,
              fun _ => some recoveryAcceptedDigest⟩) := by
  obtain ⟨sig, execution⟩ := c10_sign_full_cache_accept id sessionExampleRequest.random
    sessionExampleRequest.message sessionExampleConfig.seed sessionExampleConfig.root
    sessionExampleRequest.shuffle
  have shape : C10SignatureWellFormed sig :=
    c10_sign_signature_shape id (fun _ => some recoveryAcceptedDigest) sessionExampleRequest.random
      sessionExampleRequest.message sessionExampleConfig.seed sessionExampleConfig.root
      sessionExampleRequest.shuffle 1 1 (by decide) (by decide)
      (some sig, fun _ => some recoveryAcceptedDigest) (by rw [execution]; simp)
  refine ⟨wireEncode (wireSignatureFromStructured sig shape), wire_encode_length _, ?_⟩
  have admitted : sessionAdmits emptySessionLedger sessionExampleRequest = true := by decide +kernel
  simp only [c10StatefulByteStep, PMF.pure_bind]
  rw [if_pos admitted, c10SignBytes]
  simp only [sessionExampleConfig] at execution ⊢
  rw [execution, PMF.pure_map, PMF.pure_map, byte_sign_reply_some sig shape]
  rfl

def byteReplyCoin (key : ByteKey) : Option Digest → PMF (C10ByteAction (Option Digest) (Digest × Bool))
  | none => PMF.pure (.hash key some)
  | some reply => (PMF.bernoulli (1 / 2) (by norm_num)).map (fun coin => .done (reply, coin))

theorem byte_stateful_randomness_after_reply (cfg : C10SessionConfig) (key : ByteKey)
    (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo WotsQuery Digest) :
    c10StatefulByteCutoff id cfg (byteReplyCoin key) 2 none (qr + 1) qs ledger table =
      (memoQuery digestDraw table (.inl key)).bind fun reply =>
        (PMF.bernoulli (1 / 2) (by norm_num)).map
          (fun coin => (⟨some (reply.1, coin), ledger, qr, qs⟩, reply.2)) := by
  simp only [c10StatefulByteCutoff, byteReplyCoin, PMF.pure_bind, PMF.bind_bind,
    id_eq, PMF.map, Function.comp_def]

end
end C10Probability
