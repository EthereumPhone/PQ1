import C10Probability.ByteSession
import C10Probability.SessionDriver

/-! Final byte-game admission rejects malformed lengths before verification.
The structured translation represents rejected bytes by a deliberately
malformed value, which also fails its existing admission guard. This is a
proof translation only, not a runtime fallback or an accepted signature. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

abbrev C10ByteForgery := ByteKey × ByteKey

def invalidByteSignature : C10Signature := ⟨0, [], [], []⟩

theorem invalid_byte_signature_shape : ¬ C10SignatureWellFormed invalidByteSignature := by
  simp [C10SignatureWellFormed, invalidByteSignature]

def byteForgeryToStructured (value : C10ByteForgery) : C10Forgery :=
  (value.1, (c10DecodeSignature value.2).getD invalidByteSignature)

theorem byte_forgery_decoded (message bytes : ByteKey) (sig : C10Signature)
    (decoded : c10DecodeSignature bytes = some sig) :
    byteForgeryToStructured (message, bytes) = (message, sig) := by
  change (message, (c10DecodeSignature bytes).getD invalidByteSignature) = _
  rw [decoded, Option.getD_some]

theorem byte_forgery_shape_iff (value : C10ByteForgery) :
    C10SignatureWellFormed (byteForgeryToStructured value).2 ↔ value.2.length = 4008 := by
  by_cases width : value.2.length = 4008
  · rw [byteForgeryToStructured, c10DecodeSignature, if_pos width, Option.getD_some]
    exact ⟨fun _ => width, fun _ => wire_signature_shape _⟩
  · rw [byteForgeryToStructured, c10DecodeSignature, if_neg width, Option.getD_none]
    exact iff_of_false invalid_byte_signature_shape width

def byteFinalAdmits (out : C10SessionResult C10ByteForgery) : Bool :=
  !out.ledger.failed && decide (out.value.1.length = 32) &&
    decide (out.value.2.length = 4008) && decide (out.value.1 ∉ out.ledger.signedMessages)

theorem byte_final_admits_iff (out : C10SessionResult C10ByteForgery) :
    byteFinalAdmits out = true ↔ out.ledger.failed = false ∧
      out.value.1.length = 32 ∧ out.value.2.length = 4008 ∧
      out.value.1 ∉ out.ledger.signedMessages := by
  simp only [byteFinalAdmits, Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq]
  tauto

theorem byte_final_admits_eq (out : C10SessionResult C10ByteForgery) :
    byteFinalAdmits out = sessionFinalAdmits (mapSessionValue byteForgeryToStructured out) := by
  apply Bool.eq_iff_iff.mpr
  rw [byte_final_admits_iff, session_final_admits_iff]
  change (out.ledger.failed = false ∧ out.value.1.length = 32 ∧
    out.value.2.length = 4008 ∧ out.value.1 ∉ out.ledger.signedMessages) ↔
    (out.ledger.failed = false ∧ out.value.1.length = 32 ∧
    C10SignatureWellFormed (byteForgeryToStructured out.value).2 ∧
      out.value.1 ∉ out.ledger.signedMessages)
  rw [byte_forgery_shape_iff]

def c10ByteFinal [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (out : C10SessionResult C10ByteForgery) (table : Memo K Digest) : PMF (Bool × Memo K Digest) :=
  if byteFinalAdmits out then
    match c10DecodeSignature out.value.2 with
    | none => PMF.pure (false, table)
    | some sig => c10Verify (encode ∘ Sum.inl) table cfg.seed cfg.root out.value.1 sig
  else PMF.pure (false, table)

theorem c10_byte_final_bad_length [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (out : C10SessionResult C10ByteForgery) (table : Memo K Digest)
    (width : out.value.2.length ≠ 4008) :
    c10ByteFinal encode cfg out table = PMF.pure (false, table) := by
  have refused : byteFinalAdmits out ≠ true := fun admitted =>
    width ((byte_final_admits_iff out).mp admitted).2.2.1
  rw [c10ByteFinal, if_neg refused]

theorem c10_byte_final_refinement [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (out : C10SessionResult C10ByteForgery) (table : Memo K Digest) :
    c10Final encode cfg (mapSessionValue byteForgeryToStructured out) table =
      c10ByteFinal encode cfg out table := by
  rw [c10Final, ← byte_final_admits_eq]
  by_cases admitted : byteFinalAdmits out = true
  · have width := ((byte_final_admits_iff out).mp admitted).2.2.1
    rw [if_pos admitted, c10ByteFinal, if_pos admitted]
    simp only [mapSessionValue, byteForgeryToStructured, c10DecodeSignature,
      width, ↓reduceIte, Option.getD_some]
  · rw [if_neg admitted, c10ByteFinal, if_neg admitted]

def c10ByteDriver [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10ByteClient C10ByteForgery fuel) (qr qs : ℕ) (table : Memo K Digest) :
    PMF (Bool × Memo K Digest) :=
  (c10ByteSession encode cfg client qr qs emptySessionLedger table).bind
    (fun out => c10ByteFinal encode cfg out.1 out.2)

theorem c10_byte_driver_refinement [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10ByteClient C10ByteForgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) :
    c10Driver encode cfg (byteClientToStructured byteForgeryToStructured client) qr qs table =
      c10ByteDriver encode cfg client qr qs table := by
  rw [c10Driver, c10_byte_session_refinement, PMF.bind_map, c10ByteDriver]
  apply pmf_bind_support_congr
  intro out _
  exact c10_byte_final_refinement encode cfg out.1 out.2

end
end C10Probability
