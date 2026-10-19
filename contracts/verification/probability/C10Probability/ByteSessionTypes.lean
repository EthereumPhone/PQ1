import C10Probability.SignatureLayout
import C10Probability.SessionProgram

/-! Finite adaptive clients whose signing replies and final signatures are
byte lists. Hash replies retain the existing full256-bit Digest representation.
Attempted-call fuel remains distinct from admitted raw/signing caps. -/
namespace C10Probability
noncomputable section

inductive C10ByteClient (R : Type*) : ℕ → Type _ where
  | done {fuel : ℕ} (value : R) : C10ByteClient R fuel
  | hash {fuel : ℕ} (key : ByteKey) (next : Digest → C10ByteClient R fuel) :
      C10ByteClient R (fuel + 1)
  | sign {fuel : ℕ} (req : C10SignRequest) (next : Option ByteKey → C10ByteClient R fuel) :
      C10ByteClient R (fuel + 1)

def byteSignReply (reply : Option C10Signature) : Option ByteKey :=
  reply.bind c10EncodeSignature

def byteAfterSign (ledger : C10SessionLedger) (message : ByteKey)
    (reply : Option ByteKey) : C10SessionLedger :=
  match reply with
  | none => ⟨ledger.signedMessages, true⟩
  | some _ => ⟨ledger.signedMessages ++ [message], ledger.failed⟩

def mapSessionValue {R S : Type*} (finish : R → S) (out : C10SessionResult R) :
    C10SessionResult S := ⟨finish out.value, out.ledger, out.rawRemaining, out.signRemaining⟩

def byteClientToStructured {R S : Type*} (finish : R → S) :
    {fuel : ℕ} → C10ByteClient R fuel → C10Client S fuel
  | _, .done value => .done (finish value)
  | _, .hash key next => .hash key (fun reply => byteClientToStructured finish (next reply))
  | _, .sign req next =>
      .sign req (fun reply => byteClientToStructured finish (next (byteSignReply reply)))

theorem map_session_value_fields {R S : Type*} (finish : R → S) (out : C10SessionResult R) :
    (mapSessionValue finish out).value = finish out.value ∧
      (mapSessionValue finish out).ledger = out.ledger ∧
      (mapSessionValue finish out).rawRemaining = out.rawRemaining ∧
      (mapSessionValue finish out).signRemaining = out.signRemaining := by
  exact ⟨rfl, rfl, rfl, rfl⟩

theorem byte_sign_reply_none : byteSignReply none = none := rfl

theorem byte_sign_reply_some (sig : C10Signature) (shape : C10SignatureWellFormed sig) :
    byteSignReply (some sig) = some (wireEncode (wireSignatureFromStructured sig shape)) := by
  exact c10_encode_signature_wellformed sig shape

theorem byte_sign_reply_width (reply : Option C10Signature) (bytes : ByteKey)
    (encoded : byteSignReply reply = some bytes) : bytes.length = 4008 := by
  cases reply with
  | none => cases encoded
  | some sig => exact c10_encoded_signature_width sig bytes encoded

theorem byte_after_sign_eq (ledger : C10SessionLedger) (message : ByteKey)
    (reply : Option C10Signature)
    (shape : match reply with | none => True | some sig => C10SignatureWellFormed sig) :
    byteAfterSign ledger message (byteSignReply reply) = sessionAfterSign ledger message reply := by
  cases reply with
  | none => rfl
  | some sig =>
      rw [byte_sign_reply_some sig shape]
      rfl

theorem byte_sign_reply_roundtrip (reply : Option C10Signature)
    (shape : match reply with | none => True | some sig => C10SignatureWellFormed sig) :
    (byteSignReply reply).bind c10DecodeSignature = reply := by
  cases reply with
  | none => rfl
  | some sig => exact c10_signature_decode_encode sig shape

end
end C10Probability
