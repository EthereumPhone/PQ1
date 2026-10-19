import C10Probability.SignatureFields

/-! Exact byte-signature codec: R, thirteen secrets, twelve authentication
paths, then two WOTS/count/XMSS layers. Every4008-byte string is representable;
decoding does not assert that the signature will pass cryptographic verification. -/
namespace C10Probability
noncomputable section

def wireLayerEquiv : (Fin 836 → Fin 256) ≃ WireLayer :=
  codecPairEquiv 688 148 (codecArrayEquiv 43 16 randomizerBytesEquiv)
    (codecPairEquiv 4 144 counter4BytesEquiv (codecArrayEquiv 9 16 randomizerBytesEquiv))

def wireSignatureEquiv : (Fin 4008 → Fin 256) ≃ WireSignature :=
  codecPairEquiv 16 3992 randomizerBytesEquiv
    (codecPairEquiv 208 3784 (codecArrayEquiv 13 16 randomizerBytesEquiv)
      (codecPairEquiv 2112 1672
        (codecArrayEquiv 12 176 (codecArrayEquiv 11 16 randomizerBytesEquiv))
        (codecArrayEquiv 2 836 wireLayerEquiv)))

def wireEncode (fields : WireSignature) : ByteKey := codecBytes 4008 wireSignatureEquiv fields

def wireDecode (bytes : ByteKey) : WireSignature := codecRead 4008 wireSignatureEquiv bytes 0

theorem wire_encode_length (fields : WireSignature) : (wireEncode fields).length = 4008 :=
  codec_bytes_length _ _ _

theorem wire_decode_encode (fields : WireSignature) : wireDecode (wireEncode fields) = fields := by
  simpa only [List.nil_append, List.append_nil, List.length_nil] using
    codec_read_bytes 4008 wireSignatureEquiv [] [] fields

theorem wire_encode_decode (bytes : ByteKey) (width : bytes.length = 4008) :
    wireEncode (wireDecode bytes) = bytes := by
  rw [wireEncode, wireDecode, codec_bytes_read,
    codec_slice_eq_take _ _ _ (by omega)]
  simp [← width]

theorem wire_layer_layout (fields : WireLayer) :
    codecBytes 836 wireLayerEquiv fields =
      (List.ofFn (fun i => nodeValueBytes (fields.1 i))).flatten ++
        beBytes 4 fields.2.1.val ++
          (List.ofFn (fun i => nodeValueBytes (fields.2.2 i))).flatten := by
  simp only [wireLayerEquiv, codec_pair_bytes 688 148, codec_pair_bytes 4 144,
    codec_array_bytes 43 16, codec_array_bytes 9 16,
    codec_counter_bytes, codec_node_bytes, List.append_assoc]

theorem wire_signature_layout (fields : WireSignature) :
    wireEncode fields = nodeValueBytes fields.1 ++
      (List.ofFn (fun i => nodeValueBytes (fields.2.1 i))).flatten ++
        (List.ofFn (fun t =>
          (List.ofFn (fun h => nodeValueBytes (fields.2.2.1 t h))).flatten)).flatten ++
            (List.ofFn (fun l => codecBytes 836 wireLayerEquiv (fields.2.2.2 l))).flatten := by
  simp only [wireEncode, wireSignatureEquiv, codec_pair_bytes 16 3992,
    codec_pair_bytes 208 3784, codec_pair_bytes 2112 1672, codec_array_bytes 13 16,
    codec_array_bytes 12 176, codec_array_bytes 11 16, codec_array_bytes 2 836,
    codec_node_bytes, List.append_assoc]

local instance (sig : C10Signature) : Decidable (C10SignatureWellFormed sig) := by
  unfold C10SignatureWellFormed LayerSignatureWellFormed
  infer_instance

def c10EncodeSignature (sig : C10Signature) : Option ByteKey :=
  if shape : C10SignatureWellFormed sig then
    some (wireEncode (wireSignatureFromStructured sig shape))
  else none

def c10DecodeSignature (bytes : ByteKey) : Option C10Signature :=
  if bytes.length = 4008 then some (wireSignatureToStructured (wireDecode bytes)) else none

theorem c10_encode_signature_wellformed (sig : C10Signature)
    (shape : C10SignatureWellFormed sig) :
    c10EncodeSignature sig = some (wireEncode (wireSignatureFromStructured sig shape)) := by
  rw [c10EncodeSignature, dif_pos shape]

theorem c10_encode_signature_malformed (sig : C10Signature)
    (shape : ¬ C10SignatureWellFormed sig) : c10EncodeSignature sig = none := by
  rw [c10EncodeSignature, dif_neg shape]

theorem c10_decode_signature_bad_length (bytes : ByteKey) (width : bytes.length ≠ 4008) :
    c10DecodeSignature bytes = none := by
  rw [c10DecodeSignature, if_neg width]

theorem c10_signature_decode_encode (sig : C10Signature)
    (shape : C10SignatureWellFormed sig) :
    (c10EncodeSignature sig).bind c10DecodeSignature = some sig := by
  rw [c10_encode_signature_wellformed sig shape]
  simp only [Option.bind_some, c10DecodeSignature, wire_encode_length, ↓reduceIte,
    wire_decode_encode, wire_signature_structured_roundtrip]

theorem c10_signature_encode_decode (bytes : ByteKey) (width : bytes.length = 4008) :
    (c10DecodeSignature bytes).bind c10EncodeSignature = some bytes := by
  rw [c10DecodeSignature, if_pos width, Option.bind_some,
    c10_encode_signature_wellformed _ (wire_signature_shape _),
    wire_signature_fields_roundtrip, wire_encode_decode bytes width]

theorem c10_decoded_signature_shape (bytes : ByteKey) (sig : C10Signature)
    (decoded : c10DecodeSignature bytes = some sig) : C10SignatureWellFormed sig := by
  unfold c10DecodeSignature at decoded
  split at decoded
  · cases decoded
    exact wire_signature_shape _
  · cases decoded

theorem c10_decoded_signature_width (bytes : ByteKey) (sig : C10Signature)
    (decoded : c10DecodeSignature bytes = some sig) : bytes.length = 4008 := by
  unfold c10DecodeSignature at decoded
  split at decoded
  · assumption
  · cases decoded

theorem c10_encoded_signature_width (sig : C10Signature) (bytes : ByteKey)
    (encoded : c10EncodeSignature sig = some bytes) : bytes.length = 4008 := by
  unfold c10EncodeSignature at encoded
  split at encoded
  · exact (congrArg List.length (Option.some.inj encoded)).symm.trans (wire_encode_length _)
  · cases encoded

end
end C10Probability
