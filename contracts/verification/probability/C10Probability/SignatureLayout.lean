import C10Probability.SignatureCodec

/-! Positional read equations for the exact wire layout. The offsets are
independent public constants: notably3024/3860 for the full u32 counters. -/
namespace C10Probability
noncomputable section

theorem wire_layer_read_sigma (bytes : ByteKey) (offset : ℕ) (i : Fin 43) :
    (codecRead 836 wireLayerEquiv bytes offset).1 i = codecNode bytes (offset + 16 * i.val) := by
  rw [wireLayerEquiv, codec_pair_read 688 148, codec_array_read 43 16]
  rfl

theorem wire_layer_read_count (bytes : ByteKey) (offset : ℕ) :
    (codecRead 836 wireLayerEquiv bytes offset).2.1 = codecCounter bytes (offset + 688) := by
  rw [wireLayerEquiv, codec_pair_read 688 148, codec_pair_read 4 144]
  rfl

theorem wire_layer_read_auth (bytes : ByteKey) (offset : ℕ) (i : Fin 9) :
    (codecRead 836 wireLayerEquiv bytes offset).2.2 i = codecNode bytes (offset + 692 + 16 * i.val) := by
  rw [wireLayerEquiv, codec_pair_read 688 148, codec_pair_read 4 144, codec_array_read 9 16]
  change codecNode bytes (offset + 688 + 4 + 16 * i.val) = _
  congr 1

theorem wire_decode_randomizer (bytes : ByteKey) :
    (wireDecode bytes).1 = codecNode bytes 0 := by
  rw [wireDecode, wireSignatureEquiv, codec_pair_read 16 3992]
  rfl

theorem wire_decode_secret (bytes : ByteKey) (i : Fin 13) :
    (wireDecode bytes).2.1 i = codecNode bytes (16 + 16 * i.val) := by
  rw [wireDecode, wireSignatureEquiv, codec_pair_read 16 3992, codec_pair_read 208 3784,
    codec_array_read 13 16]
  rfl

theorem wire_decode_fors_auth (bytes : ByteKey) (t : Fin 12) (h : Fin 11) :
    (wireDecode bytes).2.2.1 t h = codecNode bytes (224 + 176 * t.val + 16 * h.val) := by
  rw [wireDecode, wireSignatureEquiv, codec_pair_read 16 3992, codec_pair_read 208 3784,
    codec_pair_read 2112 1672, codec_array_read 12 176]
  change codecRead 176 (codecArrayEquiv 11 16 randomizerBytesEquiv) bytes
    (224 + 176 * t.val) h = _
  rw [codec_array_read 11 16]
  rfl

theorem wire_decode_layer (bytes : ByteKey) (l : Fin 2) :
    (wireDecode bytes).2.2.2 l = codecRead 836 wireLayerEquiv bytes (2336 + 836 * l.val) := by
  rw [wireDecode, wireSignatureEquiv, codec_pair_read 16 3992, codec_pair_read 208 3784,
    codec_pair_read 2112 1672, codec_array_read 2 836]

theorem wire_decode_wots_node (bytes : ByteKey) (l : Fin 2) (i : Fin 43) :
    ((wireDecode bytes).2.2.2 l).1 i = codecNode bytes (2336 + 836 * l.val + 16 * i.val) := by
  rw [wire_decode_layer, wire_layer_read_sigma]

theorem wire_decode_wots_count (bytes : ByteKey) (l : Fin 2) :
    ((wireDecode bytes).2.2.2 l).2.1 = codecCounter bytes (3024 + 836 * l.val) := by
  rw [wire_decode_layer, wire_layer_read_count]
  congr 1
  omega

theorem wire_decode_xmss_auth (bytes : ByteKey) (l : Fin 2) (i : Fin 9) :
    ((wireDecode bytes).2.2.2 l).2.2 i = codecNode bytes (3028 + 836 * l.val + 16 * i.val) := by
  rw [wire_decode_layer, wire_layer_read_auth]
  congr 1
  omega

end
end C10Probability
