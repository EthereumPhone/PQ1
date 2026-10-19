import C10Probability.SignatureLayout

/-! Concrete layout consumers retain full counters and the final bytes of
each region. Roundtrip checks also cover arbitrary byte strings, not only
signatures produced by the signing model. -/
namespace C10Probability
noncomputable section

def wireCodecExample : WireSignature :=
  (17, fun i => ⟨100 + i.val, lt_trans (show 100 + i.val < 4096 by omega) (by decide)⟩,
    fun t h => ⟨1000 + 11 * t.val + h.val,
      lt_trans (show 1000 + 11 * t.val + h.val < 4096 by omega) (by decide)⟩,
    fun l => (fun i => ⟨200 + 43 * l.val + i.val,
      lt_trans (show 200 + 43 * l.val + i.val < 4096 by omega) (by decide)⟩,
      if l.val = 0 then ⟨16909060, by decide⟩ else ⟨4275878552, by decide⟩,
      fun h => ⟨2000 + 9 * l.val + h.val,
        lt_trans (show 2000 + 9 * l.val + h.val < 4096 by omega) (by decide)⟩))

theorem codec_example_first_counter :
    codecSlice 4 (wireEncode wireCodecExample) 3024 = [1, 2, 3, 4] := by
  have field := wire_decode_wots_count (wireEncode wireCodecExample) 0
  rw [wire_decode_encode] at field
  change (wireCodecExample.2.2.2 0).2.1 = codecCounter (wireEncode wireCodecExample) 3024 at field
  rw [← codec_counter_slice, ← field]
  decide

theorem codec_example_second_counter :
    codecSlice 4 (wireEncode wireCodecExample) 3860 = [254, 220, 186, 152] := by
  have field := wire_decode_wots_count (wireEncode wireCodecExample) 1
  rw [wire_decode_encode] at field
  change (wireCodecExample.2.2.2 1).2.1 = codecCounter (wireEncode wireCodecExample) 3860 at field
  rw [← codec_counter_slice, ← field]
  decide

theorem codec_example_last_secret :
    codecSlice 16 (wireEncode wireCodecExample) 208 = nodeValueBytes 112 := by
  have field := wire_decode_secret (wireEncode wireCodecExample) 12
  rw [wire_decode_encode] at field
  change wireCodecExample.2.1 12 = codecNode (wireEncode wireCodecExample) 208 at field
  rw [← codec_node_slice, ← field]
  rfl

theorem codec_example_last_fors_auth :
    codecSlice 16 (wireEncode wireCodecExample) 2320 = nodeValueBytes 1131 := by
  have field := wire_decode_fors_auth (wireEncode wireCodecExample) 11 10
  rw [wire_decode_encode] at field
  change wireCodecExample.2.2.1 11 10 = codecNode (wireEncode wireCodecExample) 2320 at field
  rw [← codec_node_slice, ← field]
  rfl

theorem codec_example_last_signature_node :
    codecSlice 16 (wireEncode wireCodecExample) 3992 = nodeValueBytes 2017 := by
  have field := wire_decode_xmss_auth (wireEncode wireCodecExample) 1 8
  rw [wire_decode_encode] at field
  change (wireCodecExample.2.2.2 1).2.2 8 = codecNode (wireEncode wireCodecExample) 3992 at field
  rw [← codec_node_slice, ← field]
  rfl

theorem codec_example_short_refuses :
    c10DecodeSignature (List.replicate 4007 0) = none := by
  have width : (List.replicate 4007 (0 : Fin 256)).length = 4007 := List.length_replicate
  exact c10_decode_signature_bad_length _ (by omega)

theorem codec_example_long_refuses :
    c10DecodeSignature (List.replicate 4009 255) = none := by
  have width : (List.replicate 4009 (255 : Fin 256)).length = 4009 := List.length_replicate
  exact c10_decode_signature_bad_length _ (by omega)

theorem codec_example_all_ff_roundtrip :
    (c10DecodeSignature (List.replicate 4008 255)).bind c10EncodeSignature =
      some (List.replicate 4008 255) := by
  exact c10_signature_encode_decode _ List.length_replicate

theorem codec_example_max_counter :
    codecCounter [255, 255, 255, 255] 0 = ⟨4294967295, by decide⟩ := by
  have roundtrip := codec_counter_roundtrip [] [] ⟨4294967295, by decide⟩
  convert roundtrip using 1

theorem codec_node_offset_example : codecNode [0, 1] 1 = 2 ^ 120 := by
  decide +kernel

end
end C10Probability
