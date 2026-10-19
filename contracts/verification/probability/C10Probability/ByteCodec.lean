import C10Probability.LayerInputs

/-! Fixed-width byte encodings. Reads are total on arbitrary lists; later
signature admission checks the complete length before these reads are used.
No hash or probability assumption occurs in the codec. -/
namespace C10Probability
noncomputable section

def codecSlice (width : ℕ) (bytes : ByteKey) (offset : ℕ) : ByteKey :=
  List.ofFn (fun i : Fin width => bytes[offset + i.val]!)

theorem codec_slice_length (width : ℕ) (bytes : ByteKey) (offset : ℕ) :
    (codecSlice width bytes offset).length = width := by
  simp only [codecSlice, List.length_ofFn]

theorem codec_slice_eq_take (width : ℕ) (bytes : ByteKey) (offset : ℕ)
    (fits : offset + width ≤ bytes.length) :
    codecSlice width bytes offset = (bytes.drop offset).take width := by
  apply List.ext_getElem
  · simp only [codecSlice, List.length_ofFn, List.length_take, List.length_drop]
    omega
  intro i hi hj
  simp only [codecSlice, List.getElem_ofFn, List.getElem_take, List.getElem_drop]
  rw [getElem!_pos bytes (offset + i) (by simp only [codecSlice, List.length_ofFn] at hi; omega)]

theorem codec_slice_append (width : ℕ) (before body suffix : ByteKey)
    (length : body.length = width) :
    codecSlice width (before ++ body ++ suffix) before.length = body := by
  rw [codec_slice_eq_take width _ _ (by simp only [List.length_append]; omega)]
  simp [List.append_assoc, ← length]

def codecBytes {α : Type*} (width : ℕ) (encoding : (Fin width → Fin 256) ≃ α)
    (value : α) : ByteKey := List.ofFn (encoding.symm value)

def codecRead {α : Type*} (width : ℕ) (encoding : (Fin width → Fin 256) ≃ α)
    (bytes : ByteKey) (offset : ℕ) : α :=
  encoding (fun i => bytes[offset + i.val]!)

theorem codec_bytes_length {α : Type*} (width : ℕ)
    (encoding : (Fin width → Fin 256) ≃ α) (value : α) :
    (codecBytes width encoding value).length = width := by
  simp only [codecBytes, List.length_ofFn]

theorem codec_bytes_read {α : Type*} (width : ℕ)
    (encoding : (Fin width → Fin 256) ≃ α) (bytes : ByteKey) (offset : ℕ) :
    codecBytes width encoding (codecRead width encoding bytes offset) =
      codecSlice width bytes offset := by
  simp only [codecBytes, codecRead, Equiv.symm_apply_apply, codecSlice]

theorem codec_read_bytes {α : Type*} (width : ℕ)
    (encoding : (Fin width → Fin 256) ≃ α) (before suffix : ByteKey) (value : α) :
    codecRead width encoding (before ++ codecBytes width encoding value ++ suffix)
      before.length = value := by
  apply encoding.symm.injective
  apply List.ofFn_injective
  change codecBytes width encoding (codecRead width encoding _ _) = codecBytes width encoding value
  rw [codec_bytes_read, codec_slice_append _ _ _ _ (codec_bytes_length _ _ _)]

def reverseCounterBytes : (Fin 4 → Fin 256) ≃ (Fin 4 → Fin 256) where
  toFun bytes i := bytes i.rev
  invFun bytes i := bytes i.rev
  left_inv bytes := by funext i; simp
  right_inv bytes := by funext i; simp

def counter4BytesEquiv : (Fin 4 → Fin 256) ≃ Counter :=
  reverseCounterBytes.trans (finFunctionFinEquiv.trans (finCongr (by norm_num)))

theorem counter4_byte_value (value : Counter) (i : Fin 4) :
    (counter4BytesEquiv.symm value i).val = value.val / 256 ^ (3 - i.val) % 256 := by
  change value.val / 256 ^ i.rev.val % 256 = _
  simp only [Fin.val_rev]
  congr 3
  omega

theorem codec_counter_bytes (value : Counter) :
    codecBytes 4 counter4BytesEquiv value = beBytes 4 value.val := by
  unfold codecBytes beBytes
  apply congrArg List.ofFn
  funext i
  apply Fin.ext
  exact counter4_byte_value value i

def codecNode (bytes : ByteKey) (offset : ℕ) : Randomizer :=
  codecRead 16 randomizerBytesEquiv bytes offset

theorem codec_node_bytes (value : Randomizer) :
    codecBytes 16 randomizerBytesEquiv value = nodeValueBytes value := rfl

theorem codec_node_roundtrip (before suffix : ByteKey) (value : Randomizer) :
    codecNode (before ++ nodeValueBytes value ++ suffix) before.length = value := by
  exact codec_read_bytes 16 randomizerBytesEquiv before suffix value

theorem codec_node_slice (bytes : ByteKey) (offset : ℕ) :
    nodeValueBytes (codecNode bytes offset) = codecSlice 16 bytes offset := by
  simp only [nodeValueBytes, codecNode, codecRead, Equiv.symm_apply_apply, codecSlice]

def codecCounter (bytes : ByteKey) (offset : ℕ) : Counter :=
  codecRead 4 counter4BytesEquiv bytes offset

theorem codec_counter_roundtrip (before suffix : ByteKey) (value : Counter) :
    codecCounter (before ++ beBytes 4 value.val ++ suffix) before.length = value := by
  rw [← codec_counter_bytes]
  exact codec_read_bytes 4 counter4BytesEquiv before suffix value

theorem codec_counter_slice (bytes : ByteKey) (offset : ℕ) :
    beBytes 4 (codecCounter bytes offset).val = codecSlice 4 bytes offset := by
  rw [← codec_counter_bytes]
  exact codec_bytes_read 4 counter4BytesEquiv bytes offset

end
end C10Probability
