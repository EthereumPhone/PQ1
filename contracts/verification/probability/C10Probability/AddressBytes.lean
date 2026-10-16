import C10Probability.NodeDomain

/-! Manual byte transcription of C10's big-endian address fields. Natural
arguments are truncated to the field width, as in the byte encoding. Matching
Rust uses its u32/u64 argument domains; no extraction theorem is asserted. -/
namespace C10Probability
noncomputable section

def beBytes (width value : ℕ) : ByteKey :=
  List.ofFn fun i : Fin width =>
    (⟨value / 256 ^ (width - 1 - i.val) % 256, Nat.mod_lt _ (by decide)⟩ : Fin 256)

theorem be_bytes_length (width value : ℕ) : (beBytes width value).length = width := by
  simp [beBytes]

theorem be_bytes_zero (width : ℕ) : beBytes width 0 = List.replicate width 0 := by
  simp [beBytes]

theorem be_bytes_get (width value : ℕ) (i : Fin width) :
    ((beBytes width value).get ⟨i.val, by simp [be_bytes_length]⟩).val =
      value / 256 ^ (width - 1 - i.val) % 256 := by
  simp [beBytes]

theorem be_bytes_counter (nonce : Counter) :
    beBytes 32 nonce.val = List.ofFn (counterBytes nonce) := by
  apply congrArg List.ofFn
  funext i
  apply Fin.ext
  exact (counter_byte_value nonce i).symm

def c10Address (layer tree kind kp index position hashAddress : ℕ) : ByteKey :=
  beBytes 4 layer ++ beBytes 8 tree ++ beBytes 4 kind ++ beBytes 4 kp ++
    beBytes 4 index ++ beBytes 4 position ++ beBytes 4 hashAddress

theorem c10_address_length (layer tree kind kp index position hashAddress : ℕ) :
    (c10Address layer tree kind kp index position hashAddress).length = 32 := by
  simp [c10Address, be_bytes_length]

theorem c10_address_kind (layer tree kind kp index position hashAddress : ℕ) :
    ((c10Address layer tree kind kp index position hashAddress).drop 12).take 4 =
      beBytes 4 kind := by
  simp [c10Address, List.append_assoc, List.drop_append, be_bytes_length,
    List.take_append]

theorem c10_address_count_kind (layer tree kp : ℕ) :
    ((c10Address layer tree 0 kp 0 0 0).drop 12).take 4 = List.replicate 4 0 := by
  rw [c10_address_kind, be_bytes_zero]

end
end C10Probability
