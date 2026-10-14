/- Paired forest/layer label bytes used by the actual signer factorizations.
   Equality concerns input construction, not hash security or physical leakage. -/
import Extracted.C10HashInputBridge

open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open C10Representation C10HashInputBridge

def pairedForestLabel : Std.Array Std.U8 4#usize :=
  ⟨bytesOfInts shuffle_forest_label, by rfl⟩

def pairedLayerLabel (layer : Std.U32) : Std.Array Std.U8 7#usize :=
  ⟨bytesOfInts (shuffle_layer_label (Int.ofNat layer.val)), by
    unfold shuffle_layer_label
    split <;> rfl⟩

theorem actual_forest_label :
    (Array.make 4#usize [102#u8,111#u8,114#u8,115#u8] : Std.Array Std.U8 4#usize) =
      pairedForestLabel := by rfl

theorem actual_layer_label (layer : Std.U32) :
    (match layer with
      | 0#uscalar => .ok (Array.make 7#usize
          [119#u8,111#u8,116#u8,115#u8,45#u8,48#u8,0#u8] : Std.Array Std.U8 7#usize)
      | _ => .ok (Array.make 7#usize
          [119#u8,111#u8,116#u8,115#u8,45#u8,49#u8,0#u8] : Std.Array Std.U8 7#usize)) =
      Result.ok (pairedLayerLabel layer) := by
  split
  · rfl
  · rename_i value h
    have hv : Int.ofNat layer.val ≠ 0 := by
      intro hv
      apply h
      apply UScalar.eq_of_val_eq
      change layer.val = 0
      exact Int.ofNat.inj hv
    simp only [pairedLayerLabel, shuffle_layer_label, if_neg hv]
    rfl

end Extracted.Equiv
