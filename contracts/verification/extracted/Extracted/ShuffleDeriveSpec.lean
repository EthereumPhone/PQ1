/- Actual seed derivation, with a supplied software SHA backend. -/
import Extracted.ShuffleDerive.Funs

open Aeneas Aeneas.Std Result
open sphincs_c10
namespace Extracted.Equiv
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

private theorem all_zip_eq (xs ys : List Std.U8) (hlen : xs.length = ys.length) :
    (xs.zip ys).all (fun p => decide (p.1 = p.2)) = decide (xs = ys) := by
  induction xs generalizing ys with
  | nil => cases ys <;> simp_all
  | cons x xs ih =>
    cases ys with
    | nil => simp_all
    | cons y ys => simp [ih ys (by simpa using hlen)]

theorem shuffle_seed_compare (a b : Std.Array Std.U8 32#usize) :
    core.array.equality.PartialEqArray.eq core.cmp.PartialEqU8 a b =
      .ok (decide (a.val = b.val)) := by
  unfold core.array.equality.PartialEqArray.eq
  simp only [Array.length, core.cmp.PartialEqU8, liftFun2,
    core.cmp.impls.PartialEqU8.eq, lift]
  rw [if_pos (by rw [a.property, b.property])]
  have hall : List.allM (fun p : Std.U8 × Std.U8 => Result.ok (decide (p.1 = p.2)))
      (a.val.zip b.val) = .ok ((a.val.zip b.val).all (fun p => decide (p.1 = p.2))) :=
    List.allM_pure
  rw [hall, all_zip_eq _ _ (by rw [a.property, b.property])]

theorem shuffle_derive_exact (seed : shuffle.ShuffleSeed) (label : Slice Std.U8) :
    shuffle.ShuffleSeed.derive seed label =
      if seed.val = List.replicate 32 0#u8 then .ok (Array.repeat 32#usize 0#u8)
      else .ok (sha256_pure
        ([115#u8,112#u8,104#u8,105#u8,110#u8,99#u8,115#u8,45#u8,99#u8,
          49#u8,48#u8,45#u8,115#u8,104#u8,117#u8,102#u8,102#u8,108#u8,
          101#u8,45#u8,118#u8,49#u8] ++ seed.val ++ label.val)) := by
  unfold shuffle.ShuffleSeed.derive
  try dsimp only
  rw [shuffle_seed_compare]
  simp only [Array.repeat, bind_tc_ok, decide_eq_true_eq]
  split <;> simp_all [lift, Array.to_slice, Array.make, shuffle.shuffle_hash_parts]

theorem shuffle_derive_total (seed : shuffle.ShuffleSeed) (label : Slice Std.U8) :
    shuffle.ShuffleSeed.derive seed label ⦃ _ => True ⦄ := by
  rw [shuffle_derive_exact]
  split <;> simp [WP.spec_ok]

end Extracted.Equiv
