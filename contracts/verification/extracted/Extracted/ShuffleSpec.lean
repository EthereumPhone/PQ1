/- Actual Fisher–Yates loops: totality and prefix permutation. The SHA block
   and discarded zeroization results use the explicit functional models. -/
import Extracted.Shuffle.Funs
open Aeneas Aeneas.Std Result
set_option maxHeartbeats 2000000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes
namespace Extracted.Equiv
open sphincs_c10

def shuffleByte (j : Nat) : Std.U8 := ⟨BitVec.ofNat 8 j⟩

theorem shuffle_init_spec (n t : Std.Usize) (buf : Std.Array Std.U8 64#usize)
    (hn : n.val ≤ 64) (ht : t.val ≤ n.val)
    (hb : ∀ j, j < 64 → buf.val[j]! = if j < t.val then shuffleByte j else 0#u8) :
    shuffle.fisher_yates_loop0 n buf t
      ⦃ r => ∀ j, j < 64 → r.val[j]! = if j < n.val then shuffleByte j else 0#u8 ⦄ := by
  unfold shuffle.fisher_yates_loop0
  apply loop.spec_decr_nat
    (measure := fun (s : Std.Array Std.U8 64#usize × Std.Usize) => n.val - s.2.val)
    (inv := fun (s : Std.Array Std.U8 64#usize × Std.Usize) => s.2.val ≤ n.val ∧
      ∀ j, j < 64 → s.1.val[j]! = if j < s.2.val then shuffleByte j else 0#u8)
  · rintro ⟨arr, k⟩ ⟨hk, ha⟩
    simp only at hk ha
    unfold shuffle.fisher_yates_loop0.body
    simp only [lift]
    split
    · rename_i hlt
      have hkv : k.val < n.val := by scalar_tac
      step* <;> first | scalar_tac | skip
      refine ⟨by omega, ?_, by omega⟩
      intro j hj
      rw [a_post, Array.set_val_eq]
      have hlen : arr.val.length = 64 := by simpa using arr.property
      by_cases he : j = k.val
      · subst j
        rw [List.set_getElem!_eq _ _ _ _ ⟨by omega, rfl⟩, if_pos (by omega)]
        apply UScalar.eq_of_val_eq
        show (UScalar.cast .U8 k).val = (shuffleByte k.val).val
        rw [UScalar.cast_val_eq]
        rfl
      · rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega), ha j hj]
        have hiff : (j < k.val) ↔ (j < t1.val) := by omega
        simp only [hiff]
    · rename_i hlt
      have hkv : k.val = n.val := by scalar_tac
      simp only [WP.spec_ok]
      simpa [hkv] using ha
  · exact ⟨ht, hb⟩

theorem shuffle_nonzero_total (seed : Std.Array Std.U8 32#usize) (z : Std.U8)
    (s : Std.Usize) (hs : s.val ≤ 32) :
    shuffle.fisher_yates_loop1 seed z s ⦃ _ => True ⦄ := by
  unfold shuffle.fisher_yates_loop1
  apply loop.spec_decr_nat
    (measure := fun (s : Std.U8 × Std.Usize) => 32 - s.2.val)
    (inv := fun (s : Std.U8 × Std.Usize) => s.2.val ≤ 32)
  · rintro ⟨v, j⟩ hj
    simp only at hj
    unfold shuffle.fisher_yates_loop1.body
    simp only [lift]
    split
    · step* <;> scalar_tac
    · simp
  · exact hs

theorem shuffle_copy_total (stream : Std.Array Std.U8 128#usize)
    (d : Std.Array Std.U8 32#usize) (w b : Std.Usize)
    (hb : b.val ≤ 32) (hw : w.val + (32 - b.val) ≤ 128) :
    shuffle.fisher_yates_loop2_loop0 stream d w b ⦃ _ => True ⦄ := by
  unfold shuffle.fisher_yates_loop2_loop0
  apply loop.spec_decr_nat
    (measure := fun (s : Std.Array Std.U8 128#usize × Std.Usize × Std.Usize) => 32 - s.2.2.val)
    (inv := fun (s : Std.Array Std.U8 128#usize × Std.Usize × Std.Usize) =>
      s.2.2.val ≤ 32 ∧ s.2.1.val + (32 - s.2.2.val) ≤ 128)
  · rintro ⟨a, w, b⟩ ⟨hb, hw⟩
    simp only at hb hw
    unfold shuffle.fisher_yates_loop2_loop0.body
    simp only [lift]
    split
    · step* <;> scalar_tac
    · simp
  · exact ⟨hb, hw⟩

theorem shuffle_stream_total (seed : Std.Array Std.U8 32#usize)
    (stream : Std.Array Std.U8 128#usize) (blk : Std.U32) (hb : blk.val ≤ 4) :
    shuffle.fisher_yates_loop2 seed stream blk ⦃ _ => True ⦄ := by
  unfold shuffle.fisher_yates_loop2
  apply loop.spec_decr_nat
    (measure := fun (s : Std.Array Std.U8 128#usize × Std.U32) => 4 - s.2.val)
    (inv := fun (s : Std.Array Std.U8 128#usize × Std.U32) => s.2.val ≤ 4)
  · rintro ⟨a, k⟩ hk
    simp only at hk
    unfold shuffle.fisher_yates_loop2.body
    simp only [lift]
    split
    · rename_i hlt
      have hkv : k.val < 4 := by scalar_tac
      simp only [shuffle.shuffle_hash_block, bind_tc_ok, lift]
      let* ⟨w, hw⟩ ← Std.Usize.mul_spec (x := UScalar.cast .Usize k)
        (y := 32#usize) (by simp [UScalar.cast_val_eq]; scalar_tac)
      let* ⟨out, _⟩ ← shuffle_copy_total a _ w 0#usize (by simp)
        (by simp only [UScalar.cast_val_eq] at hw; have := Nat.mod_le k.val (2 ^ UScalarTy.Usize.numBits); scalar_tac)
      simp only [Array.Insts.ZeroizeZeroize.zeroize, bind_tc_ok]
      step* <;> scalar_tac
    · simp
  · exact hb

/-- Permutation of the initialized prefix, with its unused tail still zero. -/
def shufflePermutation (n : Nat) (a : Std.Array Std.U8 64#usize) : Prop :=
  (a.val.take n).Perm ((List.range n).map shuffleByte) ∧
  ∀ j, n ≤ j → j < 64 → a.val[j]! = 0#u8

theorem shuffle_swap_preserves (n i j : Nat) (a : Std.Array Std.U8 64#usize)
    (hn : n ≤ 64) (hi : i < n) (hj : j < n) (hp : shufflePermutation n a) :
    shufflePermutation n
      ⟨(a.val.set i a.val[j]!).set j a.val[i]!, by simpa using a.property⟩ := by
  have hlen : a.val.length = 64 := by simpa using a.property
  constructor
  · simp only
    rw [List.take_set, List.take_set]
    have ht : (a.val.take n).length = n := by simp [List.length_take, hlen, hn]
    have pi : i < (a.val.take n).length := by omega
    have pj : j < (a.val.take n).length := by omega
    have ei : a.val[i]! = (a.val.take n)[i] := by rw [getElem!_pos a.val i (by omega), List.getElem_take]
    have ej : a.val[j]! = (a.val.take n)[j] := by rw [getElem!_pos a.val j (by omega), List.getElem_take]
    rw [ei, ej]
    exact (List.set_set_perm pi pj).trans hp.1
  · intro k hnk hk
    simp only
    rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega),
      List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega)]
    exact hp.2 k hnk hk

theorem shuffle_reduction_bounds (r : Std.U16) (b : Std.Usize)
    (hb0 : 0 < b.val) (hb : b.val ≤ 64) :
    (UScalar.cast .U32 r).val * (UScalar.cast .U32 (UScalar.cast .U16 b)).val ≤ Std.U32.max ∧
    ((UScalar.cast .U32 r).val * (UScalar.cast .U32 (UScalar.cast .U16 b)).val) >>> 16 < b.val := by
  have hr : (UScalar.cast .U32 r).val = r.val := by
    rw [UScalar.cast_val_eq]
    exact Nat.mod_eq_of_lt (by scalar_tac)
  have hbr : (UScalar.cast .U32 (UScalar.cast .U16 b)).val = b.val := by
    simp only [UScalar.cast_val_eq]
    norm_num
    rw [Nat.mod_eq_of_lt (by omega), Nat.mod_eq_of_lt (by omega)]
  rw [hr, hbr, Nat.shiftRight_eq_div_pow]
  have hm : r.val * b.val < 65536 * b.val :=
    Nat.mul_lt_mul_of_pos_right (by scalar_tac) hb0
  have hu : 65536 * b.val ≤ 65536 * 64 := Nat.mul_le_mul_left _ hb
  constructor
  · scalar_tac
  · exact Nat.div_lt_of_lt_mul (by simpa [Nat.mul_comm] using hm)

theorem shuffle_swap_loop_spec (n : Nat) (stream : Std.Array Std.U8 128#usize)
    (buf : Std.Array Std.U8 64#usize) (pos i : Std.Usize)
    (hn : n ≤ 64) (hi : i.val < n) (hpos : pos.val + 2*i.val ≤ 128)
    (hp : shufflePermutation n buf) :
    shuffle.fisher_yates_loop3 buf stream pos i ⦃ r => shufflePermutation n r ⦄ := by
  unfold shuffle.fisher_yates_loop3
  apply loop.spec_decr_nat
    (measure := fun (s : Std.Array Std.U8 64#usize × Std.Usize × Std.Usize) => s.2.2.val)
    (inv := fun (s : Std.Array Std.U8 64#usize × Std.Usize × Std.Usize) =>
      s.2.2.val < n ∧ s.2.1.val + 2*s.2.2.val ≤ 128 ∧ shufflePermutation n s.1)
  · rintro ⟨arr, p, k⟩ ⟨hk, hpk, ha⟩
    simp only at hk hpk ha
    unfold shuffle.fisher_yates_loop3.body
    simp only [lift]
    split
    · rename_i hge
      have hkv : 1 ≤ k.val := by scalar_tac
      step* <;> first | scalar_tac | skip
      all_goals have hred := shuffle_reduction_bounds (i5 ||| UScalar.cast .U16 i2) i1 (by omega) (by omega)
      case hmax => exact hred.1
      all_goals
        have hjv : (UScalar.cast .Usize i9).val < n := by
          rw [← i8_post, ← i9_post1] at hred
          have := Nat.mod_le i9.val (2 ^ UScalarTy.Usize.numBits)
          rw [UScalar.cast_val_eq]
          omega
      · scalar_tac
      · scalar_tac
      refine ⟨by omega, by omega, ?_, by omega⟩
      rw [a_post, buf1_post]
      have hlen : arr.val.length = 64 := by simpa using arr.property
      have hei : tmp = arr.val[k.val]! := by rw [tmp_post, getElem!_pos arr.val k.val (by omega)]
      have hej : i10 = arr.val[(UScalar.cast .Usize i9).val]! := by
        rw [i10_post, getElem!_pos arr.val (UScalar.cast .Usize i9).val (by omega)]
      rw [hei, hej]
      exact shuffle_swap_preserves n k.val (UScalar.cast .Usize i9).val arr hn hk hjv ha
    · simp only [WP.spec_ok]
      exact ha
  · exact ⟨hi, hpos, hp⟩
theorem shuffle_initialized_permutation (n : Nat) (a : Std.Array Std.U8 64#usize)
    (hn : n ≤ 64)
    (ha : ∀ j, j < 64 → a.val[j]! = if j < n then shuffleByte j else 0#u8) :
    shufflePermutation n a := by
  have hlen : a.val.length = 64 := by simpa using a.property
  constructor
  · have he : a.val.take n = (List.range n).map shuffleByte := by
      apply List.ext_getElem
      · simp [List.length_take, hlen, hn]
      intro j hj hj'
      have hjn : j < n := by simpa using hj'
      rw [List.getElem_take, ← getElem!_pos a.val j (by omega), ha j (by omega), if_pos hjn]
      simp
    rw [he]
  · intro j hj hj64
    rw [ha j hj64, if_neg (by omega)]

/-- Every valid length and every seed terminates and returns each prefix index
    exactly once. No distribution, freshness, timing or physical-erasure claim. -/
@[step] theorem shuffle_permutation_spec (seed : Std.Array Std.U8 32#usize)
    (n : Std.Usize) (hn : n.val ≤ 64) :
    shuffle.fisher_yates seed n ⦃ r => shufflePermutation n.val r ⦄ := by
  unfold shuffle.fisher_yates
  simp only [massert, if_pos (show n ≤ 64#usize from by scalar_tac), bind_tc_ok]
  let* ⟨initial, hi⟩ ← shuffle_init_spec n 0#usize (Array.repeat 64#usize 0#u8)
    hn (by simp) (by
      intro j hj
      change (List.replicate 64 0#u8)[j]! = if j < 0 then shuffleByte j else 0#u8
      rw [List.getElem!_replicate]
      simp only [Nat.not_lt_zero, if_false]
      exact hj)
  have hp := shuffle_initialized_permutation n.val initial hn hi
  let* ⟨nonzero, _⟩ ← shuffle_nonzero_total seed 0#u8 0#usize (by simp)
  split
  · exact hp
  split
  · exact hp
  · rename_i hn1
    have hn2 : 1 < n.val := by scalar_tac
    let* ⟨stream, _⟩ ← shuffle_stream_total seed (Array.repeat 128#usize 0#u8) 0#u32 (by simp)
    let* ⟨i, hi, _⟩ ← Std.Usize.sub_spec (x := n) (y := 1#usize) (by scalar_tac)
    let* ⟨out, ho⟩ ← shuffle_swap_loop_spec n.val stream initial 0#usize i hn
      (by omega) (by scalar_tac) hp
    simp only [Array.Insts.ZeroizeZeroize.zeroize, bind_tc_ok, WP.spec_ok]
    exact ho
end Extracted.Equiv
