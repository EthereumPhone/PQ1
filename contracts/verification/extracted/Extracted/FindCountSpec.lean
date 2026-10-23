/- Functional correctness of the actual bounded WOTS count search.
   SHA uses the existing supplied backend; lean_extract erases progress
   callbacks. No probability of success, independence, or callback behavior
   is assumed or established here. -/
import Extracted.FindCount.Funs
import Extracted.PkFromSigSpec
import Extracted.WotsSpecBridge

open Aeneas Aeneas.Std Result ControlFlow
set_option maxRecDepth 4096
set_option maxHeartbeats 8000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open sphincs_c10

noncomputable def grindSum (d : Std.Array Std.U8 32#usize) : Nat :=
  ((List.range 43).map (wotsDigit d)).sum

noncomputable def grindAccept (seed adrs message : Std.Array Std.U8 32#usize)
    (count : Std.U32) : Prop :=
  grindSum (wots_digest_pure seed adrs message count) = 205

/-- Every partial digit sum is bounded by `7` per digit. -/
theorem sum_wotsDigit_le (d : Std.Array Std.U8 32#usize) (n : Nat) :
    ((List.range n).map (wotsDigit d)).sum ≤ 7 * n := by
  calc ((List.range n).map (wotsDigit d)).sum
      ≤ ((List.range n).map (fun _ => 7)).sum := by
        apply List.sum_le_sum
        intro i _
        have := wotsDigit_lt d i
        omega
    _ = 7 * n := by
        simp [List.map_const', List.sum_replicate, smul_eq_mul, List.length_range]
        ring

theorem land_split (k a b c d : Nat) (ha : a < 2 ^ k) (hc : c < 2 ^ k) :
    (2 ^ k * b + a) &&& (2 ^ k * d + c) = 2 ^ k * (b &&& d) + (a &&& c) := by
  apply Nat.eq_of_testBit_eq; intro j
  rw [Nat.testBit_and, Nat.testBit_two_pow_mul_add _ ha, Nat.testBit_two_pow_mul_add _ hc,
    Nat.testBit_two_pow_mul_add _ (Nat.and_lt_two_pow _ hc)]
  split <;> simp [Nat.testBit_and]

theorem land_mask_step (x m : Nat) :
    x &&& (2 ^ 6 * m + 7) = x % 8 + 2 ^ 6 * ((x >>> 6) &&& m) := by
  have hx : x = 2 ^ 6 * (x >>> 6) + x % 2 ^ 6 := by
    rw [Nat.shiftRight_eq_div_pow]; exact (Nat.div_add_mod x (2 ^ 6)).symm
  conv_lhs => rw [hx]
  rw [land_split _ _ _ _ _ (Nat.mod_lt _ (by norm_num)) (by norm_num),
    show (7:Nat) = 2 ^ 3 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod,
    Nat.mod_mod_of_dvd _ (by norm_num)]
  omega

theorem land_mask (v : Nat) :
    v &&& 1864135 = v % 8 + 2 ^ 6 * ((v >>> 6) % 8 + 2 ^ 6 * ((v >>> 12) % 8 + 2 ^ 6 * ((v >>> 18) % 8))) := by
  have h1 : (1864135:Nat) = 2 ^ 6 * (2 ^ 6 * (2 ^ 6 * 7 + 7) + 7) + 7 := by norm_num
  rw [h1, land_mask_step, land_mask_step, land_mask_step, ← Nat.shiftRight_add, ← Nat.shiftRight_add,
    show (7:Nat) = 2 ^ 3 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod]

theorem fields (d0 d1 d2 d3 d4 d5 d6 d7 : Nat)
    (h0 : d0 < 8) (h1 : d1 < 8) (h2 : d2 < 8) (h3 : d3 < 8)
    (h4 : d4 < 8) (h5 : d5 < 8) (h6 : d6 < 8) (h7 : d7 < 8) :
    let s1 := d0 + 64 * (d2 + 64 * (d4 + 64 * d6)) + (d1 + 64 * (d3 + 64 * (d5 + 64 * d7)))
    let s2 := s1 + s1 / 4096
    s2 % 64 + s2 / 64 % 64 = d0 + d1 + d2 + d3 + d4 + d5 + d6 + d7 := by
  intro s1 s2
  have hs1 : s1 = (d0 + d1 + 64 * (d2 + d3)) + 4096 * (d4 + d5 + 64 * (d6 + d7)) := by
    simp only [s1]; omega
  have hdiv : s1 / 4096 = d4 + d5 + 64 * (d6 + d7) := by
    rw [hs1, Nat.add_mul_div_left _ _ (by omega), Nat.div_eq_of_lt (by omega)]; omega
  have hs2 : s2 = (d0 + d1 + d4 + d5) + 64 * ((d2 + d3 + d6 + d7) + 64 * (d4 + d5 + 64 * (d6 + d7))) := by
    simp only [s2]; rw [hdiv, hs1]; omega
  rw [hs2, Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt (by omega),
    Nat.add_mul_div_left _ _ (by omega), Nat.div_eq_of_lt (by omega), Nat.zero_add,
    Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt (by omega)]
  omega

/-- The field-parallel sum of eight 3-bit digits equals their plain sum. -/
theorem group_sum (v : Nat) :
    let s1 := (v &&& 1864135) + ((v >>> 3) &&& 1864135)
    let s2 := s1 + (s1 >>> 12)
    (s2 &&& 63) + ((s2 >>> 6) &&& 63) =
      ((List.range 8).map (fun i => (v >>> (3 * i)) % 8)).sum := by
  intro s1 s2
  simp only [List.range_succ, List.range_zero, List.map_append, List.map_cons, List.map_nil,
    List.sum_append, List.sum_cons, List.sum_nil, Nat.mul_zero, Nat.mul_one, Nat.shiftRight_zero,
    Nat.reduceMul]
  simp only [s2, s1, land_mask, ← Nat.shiftRight_add, Nat.reduceAdd]
  have hb0 : v % 8 < 8 := Nat.mod_lt _ (by omega)
  have hb1 : v >>> 3 % 8 < 8 := Nat.mod_lt _ (by omega)
  have hb2 : v >>> 6 % 8 < 8 := Nat.mod_lt _ (by omega)
  have hb3 : v >>> 9 % 8 < 8 := Nat.mod_lt _ (by omega)
  have hb4 : v >>> 12 % 8 < 8 := Nat.mod_lt _ (by omega)
  have hb5 : v >>> 15 % 8 < 8 := Nat.mod_lt _ (by omega)
  have hb6 : v >>> 18 % 8 < 8 := Nat.mod_lt _ (by omega)
  have hb7 : v >>> 21 % 8 < 8 := Nat.mod_lt _ (by omega)
  generalize v % 8 = d0 at hb0 ⊢
  generalize v >>> 3 % 8 = d1 at hb1 ⊢
  generalize v >>> 6 % 8 = d2 at hb2 ⊢
  generalize v >>> 9 % 8 = d3 at hb3 ⊢
  generalize v >>> 12 % 8 = d4 at hb4 ⊢
  generalize v >>> 15 % 8 = d5 at hb5 ⊢
  generalize v >>> 18 % 8 = d6 at hb6 ⊢
  generalize v >>> 21 % 8 = d7 at hb7 ⊢
  rw [show (63:Nat) = 2 ^ 6 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod,
    Nat.and_two_pow_sub_one_eq_mod, Nat.shiftRight_eq_div_pow, Nat.shiftRight_eq_div_pow]
  simp only [Nat.reducePow, Nat.zero_add, Nat.add_zero]
  have key := fields d0 d1 d2 d3 d4 d5 d6 d7 hb0 hb1 hb2 hb3 hb4 hb5 hb6 hb7
  simp only at key
  omega

/-- Three consecutive digest bytes, little-endian, are a 24-bit window of `digestWord`. -/
theorem group_window (d : Std.Array Std.U8 32#usize) (g : Nat) (hg : g < 5) :
    (d.val[31 - 3 * g]!).val + 2 ^ 8 * (d.val[31 - 3 * g - 1]!).val
      + 2 ^ 16 * (d.val[31 - 3 * g - 2]!).val = (digestWord d >>> (24 * g)) % 2 ^ 24 := by
  have h0 := digestWord_byte d (3 * g)
  have h1 := digestWord_byte d (3 * g + 1)
  have h2 := digestWord_byte d (3 * g + 2)
  rw [if_pos (by omega)] at h0 h1 h2
  have e1 := mod_window_step (digestWord d >>> (24 * g)) 16 8
  have e2 := mod_window_step (digestWord d >>> (24 * g)) 8 8
  rw [← Nat.shiftRight_add] at e1 e2
  rw [show 24 * g + 16 = 8 * (3 * g + 2) by ring] at e1
  rw [show 24 * g + 8 = 8 * (3 * g + 1) by ring] at e2
  rw [show 24 * g = 8 * (3 * g) by ring] at e1 e2 ⊢
  rw [show (16:Nat) + 8 = 24 from rfl] at e1
  rw [show (8:Nat) + 8 = 16 from rfl] at e2
  rw [e1, e2, show (2:Nat) ^ 8 = 256 by norm_num, h0, h1, h2,
    show 31 - (3 * g + 1) = 31 - 3 * g - 1 by omega, show 31 - (3 * g + 2) = 31 - 3 * g - 2 by omega]
  ring

/-- Digit `i` of the `g`-th 24-bit window is WOTS digit `8g+i`. -/
theorem window_digit (d : Std.Array Std.U8 32#usize) (g i : Nat) (hi : i < 8) :
    (((digestWord d >>> (24 * g)) % 2 ^ 24) >>> (3 * i)) % 8 = wotsDigit d (8 * g + i) := by
  have h := window_shift (digestWord d >>> (24 * g)) (3 * i) 3 24 (by omega)
  rw [← Nat.shiftRight_add, show (2:Nat) ^ 3 = 8 by norm_num] at h
  rw [wotsDigit, show (8 * g + i) * 3 = 24 * g + 3 * i by ring]
  exact h

set_option maxHeartbeats 8000000 in
theorem digit_sum_loop_value (d : Std.Array Std.U8 32#usize)
    (iter : core.ops.range.Range Std.Usize) (sum : Std.Usize)
    (hend : iter.«end».val = 5) (hle : iter.start.val ≤ 5)
    (hsum : sum.val = ((List.range (8 * iter.start.val)).map (wotsDigit d)).sum) :
    wots.digit_sum_loop iter d sum
      ⦃ r => r.val = ((List.range 40).map (wotsDigit d)).sum ⦄ := by
  unfold wots.digit_sum_loop
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize × Std.Usize) =>
       s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize × Std.Usize) =>
       s.1.«end».val = 5 ∧ s.1.start.val ≤ 5 ∧
       s.2.val = ((List.range (8 * s.1.start.val)).map (wotsDigit d)).sum)
  · rintro ⟨it, sm⟩ ⟨hbnd, hsle, hs⟩
    simp only at hbnd hsle hs
    unfold wots.digit_sum_loop.body
    simp only [lift]
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨g, it', heq, hg, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      rw [hs, show it.start.val = 5 from by omega]
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hgv : g.val = it.start.val := by rw [hg]
      have hg4 : g.val ≤ 4 := by omega
      have hlen : d.val.length = 32 := by have := d.property; simp_all
      have hsb : sm.val ≤ 7 * 40 := by
        rw [hs]; exact le_trans (sum_wotsDigit_le d _) (by omega)
      step*
      · rw [UScalar.val_and, UScalar.val_and]
        exact le_trans (Nat.add_le_add Nat.and_le_right Nat.and_le_right) (by scalar_tac)
      · have h1 : s1.val ≤ 2 * 1864135 := by
          rw [s1_post, UScalar.val_and, UScalar.val_and]
          exact le_trans (Nat.add_le_add Nat.and_le_right Nat.and_le_right) (by simp)
        have h2 := Nat.shiftRight_le s1.val 12
        rw [← i15_post1] at h2
        scalar_tac
      · rw [UScalar.val_and, UScalar.val_and]
        exact le_trans (Nat.add_le_add Nat.and_le_right Nat.and_le_right) (by scalar_tac)
      · have h19 : i19.val ≤ 126 := by
          rw [i19_post, UScalar.val_and, UScalar.val_and]
          exact le_trans (Nat.add_le_add Nat.and_le_right Nat.and_le_right) (by simp)
        have hc : (UScalar.cast .Usize i19).val = i19.val := by scalar_tac
        scalar_tac
      · refine ⟨by rw [hend']; exact hbnd, by rw [hstart']; omega, ?_, by rw [hend', hstart']; omega⟩
        have hc : (UScalar.cast .Usize i19).val = i19.val := by scalar_tac
        have hlo : lo.val = 31 - 3 * g.val := by rw [lo_post1, i_post]
        have hi3 : i3.val = 31 - 3 * g.val - 1 := by rw [i3_post1, hlo]
        have hi8 : i8.val = 31 - 3 * g.val - 2 := by rw [i8_post1, hlo]
        have hi1v : i1.val = (d.val[31 - 3 * g.val]!).val := by
          rw [i1_post, ← hlo, getElem!_pos d.val lo.val (by rw [hlen]; omega)]
        have hi4v : i4.val = (d.val[31 - 3 * g.val - 1]!).val := by
          rw [i4_post, ← hi3, getElem!_pos d.val i3.val (by rw [hlen]; omega)]
        have hi9v : i9.val = (d.val[31 - 3 * g.val - 2]!).val := by
          rw [i9_post, ← hi8, getElem!_pos d.val i8.val (by rw [hlen]; omega)]
        have hb1 : i1.val < 2 ^ 8 := by have := i1.hBounds; omega
        have hb4 : i4.val < 2 ^ 8 := by have := i4.hBounds; omega
        have hb9 : i9.val < 2 ^ 8 := by have := i9.hBounds; omega
        have hsize : U32.size = 2 ^ 32 := by simp [U32.size, U32.numBits]
        have hc1 : (UScalar.cast .U32 i1).val = i1.val := by scalar_tac
        have hc4 : (UScalar.cast .U32 i4).val = i4.val := by scalar_tac
        have hc9 : (UScalar.cast .U32 i9).val = i9.val := by scalar_tac
        have hi6 : i6.val = i4.val <<< 8 := by
          rw [i6_post1, hc4, Nat.mod_eq_of_lt]
          rw [Nat.shiftLeft_eq, hsize]; omega
        have hi11 : i11.val = i9.val <<< 16 := by
          rw [i11_post1, hc9, Nat.mod_eq_of_lt]
          rw [Nat.shiftLeft_eq, hsize]; omega
        have hv : (UScalar.cast .U32 i1 ||| i6 ||| i11).val = (digestWord d >>> (24 * g.val)) % 2 ^ 24 := by
          rw [UScalar.val_or, UScalar.val_or, hi6, hi11, hc1, lor_shiftLeft_add _ _ _ hb1,
            lor_shiftLeft_add _ _ _ (by omega), ← group_window d g.val (by omega), hi1v, hi4v, hi9v]
          ring
        have hM : (1864135#u32).val = 1864135 := by simp
        have h63 : (63#u32).val = 63 := by simp
        have gs := group_sum ((digestWord d >>> (24 * g.val)) % 2 ^ 24)
        simp only at gs
        have hi19 : i19.val = ((List.range 8).map
            (fun i => (((digestWord d >>> (24 * g.val)) % 2 ^ 24) >>> (3 * i)) % 8)).sum := by
          rw [i19_post, UScalar.val_and, UScalar.val_and, i17_post1, s2_post, i15_post1, s1_post,
            UScalar.val_and, UScalar.val_and, i13_post1, h63, hM, hv]
          exact gs
        have hl : (List.range 8).map
            (fun i => (((digestWord d >>> (24 * g.val)) % 2 ^ 24) >>> (3 * i)) % 8) =
            ((List.range 8).map (fun x => 8 * it.start.val + x)).map (wotsDigit d) := by
          rw [List.map_map]
          apply List.map_congr_left
          intro i hi
          simp only [List.mem_range] at hi
          simp only [Function.comp]
          rw [window_digit d g.val i hi, hgv]
        rw [sum1_post, hc, hi19, hs, hstart', show 8 * (it.start.val + 1) = 8 * it.start.val + 8 by ring,
          List.range_add, List.map_append, List.sum_append, hl]
  · exact ⟨hend, hle, hsum⟩

/-- Digits 40, 41, 42 live in bits 120..=128: all of byte 16 and bit 0 of byte 15. -/
theorem top_window (d : Std.Array Std.U8 32#usize) :
    (d.val[16]!).val + 2 ^ 8 * ((d.val[15]!).val &&& 1) = (digestWord d >>> 120) % 2 ^ 9 := by
  have h0 := digestWord_byte d 15
  have h1 := digestWord_byte d 16
  rw [if_pos (by omega)] at h0 h1
  have e := mod_window_step (digestWord d >>> 120) 8 1
  rw [← Nat.shiftRight_add] at e
  simp only [Nat.reduceMul, Nat.reduceAdd, show (31:Nat) - 15 = 16 from rfl,
    show (31:Nat) - 16 = 15 from rfl] at h0 h1 e
  rw [e, show (2:Nat) ^ 8 = 256 by norm_num, h0, show (1:Nat) = 2 ^ 1 - 1 from rfl,
    Nat.and_two_pow_sub_one_eq_mod, ← h1, Nat.mod_mod_of_dvd _ (by norm_num)]
  omega

theorem top_digit (d : Std.Array Std.U8 32#usize) (i : Nat) (hi : i < 3) :
    (((digestWord d >>> 120) % 2 ^ 9) >>> (3 * i)) % 8 = wotsDigit d (40 + i) := by
  have h := window_shift (digestWord d >>> 120) (3 * i) 3 9 (by omega)
  rw [← Nat.shiftRight_add, show (2:Nat) ^ 3 = 8 by norm_num] at h
  rw [wotsDigit, show (40 + i) * 3 = 120 + 3 * i by ring]
  exact h

set_option maxHeartbeats 8000000 in
/-- `digit_sum` computes exactly the sum the verifier's `pk_from_sig` loop computes
    over the extracted digits (`grindSum`), without materialising them. -/
theorem digit_sum_spec (d : Std.Array Std.U8 32#usize) :
    wots.digit_sum d ⦃ r => r.val = grindSum d ⦄ := by
  unfold wots.digit_sum
  simp only [lift]
  let* ⟨sum, hsum⟩ ← digit_sum_loop_value d { start := 0#usize, «end» := 5#usize } 0#usize
    rfl (by simp) (by simp)
  have hlen : d.val.length = 32 := by have := d.property; simp_all
  have hsb : sum.val ≤ 7 * 40 := by rw [hsum]; exact sum_wotsDigit_le d 40
  step*
  · rw [UScalar.val_and, UScalar.val_and]
    exact le_trans (Nat.add_le_add Nat.and_le_right Nat.and_le_right) (by scalar_tac)
  · rw [UScalar.val_and]
    have h9 : i9.val ≤ 14 := by
      rw [i9_post, UScalar.val_and, UScalar.val_and]
      exact le_trans (Nat.add_le_add Nat.and_le_right Nat.and_le_right) (by simp)
    have := @Nat.and_le_right i10.val (7#u32).val
    scalar_tac
  · have h12 : i12.val ≤ 21 := by
      rw [i12_post, UScalar.val_and, i9_post, UScalar.val_and, UScalar.val_and]
      have := @Nat.and_le_right i10.val (7#u32).val
      have := @Nat.and_le_right (UScalar.cast .U32 i ||| i5).val (7#u32).val
      have := @Nat.and_le_right i7.val (7#u32).val
      simp at *; omega
    have hc : (UScalar.cast .Usize i12).val = i12.val := by scalar_tac
    scalar_tac
  · have hc : (UScalar.cast .Usize i12).val = i12.val := by scalar_tac
    have hiv : i.val = (d.val[16]!).val := by
      rw [i_post, getElem!_pos d.val 16 (by rw [hlen]; omega)]
    have hi2v : i2.val = (d.val[15]!).val := by
      rw [i2_post, getElem!_pos d.val 15 (by rw [hlen]; omega)]
    have hb : i.val < 2 ^ 8 := by have := i.hBounds; omega
    have hsize : U32.size = 2 ^ 32 := by simp [U32.size, U32.numBits]
    have hc1 : (UScalar.cast .U32 i).val = i.val := by scalar_tac
    have hc3 : (UScalar.cast .U32 (i2 &&& 1#u8)).val = (i2 &&& 1#u8).val := by scalar_tac
    have hi5 : i5.val = (i2 &&& 1#u8).val <<< 8 := by
      rw [i5_post1, hc3, Nat.mod_eq_of_lt]
      rw [Nat.shiftLeft_eq, hsize, UScalar.val_and]
      have := @Nat.and_le_right i2.val (1#u8).val
      have h1 : (1#u8).val = 1 := by simp
      omega
    have hv : (UScalar.cast .U32 i ||| i5).val = (digestWord d >>> 120) % 2 ^ 9 := by
      rw [UScalar.val_or, hi5, hc1, lor_shiftLeft_add _ _ _ hb, ← top_window d, hiv,
        UScalar.val_and, hi2v, show (1#u8).val = 1 by simp]
      ring
    have h7 : (7#u32).val = 7 := by simp
    have hW : ((digestWord d >>> 120) % 2 ^ 9) % 8 = wotsDigit d 40 := by
      simpa using top_digit d 0 (by omega)
    have hW1 : (((digestWord d >>> 120) % 2 ^ 9) >>> 3) % 8 = wotsDigit d 41 := by
      simpa using top_digit d 1 (by omega)
    have hW2 : (((digestWord d >>> 120) % 2 ^ 9) >>> 6) % 8 = wotsDigit d 42 := by
      simpa using top_digit d 2 (by omega)
    have hmask : ∀ x : Nat, x &&& 7 = x % 8 := fun x => by
      rw [show (7:Nat) = 2 ^ 3 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod]
    have e40 : ((UScalar.cast .U32 i ||| i5) &&& 7#u32).val = wotsDigit d 40 := by
      rw [UScalar.val_and, h7, hmask, hv, hW]
    have e41 : (i7 &&& 7#u32).val = wotsDigit d 41 := by
      rw [UScalar.val_and, h7, hmask, i7_post1, hv, hW1]
    have e42 : (i10 &&& 7#u32).val = wotsDigit d 42 := by
      rw [UScalar.val_and, h7, hmask, i10_post1, hv, hW2]
    have hG : grindSum d = ((List.range 40).map (wotsDigit d)).sum
        + wotsDigit d 40 + wotsDigit d 41 + wotsDigit d 42 := by
      unfold grindSum
      rw [show (43:Nat) = 40 + 3 from rfl, List.range_add, List.map_append, List.sum_append,
        show List.range 3 = [0, 1, 2] from rfl]
      simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero,
        Nat.reduceAdd]
      omega
    rw [r_post, hc, i12_post, i9_post, e40, e41, e42, hsum, hG]
    omega

set_option maxHeartbeats 8000000 in
theorem grind_body_spec (seed adrs message : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (pct : Std.U8) (count : Std.U32)
    (hcount : count.val < 10000000) :
    wots.find_count_loop.body seed message progress pct adrs count
      ⦃ r =>
        (∃ digits, r = done (count, wots_digest_pure seed adrs message count, digits) ∧
          grindAccept seed adrs message count ∧
          ∀ j, j < 43 → (digits.val[j]!).val =
            wotsDigit (wots_digest_pure seed adrs message count) j) ∨
        (∃ next, r = cont next ∧ next.val = count.val + 1 ∧
          ¬ grindAccept seed adrs message count) ⦄ := by
  unfold wots.find_count_loop.body
  have hT : params.TARGET_SUM = 205#usize := by unfold params.TARGET_SUM; rfl
  simp only [hT]
  step
  let* ⟨d, hd⟩ ← hash.wots_digest_spec seed adrs message count
  let* ⟨sum, hsum⟩ ← digit_sum_spec d
  have heq : sum = 205#usize ↔ grindAccept seed adrs message count := by
    constructor
    · intro h
      have hv : sum.val = 205 := congrArg UScalar.val h
      rw [hsum, hd] at hv
      exact hv
    · intro h
      apply UScalar.eq_of_val_eq
      change sum.val = 205
      rw [hsum, hd]
      exact h
  split
  · rename_i h
    let* ⟨digits, hdigits⟩ ← extract_digits_spec d
    try simp only [WP.spec_ok]
    exact Or.inl ⟨digits, by rw [hd], heq.mp h, by simpa [hd, wotsDigit] using hdigits⟩
  · rename_i h
    have hreject := mt heq.mpr h
    simp only [wots.GRIND_REPORT_EVERY]
    step* <;> first | scalar_tac | skip
    all_goals
      simp only [hypertree.report, ite_self, bind_tc_ok]
      step* <;> first | scalar_tac | skip

set_option maxHeartbeats 8000000 in
theorem grind_loop_first (seed adrs message : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (pct : Std.U8) (start target : Std.U32)
    (hle : start.val ≤ target.val) (hbound : target.val < 10000000)
    (haccept : grindAccept seed adrs message target)
    (hfirst : ∀ c : Std.U32, start.val ≤ c.val → c.val < target.val →
      ¬ grindAccept seed adrs message c) :
    wots.find_count_loop seed message progress pct adrs start
      ⦃ r => r.1 = target ∧ r.2.1 = wots_digest_pure seed adrs message target ∧
        ∀ j, j < 43 → (r.2.2.val[j]!).val =
          wotsDigit (wots_digest_pure seed adrs message target) j ⦄ := by
  unfold wots.find_count_loop
  apply loop.spec_decr_nat
    (measure := fun c : Std.U32 => target.val - c.val)
    (inv := fun c : Std.U32 => start.val ≤ c.val ∧ c.val ≤ target.val)
  · intro c hc
    let* ⟨r, hr⟩ ← grind_body_spec seed adrs message progress pct c (by omega)
    rcases hr with ⟨digits, rfl, ha, hd⟩ | ⟨next, rfl, hn, hno⟩
    · have hct : c = target := by
        apply UScalar.eq_of_val_eq
        by_contra h
        exact hfirst c hc.1 (by omega) ha
      subst c
      exact ⟨rfl, rfl, hd⟩
    · have hne : c.val ≠ target.val := by
        intro h
        have he : c = target := UScalar.eq_of_val_eq h
        exact hno (he ▸ haccept)
      exact ⟨by omega, by omega, by omega⟩
  · exact ⟨by omega, hle⟩

theorem grind_loop_exhausted (seed adrs message : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (pct : Std.U8) (start : Std.U32)
    (hbound : start.val ≤ 10000000)
    (hreject : ∀ c : Std.U32, start.val ≤ c.val → c.val < 10000000 →
      ¬ grindAccept seed adrs message c) :
    wots.find_count_loop seed message progress pct adrs start = .fail .assertionFailure := by
  generalize hmeasure : 10000000 - start.val = n
  induction n using Nat.strong_induction_on generalizing start with
  | h n ih =>
    unfold wots.find_count_loop
    rw [loop.eq_1]
    by_cases hb : start.val < 10000000
    · obtain ⟨r, hr, hp⟩ := WP.spec_imp_exists
        (grind_body_spec seed adrs message progress pct start hb)
      rw [hr]
      rcases hp with ⟨digits, rfl, ha, _⟩ | ⟨next, rfl, hn, _⟩
      · exact False.elim (hreject start (by omega) hb ha)
      · exact ih (10000000 - next.val) (by omega) next (by omega)
          (fun c hc hcmax => hreject c (by omega) hcmax) rfl
    · have hfalse : ¬ start < 10000000#u32 := by scalar_tac
      simp only [wots.find_count_loop.body, massert, hfalse, if_false, bind_tc_fail]

set_option maxHeartbeats 300000 in
/-- The actual source returns the first accepted count, its complete digest,
    and all 43 digits. The premise identifies an accepted trial, not a result
    of the search. The unconditional theorem below also covers exhaustion. -/
theorem find_count_first_success (seed message : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (progress : hypertree.ProgressSink) (pct : Std.U8) (target : Std.U32)
    (hbound : target.val < 10000000)
    (haccept : grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message target)
    (hfirst : ∀ c : Std.U32, c.val < target.val →
      ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message c) :
    wots.find_count seed layer tree kp message progress pct
      ⦃ r => r.1 = target ∧
        r.2.1 = wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0) message target ∧
        ∀ j, j < 43 → (r.2.2.val[j]!).val =
          wotsDigit r.2.1 j ⦄ := by
  obtain ⟨a, ha, hv⟩ := WP.spec_imp_exists
    (make_adrs_spec layer tree 0#u32 kp 0#u32 0#u32 0#u32)
  unfold wots.find_count
  simp only [params.ADRS_WOTS, ha, bind_tc_ok]
  rw [← adrsArr_eq_of_map_val a layer tree 0 kp.val 0 0 0 hv]
  obtain ⟨r, hr, hc, hd, hi⟩ := WP.spec_imp_exists
    (grind_loop_first seed (adrsArr layer tree 0 kp.val 0 0 0) message progress pct
      0#u32 target (Nat.zero_le _) hbound haccept (fun c _ hc => hfirst c hc))
  rw [hr]
  exact ⟨hc, hd, fun j hj => by rw [hd]; exact hi j hj⟩

/-- Rust's terminal panic is reconstructed by Charon as an assertion; its
    extracted result is a failure, never divergence or a successful tuple. -/
theorem find_count_exhausted (seed message : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (progress : hypertree.ProgressSink) (pct : Std.U8)
    (hreject : ∀ c : Std.U32, c.val < 10000000 →
      ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message c) :
    wots.find_count seed layer tree kp message progress pct = .fail .assertionFailure := by
  obtain ⟨a, ha, hv⟩ := WP.spec_imp_exists
    (make_adrs_spec layer tree 0#u32 kp 0#u32 0#u32 0#u32)
  unfold wots.find_count
  simp only [params.ADRS_WOTS, ha, bind_tc_ok]
  rw [← adrsArr_eq_of_map_val a layer tree 0 kp.val 0 0 0 hv]
  exact grind_loop_exhausted seed _ message progress pct 0#u32 (by decide)
    (fun c _ hc => hreject c hc)

/-- No success assumption: every input either returns its first accepted
    trial, or fails exactly because the bounded interval contains none.
    This is functional totality, not a probability bound or a callback proof. -/
theorem find_count_total (seed message : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (progress : hypertree.ProgressSink) (pct : Std.U8) :
    (∃ c d digits,
      wots.find_count seed layer tree kp message progress pct = .ok (c, d, digits) ∧
      c.val < 10000000 ∧
      grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message c ∧
      (∀ earlier : Std.U32, earlier.val < c.val →
        ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message earlier) ∧
      d = wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0) message c ∧
      ∀ j, j < 43 → (digits.val[j]!).val = wotsDigit d j) ∨
    (wots.find_count seed layer tree kp message progress pct = .fail .assertionFailure ∧
      ∀ c : Std.U32, c.val < 10000000 →
        ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message c) := by
  classical
  by_cases h : ∃ n : Nat, ∃ c : Std.U32, c.val = n ∧ c.val < 10000000 ∧
      grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message c
  · obtain ⟨c, hc, hb, ha⟩ := Nat.find_spec h
    have hf : ∀ earlier : Std.U32, earlier.val < c.val →
        ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message earlier := by
      intro earlier he hea
      exact Nat.find_min h (by omega) ⟨earlier, rfl, by omega, hea⟩
    obtain ⟨⟨c', d, digits⟩, hr, hc', hd, hi⟩ := WP.spec_imp_exists
      (find_count_first_success seed message layer tree kp progress pct c hb ha hf)
    dsimp only at hc'
    subst c'
    exact Or.inl ⟨c, d, digits, hr, hb, ha, hf, hd, hi⟩
  · have hn : ∀ c : Std.U32, c.val < 10000000 →
        ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message c := by
      intro c hc ha
      exact h ⟨c.val, c, rfl, hc, ha⟩
    exact Or.inr ⟨find_count_exhausted seed message layer tree kp progress pct hn, hn⟩

end Extracted.Equiv
