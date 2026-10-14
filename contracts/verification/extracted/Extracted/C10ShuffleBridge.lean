/- Exact shuffle endpoints and extracted control flow. The supplied SHA block
   and seed-derivation models remain backend boundaries; the paired expression
   generator and its cross-tool interpretation are not a cross-kernel exporter. -/
import Extracted.C10Representation
import Extracted.C10HashInputBridge
import Extracted.ShuffleOrder
import Extracted.SignForest.FunsExternal

open Aeneas Aeneas.Std Result
open sphincs_c10
namespace Extracted.C10ShuffleBridge
open C10Representation C10HashInputBridge Equiv
set_option maxHeartbeats 2000000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

theorem shuffle_seed_input (seed : Std.Array Std.U8 32#usize) (label : Slice Std.U8) :
    byteInts (("sphincs-c10-shuffle-v1".toUTF8.toList.map Sha256Pure.ofUInt8) ++
      seed.val ++ label.val) = shuffle_seed_preimage (byteInts seed.val) (byteInts label.val) := by
  have tag : byteInts ("sphincs-c10-shuffle-v1".toUTF8.toList.map Sha256Pure.ofUInt8) =
      [115,112,104,105,110,99,115,45,99,49,48,45,115,104,117,102,102,108,101,45,118,49] := by
    simp only [String.toUTF8_eq_toByteArray]
    rw [← String.ofList_toList (s := "sphincs-c10-shuffle-v1"), String.toByteArray_ofList]
    simp [List.utf8Encode, String.utf8EncodeChar, byteInts, Sha256Pure.ofUInt8,
      ByteArray.toList, ByteArray.toList.loop, ByteArray.get!, List.data_toByteArray]
    decide
  simp only [byteInts_append, tag, shuffle_seed_preimage]

theorem shuffle_block_input (seed : Std.Array Std.U8 32#usize) (counter : Std.U32) :
    byteInts (shuffle.blockPreimage seed counter) =
      shuffle_block_preimage (byteInts seed.val) (Int.ofNat counter.val) := by
  have tag : byteInts ("sphincs-c10-fisher-yates-v1".toUTF8.toList.map Sha256Pure.ofUInt8) =
      [115,112,104,105,110,99,115,45,99,49,48,45,102,105,115,104,101,114,45,121,97,116,101,115,45,118,49] := by
    simp only [String.toUTF8_eq_toByteArray]
    rw [← String.ofList_toList (s := "sphincs-c10-fisher-yates-v1"), String.toByteArray_ofList]
    simp [List.utf8Encode, String.utf8EncodeChar, byteInts, Sha256Pure.ofUInt8,
      ByteArray.toList, ByteArray.toList.loop, ByteArray.get!, List.data_toByteArray]
    decide
  have layout : shuffle.blockPreimage seed counter =
      ("sphincs-c10-fisher-yates-v1".toUTF8.toList.map Sha256Pure.ofUInt8) ++
        seed.val ++ u32beBytes counter.val := by
    simp [shuffle.blockPreimage, u32beBytes, Nat.shiftRight_eq_div_pow]
  rw [layout]
  simp only [byteInts_append, tag, u32_bytes_value, shuffle_block_preimage]

theorem modeled_shuffle_derive (seed : shuffle.ShuffleSeed) (label : Slice Std.U8) :
    shuffle.ShuffleSeed.derive seed label =
      if seed.val = List.replicate 32 0#u8 then .ok (Array.repeat 32#usize 0#u8)
      else .ok (sha256_pure (bytesOfInts
        (shuffle_seed_preimage (byteInts seed.val) (byteInts label.val)))) := by
  rw [← shuffle_seed_input, bytesOfInts_byteInts]
  rfl

theorem modeled_shuffle_block (seed : Std.Array Std.U8 32#usize) (counter : Std.U32) :
    shuffle.shuffle_hash_block seed counter = .ok (sha256_pure (bytesOfInts
      (shuffle_block_preimage (byteInts seed.val) (Int.ofNat counter.val)))) := by
  rw [← shuffle_block_input, bytesOfInts_byteInts]
  rfl

theorem u8_or_zero (a b : Std.U8) : (a ||| b) = 0#u8 ↔ a = 0#u8 ∧ b = 0#u8 := by
  simp only [UScalar.eq_equiv_bv_eq]
  exact BitVec.or_eq_zero_iff

theorem shuffle_nonzero_exact (seed : Std.Array Std.U8 32#usize) :
    shuffle.fisher_yates_loop1 seed 0#u8 0#usize
      ⦃ z => z = 0#u8 ↔ ∀ j, j < 32 → seed.val[j]! = 0#u8 ⦄ := by
  unfold shuffle.fisher_yates_loop1
  apply loop.spec_decr_nat
    (measure := fun (s : Std.U8 × Std.Usize) => 32 - s.2.val)
    (inv := fun (s : Std.U8 × Std.Usize) => s.2.val ≤ 32 ∧
      (s.1 = 0#u8 ↔ ∀ j, j < s.2.val → seed.val[j]! = 0#u8))
  · rintro ⟨v, k⟩ ⟨hk, hv⟩
    simp only at hk hv
    unfold shuffle.fisher_yates_loop1.body
    simp only [lift]
    split
    · rename_i hlt
      have hkv : k.val < 32 := by scalar_tac
      step*
      refine ⟨by omega, ?_, by omega⟩
      rw [u8_or_zero, hv]
      have he : i = seed.val[k.val]! := by
        rw [i_post, getElem!_pos seed.val k.val (by simpa using hkv)]
      rw [he]
      constructor
      · rintro ⟨old, current⟩ j hj
        by_cases h : j < k.val
        · exact old j h
        · have : j = k.val := by omega
          simpa [this] using current
      · intro all
        exact ⟨fun j hj => all j (by omega), all k.val (by omega)⟩
    · have he : k.val = 32 := by scalar_tac
      simp only [WP.spec_ok]
      simpa [he] using hv
  · simp

theorem shuffle_copy_exact (stream : Std.Array Std.U8 128#usize)
    (d : Std.Array Std.U8 32#usize) (w : Std.Usize) (hw : w.val + 32 ≤ 128) :
    shuffle.fisher_yates_loop2_loop0 stream d w 0#usize
      ⦃ out => ∀ j, j < 128 → out.val[j]! =
        if w.val ≤ j ∧ j < w.val + 32 then d.val[j-w.val]! else stream.val[j]! ⦄ := by
  unfold shuffle.fisher_yates_loop2_loop0
  apply loop.spec_decr_nat
    (measure := fun (s : Std.Array Std.U8 128#usize × Std.Usize × Std.Usize) => 32 - s.2.2.val)
    (inv := fun (s : Std.Array Std.U8 128#usize × Std.Usize × Std.Usize) =>
      s.2.2.val ≤ 32 ∧ s.2.1.val = w.val + s.2.2.val ∧
      ∀ j, j < 128 → s.1.val[j]! =
        if w.val ≤ j ∧ j < w.val + s.2.2.val then d.val[j-w.val]! else stream.val[j]!)
  · rintro ⟨arr, p, b⟩ ⟨hb, hp, ha⟩
    simp only at hb hp ha
    unfold shuffle.fisher_yates_loop2_loop0.body
    simp only []
    split
    · have hb32 : b.val < 32 := by scalar_tac
      have hp128 : p.val < 128 := by omega
      step*
      refine ⟨by omega, by omega, ?_, by omega⟩
      intro j hj
      rw [a_post, Array.set_val_eq]
      by_cases he : j = p.val
      · subst j
        rw [List.set_getElem!_eq _ _ _ _ ⟨by simpa using hp128, rfl⟩]
        have hd : i = d.val[b.val]! := by
          rw [i_post, getElem!_pos d.val b.val (by simpa using hb32)]
        rw [hd, if_pos (by omega)]
        congr 1
        omega
      · rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega), ha j hj]
        have hh : (w.val ≤ j ∧ j < w.val + b.val) ↔
            (w.val ≤ j ∧ j < w.val + b1.val) := by omega
        simp only [hh]
    · have he : b.val = 32 := by scalar_tac
      simp only [WP.spec_ok]
      simpa [he] using ha
  · refine ⟨by simp, by simp, ?_⟩
    intro j hj
    simp

def streamByte (seed : Std.Array Std.U8 32#usize) (j : Nat) : Std.U8 :=
  (sha256_pure (shuffle.blockPreimage seed ⟨BitVec.ofNat 32 (j / 32)⟩)).val[j % 32]!

theorem shuffle_stream_exact (seed : Std.Array Std.U8 32#usize)
    (stream : Std.Array Std.U8 128#usize) :
    shuffle.fisher_yates_loop2 seed stream 0#u32
      ⦃ out => ∀ j, j < 128 → out.val[j]! = streamByte seed j ⦄ := by
  unfold shuffle.fisher_yates_loop2
  apply loop.spec_decr_nat
    (measure := fun (s : Std.Array Std.U8 128#usize × Std.U32) => 4 - s.2.val)
    (inv := fun (s : Std.Array Std.U8 128#usize × Std.U32) => s.2.val ≤ 4 ∧
      ∀ j, j < 128 → s.1.val[j]! =
        if j < 32*s.2.val then streamByte seed j else stream.val[j]!)
  · rintro ⟨arr, k⟩ ⟨hk, ha⟩
    simp only at hk ha
    unfold shuffle.fisher_yates_loop2.body
    simp only [lift]
    split
    · have hk4 : k.val < 4 := by scalar_tac
      simp only [shuffle.shuffle_hash_block, bind_tc_ok]
      have hc : (UScalar.cast .Usize k).val = k.val := by
        rw [UScalar.cast_val_eq]
        exact Nat.mod_eq_of_lt (by scalar_tac)
      let* ⟨w, hw⟩ ← Std.Usize.mul_spec (x := UScalar.cast .Usize k)
        (y := 32#usize) (by rw [hc]; scalar_tac)
      simp only [hc] at hw
      let* ⟨out, ho⟩ ← shuffle_copy_exact arr _ w (by scalar_tac)
      simp only [Array.Insts.ZeroizeZeroize.zeroize, bind_tc_ok]
      step*
      refine ⟨by omega, ?_, by omega⟩
      intro j hj
      rw [ho j hj]
      by_cases h : w.val ≤ j ∧ j < w.val + 32
      · rw [if_pos h, if_pos (by omega)]
        have hq : j / 32 = k.val := by omega
        have hm : j % 32 = j - w.val := by omega
        have he : (⟨BitVec.ofNat 32 k.val⟩ : Std.U32) = k := by
          apply UScalar.eq_of_val_eq
          change k.val % 4294967296 = k.val
          exact Nat.mod_eq_of_lt k.hBounds
        simp only [streamByte, hq, hm, he]
      · rw [if_neg h, ha j hj]
        have hh : j < 32*k.val ↔ j < 32*blk1.val := by omega
        simp only [hh]
    · have he : k.val = 4 := by scalar_tac
      simp only [WP.spec_ok]
      intro j hj
      simpa [he, hj] using ha j hj
  · simp

def finishOrder (n : Nat) (stream : List Nat) (k : Nat) (order : List Nat) : List Nat :=
  ((List.range k).map (fun j => j + 1)).foldr
    (fun i out => shuffle_swap out i
      (shuffle_choice (stream.getD (2 * ((n - 1) - i)) 0)
        (stream.getD (2 * ((n - 1) - i) + 1) 0) (i + 1))) order

theorem finishOrder_zero (n : Nat) (stream order : List Nat) :
    finishOrder n stream 0 order = order := by simp [finishOrder]

theorem finishOrder_succ (n k : Nat) (stream order : List Nat) :
    finishOrder n stream (k + 1) order = finishOrder n stream k
      (shuffle_swap order (k + 1)
        (shuffle_choice (stream.getD (2 * ((n - 1) - (k + 1))) 0)
          (stream.getD (2 * ((n - 1) - (k + 1)) + 1) 0) (k + 2))) := by
  simp [finishOrder, List.range_succ, List.map_append, List.foldr_append, Nat.add_assoc]

theorem finishOrder_initial (n : Nat) (stream : List Nat) :
    finishOrder n stream (n - 1) (List.range n) = shuffle_order n stream := by
  simp [finishOrder, shuffle_order]

def prefixCounts (n : Nat) (a : Std.Array Std.U8 64#usize) : List Nat :=
  (a.val.take n).map (fun b => b.val)

theorem shuffle_swap_prefix (n i j : Nat) (a : Std.Array Std.U8 64#usize)
    (hn : n ≤ 64) (hi : i < n) (hj : j < n) :
    prefixCounts n ⟨(a.val.set i a.val[j]!).set j a.val[i]!, by simp⟩ =
      shuffle_swap (prefixCounts n a) i j := by
  have hlen : a.val.length = 64 := by simp
  have get (k : Nat) (hk : k < n) :
      ((a.val.take n).map (fun b => b.val)).getD k 0 = (a.val[k]!).val := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by simp; omega)]
    simp only [Option.getD_some, List.getElem_map, List.getElem_take]
    rw [getElem!_pos a.val k (by omega)]
  simp only [prefixCounts, List.take_set, List.map_set, shuffle_swap, get i hi, get j hj]

theorem little_endian_or (lo hi : Std.U8) (shifted : Std.U16)
    (h : shifted.val = hi.val * 256) :
    (shifted ||| UScalar.cast .U16 lo).val = hi.val * 256 + lo.val := by
  rw [UScalar.val_or, U8.cast_U16_val_eq, h]
  have hl : lo.val < 2^8 := lo.hBounds
  simpa [Nat.shiftLeft_eq] using (Nat.shiftLeft_add_eq_or_of_lt hl hi.val).symm

theorem shuffle_swap_loop_exact (n : Nat) (stream : Std.Array Std.U8 128#usize)
    (buf : Std.Array Std.U8 64#usize) (pos i : Std.Usize)
    (hn : n ≤ 64) (hi : i.val < n)
    (hpos : pos.val + 2*i.val = 2*(n-1)) :
    shuffle.fisher_yates_loop3 buf stream pos i
      ⦃ out => prefixCounts n out =
        finishOrder n (stream.val.map (fun b => b.val)) i.val (prefixCounts n buf) ⦄ := by
  unfold shuffle.fisher_yates_loop3
  apply loop.spec_decr_nat
    (measure := fun (s : Std.Array Std.U8 64#usize × Std.Usize × Std.Usize) => s.2.2.val)
    (inv := fun (s : Std.Array Std.U8 64#usize × Std.Usize × Std.Usize) =>
      s.2.2.val < n ∧ s.2.1.val + 2*s.2.2.val = 2*(n-1) ∧
      finishOrder n (stream.val.map (fun b => b.val)) s.2.2.val (prefixCounts n s.1) =
        finishOrder n (stream.val.map (fun b => b.val)) i.val (prefixCounts n buf))
  · rintro ⟨arr, p, k⟩ ⟨hk, hpk, ha⟩
    simp only at hk hpk ha
    unfold shuffle.fisher_yates_loop3.body
    simp only [lift]
    split
    · rename_i hge
      have hkv : 1 ≤ k.val := by scalar_tac
      have hspace : p.val + 2*k.val ≤ 128 := by omega
      step*
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
      have hlen : arr.val.length = 64 := by simp
      have hei : tmp = arr.val[k.val]! := by rw [tmp_post, getElem!_pos arr.val k.val (by omega)]
      have hej : i10 = arr.val[(UScalar.cast .Usize i9).val]! := by
        rw [i10_post, getElem!_pos arr.val (UScalar.cast .Usize i9).val (by omega)]
      rw [a_post, buf1_post, hei, hej]
      have heq :
          (arr.set k arr.val[(UScalar.cast .Usize i9).val]!).set
            (UScalar.cast .Usize i9) arr.val[k.val]! =
          (⟨(arr.val.set k.val arr.val[(UScalar.cast .Usize i9).val]!).set
            (UScalar.cast .Usize i9).val arr.val[k.val]!, by simp⟩ :
              Std.Array Std.U8 64#usize) := by
        apply Subtype.ext
        simp only [Array.set_val_eq]
      rw [heq, shuffle_swap_prefix n k.val _ arr hn hk hjv]
      have hs5 : i5.val = i4.val * 256 := by
        rw [i5_post1, U8.cast_U16_val_eq, Nat.shiftLeft_eq]
        norm_num
        exact Nat.mod_eq_of_lt (by scalar_tac)
      have hb : (UScalar.cast .U32 (UScalar.cast .U16 i1)).val = k.val + 1 := by
        simp only [UScalar.cast_val_eq]
        norm_num
        rw [Nat.mod_eq_of_lt (by omega), Nat.mod_eq_of_lt (by omega), i1_post]
      have hc : (UScalar.cast .Usize i9).val = shuffle_choice i2.val i4.val (k.val + 1) := by
        rw [U32.cast_Usize_val_eq, i9_post1, Nat.shiftRight_eq_div_pow, i8_post,
          U16.cast_U32_val_eq, little_endian_or i2 i4 i5 hs5, hb]
        rfl
      have get (j : Nat) (hj : j < 128) :
          (stream.val.map (fun b => b.val)).getD j 0 = (stream.val[j]!).val := by
        rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by simp; omega)]
        simp only [Option.getD_some, List.getElem_map]
        rw [getElem!_pos stream.val j (by simpa using hj)]
      have hlo : (stream.val.map (fun b => b.val)).getD p.val 0 = i2.val := by
        rw [get p.val (by omega), i2_post, getElem!_pos stream.val p.val (by simp; omega)]
      have hhi : (stream.val.map (fun b => b.val)).getD (p.val + 1) 0 = i4.val := by
        rw [get (p.val + 1) (by omega), i4_post, getElem!_pos stream.val (p.val + 1) (by simp; omega)]
        simp only [i3_post]
      have hp : p.val = 2*((n-1)-k.val) := by omega
      rw [hc, ← hlo, ← hhi, hp, i11_post1]
      have hrec := finishOrder_succ n (k.val - 1) (stream.val.map (fun b => b.val)) (prefixCounts n arr)
      have hk1 : k.val - 1 + 1 = k.val := by omega
      have hk2 : k.val - 1 + 2 = k.val + 1 := by omega
      simp only [hk1, hk2] at hrec
      rw [← hrec]
      exact ha
    · have hk0 : k.val = 0 := by scalar_tac
      simp only [WP.spec_ok]
      simpa [hk0, finishOrder_zero] using ha
  · exact ⟨hi, hpos, rfl⟩

theorem initialized_prefix (n : Nat) (a : Std.Array Std.U8 64#usize) (hn : n ≤ 64)
    (ha : ∀ j, j < 64 → a.val[j]! = if j < n then shuffleByte j else 0#u8) :
    prefixCounts n a = List.range n := by
  have hlen : a.val.length = 64 := by simp
  apply List.ext_getElem
  · simp [prefixCounts, List.length_take, hlen, hn]
  intro j hj hj'
  have hjn : j < n := by simpa using hj'
  simp only [prefixCounts, List.getElem_map, List.getElem_take]
  rw [← getElem!_pos a.val j (by omega), ha j (by omega), if_pos hjn,
    shuffleByte_val j (by omega), List.getElem_range]

theorem seed_zero_iff (seed : Std.Array Std.U8 32#usize) :
    seed.val = List.replicate 32 0#u8 ↔ ∀ j, j < 32 → seed.val[j]! = 0#u8 := by
  constructor
  · intro h j hj
    rw [h, List.getElem!_replicate]
    exact hj
  · intro h
    apply List.ext_getElem
    · simpa using seed.property
    intro j hj hj'
    rw [← getElem!_pos seed.val j hj, h j (by simpa using hj), List.getElem_replicate]

def streamCounts (seed : Std.Array Std.U8 32#usize) : List Nat :=
  (List.range 128).map (fun j => (streamByte seed j).val)

theorem stream_counts_exact (seed : Std.Array Std.U8 32#usize)
    (stream : Std.Array Std.U8 128#usize)
    (h : ∀ j, j < 128 → stream.val[j]! = streamByte seed j) :
    stream.val.map (fun b => b.val) = streamCounts seed := by
  apply List.ext_getElem
  · simp [streamCounts]
  intro j hj hj'
  have hj128 : j < 128 := by simpa using hj
  simp only [streamCounts, List.getElem_map, List.getElem_range]
  rw [← getElem!_pos stream.val j (by simpa using hj128), h j hj128]

def modeledOrder (seed : Std.Array Std.U8 32#usize) (n : Nat) : List Nat :=
  if seed.val = List.replicate 32 0#u8 ∨ n ≤ 1 then List.range n
  else shuffle_order n (streamCounts seed)

theorem shuffle_prefix_exact (seed : Std.Array Std.U8 32#usize) (n : Std.Usize)
    (hn : n.val ≤ 64) :
    shuffle.fisher_yates seed n ⦃ out => prefixCounts n.val out = modeledOrder seed n.val ⦄ := by
  unfold shuffle.fisher_yates
  let* ⟨initial, hi⟩ ← shuffle_init_spec n 0#usize (Array.repeat 64#usize 0#u8)
    hn (by simp) (by
      intro j hj
      change (List.replicate 64 0#u8)[j]! = if j < 0 then shuffleByte j else 0#u8
      rw [List.getElem!_replicate]
      simp only [Nat.not_lt_zero, if_false]
      exact hj)
  have hpref := initialized_prefix n.val initial hn hi
  let* ⟨nonzero, hz⟩ ← shuffle_nonzero_exact seed
  have he : nonzero = 0#u8 ↔ seed.val = List.replicate 32 0#u8 := hz.trans (seed_zero_iff seed).symm
  split
  · rename_i hzero
    simpa [modeledOrder, he.mp hzero] using hpref
  · rename_i hnz
    have hs : seed.val ≠ List.replicate 32 0#u8 := fun h => hnz (he.mpr h)
    split
    · have hn1 : n.val ≤ 1 := by scalar_tac
      simpa [modeledOrder, hn1] using hpref
    · have hn2 : 1 < n.val := by scalar_tac
      let* ⟨stream, hst⟩ ← shuffle_stream_exact seed (Array.repeat 128#usize 0#u8)
      have hstream := stream_counts_exact seed stream hst
      let* ⟨i, hi, _⟩ ← Std.Usize.sub_spec (x := n) (y := 1#usize) (by scalar_tac)
      let* ⟨out, ho⟩ ← shuffle_swap_loop_exact n.val stream initial 0#usize i hn
        (by omega) (by scalar_tac)
      simp only [Array.Insts.ZeroizeZeroize.zeroize, bind_tc_ok, WP.spec_ok]
      rw [ho, hi, hstream, hpref, finishOrder_initial]
      simp only [modeledOrder, hs, Nat.not_le.mpr hn2, or_self, if_false]

theorem shuffle_exact (seed : Std.Array Std.U8 32#usize) (n : Std.Usize)
    (hn : n.val ≤ 64) :
    shuffle.fisher_yates seed n ⦃ out =>
      prefixCounts n.val out = modeledOrder seed n.val ∧
      ∀ j, n.val ≤ j → j < 64 → out.val[j]! = 0#u8 ⦄ := by
  obtain ⟨out, ho, hp⟩ := WP.spec_imp_exists (shuffle_prefix_exact seed n hn)
  have perm := shuffle_permutation_spec seed n hn
  rw [ho, WP.spec_ok] at perm ⊢
  exact ⟨hp, perm.2⟩

end Extracted.C10ShuffleBridge
