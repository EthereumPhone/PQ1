/- §33 P3 — read_bits_le FUNCTIONAL spec (verification-target catalog rank 1).

   Panic-freedom + range are proven (ForsLoop.lean). This states the exact
   VALUE: `read_bits_le digest off n` equals bits [off, off+n) of the digest
   interpreted as a 256-bit word (bit 0 = LSB of digest[31] — the same word the
   EVM loads, so the Yul `and(shr(143, digest), 0x3FFFF)` composes at rank 2).

   Decomposition (executably sanity-checked on 6 shapes incl. unaligned-57 and
   past-the-end):
     (A) ofDigits_byte   — byte p of a base-256 digit list = the p-th digit
     (B) mod_window_step — split the top byte off a mod-window
     (L) the loop-accumulator induction: val = (digestWord >>> 8q) % 2^(8·bn),
         OR→ADD at each step via Bits.lor_eq_add_disjoint (PROVEN)
     (F) the final (val >>> bit_in_byte) & mask arithmetic. -/
import Extracted.ForsLoop
import Extracted.Bits
import Mathlib.Data.Nat.Digits.Defs

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open sphincs_c10

/-- The digest as the 256-bit word the firmware and the EVM agree on:
    byte 31 is least significant. `ofDigits 256 [d31, d30, …, d0]`. -/
def digestWord (digest : Std.Array Std.U8 32#usize) : Nat :=
  Nat.ofDigits 256 ((List.range 32).map (fun i => (digest.val[31 - i]!).val))

/-! ### Reusable bit/byte arithmetic (A), (B) -/

/-- Dividing `ofDigits` by `base^(p+1)` drops the head digit and divides the
    tail by `base^p` (when the head is a real byte). -/
private theorem ofDigits_div_cons (d : Nat) (tl : List Nat) (p : Nat) (hd : d < 256) :
    Nat.ofDigits 256 (d :: tl) / 256 ^ (p + 1) = Nat.ofDigits 256 tl / 256 ^ p := by
  rw [Nat.ofDigits_cons, show (256:Nat) ^ (p + 1) = 256 * 256 ^ p by rw [pow_succ]; ring,
      ← Nat.div_div_eq_div_mul, Nat.add_comm d, Nat.mul_add_div (by norm_num),
      Nat.div_eq_of_lt hd, Nat.add_zero]

/-- (A) Byte `p` of a bounded base-256 digit list equals the `p`-th digit
    (0 past the end). `>>> (8*p)` then `% 256` is exactly digit extraction. -/
theorem ofDigits_byte (L : List Nat) (p : Nat) (hb : ∀ d ∈ L, d < 256) :
    (Nat.ofDigits 256 L >>> (8 * p)) % 256 = L.getD p 0 := by
  rw [Nat.shiftRight_eq_div_pow, show (2:Nat) ^ (8 * p) = 256 ^ p by rw [pow_mul]; norm_num]
  induction p generalizing L with
  | zero =>
    cases L with
    | nil => simp [Nat.ofDigits_nil, List.getD]
    | cons d tl =>
      simp only [pow_zero, Nat.div_one, Nat.ofDigits_cons, List.getD_cons_zero]
      rw [Nat.add_mul_mod_self_left]
      exact Nat.mod_eq_of_lt (hb d (by simp))
  | succ p ih =>
    cases L with
    | nil => simp [Nat.ofDigits_nil, List.getD]
    | cons d tl =>
      rw [ofDigits_div_cons d tl p (hb d (by simp)), ih tl (fun x hx => hb x (by simp [hx])),
          List.getD_cons_succ]

/-- (B) Peel the top byte off a `2^(8·k)`-wide mod-window. -/
theorem mod_window_step (X a c : Nat) :
    X % 2 ^ (a + c) = X % 2 ^ a + ((X >>> a) % 2 ^ c) * 2 ^ a := by
  rw [Nat.shiftRight_eq_div_pow, pow_add, Nat.mod_mul]; ring

/-- The `i`-th digit of `digestWord` is the byte `digest[31-i]` (all < 256). -/
theorem digestWord_digits_lt (digest : Std.Array Std.U8 32#usize) :
    ∀ d ∈ (List.range 32).map (fun i => (digest.val[31 - i]!).val), d < 256 := by
  intro d hd
  simp only [List.mem_map, List.mem_range] at hd
  obtain ⟨i, _, rfl⟩ := hd
  have := (digest.val[31 - i]!).hBounds
  simp only [Std.U8.size] at this ⊢; omega

theorem digestWord_getD (digest : Std.Array Std.U8 32#usize) (p : Nat) (hp : p < 32) :
    ((List.range 32).map (fun i => (digest.val[31 - i]!).val)).getD p 0
      = (digest.val[31 - p]!).val := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hp]; rfl

/-- Byte `p` of `digestWord` = `digest[31-p]` (0 past the end). Combines (A)
    `ofDigits_byte` with the digit↔index identity. -/
theorem digestWord_byte (digest : Std.Array Std.U8 32#usize) (p : Nat) :
    (digestWord digest >>> (8 * p)) % 256 = if p < 32 then (digest.val[31 - p]!).val else 0 := by
  rw [digestWord, ofDigits_byte _ _ (digestWord_digits_lt digest)]
  split
  · exact digestWord_getD digest p ‹_›
  · rw [List.getD_eq_getElem?_getD, List.getElem?_map,
        List.getElem?_eq_none (by simp only [List.length_range]; omega)]; rfl

/-! ### `wrapping_sub` value (the loop's `byte_start - b` index, platform-generic) -/

theorem usize_wsub_val (a b : Std.Usize) :
    (core.num.Usize.wrapping_sub a b).val
      = (a.val + (2 ^ System.Platform.numBits - b.val)) % 2 ^ System.Platform.numBits := by
  simp only [core.num.Usize.wrapping_sub, UScalar.wrapping_sub, UScalar.val, UScalar.bv,
             UScalarTy.Usize, BitVec.toNat_sub,
             show UScalarTy.Usize.numBits = System.Platform.numBits from rfl]
  congr 1; omega

/-- In-range index: `byte_start - b` when `b ≤ byte_start` (≤ 31). -/
theorem wsub_eq_of_le (a b : Std.Usize) (hb : b.val ≤ a.val) (ha : a.val ≤ 31) :
    (core.num.Usize.wrapping_sub a b).val = a.val - b.val := by
  rw [usize_wsub_val]
  have h32 : (32:Nat) ≤ 2 ^ System.Platform.numBits := by
    rcases System.Platform.numBits_eq with h | h <;> rw [h] <;> norm_num
  rw [show a.val + (2 ^ System.Platform.numBits - b.val)
        = 2 ^ System.Platform.numBits + (a.val - b.val) by omega,
      Nat.add_mod_left, Nat.mod_eq_of_lt (by omega)]

/-- Out-of-range: `b > byte_start` wraps to a huge value, so `¬ idx < 32`. -/
theorem not_wsub_lt32_of_gt (a b : Std.Usize) (ha : a.val ≤ 31) (hbs : b.val ≤ 8)
    (h : a.val < b.val) : ¬ (core.num.Usize.wrapping_sub a b).val < 32 := by
  rw [usize_wsub_val]
  have h32 : (2:Nat) ^ 32 ≤ 2 ^ System.Platform.numBits := by
    rcases System.Platform.numBits_eq with h | h <;> rw [h] <;> norm_num
  rw [Nat.mod_eq_of_lt (by omega)]; omega

/-! ### The loop accumulator invariant (L) -/

/-- The digest word shifted to the byte the loop starts reading. -/
def W (digest : Std.Array Std.U8 32#usize) (byte_start : Nat) : Nat :=
  digestWord digest >>> (8 * (31 - byte_start))

set_option maxHeartbeats 4000000 in
theorem read_bits_le_loop_value
    (iter : core.ops.range.Range Std.Usize) (digest : Std.Array Std.U8 32#usize)
    (byte_start : Std.Usize) (val : Std.U64) (bn : Nat)
    (hbs : byte_start.val ≤ 31) (hbn : bn ≤ 8)
    (hend : iter.«end».val = bn) (hle : iter.start.val ≤ bn)
    (hval : val.val = W digest byte_start.val % 2 ^ (8 * iter.start.val)) :
    fors.read_bits_le_loop iter digest byte_start val
      ⦃ r => r.val = W digest byte_start.val % 2 ^ (8 * bn) ⦄ := by
  unfold fors.read_bits_le_loop
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize × Std.U64) => s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize × Std.U64) =>
      s.1.«end».val = bn ∧ s.1.start.val ≤ bn ∧
      s.2.val = W digest byte_start.val % 2 ^ (8 * s.1.start.val))
  · rintro ⟨it, v⟩ ⟨hbnd, hslt, hvinv⟩
    simp only at hbnd hslt hvinv
    unfold fors.read_bits_le_loop.body
    simp only []
    let* ⟨o, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨b, it', heq, hb, hlt, hend', hstart'⟩
    · subst ho; simp only [WP.spec_ok]
      have hbeq : it.start.val = bn := by omega
      rw [← hbeq]; exact hvinv
    · simp only [Prod.mk.injEq] at heq; obtain ⟨rfl, rfl⟩ := heq
      have hsb : it.start.val < bn := by omega
      have hs7 : it.start.val ≤ 7 := by omega
      simp only [lift, hb, bind_tc_ok]
      -- common: end=bn, start+1≤bn, measure decreases
      have hwbnd : (W digest byte_start.val >>> (8 * it.start.val)) % 256
          = (digestWord digest >>> (8 * (31 - byte_start.val + it.start.val))) % 256 := by
        rw [W, ← Nat.shiftRight_add]; congr 2; omega
      -- the mod-window step at this byte
      have hstep : W digest byte_start.val % 2 ^ (8 * (it.start.val + 1))
          = W digest byte_start.val % 2 ^ (8 * it.start.val)
            + ((W digest byte_start.val >>> (8 * it.start.val)) % 256) * 2 ^ (8 * it.start.val) := by
        rw [show 8 * (it.start.val + 1) = 8 * it.start.val + 8 by ring, mod_window_step]; norm_num
      by_cases hcase : it.start.val ≤ byte_start.val
      · -- in-range: reads digest[byte_start - it.start]
        have hidx : (core.num.Usize.wrapping_sub byte_start it.start).val < 32 := by
          rw [wsub_eq_of_le _ _ hcase hbs]; omega
        have hp32 : 31 - byte_start.val + it.start.val < 32 := by omega
        rw [if_pos (by scalar_tac)]
        have hp32 : 31 - byte_start.val + it.start.val < 32 := by omega
        have hbyte : 31 - (31 - byte_start.val + it.start.val) = byte_start.val - it.start.val := by omega
        have hidxv : (core.num.Usize.wrapping_sub byte_start it.start).val = byte_start.val - it.start.val :=
          wsub_eq_of_le _ _ hcase hbs
        have hlen : digest.val.length = 32 := by have h := digest.property; simpa using h
        step*
        have hi_lt : i.val < 256 := by have := i.hBounds; simp only [Std.U8.size] at this; omega
        -- the byte read equals digit (byte_start - it.start)
        have hival : i.val = (digest.val[byte_start.val - it.start.val]!).val := by
          rw [i_post, getElem!_pos digest.val _ (by rw [hlen]; omega)]
          congr 1
          simp only [hidxv]
        refine ⟨by rw [hend']; exact hbnd, by rw [hstart']; omega, ?_, by rw [hend', hstart']; omega⟩
        rw [hstart']
        have hfrom : (core.convert.num.FromU64U8.from i).val = i.val := by scalar_tac
        have h2bd : i.val * 2 ^ (8 * it.start.val) < 2 ^ 64 :=
          calc i.val * 2 ^ (8 * it.start.val)
                ≤ 255 * 2 ^ 56 := Nat.mul_le_mul (by omega) (Nat.pow_le_pow_right (by norm_num) (by omega))
            _ < 2 ^ 64 := by norm_num
        have hi3v : i3.val = i.val * 2 ^ (8 * it.start.val) := by
          rw [i3_post1, hfrom, i2_post, Nat.shiftLeft_eq,
              show it.start.val * 8 = 8 * it.start.val by ring,
              show U64.size = 2 ^ 64 by simp [U64.size, U64.numBits], Nat.mod_eq_of_lt h2bd]
        have hvlt : v.val < 2 ^ (8 * it.start.val) := by
          rw [hvinv]; exact Nat.mod_lt _ (Nat.two_pow_pos _)
        rw [UScalar.val_or, hi3v, ← Nat.shiftLeft_eq,
            lor_eq_add_disjoint v.val i.val it.start.val hvlt hi_lt,
            hstep, hwbnd, digestWord_byte, if_pos hp32, hbyte, hvinv, hival]
      · -- out of range: byte is 0, val unchanged
        have hidx := not_wsub_lt32_of_gt byte_start it.start hbs (by omega) (by omega)
        rw [if_neg (by scalar_tac)]
        simp only [WP.spec_ok]
        refine ⟨by simp [hend', hbnd], by simp only [hstart']; omega, ?_, by simp only [hstart', hend', hbnd]; omega⟩
        simp only [hstart']
        rw [hstep, hwbnd, digestWord_byte, if_neg (by omega), Nat.zero_mul, Nat.add_zero]
        exact hvinv
  · exact ⟨hend, hle, hval⟩

/-! ### The functional spec (main goal) -/

/-- (F) A window strictly inside the kept low bits is unaffected by the outer mod. -/
theorem window_shift (X k n m : Nat) (h : n + k ≤ m) :
    ((X % 2 ^ m) >>> k) % 2 ^ n = (X >>> k) % 2 ^ n := by
  rw [Nat.shiftRight_eq_div_pow, Nat.shiftRight_eq_div_pow,
      show m = k + (m - k) by omega, pow_add, Nat.mod_mul,
      Nat.add_mul_div_left _ _ (Nat.two_pow_pos k),
      Nat.div_eq_of_lt (Nat.mod_lt _ (Nat.two_pow_pos k)), Nat.zero_add,
      Nat.mod_mod_of_dvd _ (pow_dvd_pow 2 (by omega))]

set_option maxHeartbeats 4000000 in
/-- **Functional spec**: `read_bits_le` returns exactly the `num_bits`-wide
    little-endian window at `bit_offset` of the digest word (= the EVM's
    `(digest >> bit_offset) & ((1<<num_bits)-1)`). Preconditions mirror
    `read_bits_le_terminates`. -/
theorem read_bits_le_spec (digest : Std.Array Std.U8 32#usize)
    (bit_offset num_bits : Std.Usize)
    (hpos : 0 < num_bits.val) (h : num_bits.val ≤ 57) (hoff : bit_offset.val ≤ 248) :
    fors.read_bits_le digest bit_offset num_bits
      ⦃ r => r.val = (digestWord digest >>> bit_offset.val) % 2 ^ num_bits.val ⦄ := by
  unfold fors.read_bits_le
  let* ⟨i, hi⟩ ← Std.Usize.div_spec
  let* ⟨byte_start, hbsv, hile⟩ ← Std.Usize.sub_spec
  let* ⟨bib, hbib⟩ ← Std.Usize.rem_spec
  let* ⟨i1, hi1⟩ ← Std.Usize.add_spec
  let* ⟨i2, hi2⟩ ← Std.Usize.add_spec
  let* ⟨bytes_needed, hbnv⟩ ← Std.Usize.div_spec
  have hbs31 : byte_start.val ≤ 31 := by omega
  have hbn8 : bytes_needed.val ≤ 8 := by rw [hbnv, hi2, hi1, hbib]; omega
  let* ⟨val, hvloop⟩ ← read_bits_le_loop_value
        { start := 0#usize, «end» := bytes_needed } digest byte_start 0#u64 bytes_needed.val
        hbs31 hbn8 rfl (Nat.zero_le _) (by simp [Nat.mod_one])
  have hlt64 : (2:Nat) ^ num_bits.val < 2 ^ 64 :=
    calc 2 ^ num_bits.val ≤ 2 ^ 57 := Nat.pow_le_pow_right (by norm_num) h
      _ < 2 ^ 64 := by norm_num
  step*
  · -- side goal: 1#u64 ≤ i3  (i3 = 2^num_bits ≥ 1)
    rw [i3_post1, Nat.shiftLeft_eq, Nat.one_mul,
        show U64.size = 2 ^ 64 by simp [U64.size, U64.numBits], Nat.mod_eq_of_lt hlt64]
    exact Nat.one_le_two_pow
  have hi3v : i3.val = 2 ^ num_bits.val := by
    rw [i3_post1, Nat.shiftLeft_eq, Nat.one_mul,
        show U64.size = 2 ^ 64 by simp [U64.size, U64.numBits], Nat.mod_eq_of_lt hlt64]
  have hprec : num_bits.val + bit_offset.val % 8 ≤ 8 * bytes_needed.val := by
    rw [hbnv, hi2, hi1, hbib]; omega
  have hq : 8 * (31 - byte_start.val) = 8 * (bit_offset.val / 8) := by rw [hbsv]; omega
  have hbo : 8 * (bit_offset.val / 8) + bit_offset.val % 8 = bit_offset.val := by omega
  rw [UScalar.val_and, i4_post1, mask_post1, hi3v, Nat.and_two_pow_sub_one_eq_mod,
      hvloop, W, hq, hbib, window_shift _ _ _ _ hprec, ← Nat.shiftRight_add, hbo]

/-! ### rank 2 — FORS index extraction (composes read_bits_le_spec) -/

/-- `extract_ht_index` = the 18-bit hypertree index at offset 143 = K·A. -/
theorem extract_ht_index_spec (digest : Std.Array Std.U8 32#usize) :
    fors.extract_ht_index digest ⦃ r => r.val = (digestWord digest >>> 143) % 2 ^ 18 ⦄ := by
  unfold fors.extract_ht_index
  simp only [params.K, params.A, params.H]
  let* ⟨i, hi⟩ ← Std.Usize.mul_spec
  let* ⟨i1, hi1⟩ ← read_bits_le_spec digest i 18#usize (by scalar_tac) (by scalar_tac) (by rw [hi]; omega)
  rw [UScalar.cast_val_eq, show UScalarTy.U32.numBits = 32 from rfl, hi1, hi,
      show (13 * 11 : Nat) = 143 by norm_num,
      Nat.mod_eq_of_lt (lt_of_lt_of_le (Nat.mod_lt _ (Nat.two_pow_pos 18))
        (Nat.pow_le_pow_right (by norm_num) (by norm_num)))]

set_option maxHeartbeats 16000000 in
theorem extract_fors_indices_loop_value
    (iter : core.ops.range.Range Std.Usize) (digest : Std.Array Std.U8 32#usize)
    (indices : Std.Array Std.U32 13#usize) (hb : iter.«end».val = 13)
    (hinit : ∀ j, j < iter.start.val → (indices.val[j]!).val = (digestWord digest >>> (j * 11)) % 2 ^ 11) :
    fors.extract_fors_indices_loop iter digest indices
      ⦃ r => ∀ j, j < 13 → (r.val[j]!).val = (digestWord digest >>> (j * 11)) % 2 ^ 11 ⦄ := by
  unfold fors.extract_fors_indices_loop
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize × Std.Array Std.U32 13#usize) =>
       s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize × Std.Array Std.U32 13#usize) =>
       s.1.«end».val = 13 ∧ ∀ j, j < s.1.start.val →
         (s.2.val[j]!).val = (digestWord digest >>> (j * 11)) % 2 ^ 11)
  · rintro ⟨it, ind⟩ ⟨hend, hinv⟩
    unfold fors.extract_fors_indices_loop.body
    simp only []
    let* ⟨o, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hle⟩ | ⟨b, it', heq, hb', hlt, hend', hstart⟩
    · subst ho; simp only [WP.spec_ok]
      exact fun j hj => hinv j (by scalar_tac)
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hbeq : b.val = it.start.val := by rw [hb']
      have h12 : b.val ≤ 12 := by scalar_tac
      simp only [params.A]
      let* ⟨i1, hi1m⟩ ← Std.Usize.mul_spec
      let* ⟨i2, hi2⟩ ← read_bits_le_spec digest i1 11#usize (by scalar_tac) (by scalar_tac) (by rw [hi1m]; omega)
      have hi3val : (UScalar.cast UScalarTy.U32 i2).val = (digestWord digest >>> (b.val * 11)) % 2 ^ 11 := by
        rw [UScalar.cast_val_eq, show UScalarTy.U32.numBits = 32 from rfl, hi2, hi1m,
            Nat.mod_eq_of_lt (lt_of_lt_of_le (Nat.mod_lt _ (Nat.two_pow_pos 11))
              (Nat.pow_le_pow_right (by norm_num) (by norm_num)))]
      step*
      refine ⟨by rw [hend']; exact hend, fun j hj => ?_, by scalar_tac⟩
      have hlen : ind.val.length = 13 := by have := ind.property; simp_all
      rw [a_post, Array.set_val_eq]
      by_cases hjb : j = b.val
      · subst hjb
        rw [List.set_getElem!_eq _ b.val b.val i3 ⟨by omega, rfl⟩, i3_post]
        exact hi3val
      · rw [List.set_getElem!_ne _ b.val j i3 (by simp only [Nat.not_eq]; omega)]
        rw [hbeq] at hjb
        have hj' : j < it.start.val + 1 := by rw [← hstart]; exact hj
        apply hinv j
        show j < it.start.val
        omega
  · exact ⟨hb, hinit⟩

attribute [step] extract_fors_indices_loop_value

open sphincs_c10 in
set_option maxHeartbeats 16000000 in
theorem extract_fors_indices_spec (digest : Std.Array Std.U8 32#usize) :
    fors.extract_fors_indices digest
      ⦃ r => ∀ j, j < 13 → (r.val[j]!).val = (digestWord digest >>> (j * 11)) % 2 ^ 11 ⦄ := by
  unfold fors.extract_fors_indices
  simp only [params.K]
  step* <;>
    first
    | (apply extract_fors_indices_loop_value)
    | scalar_tac
    | (intro j hj; simp_all)
    | simp_all
    | trivial


end Extracted.Equiv
