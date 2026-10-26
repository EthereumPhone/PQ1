import Extracted.Sha256Portable.Core

open Aeneas Aeneas.Std Result
open SphincsCVerify.Spec.Sha256Impl
open sha256_portable

namespace Sha256Portable

set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

theorem shr_u32_eq (x n : Std.U32) (hn : n.val < 32) :
    (x >>> n) = ok (⟨x.bv >>> n.val⟩ : Std.U32) := by
  change (if n.val < 32 then ok _ else fail .integerOverflow) = _
  simp only [hn, if_true]
  rfl

theorem shl_u32_eq (x n : Std.U32) (hn : n.val < 32) :
    (x <<< n) = ok (⟨x.bv <<< n.val⟩ : Std.U32) := by
  change (if n.val < 32 then ok _ else fail .integerOverflow) = _
  simp only [hn, if_true]
  rfl

theorem shr_i32_ten_eq (x : Std.U32) :
    (x >>> 10#i32) = ok (⟨x.bv >>> 10⟩ : Std.U32) := by rfl

theorem add_eq (a b c d e f g h : BitVec 32) :
    soft.add (pack4 a b c d) (pack4 e f g h) =
      ok (pack4 (a + e) (b + f) (c + g) (d + h)) := by
  simp [soft.add, pack4, Std.Array.index_usize, Std.Array.make, lift,
    core.num.U32.wrapping_add, UScalar.wrapping_add]

theorem load_eq (a b c d e f g h : BitVec 32) :
    soft.sha256load (pack4 a b c d) (pack4 e f g h) =
      ok (pack4 h a b c) := by
  simp [soft.sha256load, pack4, Std.Array.index_usize, Std.Array.make]

theorem swap_eq (a b c d : BitVec 32) :
    soft.sha256swap (pack4 a b c d) = ok (pack4 c d a b) := by
  simp [soft.sha256swap, pack4, Std.Array.index_usize, Std.Array.make]

theorem sigma0x4_eq (a b c d : BitVec 32) :
    soft.sha256msg1.sigma0x4 (pack4 a b c d) =
      ok (pack4 (smallSigma0 a) (smallSigma0 b) (smallSigma0 c) (smallSigma0 d)) := by
  simp [soft.sha256msg1.sigma0x4, soft.shl, soft.shr, soft.or, soft.xor,
    pack4, Std.Array.index_usize, Std.Array.make, lift,
    shr_u32_eq, shl_u32_eq, smallSigma0, rotr]
  rfl

theorem msg1_eq (a b c d e f g h : BitVec 32) :
    soft.sha256msg1 (pack4 a b c d) (pack4 e f g h) =
      ok (pack4 (a + smallSigma0 h) (b + smallSigma0 a)
        (c + smallSigma0 b) (d + smallSigma0 c)) := by
  simp [soft.sha256msg1, load_eq, sigma0x4_eq, add_eq]

theorem msg2_eq (x3 x2 x1 x0 w15 w14 w13 w12 : BitVec 32) :
    soft.sha256msg2 (pack4 x3 x2 x1 x0) (pack4 w15 w14 w13 w12) =
      let w16 := x0 + smallSigma1 w14
      let w17 := x1 + smallSigma1 w15
      ok (pack4 (x3 + smallSigma1 w17) (x2 + smallSigma1 w16) w17 w16) := by
  simp [soft.sha256msg2, pack4, Std.Array.index_usize, Std.Array.make, lift,
    core.num.U32.wrapping_add, UScalar.wrapping_add,
    core.num.U32.rotate_right, UScalar.rotate_right,
    shr_i32_ten_eq,
    smallSigma1, rotate_right_eq _ 17 (by decide),
    rotate_right_eq _ 19 (by decide)]

/-- The standard SHA-256 schedule recurrence, in chronological argument order. -/
def nextWord (w0 w1 w9 w14 : BitVec 32) : BitVec 32 :=
  smallSigma1 w14 + w9 + smallSigma0 w1 + w0

theorem nextWord_order (w0 w1 w9 w14 : BitVec 32) :
    (w0 + smallSigma0 w1 + w9) + smallSigma1 w14 = nextWord w0 w1 w9 w14 := by
  unfold nextWord
  ac_rfl

/-- The actual rolling four-word implementation computes four successive
    standard schedule words. Input/output groups use RustCrypto's reverse order. -/
theorem schedule_eq
    (w0 w1 w2 w3 w4 w5 w6 w7 w8 w9 w10 w11 w12 w13 w14 w15 : BitVec 32) :
    soft.schedule (pack4 w3 w2 w1 w0) (pack4 w7 w6 w5 w4)
      (pack4 w11 w10 w9 w8) (pack4 w15 w14 w13 w12) =
      let w16 := nextWord w0 w1 w9 w14
      let w17 := nextWord w1 w2 w10 w15
      let w18 := nextWord w2 w3 w11 w16
      let w19 := nextWord w3 w4 w12 w17
      ok (pack4 w19 w18 w17 w16) := by
  simp [soft.schedule, msg1_eq, load_eq, add_eq, msg2_eq, nextWord_order]

end Sha256Portable
