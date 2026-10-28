import Extracted.Sha256Portable.Funs
import Extracted.Sha256Vendored

open Aeneas Aeneas.Std Result
open SphincsCVerify.Spec.Sha256Impl
open sha256_portable

/-! Refinement of the actual RustCrypto portable word kernel.
This does not model the Digest API, padding, dispatch or hardware. -/
namespace Sha256Portable

set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

def pack4 (a b c d : BitVec 32) : Std.Array Std.U32 4#usize :=
  Std.Array.make 4#usize [⟨a⟩, ⟨b⟩, ⟨c⟩, ⟨d⟩]

theorem optimized_ch_eq (e f g : BitVec 32) :
    g ^^^ (e &&& (f ^^^ g)) = ch e f g := by
  unfold ch
  ext i
  simp only [BitVec.getElem_xor, BitVec.getElem_and, BitVec.getElem_not]
  cases e[i] <;> cases f[i] <;> cases g[i] <;> rfl

theorem rotate_right_eq (x : BitVec 32) (n : Nat) (h : n < 32) :
    x.rotateRight n = rotr x n := by
  rw [BitVec.rotateRight_eq_rotateRightAux_of_lt h]
  rfl

def implT1 (h e f g kw : BitVec 32) : BitVec 32 :=
  (e.rotateRight 6 ^^^ e.rotateRight 11 ^^^ e.rotateRight 25) +
    (g ^^^ (e &&& (f ^^^ g))) + kw + h

def implT2 (a b c : BitVec 32) : BitVec 32 :=
  (a.rotateRight 2 ^^^ a.rotateRight 13 ^^^ a.rotateRight 22) +
    ((a &&& b) ^^^ (a &&& c) ^^^ (b &&& c))

def implRound (s : Working) (k w : BitVec 32) : Working :=
  let t1 := implT1 s.h s.e s.f s.g (k + w)
  { a := t1 + implT2 s.a s.b s.c, b := s.a, c := s.b, d := s.c,
    e := t1 + s.d, f := s.e, g := s.f, h := s.g }

theorem implT1_eq (h e f g k w : BitVec 32) :
    implT1 h e f g (k + w) = h + bigSigma1 e + ch e f g + k + w := by
  simp only [implT1, optimized_ch_eq,
    rotate_right_eq _ 6 (by decide), rotate_right_eq _ 11 (by decide),
    rotate_right_eq _ 25 (by decide), bigSigma1]
  ac_rfl

theorem implT2_eq (a b c : BitVec 32) :
    implT2 a b c = bigSigma0 a + maj a b c := by
  simp only [implT2, rotate_right_eq _ 2 (by decide),
    rotate_right_eq _ 13 (by decide), rotate_right_eq _ 22 (by decide),
    bigSigma0, maj]

theorem implRound_eq_round (s : Working) (k w : BitVec 32) :
    implRound s k w = round s k w := by
  simp only [implRound, implT1_eq, implT2_eq, round]
  congr 1
  exact BitVec.add_comm _ _

theorem round2_impl (s : Working) (k0 w0 k1 w1 unused0 unused1 : BitVec 32) :
  soft.sha256_digest_round_x2
    (pack4 s.c s.d s.g s.h) (pack4 s.a s.b s.e s.f)
    (pack4 unused0 unused1 (k1 + w1) (k0 + w0)) =
  let s2 := implRound (implRound s k0 w0) k1 w1
  ok (pack4 s2.a s2.b s2.e s2.f) := by
  simp [soft.sha256_digest_round_x2, pack4, Std.Array.index_usize,
    Std.Array.make, lift, implRound, implT1, implT2, core.num.U32.wrapping_add,
    UScalar.wrapping_add, core.num.U32.rotate_right, UScalar.rotate_right]

theorem round2_eq (s : Working) (k0 w0 k1 w1 unused0 unused1 : BitVec 32) :
  soft.sha256_digest_round_x2
    (pack4 s.c s.d s.g s.h) (pack4 s.a s.b s.e s.f)
    (pack4 unused0 unused1 (k1 + w1) (k0 + w0)) =
  let s2 := round (round s k0 w0) k1 w1
  ok (pack4 s2.a s2.b s2.e s2.f) := by
  simpa only [implRound_eq_round] using round2_impl s k0 w0 k1 w1 unused0 unused1

end Sha256Portable
