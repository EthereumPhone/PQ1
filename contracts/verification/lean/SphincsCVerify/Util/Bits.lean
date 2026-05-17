/-
Bit-level operations: base-w digit extraction, target-sum check,
read_bits_le (the bit-window helper used by FORS index decoding).

These are pure `Nat` / `ByteVec`-level operations with no SHA-256
dependence; every lemma in this file is closed by `decide` or by
elementary induction.
-/

import SphincsCVerify.Spec.Bytes
import SphincsCVerify.Spec.Params

namespace SphincsCVerify.Util

open SphincsCVerify.Spec
open ByteVec

/-- One bit-extraction step: read the `i`-th bit (in little-endian
    ordering) starting at `bitOffset` from a 32-byte digest, shifted
    to its target position. Used in the body of `readBitsLe`. -/
@[inline] def readBitsLe.stepValue
    (digest : ByteVec 32) (bitOffset i : Nat) : Nat :=
  let bitIdx := bitOffset + i
  let byteIdx := 31 - bitIdx / 8
  let bitInByte := bitIdx % 8
  let b : UInt8 :=
    if byteIdx < 32 then
      digest.get ⟨byteIdx, by omega⟩
    else
      0
  ((b.toNat >>> bitInByte) &&& 1) <<< i

/-- Read `numBits` bits (≤ 57) starting at logical bit `bitOffset` from a
    32-byte big-endian digest. Bit 0 is the LSB of `digest[31]`.

    Mirrors `read_bits_le` in `sphincs-c10/src/fors.rs`. -/
def readBitsLe (digest : ByteVec 32) (bitOffset numBits : Nat) : Nat :=
  let rec loop (i acc : Nat) : Nat :=
    if i < numBits then
      loop (i + 1) (acc ||| readBitsLe.stepValue digest bitOffset i)
    else
      acc
  termination_by numBits - i
  loop 0 0

/-- Extract `L = 43` base-w digits from a 32-byte digest.

    digit[i] = `(digest >> (i * LogW)) & WMask` -/
def extractDigits (digest : ByteVec 32) : Array Nat :=
  Array.ofFn (n := L) fun i =>
    readBitsLe digest (i * LogW) LogW

/-- Sum of a list of `Nat`s — used for the target-sum check. -/
def digitSum (digits : Array Nat) : Nat :=
  digits.foldl (init := 0) (· + ·)

/-- Extract the `K = 13` FORS leaf indices from a 32-byte digest.

    index[i] = `(digest >> (i * A)) & ((1 << A) - 1)` -/
def extractForsIndices (digest : ByteVec 32) : Array Nat :=
  Array.ofFn (n := K) fun i =>
    readBitsLe digest (i * A) A

/-- Extract the 18-bit hypertree index. -/
def extractHtIndex (digest : ByteVec 32) : Nat :=
  readBitsLe digest (K * A) H

/-! ## Spec-level properties -/

/-- Any natural number ANDed with 1 is less than 2. -/
private theorem and_one_lt_two (x : Nat) : x &&& 1 < 2 := by
  have h : x &&& 1 < 2 ^ 1 :=
    Nat.and_lt_two_pow x (by decide : (1 : Nat) < 2 ^ 1)
  simpa using h

/-- The bit-extraction step produces a value below `2 ^ (i + 1)`. -/
private theorem readBitsLe.stepValue_lt
    (digest : ByteVec 32) (bitOffset i : Nat) :
    readBitsLe.stepValue digest bitOffset i < 2 ^ (i + 1) := by
  unfold readBitsLe.stepValue
  -- The value is `(b.toNat >>> _ &&& 1) <<< i`. The inner part is < 2 (from `&&& 1`),
  -- so the shifted value is < 2 * 2^i = 2^(i+1).
  rw [Nat.shiftLeft_eq, Nat.pow_succ, Nat.mul_comm (2 ^ i) 2]
  exact (Nat.mul_lt_mul_right (Nat.two_pow_pos i)).mpr (and_one_lt_two _)

/-- Strengthened induction lemma for `readBitsLe.loop`: starting from
    `acc < 2 ^ i`, the loop's accumulator after termination is
    `< 2 ^ numBits`. Each iteration ORs in `stepValue _ _ i` which is
    `< 2 ^ (i + 1)`, so the invariant `acc < 2 ^ i` is preserved across
    the step `i → i + 1`. -/
private theorem readBitsLe_loop_lt
    (digest : ByteVec 32) (bitOffset numBits : Nat) :
    ∀ (d i acc : Nat), numBits - i = d → i ≤ numBits → acc < 2 ^ i →
      readBitsLe.loop digest bitOffset numBits i acc < 2 ^ numBits := by
  intro d
  induction d with
  | zero =>
    intro i acc hd hi hacc
    have hi_eq : i = numBits := by omega
    subst hi_eq
    unfold readBitsLe.loop
    simp
    exact hacc
  | succ d ih =>
    intro i acc hd hi hacc
    have hilt : i < numBits := by omega
    unfold readBitsLe.loop
    rw [if_pos hilt]
    -- After if-reduction the goal is:
    --   readBitsLe.loop digest bitOffset numBits (i+1)
    --     (acc ||| readBitsLe.stepValue digest bitOffset i) < 2^numBits
    apply ih (i + 1) (acc ||| readBitsLe.stepValue digest bitOffset i)
      (by omega) (by omega)
    -- Goal: acc ||| stepValue digest bitOffset i < 2 ^ (i + 1)
    apply Nat.or_lt_two_pow
    · -- acc < 2 ^ (i + 1)
      exact Nat.lt_of_lt_of_le hacc
        (Nat.pow_le_pow_right (by decide) (Nat.le_succ _))
    · exact readBitsLe.stepValue_lt _ _ _

/-- A digit returned by `readBitsLe _ _ k` is bounded above by `2^k`. -/
theorem readBitsLe_lt (digest : ByteVec 32) (off k : Nat) :
    readBitsLe digest off k < 2 ^ k := by
  unfold readBitsLe
  exact readBitsLe_loop_lt digest off k k 0 0 rfl (Nat.zero_le _) (by simp)

/-- A FORS index lies in `[0, 2^A)`. -/
theorem extractForsIndices_lt (digest : ByteVec 32) (i : Fin K) :
    (extractForsIndices digest)[i.val]! < 2 ^ A := by
  unfold extractForsIndices
  -- `getElem!_pos` reduces `xs[i.val]!` to `xs[i.val]` given the bound.
  rw [getElem!_pos (Array.ofFn (n := K) fun j => readBitsLe digest (j.val * A) A) i.val
        (by simp [i.isLt])]
  simp
  exact readBitsLe_lt _ _ _

/-- The hypertree index lies in `[0, 2^H)` = `[0, 262144)`. -/
theorem extractHtIndex_lt (digest : ByteVec 32) :
    extractHtIndex digest < 2 ^ H := by
  exact readBitsLe_lt _ _ _

/-- A WOTS digit lies in `[0, W)` = `[0, 8)`. -/
theorem extractDigits_lt (digest : ByteVec 32) (i : Fin L) :
    (extractDigits digest)[i.val]! < W := by
  unfold extractDigits
  rw [getElem!_pos (Array.ofFn (n := L) fun j => readBitsLe digest (j.val * LogW) LogW) i.val
        (by simp [i.isLt])]
  simp [W_eq_two_pow_LogW]
  exact readBitsLe_lt _ _ _

end SphincsCVerify.Util
