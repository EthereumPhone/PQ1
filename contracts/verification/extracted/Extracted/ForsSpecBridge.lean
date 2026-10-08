/- The extracted Rust digest decoders agree with the verifier's vendored
   bit-loop specification on every digest. Trust boundaries: the Aeneas
   translation and the source-checked version bridge, not hash hardness.
   Bit extensionality follows the argument in Interpreter/Phases.lean,
   using the independently proved extracted digestWord_byte theorem. -/
import Extracted.ForsExtract
import Extracted.ForsSpecVendored

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open SphincsCVerify.Spec

/-- Preserve each byte and its order when crossing the two Lean byte types. -/
def toSpecDigest (digest : Std.Array Std.U8 32#usize) : ByteVec 32 :=
  ⟨(digest.val.map (fun b => UInt8.ofNat b.val)).toArray, by
    simpa using digest.property⟩

theorem toSpecDigest_get (digest : Std.Array Std.U8 32#usize) (i : Fin 32) :
    ((toSpecDigest digest).get i).toNat = (digest.val[i.val]!).val := by
  have hlen : digest.val.length = 32 := by simpa using digest.property
  have hi : i.val < digest.val.length := by omega
  change ((digest.val.map (fun b => UInt8.ofNat b.val))[i.val]'(by simpa using hi)).toNat
    = (digest.val[i.val]!).val
  rw [List.getElem_map, UInt8.toNat_ofNat', getElem!_pos digest.val i.val hi,
    Nat.mod_eq_of_lt]
  exact (digest.val[i.val]).hBounds

private theorem digestWord_testBit (digest : Std.Array Std.U8 32#usize)
    (b : Nat) (hb : b < 256) :
    (digestWord digest).testBit b = (digest.val[31 - b / 8]!).val.testBit (b % 8) := by
  have h := digestWord_byte digest (b / 8)
  rw [if_pos (show b / 8 < 32 by omega)] at h
  rw [← h, show (256 : Nat) = 2 ^ 8 from rfl,
    Nat.testBit_mod_two_pow, Nat.testBit_shiftRight]
  rw [show 8 * (b / 8) + b % 8 = b by omega,
    decide_eq_true (show b % 8 < 8 by omega), Bool.true_and]

private theorem vendored_step_testBit (digest : Std.Array Std.U8 32#usize)
    (off i j : Nat) (hoi : off + i < 256) :
    (SphincsCVerify.Util.readBitsLe.stepValue (toSpecDigest digest) off i).testBit j
      = (decide (j = i) && (digestWord digest).testBit (off + i)) := by
  unfold SphincsCVerify.Util.readBitsLe.stepValue
  simp only []
  rw [Nat.testBit_shiftLeft]
  by_cases hj : i ≤ j
  · rw [decide_eq_true hj, Bool.true_and]
    by_cases hji : j = i
    · subst hji
      rw [decide_eq_true (rfl : j = j), Bool.true_and, Nat.sub_self,
        if_pos (show 31 - (off + j) / 8 < 32 by omega),
        Nat.testBit_and, Nat.testBit_shiftRight,
        show (1 : Nat).testBit 0 = true from rfl, Bool.and_true,
        Nat.add_zero, toSpecDigest_get, digestWord_testBit digest (off + j) hoi]
    · rw [decide_eq_false hji, Bool.false_and]
      apply Nat.testBit_lt_two_pow
      calc _ < 2 ^ 1 := Nat.and_lt_two_pow _ (by decide)
        _ ≤ 2 ^ (j - i) := Nat.pow_le_pow_right (by decide) (by omega)
  · rw [decide_eq_false hj, Bool.false_and,
      decide_eq_false (show ¬ j = i by omega), Bool.false_and]

private theorem vendored_loop_testBit (digest : Std.Array Std.U8 32#usize)
    (off numBits : Nat) (hbound : off + numBits ≤ 256) :
    ∀ (d i acc : Nat), numBits - i = d → i ≤ numBits →
      (∀ j, acc.testBit j = (decide (j < i) && (digestWord digest).testBit (off + j))) →
      ∀ j, (SphincsCVerify.Util.readBitsLe.loop (toSpecDigest digest) off numBits i acc).testBit j
        = (decide (j < numBits) && (digestWord digest).testBit (off + j)) := by
  intro d
  induction d with
  | zero =>
      intro i acc hd hi hacc j
      have hie : i = numBits := by omega
      subst hie
      unfold SphincsCVerify.Util.readBitsLe.loop
      rw [if_neg (by omega)]
      exact hacc j
  | succ d ih =>
      intro i acc hd hi hacc j
      have hilt : i < numBits := by omega
      unfold SphincsCVerify.Util.readBitsLe.loop
      rw [if_pos hilt]
      apply ih (i + 1)
        (acc ||| SphincsCVerify.Util.readBitsLe.stepValue (toSpecDigest digest) off i)
        (by omega) (by omega)
      intro j'
      rw [Nat.testBit_or, hacc j', vendored_step_testBit digest off i j' (by omega)]
      by_cases hji : j' = i
      · subst hji
        rw [decide_eq_true (rfl : j' = j'), Bool.true_and,
          decide_eq_false (Nat.lt_irrefl j'), Bool.false_and, Bool.false_or,
          decide_eq_true (Nat.lt_succ_self j'), Bool.true_and]
      · rw [decide_eq_false hji, Bool.false_and, Bool.or_false]
        by_cases hjlt : j' < i
        · rw [decide_eq_true hjlt, decide_eq_true (Nat.lt_succ_of_lt hjlt)]
        · rw [decide_eq_false hjlt, decide_eq_false (show ¬ j' < i + 1 by omega)]

/-- The independently defined verifier bit loop reads the same word window.
    The bound is essential: the vendored specification is used only in-range. -/
theorem vendored_readBitsLe_eq_digestWord (digest : Std.Array Std.U8 32#usize)
    (off k : Nat) (hbound : off + k ≤ 256) :
    SphincsCVerify.Util.readBitsLe (toSpecDigest digest) off k
      = (digestWord digest >>> off) % 2 ^ k := by
  apply Nat.eq_of_testBit_eq
  intro j
  unfold SphincsCVerify.Util.readBitsLe
  rw [vendored_loop_testBit digest off k hbound k 0 0 rfl (Nat.zero_le _)
    (fun j => by rw [Nat.zero_testBit, decide_eq_false (Nat.not_lt_zero j), Bool.false_and]) j]
  rw [Nat.testBit_mod_two_pow, Nat.testBit_shiftRight]

/-- Rust's extracted hypertree decoder terminates and agrees with the actual
    verifier specification, for all 32-byte digests. -/
theorem firmware_extract_ht_index_matches_vendored (digest : Std.Array Std.U8 32#usize) :
    sphincs_c10.fors.extract_ht_index digest
      ⦃ r => r.val = SphincsCVerify.Util.extractHtIndex (toSpecDigest digest) ⦄ := by
  unfold SphincsCVerify.Util.extractHtIndex
  rw [vendored_readBitsLe_eq_digestWord digest _ _ (by decide)]
  exact extract_ht_index_spec digest

/-- All thirteen extracted FORS fields agree, including the last field whose
    forced-zero predicate the verifier checks. No accepted-digest premise. -/
theorem firmware_extract_fors_indices_matches_vendored (digest : Std.Array Std.U8 32#usize) :
    sphincs_c10.fors.extract_fors_indices digest
      ⦃ r => ∀ j, j < 13 → (r.val[j]!).val =
        (SphincsCVerify.Util.extractForsIndices (toSpecDigest digest)).getD j 0 ⦄ := by
  let* ⟨indices, hi⟩ ← extract_fors_indices_spec digest
  rename_i j hj
  unfold SphincsCVerify.Util.extractForsIndices
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_ofFn,
    dif_pos (show j < K from hj), Option.getD_some,
    vendored_readBitsLe_eq_digestWord digest _ _ (by simp only [A]; omega)]
  exact hi j hj

end Extracted.Equiv
