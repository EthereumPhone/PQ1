/- Exact search-acceptance computations against the paired forms. The extracted
   searches retain their supplied SHA backend and erased progress callbacks.
   This does not identify that backend with an EasyCrypt oracle or its state. -/
import Extracted.C10Representation
import Extracted.C10RepresentationBridge
import Extracted.FindCountSpec
import Extracted.GrindRSpec

open Aeneas Aeneas.Std Result ControlFlow

namespace Extracted.C10AcceptanceBridge
open C10Representation Extracted.Equiv Extracted.C10RepresentationBridge sphincs_c10

theorem int_fold_sum (xs : List Nat) :
    (xs.map Int.ofNat).foldr (fun b acc => b + acc) 0 = Int.ofNat xs.sum := by
  induction xs with
  | nil => rfl
  | cons x xs ih => simp only [List.map_cons, List.foldr_cons, List.sum_cons, ih,
      Int.natCast_add, Int.ofNat_eq_natCast]

theorem wots_sum_value (d : Std.Array Std.U8 32#usize) :
    wots_sum (d.val.map (fun b => Int.ofNat b.val)) = Int.ofNat (grindSum d) := by
  unfold wots_sum grindSum
  have h : (List.range 43).map (fun i =>
      wots_field (d.val.map (fun b => Int.ofNat b.val)) i) =
      ((List.range 43).map (wotsDigit d)).map Int.ofNat := by
    simp only [List.map_map]
    apply List.map_congr_left
    intro i hi
    simp only [Function.comp_apply, wots_field, digest_word_window, wotsDigit,
      show (2:Nat)^3=8 by decide, Nat.mul_comm]
  rw [h, int_fold_sum]

theorem wots_accept_common (seed adrs message : Std.Array Std.U8 32#usize)
    (count : Std.U32) :
    grindAccept seed adrs message count ↔
      wots_sum ((wots_digest_pure seed adrs message count).val.map
        (fun b => Int.ofNat b.val)) = wots_target := by
  rw [wots_sum_value]
  unfold grindAccept wots_target
  simp only [Int.ofNat_eq_natCast]
  omega

theorem fors_accept_common (sk seed root message : Std.Array Std.U8 32#usize)
    (opt : Option (Std.Array Std.U8 16#usize)) (nonce : Std.U32) :
    forsGrindAccept sk seed root message opt nonce ↔
      fors_zero_field ((forsGrindDigest sk seed root message opt nonce).val.map
        (fun b => Int.ofNat b.val)) = 0 := by
  unfold fors_zero_field forsGrindAccept
  rw [digest_word_window]
  simp only [Int.ofNat_eq_natCast, Int.natCast_eq_zero]

/-- Both branches of the actual extracted WOTS trial use the paired test. -/
theorem extracted_wots_trial (seed adrs message : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (pct : Std.U8) (count : Std.U32)
    (hcount : count.val < 10000000) :
    wots.find_count_loop0.body seed message progress pct adrs count ⦃ r =>
      (∃ digits, r = done (count, wots_digest_pure seed adrs message count, digits) ∧
        wots_sum ((wots_digest_pure seed adrs message count).val.map
          (fun b => Int.ofNat b.val)) = wots_target ∧
        ∀ j, j < 43 → (digits.val[j]!).val =
          wotsDigit (wots_digest_pure seed adrs message count) j) ∨
      (∃ next, r = cont next ∧ next.val = count.val + 1 ∧
        wots_sum ((wots_digest_pure seed adrs message count).val.map
          (fun b => Int.ofNat b.val)) ≠ wots_target) ⦄ := by
  simpa only [wots_accept_common] using
    grind_body_spec seed adrs message progress pct count hcount

/-- Both branches of the actual FORS trial use the paired zero window. -/
theorem extracted_fors_trial (sk seed root message : Std.Array Std.U8 32#usize)
    (opt : Option (Std.Array Std.U8 16#usize)) (nonce : Std.U32)
    (hbound : nonce.val < 10000000) :
    fors.grind_r_loop.body sk message opt seed root 132#usize nonce ⦃ r =>
      (r = done (forsRandomizer sk message opt nonce,
        forsGrindDigest sk seed root message opt nonce) ∧
        fors_zero_field ((forsGrindDigest sk seed root message opt nonce).val.map
          (fun b => Int.ofNat b.val)) = 0) ∨
      (∃ next, r = cont next ∧ next.val = nonce.val + 1 ∧
        fors_zero_field ((forsGrindDigest sk seed root message opt nonce).val.map
          (fun b => Int.ofNat b.val)) ≠ 0) ⦄ := by
  simpa only [fors_accept_common] using
    fors_grind_body_spec sk seed root message opt nonce hbound


noncomputable def pairedWotsAccept (seed adrs message : Std.Array Std.U8 32#usize)
    (count : Std.U32) : Prop :=
  wots_sum ((wots_digest_pure seed adrs message count).val.map
    (fun b => Int.ofNat b.val)) = wots_target

noncomputable def pairedForsAccept (sk seed root message : Std.Array Std.U8 32#usize)
    (opt : Option (Std.Array Std.U8 16#usize)) (nonce : Std.U32) : Prop :=
  fors_zero_field ((forsGrindDigest sk seed root message opt nonce).val.map
    (fun b => Int.ofNat b.val)) = 0

/-- The complete bounded WOTS search either returns the first paired-test hit,
    its digest and digits, or reconstructs the source exhaustion failure. -/
theorem extracted_wots_search (seed message : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (progress : hypertree.ProgressSink) (pct : Std.U8) :
    (∃ c d digits,
      wots.find_count seed layer tree kp message progress pct = .ok (c, d, digits) ∧
      c.val < 10000000 ∧
      pairedWotsAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message c ∧
      (∀ earlier : Std.U32, earlier.val < c.val →
        ¬ pairedWotsAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message earlier) ∧
      d = wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0) message c ∧
      ∀ j, j < 43 → (digits.val[j]!).val = wotsDigit d j) ∨
    (wots.find_count seed layer tree kp message progress pct = .fail .assertionFailure ∧
      ∀ c : Std.U32, c.val < 10000000 →
        ¬ pairedWotsAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message c) := by
  simpa only [pairedWotsAccept, wots_accept_common] using
    find_count_total seed message layer tree kp progress pct

/-- Both OptRand modes retain their actual first hit or exhaustion result.
    No existence, freshness or success-probability premise is introduced. -/
theorem extracted_fors_search (sk message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize)) :
    (∃ c : Std.U32, c.val < 10000000 ∧
      pairedForsAccept sk (pad16Pure seed) (pad16Pure root) message opt c ∧
      (∀ earlier : Std.U32, earlier.val < c.val →
        ¬ pairedForsAccept sk (pad16Pure seed) (pad16Pure root) message opt earlier) ∧
      fors.grind_r sk seed root message opt = .ok
        (forsRandomizer sk message opt c,
          forsGrindDigest sk (pad16Pure seed) (pad16Pure root) message opt c)) ∨
    (fors.grind_r sk seed root message opt = .fail .assertionFailure ∧
      ∀ c : Std.U32, c.val < 10000000 →
        ¬ pairedForsAccept sk (pad16Pure seed) (pad16Pure root) message opt c) := by
  simpa only [pairedForsAccept, fors_accept_common] using
    grind_r_total sk message seed root opt

end Extracted.C10AcceptanceBridge
