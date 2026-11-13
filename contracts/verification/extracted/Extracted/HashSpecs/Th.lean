/- §33 axiom-collapse — `hash.th` spec: the extracted body (fresh 96-zero
   buffer, copy seed/adrs/val at [0..32)/[32..64)/[64..96), sha256, truncate)
   returns exactly `th_pure seed adrs val =
   truncate16 (sha256_pure (seed ‖ adrs ‖ val))`. -/
import Extracted.Hash.Funs
import Extracted.HashPure
import Extracted.SetSliceLemmas
import Extracted.HashSpecs.Truncate

set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false
set_option linter.unreachableTactic false
set_option linter.unnecessarySeqFocus false

open Aeneas Aeneas.Std Result
open Extracted.SetSlice

namespace sphincs_c10

set_option maxRecDepth 16384 in
/-- The 96-byte `th` preimage buffer: three 32-byte writes at 0/32/64 over a
    fresh zero buffer collapse to the concatenation. -/
theorem thBuf_eq (a b c : List Std.U8) (ha : a.length = 32)
    (hb : b.length = 32) (hc : c.length = 32) :
    (((List.replicate 96 0#u8).setSlice! 0 a).setSlice! 32 b).setSlice! 64 c
      = a ++ b ++ c := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, List.length_append, List.length_replicate, *]
  intro j
  by_cases h0 : j < 32
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h1 : j < 64
  · simp_lists [List.length_replicate, List.length_append, *]
  by_cases h2 : j < 96
  · simp_lists [List.length_replicate, List.length_append, *]
  · simp_lists [List.length_replicate, List.length_append, *]

set_option maxHeartbeats 4000000 in
@[step] theorem hash.th_spec (seed adrs val : Std.Array Std.U8 32#usize) :
    hash.th seed adrs val ⦃ r => r = th_pure seed adrs val ⦄ := by
  have l_seed : seed.val.length = 32 := by have := seed.property; simp_all
  have l_adrs : adrs.val.length = 32 := by have := adrs.property; simp_all
  have l_val : val.val.length = 32 := by have := val.property; simp_all
  unfold hash.th
  step* <;>
    first
    | scalar_tac
    | (simp only [params.N, Slice.length, Array.length_to_slice]; scalar_tac)
    | (simp only [Slice.length, Array.length_to_slice] at *; scalar_tac)
    | skip
  have hs9 : (s9 : List Std.U8) = seed.val ++ adrs.val ++ val.val := by
    simp only [s9_post, s8_post, s7_post, s6_post3, s5_post, s4_post, s3_post3,
               s2_post, s1_post, s_post3, Array.val_to_slice, Array.repeat_val]
    norm_num
    rw [thBuf_eq _ _ _ l_seed l_adrs l_val]
    simp only [List.append_assoc]
  rw [r_post, hs9, th_pure_def]

end sphincs_c10
