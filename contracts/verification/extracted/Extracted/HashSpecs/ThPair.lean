/- §33 axiom-collapse — `hash.th_pair` spec: the extracted body (fresh
   128-zero buffer; seed/adrs/left/right copied at [0,32)/[32,64)/[64,96)/
   [96,128); sha256; truncate) returns exactly
   `th_pair_pure seed adrs left right`
   = `truncate16 (sha256_pure (seed ‖ adrs ‖ left ‖ right))`. -/
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
/-- 4-segment buffer collapse: the `setSlice!` tower over a fresh 128-zero
    buffer is the plain concatenation (4-segment `structBuf_eq`). -/
theorem thPairBuf_eq (a b c d : List Std.U8)
    (ha : a.length = 32) (hb : b.length = 32) (hc : c.length = 32)
    (hd : d.length = 32) :
    ((((List.replicate 128 0#u8).setSlice! 0 a).setSlice! 32 b).setSlice!
        64 c).setSlice! 96 d
      = a ++ b ++ c ++ d := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, List.length_append, List.length_replicate, *]
  intro j
  by_cases h0 : j < 32
  · simp_lists [List.length_replicate, *] <;> (try congr 1) <;>
      simp only [List.length_append, ha, hb, hc, hd] <;> omega
  by_cases h1 : j < 64
  · simp_lists [List.length_replicate, *] <;> (try congr 1) <;>
      simp only [List.length_append, ha, hb, hc, hd] <;> omega
  by_cases h2 : j < 96
  · simp_lists [List.length_replicate, *] <;> (try congr 1) <;>
      simp only [List.length_append, ha, hb, hc, hd] <;> omega
  by_cases h3 : j < 128
  · simp_lists [List.length_replicate, *] <;> (try congr 1) <;>
      simp only [List.length_append, ha, hb, hc, hd] <;> omega
  · simp_lists [List.length_replicate, *] <;> (try congr 1) <;>
      simp only [List.length_append, ha, hb, hc, hd] <;> omega

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 100000 in
@[step] theorem hash.th_pair_spec (seed adrs left right : Std.Array Std.U8 32#usize) :
    hash.th_pair seed adrs left right ⦃ r => r = th_pair_pure seed adrs left right ⦄ := by
  have l_seed : seed.val.length = 32 := by have := seed.property; simp_all
  have l_adrs : adrs.val.length = 32 := by have := adrs.property; simp_all
  have l_left : left.val.length = 32 := by have := left.property; simp_all
  have l_right : right.val.length = 32 := by have := right.property; simp_all
  unfold hash.th_pair
  step* <;>
    first
    | scalar_tac
    | (simp only [params.N, Slice.length, Array.length_to_slice] at *; scalar_tac)
    | skip
  have hbuf : s12.val = seed.val ++ adrs.val ++ left.val ++ right.val := by
    simp only [s12_post, s11_post, s10_post, s9_post3, s8_post, s7_post, s6_post3,
               s5_post, s4_post, s3_post3, s2_post, s1_post, s_post3,
               Array.val_to_slice, Array.repeat_val]
    norm_num
    rw [thPairBuf_eq _ _ _ _ l_seed l_adrs l_left l_right]
    simp only [List.append_assoc]
  rw [r_post, hbuf, th_pair_pure_def]

end sphincs_c10
