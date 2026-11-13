/- Actual FORS secret derivation: the contiguous 48-byte preimage buffer (all
   fields, including the full-width hypertree position) hashed through the
   one-shot `sha256_bytes` boundary and truncated to 16 bytes
   (`hash.sha256_bytes16`). -/
import Extracted.ForsSecret.Funs
import Extracted.HashSpecs.WotsDigest
import Extracted.HashSpecs.Truncate

open Aeneas Aeneas.Std Result
open Extracted.SetSlice
set_option maxRecDepth 4096
set_option maxHeartbeats 800000
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false
set_option linter.unreachableTactic false
set_option linter.unnecessarySeqFocus false
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open sphincs_c10

def forsSecretPreimage (sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) : List Std.U8 :=
  sk.val ++ [102#u8, 111#u8, 114#u8, 115#u8] ++ u32beBytes ht.val ++
    u32beBytes tree.val ++ u32beBytes leaf.val

def forsSecretPure (sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) : Std.Array Std.U8 16#usize :=
  truncate16 (sha256_pure (forsSecretPreimage sk ht tree leaf))

theorem forsSecretPreimage_length (sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) : (forsSecretPreimage sk ht tree leaf).length = 48 := by
  have hs : sk.val.length = 32 := by simpa using sk.property
  simp [forsSecretPreimage, u32beBytes, hs]

set_option maxRecDepth 16384 in
/-- The contiguous 48-byte `fors_secret` preimage buffer: `sk_seed` at 0,
    the `"fors"` tag at 32, then `to_b4(ht)`, `to_b4(tree)`, `to_b4(leaf)`
    at 36/40/44, over a fresh zero buffer. -/
theorem forsSecretBuf_eq (sk tag h t l : List Std.U8)
    (hs : sk.length = 32) (hg : tag.length = 4) (hh : h.length = 4)
    (ht : t.length = 4) (hl : l.length = 4) :
    (((((List.replicate 48 0#u8).setSlice! 0 sk).setSlice! 32 tag).setSlice! 36 h
        ).setSlice! 40 t).setSlice! 44 l
      = sk ++ tag ++ h ++ t ++ l := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, List.length_append, List.length_replicate, *]
  intro j
  by_cases h0 : j < 32
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hs, hg, hh, ht, hl] <;> omega
  by_cases h1 : j < 36
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hs, hg, hh, ht, hl] <;> omega
  by_cases h2 : j < 40
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hs, hg, hh, ht, hl] <;> omega
  by_cases h3 : j < 44
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hs, hg, hh, ht, hl] <;> omega
  by_cases h4 : j < 48
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hs, hg, hh, ht, hl] <;> omega
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hs, hg, hh, ht, hl] <;> omega

set_option maxHeartbeats 4000000 in
@[step] theorem fors_secret_spec (sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) :
    hash.fors_secret sk ht tree leaf ⦃ r => r = forsSecretPure sk ht tree leaf ⦄ := by
  have l_sk : sk.val.length = 32 := by have := sk.property; simp_all
  have l4 : ∀ x : Std.U32, (x.bv.toBEBytes.map (@UScalar.mk .U8)).length = 4 := by
    intro x; rw [List.length_map, BitVec.toBEBytes_length]
  unfold hash.fors_secret
  step* <;>
    first
    | scalar_tac
    | (simp only [Slice.length, Array.length_to_slice] at *; scalar_tac)
    | skip
  have hbuf : (s15 : List Std.U8) = forsSecretPreimage sk ht tree leaf := by
    simp only [s15_post, s14_post, s13_post, s12_post3, s11_post, s10_post, s9_post3,
               s8_post, s7_post, s6_post3, s5_post, s4_post, s3_post3, s2_post, s1_post,
               s_post3, a_post, a1_post, a2_post,
               Array.val_to_slice, Array.repeat_val, Array.make]
    norm_num
    rw [forsSecretBuf_eq _ _ _ _ _ l_sk (by rfl) (l4 ht) (l4 tree) (l4 leaf),
      u32_toBEBytes_map_mk, u32_toBEBytes_map_mk, u32_toBEBytes_map_mk]
    simp only [forsSecretPreimage, List.append_assoc]
  rw [r_post, hbuf]
  rfl

end Extracted.Equiv
