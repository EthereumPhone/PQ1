/- Actual WOTS secret derivation: the contiguous 80-byte preimage buffer (all
   fields, full-width positions) hashed through the one-shot `sha256_bytes`
   boundary and truncated to 16 bytes (`hash.sha256_bytes16`). -/
import Extracted.WotsSecret.Funs
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

def wotsTreeBytes (tree : Std.U64) : List Std.U8 :=
  List.replicate 24 0#u8 ++ tree.bv.toBEBytes.map (@UScalar.mk .U8)

def wotsSecretPreimage (sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp chain : Std.U32) : List Std.U8 :=
  sk.val ++ [119#u8, 111#u8, 116#u8, 115#u8] ++ u32beBytes layer.val ++
    wotsTreeBytes tree ++ u32beBytes kp.val ++ u32beBytes chain.val

def wotsSecretPure (sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp chain : Std.U32) : Std.Array Std.U8 16#usize :=
  truncate16 (sha256_pure (wotsSecretPreimage sk layer tree kp chain))

theorem wotsSecretPreimage_length (sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp chain : Std.U32) :
    (wotsSecretPreimage sk layer tree kp chain).length = 80 := by
  have hs : sk.val.length = 32 := by simpa using sk.property
  simp [wotsSecretPreimage, wotsTreeBytes, u32beBytes, hs, BitVec.toBEBytes_length]

set_option maxRecDepth 16384 in
/-- The contiguous 80-byte `wots_secret` preimage buffer: `sk_seed` at 0,
    the `"wots"` tag at 32, `to_b4(layer)` at 36, the 8 big-endian `tree`
    bytes at 64 (bytes [40..64) stay zero, i.e. `to_b32(tree)`), `to_b4(kp)`
    at 72 and `to_b4(chain)` at 76, over a fresh zero buffer. -/
theorem wotsSecretBuf_eq (sk tag l t k c : List Std.U8)
    (hs : sk.length = 32) (hg : tag.length = 4) (hl : l.length = 4)
    (ht : t.length = 8) (hk : k.length = 4) (hc : c.length = 4) :
    ((((((List.replicate 80 0#u8).setSlice! 0 sk).setSlice! 32 tag).setSlice! 36 l
        ).setSlice! 64 t).setSlice! 72 k).setSlice! 76 c
      = sk ++ tag ++ l ++ (List.replicate 24 0#u8 ++ t) ++ k ++ c := by
  apply List.ext_getElem!
  · simp [List.length_setSlice!, List.length_append, List.length_replicate, *]
  intro j
  by_cases h0 : j < 32
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hs, hg, hl, ht, hk, hc] <;> omega
  by_cases h1 : j < 36
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hs, hg, hl, ht, hk, hc] <;> omega
  by_cases h2 : j < 40
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hs, hg, hl, ht, hk, hc] <;> omega
  by_cases h3 : j < 64
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hs, hg, hl, ht, hk, hc] <;> omega
  by_cases h4 : j < 72
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hs, hg, hl, ht, hk, hc] <;> omega
  by_cases h5 : j < 76
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hs, hg, hl, ht, hk, hc] <;> omega
  by_cases h6 : j < 80
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hs, hg, hl, ht, hk, hc] <;> omega
  · simp_lists [List.length_replicate, *] <;> (try (congr 1)) <;>
      simp only [List.length_append, List.length_replicate, hs, hg, hl, ht, hk, hc] <;> omega

set_option maxHeartbeats 4000000 in
@[step] theorem wots_secret_spec (sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp chain : Std.U32) :
    hash.wots_secret sk layer tree kp chain ⦃ r => r = wotsSecretPure sk layer tree kp chain ⦄ := by
  have l_sk : sk.val.length = 32 := by have := sk.property; simp_all
  have l_t : (tree.bv.toBEBytes.map (@UScalar.mk .U8)).length = 8 := by
    rw [List.length_map, BitVec.toBEBytes_length]
  have l4 : ∀ x : Std.U32, (x.bv.toBEBytes.map (@UScalar.mk .U8)).length = 4 := by
    intro x; rw [List.length_map, BitVec.toBEBytes_length]
  unfold hash.wots_secret
  step* <;>
    first
    | scalar_tac
    | (simp only [Slice.length, Array.length_to_slice] at *; scalar_tac)
    | skip
  have hbuf : (s18 : List Std.U8) = wotsSecretPreimage sk layer tree kp chain := by
    simp only [s18_post, s17_post, s16_post, s15_post3, s14_post, s13_post, s12_post3,
               s11_post, s10_post, s9_post3, s8_post, s7_post, s6_post3, s5_post, s4_post,
               s3_post3, s2_post, s1_post, s_post3, a_post, a1_post, a2_post, a3_post,
               Array.val_to_slice, Array.repeat_val, Array.make]
    norm_num
    rw [wotsSecretBuf_eq _ _ _ _ _ _ l_sk (by rfl) (l4 layer) l_t (l4 kp) (l4 chain),
      u32_toBEBytes_map_mk, u32_toBEBytes_map_mk, u32_toBEBytes_map_mk]
    simp only [wotsSecretPreimage, wotsTreeBytes, List.append_assoc]
  rw [r_post, hbuf]
  rfl

end Extracted.Equiv
