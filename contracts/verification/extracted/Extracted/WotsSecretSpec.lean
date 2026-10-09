/- Actual WOTS secret derivation: all 80 preimage bytes, full-width position
   fields, and 16-byte truncation under the existing supplied SHA backend. -/
import Extracted.WotsSecret.Funs
import Extracted.HashSpecs.WotsDigest
import Extracted.HashSpecs.Truncate

open Aeneas Aeneas.Std Result
open Extracted.SetSlice
set_option maxRecDepth 4096
set_option maxHeartbeats 800000
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

@[step] theorem u64_to_b32_spec (tree : Std.U64) :
    hash.u64_to_b32 tree ⦃ r => r.val = wotsTreeBytes tree ⦄ := by
  unfold hash.u64_to_b32
  step
  step
  step
  step
  simp only [r_post3, s2_post, s1_post, Array.val_to_slice, a_post, Array.repeat_val]
  exact rightAlign_word 24 _ (by simp [BitVec.toBEBytes_length]) (by decide)

@[step] theorem wots_secret_spec (sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp chain : Std.U32) :
    hash.wots_secret sk layer tree kp chain ⦃ r => r = wotsSecretPure sk layer tree kp chain ⦄ := by
  unfold hash.wots_secret
  step
  simp only [lift, Array.to_slice, Array.make, core.num.U32.to_be_bytes,
    hash.sha256_parts, bind_tc_ok, List.map_cons, List.map_nil,
    List.flatten_cons, List.flatten_nil, List.append_nil, tree_b32_post]
  let* ⟨r, hr⟩ ← hash.truncate_spec _
  simpa only [wotsSecretPure, wotsSecretPreimage, u32_toBEBytes_map_mk,
    List.append_assoc] using hr

end Extracted.Equiv
