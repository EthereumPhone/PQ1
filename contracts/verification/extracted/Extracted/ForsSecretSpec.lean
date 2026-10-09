/- Actual FORS secret derivation: all 48 preimage bytes, including full-width
   hypertree position, and truncation under the existing supplied SHA backend. -/
import Extracted.ForsSecret.Funs
import Extracted.HashSpecs.WotsDigest
import Extracted.HashSpecs.Truncate

open Aeneas Aeneas.Std Result
set_option maxRecDepth 4096
set_option maxHeartbeats 800000
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

@[step] theorem fors_secret_spec (sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) :
    hash.fors_secret sk ht tree leaf ⦃ r => r = forsSecretPure sk ht tree leaf ⦄ := by
  unfold hash.fors_secret
  simp only [lift, Array.to_slice, Array.make, core.num.U32.to_be_bytes,
    hash.sha256_parts, bind_tc_ok, List.map_cons, List.map_nil,
    List.flatten_cons, List.flatten_nil, List.append_nil]
  let* ⟨r, hr⟩ ← hash.truncate_spec _
  simpa only [forsSecretPure, forsSecretPreimage, u32_toBEBytes_map_mk,
    List.append_assoc] using hr

end Extracted.Equiv
