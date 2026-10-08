/- Exact input construction of the extracted H_msg caller. The provided
   sha256_parts model is an explicit backend boundary, like sha256_bytes;
   neither backend correctness nor cryptographic hardness is proved here. -/
import Extracted.Hash.Funs
import Extracted.HashPure

open Aeneas Aeneas.Std Result

namespace sphincs_c10

/-- All four words retain their order and all 32 FF domain bytes are hashed.
    The result is the full SHA-256 digest, without 16-byte truncation. -/
theorem hash.h_msg_spec (seed root r message : Std.Array Std.U8 32#usize) :
    hash.h_msg seed root r message = ok (sha256_pure
      (seed.val ++ root.val ++ r.val ++ message.val ++ List.replicate 32 255#u8)) := by
  simp [hash.h_msg, hash.sha256_parts, Array.to_slice, Array.make,
    Array.repeat, lift, List.append_assoc]

end sphincs_c10
