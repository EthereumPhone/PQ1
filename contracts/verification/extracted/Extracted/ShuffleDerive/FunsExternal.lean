/- The software SHA streaming backend is supplied, while the seed branch and
   ordered slice construction are extracted. This does not verify RustCrypto,
   hardware hashing, physical erasure or leakage. -/
import Extracted.SignForest.Types
import Extracted.Sha256Pure

open Aeneas Aeneas.Std Result
namespace sphincs_c10

def shuffle.shuffle_hash_parts (parts : Slice (Slice Std.U8)) :
    Result (Std.Array Std.U8 32#usize) :=
  ok (sha256_pure ((parts.val.map (fun part => part.val)).flatten))

end sphincs_c10
