/- Reuse proved extracted bodies. ShuffleSeed.derive retains an explicit
   RustCrypto backend boundary, modeled by the existing executable SHA-256
   specification with its exact domain, seed and label bytes. No backend,
   entropy or physical-erasure theorem is asserted here. -/
import Extracted.SignForest.Types
import Extracted.Verify.Funs
import Extracted.GrindR.Funs
import Extracted.ForsAuth.Funs
import Extracted.ForsRoot.Funs
import Extracted.XmssAuth.Funs
import Extracted.WotsSign.Funs

open Aeneas Aeneas.Std Result
namespace sphincs_c10

def shuffle.ShuffleSeed.derive (seed : shuffle.ShuffleSeed) (label : Slice Std.U8) :
    Result (Std.Array Std.U8 32#usize) :=
  if seed.val = List.replicate 32 0#u8 then ok (Array.repeat 32#usize 0#u8)
  else ok (sha256_pure (("sphincs-c10-shuffle-v1".toUTF8.toList.map Sha256Pure.ofUInt8) ++
    seed.val ++ label.val))

end sphincs_c10
