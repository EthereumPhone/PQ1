/- Exact FORS secret declaration from the corrected verifier reference;
   checked by the complete vendored-fidelity inventory. -/
import Extracted.WotsRecoveryVendored

namespace SphincsCVerify.Spec
namespace ByteVec

def forsTag : ByteVec 4 :=
  ⟨#[0x66, 0x6F, 0x72, 0x73], by simp⟩  -- "fors"

end ByteVec
open ByteVec

def forsSecret
    (skSeed : ByteVec 32) (htIdx treeIdx leafIdx : UInt32) : ByteVec 16 :=
  truncate16 (sha256 [
    ByteSeg.ofByteVec skSeed,
    ByteSeg.ofByteVec forsTag,
    ByteSeg.ofByteVec (ofU32BE htIdx),
    ByteSeg.ofByteVec (ofU32BE treeIdx),
    ByteSeg.ofByteVec (ofU32BE leafIdx)])

end SphincsCVerify.Spec
