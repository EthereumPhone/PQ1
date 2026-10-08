/- Faithful verifier definitions for thirteen-root FORS compression. -/
import Extracted.ForsRecoveryVendored
namespace SphincsCVerify.Spec

def ADRS_FORS_ROOTS : Nat := 4

namespace Adrs

def forsRoots (htIdx : UInt64) : Adrs :=
  make 0 htIdx (UInt32.ofNat ADRS_FORS_ROOTS) 0 0 0 0

end Adrs
namespace Fors

def computeForsPk (seed : ByteVec 32) (htIdx : UInt64) (roots : Array (ByteVec 16)) : ByteVec 16 :=
  thMulti seed (Adrs.forsRoots htIdx) roots.toList

end Fors
end SphincsCVerify.Spec
