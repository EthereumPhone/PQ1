/- Faithful verifier definitions for FORS single-tree recovery. -/
import Extracted.MerkleRecoveryVendored
namespace SphincsCVerify.Spec
open ByteVec

def ADRS_FORS_TREE : Nat := 3

namespace Adrs

def forsNode (htIdx : UInt64) (treeIdx height parentIdx : UInt32) : Adrs :=
  make 0 htIdx (UInt32.ofNat ADRS_FORS_TREE) treeIdx 0 height parentIdx

end Adrs

namespace Fors

def reconstructRoot
    (seed : ByteVec 32) (htIdx : UInt64) (treeIdx : UInt32) (leafIdx : UInt32)
    (secret : ByteVec 16)
    (authPath : Array (ByteVec 16)) : ByteVec 16 := Id.run do
  let leafAdrs := Adrs.forsNode htIdx treeIdx 0 leafIdx
  let mut node := th seed leafAdrs (pad16 secret)
  let mut pathIdx := leafIdx.toNat
  for h in [:A] do
    let parentIdx := pathIdx / 2
    let adrs :=
      Adrs.forsNode htIdx treeIdx (UInt32.ofNat (h + 1)) (UInt32.ofNat parentIdx)
    let sibling := authPath.getD h (zero 16)
    if pathIdx % 2 == 0 then
      node := thPair seed adrs (pad16 node) (pad16 sibling)
    else
      node := thPair seed adrs (pad16 sibling) (pad16 node)
    pathIdx := parentIdx
  pure node

end Fors
end SphincsCVerify.Spec
