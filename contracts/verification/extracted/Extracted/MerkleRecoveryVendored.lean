/- Faithful verifier definitions for XMSS recovery; each declaration is
   enrolled in the vendored-source fidelity gate. -/
import Extracted.WotsRecoveryVendored

namespace SphincsCVerify.Spec
open ByteVec

def SubtreeH : Nat := 9

def ADRS_TREE : Nat := 2

namespace Adrs

def treeNode (layer : UInt32) (tree : UInt64) (height parentIdx : UInt32) : Adrs :=
  make layer tree (UInt32.ofNat ADRS_TREE) 0 0 height parentIdx

end Adrs

def thPair (seed : ByteVec 32) (a : Adrs) (left right : ByteVec 32) : ByteVec 16 :=
  truncate16 (sha256 [
    ByteSeg.ofByteVec seed,
    ByteSeg.ofByteVec a,
    ByteSeg.ofByteVec left,
    ByteSeg.ofByteVec right])

namespace Hypertree

def verifyAuthPath
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (leafNode : ByteVec 16) (leafIdx : Nat)
    (authPath : Array (ByteVec 16)) : ByteVec 16 := Id.run do
  let mut node := leafNode
  let mut idx := leafIdx
  for h in [:SubtreeH] do
    let parentIdx := idx / 2
    let adrs := Adrs.treeNode layer tree (UInt32.ofNat (h + 1)) (UInt32.ofNat parentIdx)
    let sibling := authPath.getD h (zero 16)
    if idx % 2 == 0 then
      node := thPair seed adrs (pad16 node) (pad16 sibling)
    else
      node := thPair seed adrs (pad16 sibling) (pad16 node)
    idx := parentIdx
  pure node

end Hypertree
end SphincsCVerify.Spec
