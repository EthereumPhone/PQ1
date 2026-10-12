/- Faithful verifier hypertree definitions; Rust's zero-sentinel model stays separate. -/
import Extracted.MerkleRecoveryVendored
import Extracted.ForsPrefixVendored
namespace SphincsCVerify.Spec
def D : Nat := 2
namespace Hypertree
open SphincsCVerify.Spec Wots Fors SphincsCVerify.Util ByteVec

structure LayerSig where
  wots : Wots.Sigma
  authPath : Array (ByteVec 16)
  authPathLen : authPath.size = SubtreeH

def defaultLayerSig : LayerSig :=
  { wots := { chains := Array.replicate L (zero 16),
              chainsLen := Array.size_replicate,
              count := 0 },
    authPath := Array.replicate SubtreeH (zero 16),
    authPathLen := Array.size_replicate }

def verifyHypertree
    (seed : ByteVec 32) (forsPk : ByteVec 16) (htIdx : Nat)
    (layers : Array LayerSig) : Option (ByteVec 16) := Id.run do
  let mut currentNode := forsPk
  let mut idxTree := htIdx
  let mut bad : Bool := false
  let subtreeMask : Nat := (1 <<< SubtreeH) - 1
  for layer in [:D] do
    if bad then
      pure ()
    else
      let idxLeaf := idxTree &&& subtreeMask
      idxTree := idxTree >>> SubtreeH
      let layerSig := layers.getD layer defaultLayerSig
      let layer32 := UInt32.ofNat layer
      let tree64 := UInt64.ofNat idxTree
      let leaf32 := UInt32.ofNat idxLeaf
      match Wots.pkFromSig seed layer32 tree64 leaf32 currentNode layerSig.wots with
      | none => bad := true
      | some wotsPk =>
        currentNode := verifyAuthPath seed layer32 tree64 wotsPk idxLeaf layerSig.authPath
  if bad then pure none else pure (some currentNode)
end Hypertree
end SphincsCVerify.Spec
