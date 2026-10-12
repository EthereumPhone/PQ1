/- Faithful FORS tree and signer slot definitions; source-fidelity checked. -/
import Extracted.ForsSecretVendored
import Extracted.ForsRecoveryVendored

namespace SphincsCVerify.Spec
open ByteVec

def forsMtNode (seed : ByteVec 32) (htIdx : UInt64) (treeIdx : UInt32) (lf : Nat → ByteVec 16) :
    Nat → Nat → ByteVec 16
  | 0, idx =>
      Spec.th seed (Spec.Adrs.forsNode htIdx treeIdx 0 (UInt32.ofNat idx)) (ByteVec.pad16 (lf idx))
  | (ℓ + 1), idx =>
      Spec.thPair seed (Spec.Adrs.forsNode htIdx treeIdx (UInt32.ofNat (ℓ + 1)) (UInt32.ofNat idx))
        (ByteVec.pad16 (forsMtNode seed htIdx treeIdx lf ℓ (2 * idx)))
        (ByteVec.pad16 (forsMtNode seed htIdx treeIdx lf ℓ (2 * idx + 1)))


namespace Signer
def forsSigningValue (seed skSeed : ByteVec 32) (htIdx treeIdx leafIdx : Nat) :
    ByteVec 16 :=
  if treeIdx = K - 1 then
    forsMtNode seed (UInt64.ofNat htIdx) (UInt32.ofNat treeIdx)
      (fun j => forsSecret skSeed (UInt32.ofNat htIdx) (UInt32.ofNat treeIdx)
        (UInt32.ofNat j)) A 0
  else
    forsSecret skSeed (UInt32.ofNat htIdx) (UInt32.ofNat treeIdx)
      (UInt32.ofNat leafIdx)


end Signer
end SphincsCVerify.Spec
