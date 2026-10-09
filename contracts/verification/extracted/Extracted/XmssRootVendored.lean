/- Faithful recursive XMSS tree definition; source-fidelity checked. -/
import Extracted.WotsKeygenVendored
import Extracted.MerkleRecoveryVendored

namespace SphincsCVerify.Spec

def mtNode (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (lf : Nat → ByteVec 16) :
    Nat → Nat → ByteVec 16
  | 0, idx => lf idx
  | (ℓ + 1), idx =>
      Spec.thPair seed (Spec.Adrs.treeNode layer tree (UInt32.ofNat (ℓ + 1)) (UInt32.ofNat idx))
        (ByteVec.pad16 (mtNode seed layer tree lf ℓ (2 * idx)))
        (ByteVec.pad16 (mtNode seed layer tree lf ℓ (2 * idx + 1)))

end SphincsCVerify.Spec
