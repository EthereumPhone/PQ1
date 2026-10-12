/- Faithful XMSS path definition, sharing the checked sibling selector. -/
import Extracted.XmssRootVendored
import Extracted.ForsAuthVendored

namespace SphincsCVerify.Spec

def mtAuthPath (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (lf : Nat → ByteVec 16)
    (leafIdx : Nat) : Array (ByteVec 16) :=
  Array.ofFn (n := Spec.SubtreeH) fun h => mtNode seed layer tree lf h.val (sibIdx leafIdx h.val)

end SphincsCVerify.Spec
