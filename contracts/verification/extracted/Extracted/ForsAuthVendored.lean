/- Faithful FORS authentication path definitions; source-fidelity checked. -/
import Extracted.ForsRootVendored

namespace SphincsCVerify.Spec

def sibIdx (leafIdx h : Nat) : Nat :=
  let p := leafIdx / 2 ^ h
  if p % 2 = 0 then p + 1 else p - 1

def forsMtAuthPath (seed : ByteVec 32) (htIdx : UInt64) (treeIdx : UInt32) (lf : Nat → ByteVec 16)
    (leafIdx : Nat) : Array (ByteVec 16) :=
  Array.ofFn (n := Spec.A) fun h => forsMtNode seed htIdx treeIdx lf h.val (sibIdx leafIdx h.val)

end SphincsCVerify.Spec
