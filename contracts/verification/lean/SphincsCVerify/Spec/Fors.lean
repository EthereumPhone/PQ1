/-
FORS+C: Forest of Random Subsets with forced-zero last-index Constraint.

Mirrors `sphincs-c10/src/fors.rs`. FORS consists of K=13 independent
Merkle trees of height A=11. The message digest selects one leaf per
tree via A-bit indices. The last tree's index is forced to zero by
R-grinding, so its authentication path can be omitted (saving 176 bytes
per signature).
-/

import SphincsCVerify.Spec.Hash
import SphincsCVerify.Spec.Adrs
import SphincsCVerify.Spec.Params
import SphincsCVerify.Util.Bits

namespace SphincsCVerify.Spec.Fors

open SphincsCVerify.Spec
open SphincsCVerify.Util
open ByteVec

/-- A FORS+C signature component for one tree: secret leaf + auth path. -/
structure TreeSig where
  secret : ByteVec 16
  authPath : Array (ByteVec 16)  -- length A
  authPathLen : authPath.size = A

/-- The full FORS+C signature carries K secrets and K-1 auth paths
    (the last tree's auth path is empty by forced-zero). -/
structure ForsSig where
  secrets : Array (ByteVec 16)  -- length K
  secretsLen : secrets.size = K
  authPaths : Array (Array (ByteVec 16))  -- length K-1, each inner = A
  authPathsLen : authPaths.size = K - 1

/-- Reconstruct a FORS tree root from `(secret, authPath, leafIdx)`.

    Mirrors `reconstruct_fors_root` in `sphincs-c10/src/hypertree.rs`. -/
def reconstructRoot
    (seed : ByteVec 32) (treeIdx : UInt32) (leafIdx : UInt32)
    (secret : ByteVec 16)
    (authPath : Array (ByteVec 16)) : ByteVec 16 := Id.run do
  let leafAdrs := Adrs.forsNode treeIdx 0 leafIdx
  let mut node := th seed leafAdrs (pad16 secret)
  let mut pathIdx := leafIdx.toNat
  for h in [:A] do
    let parentIdx := pathIdx / 2
    let adrs :=
      Adrs.forsNode treeIdx (UInt32.ofNat (h + 1)) (UInt32.ofNat parentIdx)
    let sibling := authPath.getD h (zero 16)
    if pathIdx % 2 == 0 then
      node := thPair seed adrs (pad16 node) (pad16 sibling)
    else
      node := thPair seed adrs (pad16 sibling) (pad16 node)
    pathIdx := parentIdx
  pure node

/-- Compute the FORS public key from all K tree roots. -/
def computeForsPk (seed : ByteVec 32) (roots : Array (ByteVec 16)) : ByteVec 16 :=
  thMulti seed Adrs.forsRoots roots.toList

/-- The FORS+C verifier-side reconstruction.

    Returns `none` iff the forced-zero constraint on the last index
    is violated (the Solidity verifier `revert(0,0)`s in this case). -/
def reconstructForsPk
    (seed : ByteVec 32) (digest : ByteVec 32)
    (sig : ForsSig) : Option (ByteVec 16) :=
  let indices := extractForsIndices digest
  -- Forced-zero check.
  if indices.getD (K - 1) 0 ≠ 0 then
    none
  else
    -- Reconstruct K-1 normal trees.
    let normalRoots : Array (ByteVec 16) :=
      Array.ofFn (n := K - 1) fun t =>
        let treeIdx := UInt32.ofNat t.val
        let leafIdx := UInt32.ofNat (indices.getD t.val 0)
        let secret := sig.secrets.getD t.val (zero 16)
        let authPath := sig.authPaths.getD t.val #[]
        reconstructRoot seed treeIdx leafIdx secret authPath
    -- Last tree: secret IS the root (leaf-only hash, no auth path).
    let lastAdrs := Adrs.forsNode (UInt32.ofNat (K - 1)) 0 0
    let lastSecret := sig.secrets.getD (K - 1) (zero 16)
    let lastRoot := th seed lastAdrs (pad16 lastSecret)
    let allRoots := normalRoots.push lastRoot
    some (computeForsPk seed allRoots)

end SphincsCVerify.Spec.Fors
