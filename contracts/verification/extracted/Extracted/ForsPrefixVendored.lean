/- Faithful full FORS reconstruction definition; backend/whole-session claims stay separate. -/
import Extracted.ForsForestVendored
namespace SphincsCVerify.Spec.Fors
open SphincsCVerify.Spec SphincsCVerify.Util ByteVec

structure ForsSig where
  secrets : Array (ByteVec 16)  -- length K
  secretsLen : secrets.size = K
  authPaths : Array (Array (ByteVec 16))  -- length K-1, each inner = A
  authPathsLen : authPaths.size = K - 1

def reconstructForsPk
    (seed : ByteVec 32) (digest : ByteVec 32)
    (sig : ForsSig) : Option (ByteVec 16) :=
  let indices := extractForsIndices digest
  let htIdx : UInt64 := UInt64.ofNat (extractHtIndex digest)
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
        reconstructRoot seed htIdx treeIdx leafIdx secret authPath
    -- Last tree: secret IS the root (leaf-only hash, no auth path).
    let lastAdrs := Adrs.forsNode htIdx (UInt32.ofNat (K - 1)) 0 0
    let lastSecret := sig.secrets.getD (K - 1) (zero 16)
    let lastRoot := th seed lastAdrs (pad16 lastSecret)
    let allRoots := normalRoots.push lastRoot
    some (computeForsPk seed htIdx allRoots)

end SphincsCVerify.Spec.Fors
