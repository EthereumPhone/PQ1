/-
Hypertree: the top-level structure combining FORS+C and a D=2 layer
XMSS hypertree.

Mirrors `sphincs-c10/src/hypertree.rs::verify`. The verifier walks two
hypertree layers; in each it WOTS+C-verifies the current node to recover
a WOTS public key, then walks the SubtreeH=9 auth path to a subtree
root. After the second layer, the result is compared against `pk_root`.
-/

import SphincsCVerify.Spec.Hash
import SphincsCVerify.Spec.Adrs
import SphincsCVerify.Spec.Params
import SphincsCVerify.Spec.Wots
import SphincsCVerify.Spec.Fors
import SphincsCVerify.Util.Bits

namespace SphincsCVerify.Spec.Hypertree

open SphincsCVerify.Spec
open SphincsCVerify.Spec.Wots
open SphincsCVerify.Spec.Fors
open SphincsCVerify.Util
open ByteVec

/-- One hypertree layer's signature component: a WOTS+C signature plus
    a subtree authentication path. -/
structure LayerSig where
  wots : Wots.Sigma
  authPath : Array (ByteVec 16)
  authPathLen : authPath.size = SubtreeH

/-- The top-level SPHINCS+C10 signature: R || FORS || HT_layer0 || HT_layer1. -/
structure Signature where
  r : ByteVec 16
  fors : Fors.ForsSig
  layers : Array LayerSig
  layersLen : layers.size = D

/-- Verify a Merkle authentication path: reconstruct the root from a
    leaf node and its auth path. Mirrors `verify_auth_path` in `merkle.rs`. -/
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

/-- A default `LayerSig` used for out-of-bounds reads in the spec. The
    verifier's caller has the size invariant `layers.size = D = 2`, so
    this default is never observed in well-typed inputs. -/
def defaultLayerSig : LayerSig :=
  { wots := { chains := Array.replicate L (zero 16),
              chainsLen := Array.size_replicate,
              count := 0 },
    authPath := Array.replicate SubtreeH (zero 16),
    authPathLen := Array.size_replicate }

/-- The verifier-side hypertree walk. Returns the reconstructed root, or
    `none` if any layer's WOTS+C target-sum check fails. -/
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

/-- The top-level SPHINCS+C10 verify routine.

    Mirrors `sphincs-c10/src/hypertree.rs::verify` and the Solidity
    `SPHINCsC10Asm.verify`. Returns `true` iff the reconstructed root
    matches the supplied `pkRoot`. -/
def verify
    (pkSeed pkRoot : ByteVec 16)
    (msgHash : ByteVec 32)
    (sig : Signature) : Bool :=
  let seed := pad16 pkSeed
  let root := pad16 pkRoot
  let rB32 := pad16 sig.r
  let digest := hMsg seed root rB32 msgHash
  let indices := extractForsIndices digest
  let htIdx := extractHtIndex digest
  if indices.getD (K - 1) 0 ≠ 0 then
    false
  else
    match Fors.reconstructForsPk seed digest sig.fors with
    | none => false
    | some forsPk =>
      match verifyHypertree seed forsPk htIdx sig.layers with
      | none => false
      | some finalRoot => decide (finalRoot = pkRoot)

end SphincsCVerify.Spec.Hypertree
