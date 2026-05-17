/-
Verifier/Refined: the offset-indexed Lean model of the Solidity verifier.

This module mirrors `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol`
byte-for-byte. It indexes directly into the calldata layout rather than
through the structured `Spec.Signature` form. Two reasons for the
duplication:

  1. The equivalence theorem `Refined.verify = Spec.verify` is the
     refinement obligation that Verity-style verified compilation
     ultimately discharges — making the offset-indexed shape explicit
     in Lean lets us state and prove it without first executing the
     Solidity compiler.

  2. The Solidity verifier's correctness rests on specific offset
     arithmetic (the `AUTH_START = 224`, `HT_START = 2336`,
     `countOff = sigOff + 688`, etc. constants). Stating these as Lean
     `def`s and proving them consistent with the parameter values pins
     down the layout and catches drift between Solidity and Rust.

Reference: `SPHINCsC10Asm.sol`. Each Yul block in that file corresponds
to one helper here.
-/

import SphincsCVerify.Spec.Hash
import SphincsCVerify.Spec.Adrs
import SphincsCVerify.Spec.Params
import SphincsCVerify.Util.Bits

namespace SphincsCVerify.Verifier.Refined

open SphincsCVerify.Spec
open SphincsCVerify.Util
open ByteVec

/-! ## Hard-coded offsets matching `SPHINCsC10Asm.sol`. -/

/-- Start offset of FORS auth paths within the signature.
    Solidity: `AUTH_START = 224` (= 16 R + 13*16 secrets). -/
def AUTH_START : Nat := 224

/-- Per-FORS-tree auth-path size in bytes.
    Solidity: `auth per tree = 11*16 = 176`. -/
def AUTH_PER_TREE : Nat := A * N

/-- Start offset of the first hypertree layer.
    Solidity: `HT_START = 2336`. -/
def HT_START : Nat := SigForsTotal

/-- Per-HT-layer offsets within a layer footprint:
    chains: [0, L*N)
    count: [L*N, L*N+4)
    auth: [L*N+4, L*N+4+SubtreeH*N).

    Solidity: `countOff = sigOff + 688`, `authOff = countOff + 4`. -/
def COUNT_OFFSET_IN_LAYER : Nat := L * N
def AUTH_OFFSET_IN_LAYER : Nat := L * N + 4

theorem auth_start_consistent : AUTH_START = N + K * N := by decide
theorem ht_start_consistent : HT_START = SigForsTotal := rfl
theorem count_offset_consistent : COUNT_OFFSET_IN_LAYER = 688 := by decide

/-! ## Calldata window helpers

The verifier reads 32-byte (`bytes32`) words from calldata at byte
offsets using `calldataload`. We model this with `loadWord32` and the
N-mask AND with `loadWord32_NMask`. -/

/-- Load a 32-byte word from a calldata-shaped byte vector at `offset`.
    Out-of-bounds reads return zero (matches `calldataload`'s
    zero-padding behaviour). -/
def loadWord32 {n : Nat} (sig : ByteVec n) (offset : Nat) : ByteVec 32 :=
  if h : offset + 32 ≤ n then
    ⟨sig.data.extract offset (offset + 32), by
      have hsize : sig.data.size = n := sig.size_eq
      simp [Array.size_extract, hsize, Nat.min_eq_left h]⟩
  else
    zero 32

/-- Load a 16-byte (N-masked) value: top 16 bytes of the 32-byte word at
    `offset`. -/
def loadValue16 {n : Nat} (sig : ByteVec n) (offset : Nat) : ByteVec 16 :=
  (loadWord32 sig offset).take 16 (by decide)

/-- Load a `UInt32` (big-endian) at `offset`. Used for the per-layer
    count field. -/
def loadU32BE {n : Nat} (sig : ByteVec n) (offset : Nat) : UInt32 :=
  let b0 := if h : offset < n then sig.get ⟨offset, h⟩ else 0
  let b1 := if h : offset + 1 < n then sig.get ⟨offset+1, h⟩ else 0
  let b2 := if h : offset + 2 < n then sig.get ⟨offset+2, h⟩ else 0
  let b3 := if h : offset + 3 < n then sig.get ⟨offset+3, h⟩ else 0
  (UInt32.ofNat b0.toNat <<< 24) |||
  (UInt32.ofNat b1.toNat <<< 16) |||
  (UInt32.ofNat b2.toNat <<< 8) |||
  (UInt32.ofNat b3.toNat)

/-! ## The refined verifier

Mirrors the Yul control flow of `SPHINCsC10Asm.verify` exactly.

We split the implementation into per-section helpers to keep the
top-level loop readable and provable. Each helper corresponds to one
Yul block. -/

/-- Reconstruct one normal-FORS-tree's root from the byte signature. -/
def reconstructForsTreeRoot
    {n : Nat} (sig : ByteVec n) (seed : ByteVec 32) (digest : ByteVec 32)
    (i : Nat) : ByteVec 16 := Id.run do
  let treeIdx := readBitsLe digest (i * A) A
  let secretOff := N + i * N
  let secretVal := loadValue16 sig secretOff
  let leafAdrs := Adrs.forsNode (UInt32.ofNat i) 0 (UInt32.ofNat treeIdx)
  let mut node := th seed leafAdrs (pad16 secretVal)
  let mut pathIdx := treeIdx
  let authPtr := AUTH_START + i * AUTH_PER_TREE
  for h in [:A] do
    let sibling := loadValue16 sig (authPtr + h * N)
    let parentIdx := pathIdx / 2
    let adrs := Adrs.forsNode (UInt32.ofNat i) (UInt32.ofNat (h + 1)) (UInt32.ofNat parentIdx)
    if pathIdx % 2 == 0 then
      node := thPair seed adrs (pad16 node) (pad16 sibling)
    else
      node := thPair seed adrs (pad16 sibling) (pad16 node)
    pathIdx := parentIdx
  pure node

/-- Compress the FORS section of the byte signature into the FORS PK. -/
def reconstructForsPkRefined
    {n : Nat} (sig : ByteVec n) (seed : ByteVec 32) (digest : ByteVec 32) :
    ByteVec 16 := Id.run do
  let mut forsRoots : Array (ByteVec 16) := #[]
  for i in [:K-1] do
    forsRoots := forsRoots.push (reconstructForsTreeRoot sig seed digest i)
  let lastSecretOff := N + (K - 1) * N
  let lastSecret := loadValue16 sig lastSecretOff
  let lastAdrs := Adrs.forsNode (UInt32.ofNat (K - 1)) 0 0
  forsRoots := forsRoots.push (th seed lastAdrs (pad16 lastSecret))
  pure (thMulti seed Adrs.forsRoots forsRoots.toList)

/-- Walk one hypertree-layer's WOTS+C and subtree-Merkle reconstruction.
    Returns `(newNode, newSigOff, ok)`. `ok = false` iff the digit-sum
    check failed in that layer. -/
def hypertreeLayerStep
    {n : Nat} (sig : ByteVec n) (seed : ByteVec 32)
    (layer : Nat) (idxTree idxLeaf : Nat) (currentNode : ByteVec 16)
    (sigOff : Nat) : Option (ByteVec 16) := Id.run do
  let wotsAdrs := Adrs.wots (UInt32.ofNat layer) (UInt64.ofNat idxTree) (UInt32.ofNat idxLeaf)
  let countOff := sigOff + COUNT_OFFSET_IN_LAYER
  let count := loadU32BE sig countOff
  let d := wotsDigest seed wotsAdrs (pad16 currentNode) count
  let digits := extractDigits d
  if digitSum digits ≠ TargetSum then
    pure none
  else
    let mut endpoints : Array (ByteVec 16) := #[]
    for i in [:L] do
      let digit := digits[i]!
      let steps := (W - 1) - digit
      let val := loadValue16 sig (sigOff + i * N)
      let chainAdrs := Adrs.setChainIndex wotsAdrs (UInt32.ofNat i)
      let endpoint := chainHash seed chainAdrs val digit steps
      endpoints := endpoints.push endpoint
    let pkAdrs := Adrs.wotsPk (UInt32.ofNat layer) (UInt64.ofNat idxTree) (UInt32.ofNat idxLeaf)
    let wotsPk := thMulti seed pkAdrs endpoints.toList
    let mut node := wotsPk
    let mut mIdx := idxLeaf
    let authOff := sigOff + AUTH_OFFSET_IN_LAYER
    for h in [:SubtreeH] do
      let sibling := loadValue16 sig (authOff + h * N)
      let parentIdx := mIdx / 2
      let adrs := Adrs.treeNode (UInt32.ofNat layer) (UInt64.ofNat idxTree)
        (UInt32.ofNat (h + 1)) (UInt32.ofNat parentIdx)
      if mIdx % 2 == 0 then
        node := thPair seed adrs (pad16 node) (pad16 sibling)
      else
        node := thPair seed adrs (pad16 sibling) (pad16 node)
      mIdx := parentIdx
    pure (some node)

/-- Verify a signature using offset arithmetic (Solidity-style).

    Refines `Spec.Signature.verify` (proved in `Verifier/Equivalence.lean`). -/
def verifyRefined
    (pkSeed pkRoot : ByteVec 32)
    (message : ByteVec 32)
    (sig : ByteVec SignatureLen) : Bool := Id.run do
  let seed := pkSeed
  let r := loadValue16 sig 0
  let rB32 := pad16 r
  let digest := hMsg seed pkRoot rB32 message
  let lastIdx := readBitsLe digest ((K - 1) * A) A
  if lastIdx ≠ 0 then
    pure false
  else
    let htIdx := extractHtIndex digest
    let forsPk := reconstructForsPkRefined sig seed digest
    let mut currentNode := forsPk
    let mut idxTree := htIdx
    let mut sigOff := HT_START
    let mut bad := false
    for layer in [:D] do
      if bad then
        pure ()
      else
        let idxLeaf := idxTree &&& ((1 <<< SubtreeH) - 1)
        idxTree := idxTree >>> SubtreeH
        match hypertreeLayerStep sig seed layer idxTree idxLeaf currentNode sigOff with
        | none => bad := true
        | some node =>
          currentNode := node
          sigOff := sigOff + AUTH_OFFSET_IN_LAYER + SubtreeH * N
    if bad then
      pure false
    else
      let pkRootValue := pkRoot.take 16 (by decide)
      pure (decide (currentNode = pkRootValue))

end SphincsCVerify.Verifier.Refined
