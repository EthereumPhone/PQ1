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
import SphincsCVerify.Spec.Signature
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

The byte-extraction primitives `loadWord32`, `loadValue16`, and
`loadU32BE` are defined once in `Spec/Bytes.lean` and re-exported here
under the `Refined` namespace. Sharing the underlying definitions
is what lets `Verifier/Equivalence.lean::load_R_consistent` discharge
by `rfl`. -/

export ByteVec (loadWord32 loadValue16 loadU32BE)

/-! ## The refined verifier

The "byte-offset shape" of the Yul implementation lives entirely in
`Spec.Signature.deserialise` (see `Spec/Signature.lean`): that function
indexes `sig` at the same offsets the Yul body indexes calldata,
producing a structured `Hypertree.Signature`.

This file then assembles the per-section helpers (`reconstructFors…`,
`hypertreeLayer…`) and the top-level `verifyRefined` as the composition
of `deserialise` with the structural verifier `Hypertree.verify`. Doing
so makes the Yul-shape ↔ spec refinement closeable by `rfl` (see
`Verifier/Equivalence.lean::verifyRefined_eq_spec`) while keeping every
calldata offset visible in `deserialise`.

The per-helper definitions below are kept so call-sites looking up
"reconstruct one FORS tree root from bytes" still find a primitive at
the same name, but each is now defined in terms of the structural
operation from `Spec/Fors.lean` and `Spec/Hypertree.lean`. -/

/-- Reconstruct one normal-FORS-tree's root from the byte signature.

    Re-expressed as the structural FORS reconstruction applied at the
    `i`-th tree of the deserialised signature; the Yul body of this
    reconstruction is the inner loop of `SPHINCsC10Asm.verify` at
    lines 90-118. -/
def reconstructForsTreeRoot
    (sig : ByteVec SignatureLen) (seed : ByteVec 32) (digest : ByteVec 32)
    (i : Nat) : ByteVec 16 :=
  let dec := Spec.Signature.deserialise sig
  let indices := extractForsIndices digest
  let leafIdx := UInt32.ofNat (indices.getD i 0)
  Fors.reconstructRoot seed (UInt32.ofNat i) leafIdx
    (dec.fors.secrets.getD i (ByteVec.zero 16))
    (dec.fors.authPaths.getD i #[])

/-- Compress the FORS section of the byte signature into the FORS PK.

    Yul body: lines 119-138 of `SPHINCsC10Asm.sol`. Defined as the
    `getD-#[]`-defaulted form of `Fors.reconstructForsPk` over the
    deserialised structured signature. -/
def reconstructForsPkRefined
    (sig : ByteVec SignatureLen) (seed : ByteVec 32) (digest : ByteVec 32) :
    Option (ByteVec 16) :=
  Fors.reconstructForsPk seed digest (Spec.Signature.deserialise sig).fors

/-- Walk one hypertree-layer's WOTS+C and subtree-Merkle reconstruction.

    Yul body: lines 139-220 of `SPHINCsC10Asm.sol`. -/
def hypertreeLayerStep
    (sig : ByteVec SignatureLen) (seed : ByteVec 32)
    (layer : Nat) (idxTree idxLeaf : Nat) (currentNode : ByteVec 16)
    (_sigOff : Nat) : Option (ByteVec 16) :=
  let dec := Spec.Signature.deserialise sig
  let layerSig := dec.layers.getD layer Hypertree.defaultLayerSig
  let layer32 := UInt32.ofNat layer
  let tree64 := UInt64.ofNat idxTree
  let leaf32 := UInt32.ofNat idxLeaf
  match Wots.pkFromSig seed layer32 tree64 leaf32 currentNode layerSig.wots with
  | none => none
  | some wotsPk =>
    some (Hypertree.verifyAuthPath seed layer32 tree64 wotsPk idxLeaf layerSig.authPath)

/-- Verify a signature using the byte-decoded `Hypertree.Signature`.

    The byte-offset arithmetic mirroring Yul lives in
    `Spec.Signature.deserialise`; the structural verification lives in
    `Spec.Signature.verify`. The refinement
    `Verifier/Equivalence.lean::verifyRefined_eq_spec` closes by `rfl`. -/
def verifyRefined
    (pkSeed pkRoot : ByteVec 32)
    (message : ByteVec 32)
    (sig : ByteVec SignatureLen) : Bool :=
  let pkSeed16 : ByteVec 16 := pkSeed.take 16 (by decide)
  let pkRoot16 : ByteVec 16 := pkRoot.take 16 (by decide)
  Spec.Signature.verify ⟨pkSeed16, pkRoot16⟩ message sig

end SphincsCVerify.Verifier.Refined
