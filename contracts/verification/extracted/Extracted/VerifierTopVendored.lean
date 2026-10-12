/- Faithful top-level verifier and byte-load definitions. -/
import Extracted.HypertreeContinuationVendored
namespace SphincsCVerify.Spec
def N : Nat := 16

def SigR : Nat := N

def SigForsSecrets : Nat := K * N

def SigForsAuth : Nat := (K - 1) * A * N

def SigForsTotal : Nat := SigR + SigForsSecrets + SigForsAuth

def SigHtLayer : Nat := L * N + 4 + SubtreeH * N

def SignatureLen : Nat := SigForsTotal + D * SigHtLayer

namespace ByteVec
def loadWord32 {n : Nat} (sig : ByteVec n) (offset : Nat) : ByteVec 32 :=
  ⟨(sig.data.extract offset (offset + 32) ++ Array.replicate 32 0).extract 0 32, by
    have hsize : sig.data.size = n := sig.size_eq
    simp [Array.size_extract, Array.size_append, Array.size_replicate]
    omega⟩

def loadValue16 {n : Nat} (sig : ByteVec n) (offset : Nat) : ByteVec 16 :=
  (loadWord32 sig offset).take 16 (by decide)

def loadU32BE {n : Nat} (sig : ByteVec n) (offset : Nat) : UInt32 :=
  let b0 := if h : offset < n then sig.get ⟨offset, h⟩ else 0
  let b1 := if h : offset + 1 < n then sig.get ⟨offset+1, h⟩ else 0
  let b2 := if h : offset + 2 < n then sig.get ⟨offset+2, h⟩ else 0
  let b3 := if h : offset + 3 < n then sig.get ⟨offset+3, h⟩ else 0
  (UInt32.ofNat b0.toNat <<< 24) |||
  (UInt32.ofNat b1.toNat <<< 16) |||
  (UInt32.ofNat b2.toNat <<< 8) |||
  (UInt32.ofNat b3.toNat)

/-! ### Concrete short literals used by the SPHINCS+C10 hashes -/

end ByteVec
namespace Hypertree
open Wots Fors SphincsCVerify.Util ByteVec
structure Signature where
  r : ByteVec 16
  fors : Fors.ForsSig
  layers : Array LayerSig
  layersLen : layers.size = D

def verifyWithDigest
    (seed : ByteVec 32) (pkRoot : ByteVec 16)
    (digest : ByteVec 32) (sig : Signature) : Bool :=
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

def verify
    (pkSeed pkRoot : ByteVec 16)
    (msgHash : ByteVec 32)
    (sig : Signature) : Bool :=
  let seed := pad16 pkSeed
  let root := pad16 pkRoot
  let rB32 := pad16 sig.r
  let digest := hMsg seed root rB32 msgHash
  verifyWithDigest seed pkRoot digest sig

end Hypertree
end SphincsCVerify.Spec
