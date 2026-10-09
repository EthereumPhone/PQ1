/- Faithful complete signature deserializer and byte-level verifier. -/
import Extracted.VerifierTopVendored
namespace SphincsCVerify.Spec.Signature
open SphincsCVerify.Spec SphincsCVerify.Spec.Hypertree ByteVec
structure VerifyingKey where
  pkSeed : ByteVec 16
  pkRoot : ByteVec 16

def deserialise (bytes : ByteVec SignatureLen) : Hypertree.Signature :=
  -- R: bytes [0, 16). Read the top 16 of the 32-byte word at offset 0
  -- to match the `and(calldataload(sig.offset), N_MASK)` in Yul.
  let r : ByteVec 16 := ByteVec.loadValue16 bytes 0
  -- FORS section: K = 13 secrets, then K - 1 = 12 auth paths.
  -- Secrets at offsets [16, 32, ..., 16 + 12*16) = [16, 208].
  let forsSecrets : Array (ByteVec 16) :=
    Array.ofFn (n := K) fun i =>
      ByteVec.loadValue16 bytes (N + i.val * N)
  -- Auth paths at AUTH_START + treeIdx * (A * N) + h * N.
  let forsAuthPaths : Array (Array (ByteVec 16)) :=
    Array.ofFn (n := K - 1) fun t =>
      Array.ofFn (n := A) fun h =>
        ByteVec.loadValue16 bytes
          (SigR + SigForsSecrets + t.val * (A * N) + h.val * N)
  -- Each inner auth array has size A.
  let forsAuthPaths' : Array (Array (ByteVec 16)) := forsAuthPaths
  have hAuthLen : forsAuthPaths'.size = K - 1 := Array.size_ofFn
  let fors : Fors.ForsSig :=
    { secrets    := forsSecrets
    , secretsLen := Array.size_ofFn
    , authPaths  := forsAuthPaths'
    , authPathsLen := hAuthLen }
  -- HT layers: D = 2, each layer is SigHtLayer = 836 bytes.
  let layers : Array Hypertree.LayerSig :=
    Array.ofFn (n := D) fun ℓ =>
      let layerOff : Nat := SigForsTotal + ℓ.val * SigHtLayer
      let chains : Array (ByteVec 16) :=
        Array.ofFn (n := L) fun i =>
          ByteVec.loadValue16 bytes (layerOff + i.val * N)
      let count : UInt32 := ByteVec.loadU32BE bytes (layerOff + L * N)
      let authPath : Array (ByteVec 16) :=
        Array.ofFn (n := SubtreeH) fun h =>
          ByteVec.loadValue16 bytes (layerOff + L * N + 4 + h.val * N)
      { wots := { chains := chains, chainsLen := Array.size_ofFn, count := count }
      , authPath := authPath
      , authPathLen := Array.size_ofFn }
  { r := r
  , fors := fors
  , layers := layers
  , layersLen := Array.size_ofFn }

def verify
    (vk : VerifyingKey)
    (msgHash : ByteVec 32)
    (sig : ByteVec SignatureLen) : Bool :=
  Hypertree.verify vk.pkSeed vk.pkRoot msgHash (deserialise sig)

end SphincsCVerify.Spec.Signature
