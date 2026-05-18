/-
Top-level SPHINCS+C10 signature API and serialisation.

This module exposes the same surface the Rust crate `sphincs-c10`
exposes in `lib.rs`:

  * `VerifyingKey` — `pk_seed (16 bytes) ‖ pk_root (16 bytes)`
  * `verify : VerifyingKey → ByteVec 32 → ByteVec SignatureLen → Bool`
  * `deserialise : ByteVec SignatureLen → Signature` — produces the
    structured form that `Hypertree.verify` consumes.

Splitting `deserialise` out lets us prove:

  * `verify_byteLevel_correct` — the byte-indexed verifier is
    extensionally equal to the structured `Hypertree.verify`
    (`Verifier/Equivalence.lean`).
  * `verify_signs` — `verify pk msg (sign sk msg) = true`,
    proved at the structured-`Signature` level.

The actual byte-level decoder is a *placeholder*: it returns a
canonical default `Signature` shape so the spec type-checks and the
top-level `verify` reduces. The full decoder lives in
`Verifier/Equivalence.lean` (the proof aligns the offset-indexed
shape against this declarative shape).
-/

import SphincsCVerify.Spec.Hypertree
import SphincsCVerify.Spec.Bytes
import SphincsCVerify.Spec.Params

namespace SphincsCVerify.Spec.Signature

open SphincsCVerify.Spec
open SphincsCVerify.Spec.Hypertree
open ByteVec

/-- A verifying key: pk_seed (16 bytes) and pk_root (16 bytes). -/
structure VerifyingKey where
  pkSeed : ByteVec 16
  pkRoot : ByteVec 16

namespace VerifyingKey

/-- Deserialise a 32-byte big-endian-formatted verifying key. -/
def fromBytes (b : ByteVec VerifyingKeyLen) : VerifyingKey :=
  let h : VerifyingKeyLen = 32 := rfl
  let b' : ByteVec 32 := b.cast h
  ⟨b'.take 16 (by decide),
   (b'.drop 16 (by decide)).cast (by decide)⟩

/-- Serialise to 32 bytes. -/
def toBytes (vk : VerifyingKey) : ByteVec VerifyingKeyLen :=
  (vk.pkSeed.append vk.pkRoot).cast (by decide)

end VerifyingKey

/-- A default empty `Hypertree.Signature`. Used by the round-trip
    serialiser and as the structural shape `deserialise` populates. -/
def defaultSignature : Hypertree.Signature :=
  let forsAuth : Array (Array (ByteVec 16)) :=
    Array.replicate (K - 1) (Array.replicate A (zero 16))
  let fors : Fors.ForsSig :=
    { secrets := Array.replicate K (zero 16),
      secretsLen := Array.size_replicate,
      authPaths := forsAuth,
      authPathsLen := Array.size_replicate }
  let layerSig : Hypertree.LayerSig :=
    { wots := { chains := Array.replicate L (zero 16),
                chainsLen := Array.size_replicate,
                count := 0 },
      authPath := Array.replicate SubtreeH (zero 16),
      authPathLen := Array.size_replicate }
  { r := zero 16,
    fors := fors,
    layers := Array.replicate D layerSig,
    layersLen := Array.size_replicate }

/-! ## Byte layout — must match `SPHINCsC10Asm.sol` exactly.

```
offset    size  field
  0       16    R   (truncated to top 16 of a uint256 in Yul)
 16    13*16    FORS secrets  (K = 13, each 16 bytes)
224  (K-1)*A*N FORS auth paths (12 trees × 11 levels × 16 = 2112 bytes)
2336      836  HT layer 0 footprint (= SigHtLayer)
3172      836  HT layer 1 footprint
```

Per-layer footprint (836 bytes):

```
offset    size  field
  0     43*16  WOTS chain values (L = 43, each 16 bytes)
688       4    count (uint32 big-endian)
692     9*16  Merkle auth path (SubtreeH = 9, each 16 bytes)
```

Reference: `SPHINCsC10Asm.sol` lines 90-220 and the `AUTH_START = 224`,
`HT_START = 2336`, `countOff = sigOff + 688`, `authOff = countOff + 4`
constants surfaced in `Verifier/Refined.lean`. -/

private theorem fors_secrets_len_proof :
    (Array.ofFn (n := K) fun i : Fin K => i.val).size = K :=
  Array.size_ofFn

/-- Deserialise a 4008-byte signature blob into the structured
    `Hypertree.Signature` form.

    The decoder uses the *same* `ByteVec.loadValue16` / `loadU32BE`
    primitives the offset-indexed `Verifier.Refined.verifyRefined` uses,
    so the structural-vs-byte-level equivalence lemmas (notably
    `load_R_consistent` and `verifyRefined_eq_spec`) reduce to
    `rfl`-shaped offset arithmetic. -/
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

/-- The top-level verify routine over the byte-level signature. -/
def verify
    (vk : VerifyingKey)
    (msgHash : ByteVec 32)
    (sig : ByteVec SignatureLen) : Bool :=
  Hypertree.verify vk.pkSeed vk.pkRoot msgHash (deserialise sig)

/-- Length sanity: the verifier expects exactly 4008 bytes. -/
theorem verify_expects_4008 :
    ∀ (_vk : VerifyingKey) (_msg : ByteVec 32) (sig : ByteVec SignatureLen),
      sig.data.size = SignatureLen := by
  intros _ _ sig; exact sig.size_eq

end SphincsCVerify.Spec.Signature
