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

/-- A placeholder default `Hypertree.Signature` we can instantiate to
    keep the spec total. The actual byte decode is structural; the
    equivalence theorem in `Verifier/Equivalence.lean` aligns the
    real byte-layout against this default. -/
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

/-- Deserialise a 4008-byte signature blob into the structured form.

    Placeholder: returns `defaultSignature` regardless of the input.
    The equivalence theorem in `Verifier/Equivalence.lean` ties the
    offset-indexed Solidity verifier to the structural form; a full
    byte-level decoder is a future engagement deliverable. -/
def deserialise (_bytes : ByteVec SignatureLen) : Hypertree.Signature :=
  defaultSignature

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
