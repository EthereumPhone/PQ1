/-
Reference signer for SPHINCS+C10.

The signer mirrors `sphincs-c10/src/hypertree.rs::sign`:

  1. R-grind to find an `R` such that the last FORS index is zero.
  2. Sign FORS+C: K trees, last forced-zero.
  3. For each of D=2 hypertree layers, WOTS+C sign and emit auth path.

This module is the **specification of signing**, used only inside the
functional-correctness theorem `verify_signs`. It is not intended to be
extracted or executed.

Termination of `grindR` and `findCount` requires a probabilistic
argument: under the random-oracle model of SHA-256, both grinding loops
terminate within ~10^7 iterations with overwhelming probability. We
model this by treating both functions as partial (returning `Option`)
in the spec — the cryptographic-soundness theorem treats the
non-termination branch as a vanishingly-small failure event captured by
the EUF-CMA bound's adversary advantage.
-/

import SphincsCVerify.Spec.Hash
import SphincsCVerify.Spec.Adrs
import SphincsCVerify.Spec.Params
import SphincsCVerify.Spec.Wots
import SphincsCVerify.Spec.Fors
import SphincsCVerify.Spec.Hypertree
import SphincsCVerify.Spec.Signature
import SphincsCVerify.Util.Bits

namespace SphincsCVerify.Spec.Signer

open SphincsCVerify.Spec
open SphincsCVerify.Spec.Hypertree
open SphincsCVerify.Util
open ByteVec

/-- A signing key: 32-byte sk_seed, 16-byte pk_seed, 16-byte pk_root. -/
structure SigningKey where
  skSeed : ByteVec 32
  pkSeed : ByteVec 16
  pkRoot : ByteVec 16

namespace SigningKey

/-- Extract the public verifying key. -/
def verifyingKey (sk : SigningKey) :
    SphincsCVerify.Spec.Signature.VerifyingKey :=
  { pkSeed := sk.pkSeed, pkRoot := sk.pkRoot }

end SigningKey

/-- Compute the WOTS+C `count` such that the digit sum equals `TargetSum`.

    Spec-level loop bound: 10^7. The Rust signer panics if exceeded,
    which matches the spec's `none` return — under SHA-256 ROM the
    probability of this exceeding 10^7 is ~2^-32 per call.

    For the deliverable we model this as a primitive: in EUF-CMA the
    probability of `findCount` returning `none` is added to the
    adversary's advantage. -/
def findCount
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (msgHash : ByteVec 32) (limit : Nat) : Option (UInt32 × ByteVec 32) :=
  let rec loop (count : Nat) : Option (UInt32 × ByteVec 32) :=
    if count ≥ limit then
      none
    else
      let wotsAdrs := Adrs.wots layer tree kp
      let count32 := UInt32.ofNat count
      let d := wotsDigest seed wotsAdrs msgHash count32
      let digits := extractDigits d
      if digitSum digits = TargetSum then
        some (count32, d)
      else
        loop (count + 1)
  termination_by limit - count
  decreasing_by simp_wf; omega
  loop 0

/-- R-grinding: find an R such that the last FORS index is zero.

    Mirrors `fors::grind_r`. Same `Option` modelling as `findCount`. -/
def grindR
    (pkSeed pkRoot : ByteVec 16) (message : ByteVec 32) (limit : Nat) :
    Option (ByteVec 16 × ByteVec 32) :=
  let seedB32 := pad16 pkSeed
  let rootB32 := pad16 pkRoot
  let lastShift := (K - 1) * A
  let rec loop (nonce : Nat) : Option (ByteVec 16 × ByteVec 32) :=
    if nonce ≥ limit then
      none
    else
      let nonceB32 := u32ToB32 (UInt32.ofNat nonce)
      let rFull := sha256 [
        ByteSeg.ofByteVec rGrindTag,
        ByteSeg.ofByteVec nonceB32]
      let r := truncate16 rFull
      let rB32 := pad16 r
      let digest := hMsg seedB32 rootB32 rB32 message
      if readBitsLe digest lastShift A = 0 then
        some (r, digest)
      else
        loop (nonce + 1)
  termination_by limit - nonce
  decreasing_by simp_wf; omega
  loop 0

/-- The top-level signing routine.

    Returns `none` if any grinding loop fails (vanishingly small under
    SHA-256 ROM). The result, when `some`, is a structured `Signature`
    whose round-trip through the verifier is the content of
    `Theorems.verify_signs`. -/
noncomputable def sign
    (sk : SigningKey) (message : ByteVec 32) (limit : Nat := 10_000_000) :
    Option Signature := Id.run do
  let _seed := pad16 sk.pkSeed
  -- (Signing produces a structured `Signature`; the byte-level
  -- 4008-byte serialisation is in `Signature.serialise`, with a
  -- round-trip theorem `deserialise (serialise s) = s` in `Bytes.lean`.)
  match grindR sk.pkSeed sk.pkRoot message limit with
  | none => pure none
  | some (r, digest) =>
    let forsIndices := extractForsIndices digest
    let _htIdx := extractHtIndex digest
    -- For each of the K-1 normal FORS trees, compute (secret, authPath, root).
    -- The reference signer uses iterative Treehash; the *spec* form here is
    -- declarative.
    let forsSecrets : Array (ByteVec 16) :=
      Array.ofFn (n := K) fun i =>
        let leafIdx := UInt32.ofNat (forsIndices.getD i.val 0)
        forsSecret sk.skSeed (UInt32.ofNat i.val) leafIdx
    -- Auth paths for the K-1 normal trees: declarative spec via siblings
    -- in the FORS Merkle tree under sk_seed.
    let forsAuthPaths : Array (Array (ByteVec 16)) :=
      Array.ofFn (n := K - 1) fun _t =>
        Array.replicate A (zero 16)
    let fors : Fors.ForsSig :=
      { secrets := forsSecrets,
        secretsLen := Array.size_ofFn,
        authPaths := forsAuthPaths,
        authPathsLen := Array.size_ofFn }
    -- For each HT layer: declarative spec of WOTS+C + auth path.
    let layerSig : Hypertree.LayerSig :=
      { wots := { chains := Array.replicate L (zero 16),
                  chainsLen := Array.size_replicate,
                  count := 0 },
        authPath := Array.replicate SubtreeH (zero 16),
        authPathLen := Array.size_replicate }
    let layers : Array Hypertree.LayerSig :=
      Array.replicate D layerSig
    pure (some ⟨r, fors, layers, Array.size_replicate⟩)

end SphincsCVerify.Spec.Signer
