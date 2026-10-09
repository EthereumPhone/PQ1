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
import SphincsCVerify.Spec.Treehash
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

    Mirrors `fors::grind_r` (the deterministic `opt_rand = None` path used
    by the byte-stable test vectors). As of 2026-06-13 the R derivation is
    **secret-keyed and message-bound**:
    `R = sha256(sk_seed ‖ "R_grind" ‖ message ‖ nonce)[0..16]` — so `ht_idx`
    is unpredictable without the secret key for any chosen message (closing
    the chosen-message FORS-saturation avenue; see `fors::grind_r`). The
    production firmware additionally splices a fresh `opt_rand` between the
    tag and the message (not modelled here — `None`-path reference only). -/
def grindR
    (skSeed : ByteVec 32) (pkSeed pkRoot : ByteVec 16) (message : ByteVec 32)
    (limit : Nat) :
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
        ByteSeg.ofByteVec skSeed,
        ByteSeg.ofByteVec rGrindTag,
        ByteSeg.ofByteVec message,
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

/-- The value emitted in a FORS signature slot. The first `K-1` slots carry
    a leaf secret; the forced-zero final slot carries the complete FORS tree
    root, matching `hypertree::sign_inner` in Rust. The verifier hashes that
    final value once more at the forced-zero leaf address. -/
def forsSigningValue (seed skSeed : ByteVec 32) (htIdx treeIdx leafIdx : Nat) :
    ByteVec 16 :=
  if treeIdx = K - 1 then
    forsMtNode seed (UInt64.ofNat htIdx) (UInt32.ofNat treeIdx)
      (fun j => forsSecret skSeed (UInt32.ofNat htIdx) (UInt32.ofNat treeIdx)
        (UInt32.ofNat j)) A 0
  else
    forsSecret skSeed (UInt32.ofNat htIdx) (UInt32.ofNat treeIdx)
      (UInt32.ofNat leafIdx)

/-- The top-level signing routine.

    Returns `none` if any grinding loop fails (vanishingly small under
    SHA-256 ROM). The result, when `some`, is a structured `Signature`
    whose round-trip through the verifier is the content of
    `Theorems.verify_signs`. -/
noncomputable def sign
    (sk : SigningKey) (message : ByteVec 32) (limit : Nat := 10_000_000) :
    Option Signature :=
  -- (Signing produces a structured `Signature`; the byte-level 4008-byte
  -- serialisation is in `Signature.serialise`, with a round-trip theorem
  -- `deserialise (serialise s) = s` in `Bytes.lean`.)
  match grindR sk.skSeed sk.pkSeed sk.pkRoot message limit with
  | none => none
  | some (r, digest) =>
    let seed := pad16 sk.pkSeed
    let forsIndices := extractForsIndices digest
    let htIdxNat := extractHtIndex digest
    let htIdx : UInt64 := UInt64.ofNat htIdxNat
    -- FORS+C: normal leaf secrets, final full tree root, and normal auth paths.
    let forsSecrets : Array (ByteVec 16) :=
      Array.ofFn (n := K) fun i =>
        forsSigningValue seed sk.skSeed htIdxNat i.val (forsIndices.getD i.val 0)
    let forsAuthPaths : Array (Array (ByteVec 16)) :=
      Array.ofFn (n := K - 1) fun t =>
        forsMtAuthPath seed htIdx (UInt32.ofNat t.val)
          (fun j => forsSecret sk.skSeed (UInt32.ofNat htIdxNat) (UInt32.ofNat t.val) (UInt32.ofNat j))
          (forsIndices.getD t.val 0)
    let fors : Fors.ForsSig :=
      { secrets := forsSecrets, secretsLen := Array.size_ofFn,
        authPaths := forsAuthPaths, authPathsLen := Array.size_ofFn }
    -- The honest FORS public key = `computeForsPk` over the honest tree roots
    -- (K-1 normal roots + one hash of the final full tree root) — layer 0's msg.
    let forsPk : ByteVec 16 :=
      Fors.computeForsPk seed htIdx
        ((Array.ofFn (n := K - 1) fun t : Fin (K - 1) =>
            forsMtNode seed htIdx (UInt32.ofNat t.val)
              (fun j => forsSecret sk.skSeed (UInt32.ofNat htIdxNat) (UInt32.ofNat t.val) (UInt32.ofNat j)) A 0).push
          (th seed (Adrs.forsNode htIdx (UInt32.ofNat (K - 1)) 0 0)
            (pad16 (forsSecrets.getD (K - 1) (zero 16)))))
    let mask : Nat := (1 <<< SubtreeH) - 1
    -- Hypertree layer 0: WOTS+C over the FORS public key.
    let idxLeaf0 := htIdxNat &&& mask
    let idxTree0 := htIdxNat >>> SubtreeH
    let lf0 : Nat → ByteVec 16 := fun kp =>
      Wots.keygenPk seed sk.skSeed (UInt32.ofNat 0) (UInt64.ofNat idxTree0) (UInt32.ofNat kp)
    match findCount seed (UInt32.ofNat 0) (UInt64.ofNat idxTree0) (UInt32.ofNat idxLeaf0)
            (pad16 forsPk) limit with
    | none => none
    | some (count0, d0) =>
      let digits0 := extractDigits d0
      let chains0 : Array (ByteVec 16) :=
        Array.ofFn (n := L) fun i =>
          chainHash seed
            (Adrs.setChainIndex (Adrs.wots (UInt32.ofNat 0) (UInt64.ofNat idxTree0)
              (UInt32.ofNat idxLeaf0)) (UInt32.ofNat i.val))
            (wotsSecret sk.skSeed (UInt32.ofNat 0) (UInt64.ofNat idxTree0) (UInt32.ofNat idxLeaf0)
              (UInt32.ofNat i.val)) 0 (digits0.getD i.val 0)
      let layer0 : Hypertree.LayerSig :=
        { wots := { chains := chains0, chainsLen := Array.size_ofFn, count := count0 },
          authPath := mtAuthPath seed (UInt32.ofNat 0) (UInt64.ofNat idxTree0) lf0 idxLeaf0,
          authPathLen := mtAuthPath_size _ _ _ _ _ }
      let root0 : ByteVec 16 := mtNode seed (UInt32.ofNat 0) (UInt64.ofNat idxTree0) lf0 SubtreeH 0
      -- Hypertree layer 1: WOTS+C over layer 0's subtree root.
      let idxLeaf1 := idxTree0 &&& mask
      let idxTree1 := idxTree0 >>> SubtreeH
      let lf1 : Nat → ByteVec 16 := fun kp =>
        Wots.keygenPk seed sk.skSeed (UInt32.ofNat 1) (UInt64.ofNat idxTree1) (UInt32.ofNat kp)
      match findCount seed (UInt32.ofNat 1) (UInt64.ofNat idxTree1) (UInt32.ofNat idxLeaf1)
              (pad16 root0) limit with
      | none => none
      | some (count1, d1) =>
        let digits1 := extractDigits d1
        let chains1 : Array (ByteVec 16) :=
          Array.ofFn (n := L) fun i =>
            chainHash seed
              (Adrs.setChainIndex (Adrs.wots (UInt32.ofNat 1) (UInt64.ofNat idxTree1)
                (UInt32.ofNat idxLeaf1)) (UInt32.ofNat i.val))
              (wotsSecret sk.skSeed (UInt32.ofNat 1) (UInt64.ofNat idxTree1) (UInt32.ofNat idxLeaf1)
                (UInt32.ofNat i.val)) 0 (digits1.getD i.val 0)
        let layer1 : Hypertree.LayerSig :=
          { wots := { chains := chains1, chainsLen := Array.size_ofFn, count := count1 },
            authPath := mtAuthPath seed (UInt32.ofNat 1) (UInt64.ofNat idxTree1) lf1 idxLeaf1,
            authPathLen := mtAuthPath_size _ _ _ _ _ }
        some { r := r, fors := fors, layers := #[layer0, layer1], layersLen := rfl }

end SphincsCVerify.Spec.Signer
