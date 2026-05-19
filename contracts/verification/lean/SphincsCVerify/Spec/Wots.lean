/-
WOTS+C: Winternitz One-Time Signature with Count-grinding.

Mirrors `sphincs-c10/src/wots.rs`. The key idea of WOTS+C is that
instead of carrying a checksum (the `len_2` chains of standard WOTS+),
the signer grinds a `count` value until the base-w digit sum of the
message digest equals exactly `TARGET_SUM = 205`. This eliminates
checksum chains entirely, saving signature space.

The verifier:
  1. Reads `count` and chain values from the signature.
  2. Recomputes the WOTS digest under (seed, adrs, msg, count).
  3. Extracts L=43 base-w digits and checks their sum is exactly 205.
  4. For each chain `i`, hashes `sig[i]` forward `(w-1) - digit[i]` times
     to reach the chain endpoint.
  5. Compresses the L endpoints via `th_multi` to get the WOTS public key.
-/

import SphincsCVerify.Spec.Hash
import SphincsCVerify.Spec.Adrs
import SphincsCVerify.Spec.Params
import SphincsCVerify.Util.Bits

namespace SphincsCVerify.Spec.Wots

open SphincsCVerify.Spec
open SphincsCVerify.Util
open ByteVec

/-- A WOTS signature at one hypertree position: L chain values + count. -/
structure Sigma where
  chains : Array (ByteVec 16)
  chainsLen : chains.size = L
  count : UInt32

/-- Compute the WOTS+C public key from (sk_seed, pk_seed) at a given
    hypertree position. -/
def keygenPk
    (seed skSeed : ByteVec 32)
    (layer : UInt32) (tree : UInt64) (kp : UInt32) : ByteVec 16 :=
  let baseAdrs := Adrs.wots layer tree kp
  let chainValues : List (ByteVec 16) :=
    (List.range L).map fun i =>
      let skI := wotsSecret skSeed layer tree kp (UInt32.ofNat i)
      let chainAdrs := Adrs.setChainIndex baseAdrs (UInt32.ofNat i)
      chainHash seed chainAdrs skI 0 (W - 1)
  let pkAdrs := Adrs.wotsPk layer tree kp
  thMulti seed pkAdrs chainValues

/-- Recover the WOTS public key from a signature.

    Returns `none` if the digit-sum check fails (which the verifier
    treats as signature rejection). -/
def pkFromSig
    (seed : ByteVec 32)
    (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (msgHash : ByteVec 16)
    (sigma : Sigma) : Option (ByteVec 16) :=
  let padded := pad16 msgHash
  let wotsAdrs := Adrs.wots layer tree kp
  let d := wotsDigest seed wotsAdrs padded sigma.count
  let digits := extractDigits d
  if digitSum digits ≠ TargetSum then
    none
  else
    let chainValues : List (ByteVec 16) :=
      (List.range L).map fun i =>
        let chainAdrs := Adrs.setChainIndex wotsAdrs (UInt32.ofNat i)
        let digit := digits[i]!
        let sigI :=
          if h : i < sigma.chains.size then sigma.chains[i]
          else zero 16
        let remaining := (W - 1) - digit
        chainHash seed chainAdrs sigI digit remaining
    let pkAdrs := Adrs.wotsPk layer tree kp
    some (thMulti seed pkAdrs chainValues)

/-- The verifier-side check folded into a single Boolean. -/
def verifyAndRecover
    (seed : ByteVec 32)
    (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (msgHash : ByteVec 16)
    (sigma : Sigma) : Option (ByteVec 16) :=
  pkFromSig seed layer tree kp msgHash sigma

end SphincsCVerify.Spec.Wots
