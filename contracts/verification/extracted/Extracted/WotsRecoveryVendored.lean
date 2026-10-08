/- Exact verifier WOTS recovery definitions. Every copied declaration is
   enrolled in the vendored-fidelity gate. -/
import Extracted.WotsSpecVendored

namespace SphincsCVerify.Spec
namespace ByteVec

def take {n : Nat} (v : ByteVec n) (k : Nat) (h : k ≤ n) : ByteVec k :=
  ⟨v.data.extract 0 k, by
    have hsize : v.data.size = n := v.size_eq
    simp [Array.size_extract, hsize, Nat.min_eq_left h]⟩

def pad16 (v : ByteVec 16) : ByteVec 32 :=
  cast (by decide) (v.append (zero 16))

def truncate16 (d : ByteVec 32) : ByteVec 16 :=
  d.take 16 (by decide)

end ByteVec
open ByteVec

def W : Nat := 8

def TargetSum : Nat := 205

def ADRS_WOTS : Nat := 0

def ADRS_WOTS_PK : Nat := 1

namespace Adrs

def setChainPos (a : Adrs) (pos : UInt32) : Adrs :=
  -- Replace bytes [24..28) with `ofU32BE pos`.
  let prefix6 : ByteVec 24 :=
    ⟨a.data.extract 0 24, by
      have : a.data.size = 32 := a.size_eq
      simp [Array.size_extract, this]⟩
  let suffix : ByteVec 4 :=
    ⟨a.data.extract 28 32, by
      have : a.data.size = 32 := a.size_eq
      simp [Array.size_extract, this]⟩
  cast (by decide) (prefix6.append (ofU32BE pos) |>.append suffix)

def wots (layer : UInt32) (tree : UInt64) (kp : UInt32) : Adrs :=
  make layer tree (UInt32.ofNat ADRS_WOTS) kp 0 0 0

def wotsPk (layer : UInt32) (tree : UInt64) (kp : UInt32) : Adrs :=
  make layer tree (UInt32.ofNat ADRS_WOTS_PK) kp 0 0 0

end Adrs

def th (seed : ByteVec 32) (a : Adrs) (val : ByteVec 32) : ByteVec 16 :=
  truncate16 (sha256 [
    ByteSeg.ofByteVec seed,
    ByteSeg.ofByteVec a,
    ByteSeg.ofByteVec val])

def thMulti (seed : ByteVec 32) (a : Adrs) (vals : List (ByteVec 16)) : ByteVec 16 :=
  let header := [ByteSeg.ofByteVec seed, ByteSeg.ofByteVec a]
  let padded := vals.map fun v => ByteSeg.ofByteVec (pad16 v)
  truncate16 (sha256 (header ++ padded))

def chainHash
    (seed : ByteVec 32) (a : Adrs) (val : ByteVec 16)
    (startPos steps : Nat) : ByteVec 16 :=
  let rec aux (i : Nat) (current : ByteVec 16) : ByteVec 16 :=
    match i with
    | 0 => current
    | i+1 =>
      let pos := startPos + (steps - 1 - i)  -- traverse forward
      let a' := Adrs.setChainPos a (UInt32.ofNat pos)
      let next := th seed a' (pad16 current)
      aux i next
  aux steps val

namespace Wots
open SphincsCVerify.Util

structure Sigma where
  chains : Array (ByteVec 16)
  chainsLen : chains.size = L
  count : UInt32

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

end Wots
end SphincsCVerify.Spec
