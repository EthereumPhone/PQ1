/- Exact verifier definitions for the WOTS digest/digit version bridge.
   The vendored-fidelity gate checks every copied declaration. -/
import Extracted.HMsgSpecVendored
import Extracted.ForsSpecVendored

namespace SphincsCVerify.Spec
namespace ByteVec
def zero (n : Nat) : ByteVec n :=
  ⟨Array.replicate n (0 : UInt8), by simp⟩

def u32ToB32 (x : UInt32) : ByteVec 32 :=
  cast (by decide) ((zero 28).append (ofU32BE x))

end ByteVec
open ByteVec

def LogW : Nat := 3

def L : Nat := 43

def wotsDigest
    (seed : ByteVec 32) (wotsAdrs : Adrs)
    (msgHash : ByteVec 32) (count : UInt32) : ByteVec 32 :=
  sha256 [
    ByteSeg.ofByteVec seed,
    ByteSeg.ofByteVec wotsAdrs,
    ByteSeg.ofByteVec msgHash,
    ByteSeg.ofByteVec (u32ToB32 count)]

end SphincsCVerify.Spec

namespace SphincsCVerify.Util
open SphincsCVerify.Spec

def extractDigits (digest : ByteVec 32) : Array Nat :=
  Array.ofFn (n := L) fun i =>
    readBitsLe digest (i * LogW) LogW

def digitSum (digits : Array Nat) : Nat :=
  digits.foldl (init := 0) (· + ·)

end SphincsCVerify.Util
