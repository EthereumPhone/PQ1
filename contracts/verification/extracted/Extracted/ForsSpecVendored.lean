/- Version bridge for the C10 digest-field decoders. Definitions below are
   verbatim from SphincsCVerify Spec/Bytes.lean, Spec/Params.lean and
   Util/Bits.lean, whose Lean version differs from the Aeneas project.
   `make verify-spec-vendored-fidelity` checks every copied definition.
   No SHA256 implementation or probabilistic security claim is imported. -/
import Aeneas
import Extracted.SpecVendored

namespace SphincsCVerify.Spec
namespace ByteVec
@[inline]
def get {n : Nat} (v : ByteVec n) (i : Fin n) : UInt8 :=
  let i' : Fin v.data.size := i.cast v.size_eq.symm
  v.data[i']
end ByteVec

def H : Nat := 18

def K : Nat := 13

def A : Nat := 11
end SphincsCVerify.Spec

namespace SphincsCVerify.Util
open SphincsCVerify.Spec
open ByteVec

@[inline] def readBitsLe.stepValue
    (digest : ByteVec 32) (bitOffset i : Nat) : Nat :=
  let bitIdx := bitOffset + i
  let byteIdx := 31 - bitIdx / 8
  let bitInByte := bitIdx % 8
  let b : UInt8 :=
    if byteIdx < 32 then
      digest.get ⟨byteIdx, by omega⟩
    else
      0
  ((b.toNat >>> bitInByte) &&& 1) <<< i

/-- Read `numBits` bits (≤ 57) starting at logical bit `bitOffset` from a
    32-byte big-endian digest. Bit 0 is the LSB of `digest[31]`.

    Mirrors `read_bits_le` in `sphincs-c10/src/fors.rs`. -/
def readBitsLe (digest : ByteVec 32) (bitOffset numBits : Nat) : Nat :=
  let rec loop (i acc : Nat) : Nat :=
    if i < numBits then
      loop (i + 1) (acc ||| readBitsLe.stepValue digest bitOffset i)
    else
      acc
  termination_by numBits - i
  loop 0 0

def extractForsIndices (digest : ByteVec 32) : Array Nat :=
  Array.ofFn (n := K) fun i =>
    readBitsLe digest (i * A) A

/-- Extract the 18-bit hypertree index. -/
def extractHtIndex (digest : ByteVec 32) : Nat :=
  readBitsLe digest (K * A) H

end SphincsCVerify.Util
