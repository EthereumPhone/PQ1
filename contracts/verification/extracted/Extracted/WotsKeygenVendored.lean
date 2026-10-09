/- Exact WOTS generation declarations from the verifier reference; checked by
   the complete vendored-fidelity inventory. -/
import Extracted.WotsRecoveryVendored

namespace SphincsCVerify.Spec
namespace ByteVec

def u64ToB32 (x : UInt64) : ByteVec 32 :=
  cast (by decide) ((zero 24).append (ofU64BE x))

def wotsTag : ByteVec 4 :=
  ⟨#[0x77, 0x6F, 0x74, 0x73], by simp⟩  -- "wots"

end ByteVec
open ByteVec

def wotsSecret
    (skSeed : ByteVec 32)
    (layer : UInt32) (tree : UInt64) (kp chainIdx : UInt32) : ByteVec 16 :=
  truncate16 (sha256 [
    ByteSeg.ofByteVec skSeed,
    ByteSeg.ofByteVec wotsTag,
    ByteSeg.ofByteVec (ofU32BE layer),
    ByteSeg.ofByteVec (u64ToB32 tree),
    ByteSeg.ofByteVec (ofU32BE kp),
    ByteSeg.ofByteVec (ofU32BE chainIdx)])

namespace Wots

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

end Wots
end SphincsCVerify.Spec
