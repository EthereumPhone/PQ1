/- Executable comparison of the actual extraction, pure model, faithful spec,
   and independently assembled Rust byte-oracle corpus. -/
import Extracted.WotsSecretBridge
import Extracted.WotsSecretDiffVectors
namespace WotsSecretDiff
open Aeneas Aeneas.Std Extracted.Equiv SphincsCVerify.Spec

def bytes (n : Std.Usize) (xs : _root_.Array UInt8) : Option (Std.Array Std.U8 n) :=
  if h : xs.size = n.val then
    some ⟨xs.toList.map (fun x => ⟨BitVec.ofNat 8 x.toNat⟩), by simpa using h⟩
  else none

def run (sk : _root_.Array UInt8) (layer tree kp chain : Nat) : Option (_root_.Array UInt8) := do
  let s ← bytes 32#usize sk
  if layer ≥ 2^32 || tree ≥ 2^64 || kp ≥ 2^32 || chain ≥ 2^32 then none else do
    let l : Std.U32 := ⟨BitVec.ofNat 32 layer⟩
    let t : Std.U64 := ⟨BitVec.ofNat 64 tree⟩
    let k : Std.U32 := ⟨BitVec.ofNat 32 kp⟩
    let c : Std.U32 := ⟨BitVec.ofNat 32 chain⟩
    match sphincs_c10.hash.wots_secret s l t k c with
    | .ok result =>
      let actual := (toSpecNode result).data
      if actual != (toSpecNode (wotsSecretPure s l t k c)).data ||
          actual != (wotsSecret (toSpecDigest s) (UInt32.ofNat layer) (UInt64.ofNat tree)
            (UInt32.ofNat kp) (UInt32.ofNat chain)).data then none else some actual
    | _ => none

def agrees (result : Option (_root_.Array UInt8)) (v : Vector) : Bool :=
  v.result.size == 16 && result == some v.result

def check : IO Unit := do
  unless vectors.length == 195 do throw (IO.userError "secret corpus inventory changed")
  for v in vectors do
    let result := run v.sk v.layer v.tree v.kp v.chain
    unless agrees result v do throw (IO.userError "WOTS secret disagreement")
    for j in [0,15] do
      if agrees result {v with result := v.result.set! j (v.result[j]! ^^^ 1)} then
        throw (IO.userError "altered secret output accepted")
    unless !(agrees result {v with result := v.sk}) do
      throw (IO.userError "wrong secret output width accepted")
  let v := vectors.head!
  unless (run #[] v.layer v.tree v.kp v.chain).isNone &&
      (run (v.sk.push 0) v.layer v.tree v.kp v.chain).isNone &&
      (run v.sk (2^32) v.tree v.kp v.chain).isNone &&
      (run v.sk v.layer (2^64) v.kp v.chain).isNone &&
      (run v.sk v.layer v.tree (2^32) v.chain).isNone &&
      (run v.sk v.layer v.tree v.kp (2^32)).isNone do
    throw (IO.userError "malformed secret input accepted")
  IO.println "OK: 195 actual/pure/vendored WOTS secret executions; 390 value, 195 width, 6 malformed controls"
#eval check
end WotsSecretDiff
