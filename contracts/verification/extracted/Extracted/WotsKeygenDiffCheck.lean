/- Actual key-generation extraction versus the Rust byte oracle and faithful spec. -/
import Extracted.WotsKeygenBridge
import Extracted.WotsKeygenDiffVectors
namespace WotsKeygenDiff
open Aeneas Aeneas.Std Extracted.Equiv SphincsCVerify.Spec

def bytes (n : Std.Usize) (xs : _root_.Array UInt8) : Option (Std.Array Std.U8 n) :=
  if h : xs.size = n.val then
    some ⟨xs.toList.map (fun x => ⟨BitVec.ofNat 8 x.toNat⟩), by simpa using h⟩
  else none

def run (seed sk : _root_.Array UInt8) (layer tree kp : Nat) : Option (_root_.Array UInt8) := do
  let s ← bytes 32#usize seed
  let secret ← bytes 32#usize sk
  if layer ≥ 2^32 || tree ≥ 2^64 || kp ≥ 2^32 then none else do
    let l : Std.U32 := ⟨BitVec.ofNat 32 layer⟩
    let t : Std.U64 := ⟨BitVec.ofNat 64 tree⟩
    let k : Std.U32 := ⟨BitVec.ofNat 32 kp⟩
    match sphincs_c10.wots.keygen_pk s secret l t k with
    | .ok result =>
      let actual := (toSpecNode result).data
      if actual != (toSpecNode (wotsKeygenPure s secret l t k)).data ||
          actual != (Wots.keygenPk (toSpecDigest s) (toSpecDigest secret)
            (UInt32.ofNat layer) (UInt64.ofNat tree) (UInt32.ofNat kp)).data then
        none else some actual
    | _ => none

def agrees (result : Option (_root_.Array UInt8)) (v : Vector) : Bool :=
  v.result.size == 16 && result == some v.result

def check : IO Unit := do
  unless vectors.length == 195 do throw (IO.userError "keygen corpus inventory changed")
  for v in vectors do
    let result := run v.seed v.sk v.layer v.tree v.kp
    unless agrees result v do throw (IO.userError "WOTS keygen disagreement")
    for j in [0,15] do
      if agrees result {v with result := v.result.set! j (v.result[j]! ^^^ 1)} then
        throw (IO.userError "altered keygen output accepted")
    unless !(agrees result {v with result := v.seed}) do
      throw (IO.userError "wrong keygen output width accepted")
  let v := vectors.head!
  unless (run #[] v.sk v.layer v.tree v.kp).isNone &&
      (run (v.seed.push 0) v.sk v.layer v.tree v.kp).isNone &&
      (run v.seed #[] v.layer v.tree v.kp).isNone &&
      (run v.seed (v.sk.push 0) v.layer v.tree v.kp).isNone &&
      (run v.seed v.sk (2^32) v.tree v.kp).isNone &&
      (run v.seed v.sk v.layer (2^64) v.kp).isNone &&
      (run v.seed v.sk v.layer v.tree (2^32)).isNone do
    throw (IO.userError "malformed keygen input accepted")
  IO.println "OK: 195 actual/pure/vendored WOTS keygen executions; 390 value, 195 width, 7 malformed controls"
#eval check
end WotsKeygenDiff
