/- Executable comparison of the actual extraction, pure model, faithful spec,
   and independently assembled Rust byte-oracle corpus. -/
import Extracted.ForsSecretBridge
import Extracted.ForsSecretDiffVectors
namespace ForsSecretDiff
open Aeneas Aeneas.Std Extracted.Equiv SphincsCVerify.Spec

def bytes (n : Std.Usize) (xs : _root_.Array UInt8) : Option (Std.Array Std.U8 n) :=
  if h : xs.size = n.val then
    some ⟨xs.toList.map (fun x => ⟨BitVec.ofNat 8 x.toNat⟩), by simpa using h⟩
  else none

def run (sk : _root_.Array UInt8) (ht tree leaf : Nat) : Option (_root_.Array UInt8) := do
  let s ← bytes 32#usize sk
  if ht ≥ 2^32 || tree ≥ 2^32 || leaf ≥ 2^32 then none else do
    let h : Std.U32 := ⟨BitVec.ofNat 32 ht⟩
    let t : Std.U32 := ⟨BitVec.ofNat 32 tree⟩
    let l : Std.U32 := ⟨BitVec.ofNat 32 leaf⟩
    match sphincs_c10.hash.fors_secret s h t l with
    | .ok result =>
      let actual := (toSpecNode result).data
      if actual != (toSpecNode (forsSecretPure s h t l)).data ||
          actual != (forsSecret (toSpecDigest s) (UInt32.ofNat ht)
            (UInt32.ofNat tree) (UInt32.ofNat leaf)).data then none else some actual
    | _ => none

def agrees (result : Option (_root_.Array UInt8)) (v : Vector) : Bool :=
  v.result.size == 16 && result == some v.result

def check : IO Unit := do
  unless vectors.length == 131 do throw (IO.userError "secret corpus inventory changed")
  for v in vectors do
    let result := run v.sk v.ht v.tree v.leaf
    unless agrees result v do throw (IO.userError "FORS secret disagreement")
    for j in [0,15] do
      if agrees result {v with result := v.result.set! j (v.result[j]! ^^^ 1)} then
        throw (IO.userError "altered secret output accepted")
    unless !(agrees result {v with result := v.sk}) do
      throw (IO.userError "wrong secret output width accepted")
  let v := vectors.head!
  unless (run #[] v.ht v.tree v.leaf).isNone &&
      (run (v.sk.push 0) v.ht v.tree v.leaf).isNone &&
      (run v.sk (2^32) v.tree v.leaf).isNone &&
      (run v.sk v.ht (2^32) v.leaf).isNone &&
      (run v.sk v.ht v.tree (2^32)).isNone do
    throw (IO.userError "malformed secret input accepted")
  IO.println "OK: 131 actual/pure/vendored FORS secret executions; 262 value, 131 width, 5 malformed controls"
#eval check
end ForsSecretDiff
