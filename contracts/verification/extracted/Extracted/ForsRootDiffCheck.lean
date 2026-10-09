/- Actual extracted stack execution versus pure and faithful recursive trees,
   independently generated Rust byte-oracle roots, and the corrected final slot. -/
import Extracted.ForsRootBridge
import Extracted.ForsRootDiffVectors
namespace ForsRootDiff
open Aeneas Aeneas.Std Extracted.Equiv SphincsCVerify.Spec

def bytes (n : Std.Usize) (xs : _root_.Array UInt8) : Option (Std.Array Std.U8 n) :=
  if h : xs.size = n.val then
    some ⟨xs.toList.map (fun x => ⟨BitVec.ofNat 8 x.toNat⟩), by simpa using h⟩
  else none

def run (seed sk : _root_.Array UInt8) (ht tree : Nat) : Option (_root_.Array UInt8) := do
  let s ← bytes 32#usize seed
  let k ← bytes 32#usize sk
  if ht ≥ 2^32 || tree ≥ 2^32 then none else do
    let h : Std.U32 := ⟨BitVec.ofNat 32 ht⟩
    let t : Std.U32 := ⟨BitVec.ofNat 32 tree⟩
    match sphincs_c10.fors.compute_fors_root s k h t with
    | .ok result =>
      let actual := (toSpecNode result).data
      let reference := forsMtNode (toSpecDigest s) (UInt64.ofNat ht) (UInt32.ofNat tree)
        (fun j => forsSecret (toSpecDigest k) (UInt32.ofNat ht) (UInt32.ofNat tree) (UInt32.ofNat j)) A 0
      if actual != (toSpecNode (forsRootNode s k h t 11 0)).data || actual != reference.data then none
      else if actual == (forsSecret (toSpecDigest k) (UInt32.ofNat ht) (UInt32.ofNat tree) 0).data then none
      else if tree == 12 && actual != (Signer.forsSigningValue (toSpecDigest s) (toSpecDigest k) ht tree 0).data then none
      else some actual
    | _ => none

def agrees (result : Option (_root_.Array UInt8)) (v : Vector) : Bool :=
  v.result.size == 16 && result == some v.result

def check : IO Unit := do
  unless vectors.length == 21 do throw (IO.userError "root corpus inventory changed")
  for v in vectors do
    let result := run v.seed v.sk v.ht v.tree
    unless agrees result v do throw (IO.userError "FORS root disagreement")
    for j in [0,15] do
      if agrees result {v with result := v.result.set! j (v.result[j]! ^^^ 1)} then
        throw (IO.userError "altered root output accepted")
    if agrees result {v with result := v.sk} then
      throw (IO.userError "wrong root width accepted")
  let v := vectors.head!
  unless (run #[] v.sk v.ht v.tree).isNone && (run (v.seed.push 0) v.sk v.ht v.tree).isNone &&
      (run v.seed #[] v.ht v.tree).isNone && (run v.seed (v.sk.push 0) v.ht v.tree).isNone &&
      (run v.seed v.sk (2^32) v.tree).isNone && (run v.seed v.sk v.ht (2^32)).isNone do
    throw (IO.userError "malformed root input accepted")
  IO.println "OK: 21 actual/pure/vendored roots; 42 value, 21 width, 6 malformed controls; old final leaf rule rejected"
#eval check
end ForsRootDiff
