/- Actual Rust extraction, pure trees and faithful signer paths on independent byte-oracle cases. -/
import Extracted.ForsAuthBridge
import Extracted.ForsAuthDiffVectors
namespace ForsAuthDiff
open Aeneas Aeneas.Std Extracted.Equiv SphincsCVerify.Spec

def bytes (n : Std.Usize) (xs : _root_.Array UInt8) : Option (Std.Array Std.U8 n) :=
  if h : xs.size = n.val then
    some ⟨xs.toList.map (fun x => ⟨BitVec.ofNat 8 x.toNat⟩), by simpa using h⟩
  else none

def run (seed sk : _root_.Array UInt8) (ht tree leaf : Nat) :
    Option (_root_.Array UInt8 × _root_.Array (_root_.Array UInt8)) := do
  let s ← bytes 32#usize seed
  let k ← bytes 32#usize sk
  if ht ≥ 2^32 || tree ≥ 2^32 || leaf ≥ 2048 then none else do
    let h : Std.U32 := ⟨BitVec.ofNat 32 ht⟩
    let t : Std.U32 := ⟨BitVec.ofNat 32 tree⟩
    let l : Std.U32 := ⟨BitVec.ofNat 32 leaf⟩
    match sphincs_c10.fors.sign_fors_tree s k h t l with
    | .ok (secret, path) =>
      let actualSecret := (toSpecNode secret).data
      let actual := (path.val.map (fun v => (toSpecNode v).data)).toArray
      let pure := _root_.Array.ofFn (n := 11) fun i =>
        (toSpecNode (forsRootNode s k h t i.val (forsAuthSibling leaf i.val))).data
      let reference := (forsMtAuthPath (toSpecDigest s) (UInt64.ofNat ht) (UInt32.ofNat tree)
        (fun j => forsSecret (toSpecDigest k) (UInt32.ofNat ht) (UInt32.ofNat tree) (UInt32.ofNat j)) leaf).map (·.data)
      if actualSecret != (toSpecNode (forsSecretPure k h t l)).data ||
          actualSecret != (forsSecret (toSpecDigest k) (UInt32.ofNat ht) (UInt32.ofNat tree) (UInt32.ofNat leaf)).data ||
          actual != pure || actual != reference then none
      else some (actualSecret, actual)
    | _ => none

def agrees (result : Option (_root_.Array UInt8 × _root_.Array (_root_.Array UInt8))) (v : Vector) : Bool :=
  v.secret.size == 16 && v.path.size == 11 && v.path.all (fun n => n.size == 16) &&
    result == some (v.secret, v.path)

def check : IO Unit := do
  unless vectors.length == 23 do throw (IO.userError "auth corpus inventory changed")
  for v in vectors do
    let result := run v.seed v.sk v.ht v.tree v.leaf
    unless agrees result v do throw (IO.userError "FORS authentication-path disagreement")
    for j in [0,15] do
      if agrees result {v with secret := v.secret.set! j (v.secret[j]! ^^^ 1)} then
        throw (IO.userError "altered secret accepted")
      for h in [:11] do
        let n := v.path[h]!
        if agrees result {v with path := v.path.set! h (n.set! j (n[j]! ^^^ 1))} then
          throw (IO.userError "altered sibling accepted")
    for bad in [v.path.pop, v.path.push v.path[0]!] do
      if agrees result {v with path := bad} then throw (IO.userError "wrong path length accepted")
    for h in [:11] do
      if agrees result {v with path := v.path.set! h #[]} then
        throw (IO.userError "wrong sibling width accepted")
    if agrees result {v with secret := v.sk} then throw (IO.userError "wrong secret width accepted")
  let v := vectors.head!
  unless (run #[] v.sk v.ht v.tree v.leaf).isNone &&
      (run (v.seed.push 0) v.sk v.ht v.tree v.leaf).isNone &&
      (run v.seed #[] v.ht v.tree v.leaf).isNone &&
      (run v.seed (v.sk.push 0) v.ht v.tree v.leaf).isNone &&
      (run v.seed v.sk (2^32) v.tree v.leaf).isNone &&
      (run v.seed v.sk v.ht (2^32) v.leaf).isNone &&
      (run v.seed v.sk v.ht v.tree 2048).isNone &&
      (run v.seed v.sk v.ht v.tree (2^32)).isNone do
    throw (IO.userError "malformed auth input accepted")
  IO.println "OK: 23 actual/pure/vendored secrets and paths; 552 value, 46 path-length, 276 width, 8 malformed controls"
#eval check
end ForsAuthDiff
