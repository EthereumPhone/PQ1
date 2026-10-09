/- Actual full-width authentication tree and recovery versus the Rust oracle. -/
import Extracted.XmssAuthRecovery
import Extracted.XmssAuthDiffVectors

namespace XmssAuthDiff
open Aeneas Aeneas.Std Extracted.Equiv

def bytes (n : Std.Usize) (xs : _root_.Array UInt8) : Option (Std.Array Std.U8 n) :=
  if h : xs.size = n.val then
    some ⟨xs.toList.map (fun x => ⟨BitVec.ofNat 8 x.toNat⟩), by simpa using h⟩
  else none

def pathBytes (xs : _root_.Array (_root_.Array UInt8)) :
    Option (Std.Array (Std.Array Std.U8 16#usize) 9#usize) := do
  let rows ← xs.toList.mapM (bytes 16#usize)
  if h : rows.length = 9 then some ⟨rows, by simpa using h⟩ else none

structure Output where
  root : _root_.Array UInt8
  node : _root_.Array UInt8
  path : _root_.Array (_root_.Array UInt8)
  recovered : _root_.Array UInt8

def recover (v : Vector) (node : _root_.Array UInt8)
    (path : _root_.Array (_root_.Array UInt8)) (leaf : Nat) : Option (_root_.Array UInt8) := do
  let seed ← bytes 32#usize v.seed
  let nd ← bytes 16#usize node
  let siblings ← pathBytes path
  if v.layer ≥ 2^32 || v.tree ≥ 2^64 || leaf ≥ 512 then none else do
    match sphincs_c10.merkle.verify_auth_path seed
        (⟨BitVec.ofNat 32 v.layer⟩ : Std.U32) (⟨BitVec.ofNat 64 v.tree⟩ : Std.U64)
        nd (⟨BitVec.ofNat 32 leaf⟩ : Std.U32) siblings with
    | .ok result => some (toSpecNode result).data
    | _ => none

def run (v : Vector) : Option Output := do
  let seed ← bytes 32#usize v.seed
  let sk ← bytes 32#usize v.sk
  if v.layer ≥ 2^32 || v.tree ≥ 2^64 || v.leaf ≥ 512 || v.lo ≥ 256 || v.hi ≥ 256 then none else do
    let layer : Std.U32 := ⟨BitVec.ofNat 32 v.layer⟩
    let tree : Std.U64 := ⟨BitVec.ofNat 64 v.tree⟩
    let leaf : Std.U32 := ⟨BitVec.ofNat 32 v.leaf⟩
    let lo : Std.U8 := ⟨BitVec.ofNat 8 v.lo⟩
    let hi : Std.U8 := ⟨BitVec.ofNat 8 v.hi⟩
    let (path, root) ← match sphincs_c10.merkle.build_subtree_with_auth seed sk layer tree leaf () lo hi with
      | .ok result => some result
      | _ => none
    let node ← match sphincs_c10.wots.keygen_pk seed sk layer tree leaf with
      | .ok result => some (toSpecNode result).data
      | _ => none
    let rows := (path.val.map (fun p => (toSpecNode p).data)).toArray
    let recovered ← recover v node rows v.leaf
    some ⟨(toSpecNode root).data, node, rows, recovered⟩

def agrees (out : Output) (v : Vector) : Bool :=
  v.root.size == 16 && v.node.size == 16 && v.path.size == 9 &&
  v.path.all (fun row => row.size == 16) &&
  out.root == v.root && out.node == v.node && out.path == v.path && out.recovered == v.root

def check : IO Unit := do
  unless vectors.length == 1 do throw (IO.userError "XMSS auth corpus inventory changed")
  let v := vectors.head!
  unless v.layer > 2^31 && v.tree > 2^63 && v.leaf == 341 do
    throw (IO.userError "XMSS auth full-width fixture changed")
  let some out := run v | throw (IO.userError "actual XMSS authentication failed")
  unless agrees out v do throw (IO.userError "XMSS authentication/oracle disagreement")
  for j in [0,15] do
    if agrees out {v with root := v.root.set! j (v.root[j]! ^^^ 1)} ||
        agrees out {v with node := v.node.set! j (v.node[j]! ^^^ 1)} then
      throw (IO.userError "altered XMSS root or leaf accepted")
    let changed := out.node.set! j (out.node[j]! ^^^ 1)
    let some got := recover v changed out.path v.leaf | throw (IO.userError "changed-leaf recovery failed")
    unless got != v.root do throw (IO.userError "changed leaf recovered original root")
  for h in [:9] do
    for j in [0,15] do
      let row := v.path[h]!
      let changed := v.path.set! h (row.set! j (row[j]! ^^^ 1))
      if agrees out {v with path := changed} then throw (IO.userError "altered XMSS sibling accepted")
      let some got := recover v out.node changed v.leaf | throw (IO.userError "changed-sibling recovery failed")
      unless got != v.root do throw (IO.userError "changed sibling recovered original root")
    if agrees out {v with path := v.path.set! h v.seed} then
      throw (IO.userError "wrong sibling width accepted")
  for changed in [
      {v with root := #[]}, {v with root := v.seed},
      {v with node := #[]}, {v with node := v.seed},
      {v with path := #[]}, {v with path := v.path.extract 0 8},
      {v with path := v.path.push v.node}] do
    if agrees out changed then throw (IO.userError "wrong XMSS output shape accepted")
  let some wrongLeaf := recover v out.node out.path (v.leaf ^^^ 1)
    | throw (IO.userError "wrong-index recovery failed")
  unless wrongLeaf != v.root do throw (IO.userError "wrong index recovered original root")
  for changed in [
      {v with seed := #[]}, {v with seed := v.seed.push 0},
      {v with sk := #[]}, {v with sk := v.sk.push 0},
      {v with layer := 2^32}, {v with tree := 2^64},
      {v with leaf := 512}, {v with leaf := 2^32},
      {v with lo := 256}, {v with hi := 256}] do
    unless (run changed).isNone do throw (IO.userError "malformed XMSS auth input accepted")
  IO.println "OK: actual full-width XMSS path/root/WOTS leaf/recovery versus independent Rust oracle; 22 value, 16 shape, 10 malformed-input controls; 21 altered-value/wrong-index recoveries differ"
#eval check
end XmssAuthDiff
