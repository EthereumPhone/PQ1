/- Actual extracted forest/recovery versus independent Rust byte oracles.
   Bounded execution is not a backend-equivalence proof. -/
import Extracted.SignForestPrefix
import Extracted.SignForestDiffVectors
namespace SignForestDiff
open Aeneas Aeneas.Std Extracted.Equiv

def bytes (n : Std.Usize) (xs : _root_.Array UInt8) : Option (Std.Array Std.U8 n) :=
  if h : xs.size = n.val then
    some ⟨xs.toList.map (fun x => ⟨BitVec.ofNat 8 x.toNat⟩), by simpa using h⟩
  else none

def rows (n : Std.Usize) (xs : _root_.Array (_root_.Array UInt8)) :
    Option (Std.Array (Std.Array Std.U8 16#usize) n) := do
  let rs ← xs.toList.mapM (bytes 16#usize)
  if h : rs.length = n.val then some ⟨rs, h⟩ else none

def paths (xs : _root_.Array (_root_.Array (_root_.Array UInt8))) : Option SignForestPaths := do
  let rs ← xs.toList.mapM (rows 11#usize)
  if h : rs.length = 12 then some ⟨rs, by simpa using h⟩ else none

def indices (xs : _root_.Array Nat) : Option (Std.Array Std.U32 13#usize) :=
  if h : xs.size = 13 then
    if xs.all (· < 2^32) && (xs.extract 0 12).all (· < 2048) then
      some ⟨xs.toList.map (fun x => ⟨BitVec.ofNat 32 x⟩), by simpa using h⟩
    else none
  else none

def rowBytes {n : Std.Usize} (xs : Std.Array (Std.Array Std.U8 16#usize) n) :=
  (xs.val.map (fun x => (toSpecNode x).data)).toArray

structure Output where
  roots : _root_.Array (_root_.Array UInt8)
  secrets : _root_.Array (_root_.Array UInt8)
  paths : _root_.Array (_root_.Array (_root_.Array UInt8))
  pk : _root_.Array UInt8
  recovered : _root_.Array UInt8

def recover (v : Vector) (ss : _root_.Array (_root_.Array UInt8))
    (ps : _root_.Array (_root_.Array (_root_.Array UInt8))) : Option (_root_.Array UInt8) := do
  let seed ← bytes 32#usize v.seed
  let ix ← indices v.indices
  let ss ← rows 13#usize ss
  let ps ← paths ps
  if v.ht ≥ 2^32 then none else
    match forsForestPhase seed (⟨BitVec.ofNat 32 v.ht⟩ : Std.U32) ix ss ps with
    | .ok result => some (toSpecNode result).data
    | _ => none

def run (v : Vector) : Option Output := do
  let seed ← bytes 32#usize v.seed
  let sk ← bytes 32#usize v.sk
  let shuffle ← bytes 32#usize v.shuffle
  let ix ← indices v.indices
  if v.ht ≥ 2^32 then none else do
    let ht : Std.U32 := ⟨BitVec.ofNat 32 v.ht⟩
    let (rs, ss, ps) ← match signerForsPhase seed sk ht ix () shuffle 12#usize with
      | .ok out => some out
      | _ => none
    let pk ← match sphincs_c10.fors.compute_fors_pk seed ht rs with
      | .ok out => some (toSpecNode out).data
      | _ => none
    let secretBytes := rowBytes ss
    let pathBytes := (ps.val.map rowBytes).toArray
    let recovered ← recover v secretBytes pathBytes
    some ⟨rowBytes rs, secretBytes, pathBytes, pk, recovered⟩

def agrees (out : Output) (v : Vector) : Bool :=
  out.roots == v.roots && out.secrets == v.secrets && out.paths == v.paths &&
  out.pk == v.pk && out.recovered == v.pk

def derive (v : DeriveVector) : Option (_root_.Array UInt8) := do
  let seed ← bytes 32#usize v.seed
  if h : v.label.size ≤ 256 then
    let label : Slice Std.U8 := ⟨v.label.toList.map (fun x => ⟨BitVec.ofNat 8 x.toNat⟩), by
      simp only [List.length_map, _root_.Array.length_toList]
      scalar_tac⟩
    match sphincs_c10.shuffle.ShuffleSeed.derive seed label with
    | .ok out => some (out.val.map (fun x => UInt8.ofNat x.val)).toArray
    | _ => none
  else none

def check : IO Unit := do
  unless vectors.length == 2 && derivations.length == 15 do
    throw (IO.userError "sign forest corpus inventory changed")
  unless vectors[1]!.ht == 2^32-1 && vectors[1]!.indices[12]! == 2^32-1 &&
      vectors[1]!.indices[0]! == 0 && vectors[1]!.indices[1]! == 2047 do
    throw (IO.userError "full-width/last-slot/boundary fixture changed")
  for d in derivations do
    unless derive d == some d.derived do throw (IO.userError "shuffle derivation mismatch")
    for j in [0,31] do
      if derive d == some (d.derived.set! j (d.derived[j]! ^^^ 1)) then
        throw (IO.userError "changed derivation accepted")
  for v in vectors do
    let some out := run v | throw (IO.userError "actual forest construction failed")
    unless agrees out v do throw (IO.userError s!"forest byte oracle mismatch: {v.label}")
    for t in [:13] do
      let changed := v.secrets.set! t (v.secrets[t]!.set! 0 ((v.secrets[t]!)[0]! ^^^ 1))
      if agrees out {v with secrets := changed} then throw (IO.userError "changed secret accepted")
      let some got := recover v changed v.paths | throw (IO.userError "changed-secret recovery failed")
      unless got != v.pk do throw (IO.userError "changed secret recovered original pk")
      if agrees out {v with roots := v.roots.set! t (v.roots[t]!.set! 15 ((v.roots[t]!)[15]! ^^^ 1))} then
        throw (IO.userError "changed root accepted")
    for t in [:12] do
      for h in [:11] do
        let row := (v.paths[t]!)[h]!
        let changed := v.paths.set! t (v.paths[t]!.set! h (row.set! 0 (row[0]! ^^^ 1)))
        if agrees out {v with paths := changed} then throw (IO.userError "changed sibling accepted")
        let some got := recover v v.secrets changed | throw (IO.userError "changed-sibling recovery failed")
        unless got != v.pk do throw (IO.userError "changed sibling recovered original pk")
    for changed in [{v with roots := #[]}, {v with secrets := v.secrets.extract 0 12},
        {v with paths := #[]}, {v with paths := v.paths.set! 0 #[]},
        {v with secrets := v.secrets.set! 12 v.seed}, {v with pk := #[]},
        {v with pk := v.pk.set! 0 (v.pk[0]! ^^^ 1)}] do
      if agrees out changed then throw (IO.userError "wrong output shape/value accepted")
    for changed in [{v with seed := #[]}, {v with sk := v.sk.push 0},
        {v with shuffle := #[]}, {v with ht := 2^32}, {v with indices := #[]},
        {v with indices := v.indices.set! 0 2048}, {v with indices := v.indices.set! 12 (2^32)}] do
      unless (run changed).isNone do throw (IO.userError "malformed forest input accepted")
  IO.println "OK: two actual forest/recovery/compression oracle cases; 15 derivations; 290 changed-secret/sibling recoveries differ; malformed inputs and altered expected outputs rejected"
#eval check
end SignForestDiff
