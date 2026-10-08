/- Execute the actual extracted forest loop, compression and full refusal branch. -/
import Extracted.ForsRejectSpec
import Extracted.ForsForestDiffVectors
namespace ForsForestDiff
open Aeneas Aeneas.Std Extracted.Equiv
def word (bs : _root_.Array UInt8) : Option (Std.Array Std.U8 32#usize) :=
  let l := bs.toList.map Sha256Pure.ofUInt8
  if h : l.length = 32 then some ⟨l, by simpa using h⟩ else none

def node (bs : _root_.Array UInt8) : Option (Std.Array Std.U8 16#usize) :=
  let l := bs.toList.map Sha256Pure.ofUInt8
  if h : l.length = 16 then some ⟨l, by simpa using h⟩ else none

def path (bs : _root_.Array (_root_.Array UInt8)) :
    Option (Std.Array (Std.Array Std.U8 16#usize) 11#usize) := do
  let l ← bs.toList.mapM node
  if h : l.length = 11 then some ⟨l, by simpa using h⟩ else none


def roots (bs : _root_.Array (_root_.Array UInt8)) :
    Option (Std.Array (Std.Array Std.U8 16#usize) 13#usize) := do
  let l ← bs.toList.mapM node
  if h : l.length = 13 then some ⟨l, by simpa using h⟩ else none

def auths (bs : _root_.Array (_root_.Array (_root_.Array UInt8))) :
    Option (Std.Array (Std.Array (Std.Array Std.U8 16#usize) 11#usize) 12#usize) := do
  let l ← bs.toList.mapM path
  if h : l.length = 12 then some ⟨l, by simpa using h⟩ else none

def indexArray (bs : _root_.Array Nat) : Option (Std.Array Std.U32 13#usize) := do
  if bs.any (· ≥ 2^32) then none else do
    let l := bs.toList.map (fun n => (⟨BitVec.ofNat 32 n⟩ : Std.U32))
    if h : l.length = 13 then some ⟨l, by simpa using h⟩ else none

def run (seedBytes : _root_.Array UInt8) (ht : Nat) (is : _root_.Array Nat)
    (secretBytes initialBytes : _root_.Array (_root_.Array UInt8))
    (pathBytes : _root_.Array (_root_.Array (_root_.Array UInt8))) :
    Option (_root_.Array (_root_.Array UInt8) × _root_.Array (_root_.Array UInt8) ×
      _root_.Array UInt8 × _root_.Array UInt8) := do
  if ht ≥ 2^32 then none else do
    let s ← word seedBytes
    let secrets ← roots secretBytes
    let initial ← roots initialBytes
    let paths ← auths pathBytes
    let indices ← indexArray is
    let h : Std.U32 := ⟨BitVec.ofNat 32 ht⟩
    match sphincs_c10.hypertree.verify_loop2 {start := 0#usize, «end» := 12#usize}
        s indices h secrets initial paths with
    | .ok rs =>
      match sphincs_c10.fors.compute_fors_pk s h rs with
      | .ok pk =>
        let vs : _root_.Array (SphincsCVerify.Spec.ByteVec 16) := _root_.Array.ofFn fun j : Fin 13 =>
          if j.val < 12 then forsNormalRoot s h indices secrets paths j.val
          else toSpecNode (initial.val[j.val]!)
        some ((rs.val.map (fun n => (toSpecNode n).data)).toArray, vs.map (·.data),
          (toSpecNode pk).data,
          (SphincsCVerify.Spec.Fors.computeForsPk (toSpecDigest s) (UInt64.ofNat ht) vs).data)
      | _ => none
    | _ => none

def agrees (result : Option (_root_.Array (_root_.Array UInt8) × _root_.Array (_root_.Array UInt8) ×
    _root_.Array UInt8 × _root_.Array UInt8))
    (rs : _root_.Array (_root_.Array UInt8)) (pk : _root_.Array UInt8) : Bool :=
  match result with
  | some (actual, specification, actualPk, specificationPk) =>
    actual == rs && specification == rs && actualPk == pk && specificationPk == pk
  | none => false

def rejectCheck (c last : Nat) : Bool := Id.run do
  let seed : Std.Array Std.U8 16#usize := ⟨(List.range 16).map (fun i => ⟨BitVec.ofNat 8 (i*7+2)⟩), by simp⟩
  let root : Std.Array Std.U8 16#usize := ⟨(List.range 16).map (fun i => ⟨BitVec.ofNat 8 (i*11+5)⟩), by simp⟩
  let msg : Std.Array Std.U8 32#usize := ⟨(List.range 32).map (fun i => ⟨BitVec.ofNat 8 (c*19+i*13)⟩), by simp⟩
  let sig : Std.Array Std.U8 4008#usize := ⟨(List.range 4008).map (fun i => ⟨BitVec.ofNat 8 (c*29+i*37+3)⟩), by simp⟩
  match sphincs_c10.fors.extract_fors_indices (verifierDigest seed root msg sig) with
  | .ok indices =>
    if last == 0 || (indices.val[12]!).val != last then return false
    match sphincs_c10.hypertree.verify seed root msg sig with
    | .ok false => return true
    | _ => return false
  | _ => return false

def check : IO Unit := do
  unless vectors.size == 32 && rejectVectors.size == 16 do
    throw (IO.userError "FORS forest corpus inventory changed")
  for (ht, ins, expectedRoots, pk) in vectors do
    let result := run seed ht ins secrets initial paths
    unless expectedRoots.size == 13 && expectedRoots.all (·.size == 16) && pk.size == 16 &&
        agrees result expectedRoots pk do
      throw (IO.userError "FORS forest production/extracted/verifier mismatch")
    for j in [:13] do
      let bad := expectedRoots.set! j (expectedRoots[j]!.set! 0 ((expectedRoots[j]!)[0]! ^^^ 1))
      if agrees result bad pk then throw (IO.userError "changed root accepted")
    for j in [0,15] do
      if agrees result expectedRoots (pk.set! j (pk[j]! ^^^ 1)) then
        throw (IO.userError "changed compression accepted")
  for (c,last) in rejectVectors do
    unless rejectCheck c last && !(rejectCheck c (last ^^^ 1)) do
      throw (IO.userError "actual verifier refusal or altered-digest control failed")
  let (ht,ins,_,_) := vectors[0]!
  unless run #[] ht ins secrets initial paths == none &&
      run seed (2^32) ins secrets initial paths == none &&
      run seed ht #[] secrets initial paths == none &&
      run seed ht (ins.set! 0 (2^32)) secrets initial paths == none &&
      run seed ht ins #[] initial paths == none &&
      run seed ht ins secrets #[] paths == none &&
      run seed ht ins secrets initial #[] == none &&
      run seed ht ins (secrets.set! 0 #[]) initial paths == none &&
      run seed ht ins secrets initial (paths.set! 0 #[]) == none &&
      run seed ht ins secrets initial (paths.set! 0 (paths[0]!.set! 0 #[])) == none do
    throw (IO.userError "malformed forest input accepted")
  IO.println "OK: 32 forest/compression cases, 16 whole-verifier refusals; 480 altered-output, 16 altered-digest and 10 malformed-input controls"
#eval check
end ForsForestDiff
