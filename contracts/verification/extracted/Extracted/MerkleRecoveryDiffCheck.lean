/- Execute actual extracted and verifier computations against production Rust.
   The corpus covers every nine-bit branch pattern and full-width boundaries. -/
import Extracted.MerkleRecoveryBridge
import Extracted.MerkleRecoveryDiffVectors

namespace MerkleRecoveryDiff
open Aeneas Aeneas.Std Extracted.Equiv

def word (bs : _root_.Array UInt8) : Option (Std.Array Std.U8 32#usize) :=
  let l := bs.toList.map Sha256Pure.ofUInt8
  if h : l.length = 32 then some ⟨l, by simpa using h⟩ else none

def node (bs : _root_.Array UInt8) : Option (Std.Array Std.U8 16#usize) :=
  let l := bs.toList.map Sha256Pure.ofUInt8
  if h : l.length = 16 then some ⟨l, by simpa using h⟩ else none

def path (bs : _root_.Array (_root_.Array UInt8)) :
    Option (Std.Array (Std.Array Std.U8 16#usize) 9#usize) := do
  let l ← bs.toList.mapM node
  if h : l.length = 9 then some ⟨l, by simpa using h⟩ else none

def recoveryRun (seedBytes : _root_.Array UInt8) (layer tree idx : Nat)
    (leafBytes : _root_.Array UInt8) (authBytes : _root_.Array (_root_.Array UInt8)) :
    Option (_root_.Array UInt8 × _root_.Array UInt8) := do
  if layer ≥ 2^32 || tree ≥ 2^64 || idx ≥ 2^32 then none else do
    let s ← word seedBytes
    let leaf ← node leafBytes
    let auth ← path authBytes
    match sphincs_c10.merkle.verify_auth_path s ⟨BitVec.ofNat 32 layer⟩
        ⟨BitVec.ofNat 64 tree⟩ leaf ⟨BitVec.ofNat 32 idx⟩ auth with
    | .ok r => some ((toSpecNode r).data,
        (SphincsCVerify.Spec.Hypertree.verifyAuthPath (toSpecDigest s)
          (UInt32.ofNat layer) (UInt64.ofNat tree) (toSpecNode leaf) idx
          (auth.val.map toSpecNode).toArray).data)
    | _ => none

def pairRun (seedBytes adrsBytes leftBytes rightBytes : _root_.Array UInt8) :
    Option (_root_.Array UInt8 × _root_.Array UInt8) := do
  let s ← word seedBytes
  let a ← word adrsBytes
  let l ← word leftBytes
  let r ← word rightBytes
  match sphincs_c10.hash.th_pair s a l r with
  | .ok out => some ((toSpecNode out).data,
      (SphincsCVerify.Spec.thPair (toSpecDigest s) (toSpecDigest a)
        (toSpecDigest l) (toSpecDigest r)).data)
  | _ => none

def agrees (result : Option (_root_.Array UInt8 × _root_.Array UInt8))
    (expected : _root_.Array UInt8) : Bool :=
  match result with
  | some (actual, specification) => actual == expected && specification == expected
  | none => false

def check : IO Unit := do
  unless recoveryVectors.size == 528 && pairVectors.length == 6 do
    throw (IO.userError "Merkle recovery corpus inventory changed")
  for (l,t,i,expected) in recoveryVectors do
    let result := recoveryRun seed l t i leaf auth
    unless expected.size == 16 && agrees result expected do
      throw (IO.userError "Merkle recovery Rust/extracted/verifier mismatch")
    for j in [0,15] do
      if agrees result (expected.set! j (expected[j]! ^^^ 1)) then
        throw (IO.userError "Merkle recovery changed-output control accepted")
  for (l,r,expected) in pairVectors do
    let result := pairRun seed pairAdrs l r
    unless expected.size == 16 && agrees result expected do
      throw (IO.userError "Pair hash Rust/extracted/verifier mismatch")
    for j in [0,15] do
      if agrees result (expected.set! j (expected[j]! ^^^ 1)) then
        throw (IO.userError "Pair hash changed-output control accepted")
  let (l,t,i,_) := recoveryVectors[0]!
  let (left,right,_) := pairVectors.head!
  unless recoveryRun #[] l t i leaf auth == none &&
      recoveryRun seed l t i #[] auth == none &&
      recoveryRun seed l t i leaf #[] == none &&
      recoveryRun seed l t i leaf (auth.set! 0 #[]) == none &&
      recoveryRun seed (2^32) t i leaf auth == none &&
      recoveryRun seed l (2^64) i leaf auth == none &&
      recoveryRun seed l t (2^32) leaf auth == none &&
      pairRun #[] pairAdrs left right == none &&
      pairRun seed #[] left right == none &&
      pairRun seed pairAdrs #[] right == none &&
      pairRun seed pairAdrs left #[] == none do
    throw (IO.userError "Merkle malformed input control accepted")
  IO.println "OK: 528 recovery + 6 pair-hash Rust/extracted/verifier cases; 1068 changed-output and 11 malformed-input controls"

#eval check
end MerkleRecoveryDiff
