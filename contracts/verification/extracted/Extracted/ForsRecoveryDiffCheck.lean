/- Execute the extracted and verifier computations against the actual Rust helper. -/
import Extracted.ForsRecoveryBridge
import Extracted.ForsRecoveryDiffVectors
namespace ForsRecoveryDiff
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

def run (seedBytes : _root_.Array UInt8) (ht tree idx : Nat)
    (secretBytes : _root_.Array UInt8) (authBytes : _root_.Array (_root_.Array UInt8)) :
    Option (_root_.Array UInt8 × _root_.Array UInt8) := do
  if ht ≥ 2^32 || tree ≥ 2^32 || idx ≥ 2^32 then none else do
    let s ← word seedBytes
    let leaf ← node secretBytes
    let auth ← path authBytes
    match sphincs_c10.hypertree.reconstruct_fors_root s ⟨BitVec.ofNat 32 ht⟩
        ⟨BitVec.ofNat 32 tree⟩ ⟨BitVec.ofNat 32 idx⟩ leaf auth with
    | .ok r => some ((toSpecNode r).data,
        (SphincsCVerify.Spec.Fors.reconstructRoot (toSpecDigest s)
          (UInt64.ofNat ht) (UInt32.ofNat tree) (UInt32.ofNat idx) (toSpecNode leaf)
          (auth.val.map toSpecNode).toArray).data)
    | _ => none

def agrees (result : Option (_root_.Array UInt8 × _root_.Array UInt8))
    (expected : _root_.Array UInt8) : Bool :=
  match result with
  | some (actual, specification) => actual == expected && specification == expected
  | none => false

def check : IO Unit := do
  unless vectors.size == 2064 do throw (IO.userError "FORS recovery corpus inventory changed")
  for (ht,t,i,expected) in vectors do
    let result := run seed ht t i secret auth
    unless expected.size == 16 && agrees result expected do
      throw (IO.userError "FORS recovery Rust/extracted/verifier mismatch")
    for j in [0,15] do
      if agrees result (expected.set! j (expected[j]! ^^^ 1)) then
        throw (IO.userError "FORS recovery changed-output control accepted")
  let (ht,t,i,_) := vectors[0]!
  unless run #[] ht t i secret auth == none &&
      run seed ht t i #[] auth == none && run seed ht t i secret #[] == none &&
      run seed ht t i secret (auth.set! 0 #[]) == none &&
      run seed (2^32) t i secret auth == none &&
      run seed ht (2^32) i secret auth == none &&
      run seed ht t (2^32) secret auth == none do
    throw (IO.userError "FORS recovery malformed-input control accepted")
  IO.println "OK: 2064 FORS recovery Rust/extracted/verifier cases; 4128 changed-output and 7 malformed-input controls"
#eval check
end ForsRecoveryDiff
